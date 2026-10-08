//! Fitting one aircraft's clock model over its canonical window from ADS-B positions heard by two
//! or more of its scope's receivers, and calibrating a published model: one factorisation at its
//! estimate, from the raw it cites, for the covariance solutions need and the checks a verifier
//! makes. The specification is in the crate docs (§ The clock model); this file follows it step
//! for step, and every loop runs in a canonical order (`BTreeMap`, sorted vectors) so the output
//! does not depend on the order of the input.

use std::collections::{BTreeMap, BTreeSet};

use tally_wire::PublicKey;

use crate::banded::{At, Banded, Factor, Vector};
use crate::clock::{
    Bias, BiasKind, ClockKey, ClockModel, ClockPiece, DAY_NS, Jump, KNOT_PS, ModelTime, RATE_SCALE,
    SPEC_VERSION, Timebase,
};
use crate::geo::{self, C, Geodetic};
use crate::linalg::{self, Vec3};
use crate::modes;
use crate::obs::{ObservationId, Reception, Site};
use crate::scope::Inputs;

/// Why no clock model could be fitted or calibrated.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum FitError {
    #[error("no ADS-B position was heard by two receivers of the scope")]
    NoSyncEvents,
    #[error("the normal equations are not positive definite")]
    Singular,
    #[error("a counter jump remains after the most a fit splits")]
    UndeclaredJump,
    #[error("the model does not fit its own inputs: {0}")]
    Shape(&'static str),
    /// Clocks (receiver, counter epoch) none of whose receptions carries weight in a used event:
    /// nothing places them, so the fit drops them and starts over (`fit_read`); a verifier that
    /// meets one refuses the model.
    #[error("{} clocks carry no information", .0.len())]
    Uninformed(Vec<(PublicKey, u32)>),
}

/// Parts per million in one unit of `ClockModel::gauge_rate`.
const PPM_PER_RATE: f64 = 1e6 / RATE_SCALE as f64;

/// The most jumps one fit detects.
pub const MAX_JUMPS: usize = 4;
/// Huber's constant, in standard deviations.
pub const HUBER_K: f64 = 3.0;
/// A sync reception further than this many standard deviations from the fit gets weight zero.
pub const SYNC_CUTOFF: f64 = 10.0;
/// The jump statistic's threshold, in standard deviations of the clock's noise.
pub const JUMP_THRESHOLD: f64 = 8.0;
/// Receptions on each side of a candidate jump that the statistic compares.
pub const JUMP_SIDE: usize = 5;
/// The weakest horizontal prior a sync aircraft's position bias may have, metres (one standard
/// deviation).
pub const MAX_PRIOR_SIGMA_M: f64 = 100.0;
/// The floor on a sync aircraft's horizontal bias prior, metres.
pub const MIN_PRIOR_SIGMA_M: f64 = 5.0;
/// One standard deviation of a sync position about the aircraft's biased position, per axis,
/// metres: what changes from message to message (GNSS noise, the CPR resolution of about 5.1 m in
/// latitude, the report's latency). A GNSS position's error over a minute is mostly one bias, so
/// the declared accuracy is the bias's prior and only this is each message's own.
pub const MESSAGE_SIGMA_M: f64 = 3.0;
/// A GNSS height's bias prior, as a multiple of the horizontal one (vertical accuracy is about
/// half again worse).
pub const GNSS_HEIGHT_FACTOR: f64 = 1.5;
/// One standard deviation of a sync position's height about its reported altitude plus the
/// aircraft's own baro bias: 25 ft quantisation, latency and vertical rate.
pub const VERTICAL_SIGMA_M: f64 = 15.0;
/// One standard deviation of the difference between an aircraft's pressure altitude and its
/// height above the ellipsoid (weather and geoid), the prior on its bias.
pub const BARO_BIAS_SIGMA_M: f64 = 100.0;
/// The prior on each clock's rate over its first interval, and on a free-running gauge's rate,
/// parts per million.
pub const RATE_PRIOR_PPM: f64 = 200.0;
/// The prior on a GNSS-disciplined gauge's rate, parts per million.
pub const GNSS_GAUGE_RATE_PPM: f64 = 0.001;
/// The floor on a receiver's estimated timing noise, seconds.
pub const MIN_NOISE_S: f64 = 10e-9;
/// The farthest a receiver may be from a position it is said to have heard, metres.
pub const MAX_RANGE_M: f64 = 600_000.0;
/// The farthest a locally decoded position may lie from its aircraft's reference, metres.
pub const MAX_LOCAL_DECODE_M: f64 = 100_000.0;
/// The standard deviation of R95 for a circular normal, the divisor from a 95% radius.
const R95: f64 = 2.448;
/// Rounds of (final-weighted step, noise estimate) before the final steps: at least the first,
/// until no clock's estimate moves by more than `NOISE_SETTLED` relative, at most the second. The
/// rounds start from each clock's robust scale (`robust_noise`), so a clock several times noisier
/// than the nominal is near its estimate from the first; past three rounds a clock heard a few
/// dozen times only wanders (measured: a fifth of a tile's worst clock between rounds three and
/// four, never settling), at the cost of a factorisation and a selected inverse a round.
pub const NOISE_ROUNDS: (usize, usize) = (2, 3);
/// Standard errors a clock's noise variance estimate is raised by (`estimate_noise`): measured,
/// none left the simulator's coverage at 0.936 with a fifth of its clocks' noise underestimated
/// by more than a tenth; one standard error, 0.967; half, 0.953.
pub const NOISE_MARGIN: f64 = 0.5;
/// How little a clock's noise estimate may move for the rounds to stop early.
pub const NOISE_SETTLED: f64 = 0.05;
/// Huber-weighted steps after the unit-weight one.
pub const HUBER_STEPS: usize = 2;
/// Final steps after the noise rounds, at least.
pub const FINAL_STEPS: usize = 2;
/// Final steps at most.
pub const MAX_FINAL_STEPS: usize = 12;
/// A final step moving the estimate by at most this many squared standard deviations (its
/// squared Mahalanobis length) ends the fit: a hundredth of what a verifier allows.
pub const CONVERGED: f64 = 1e-6;
/// Receptions a clock needs before its noise is estimated rather than taken by default.
pub const MIN_NOISE_RECEPTIONS: usize = 20;
/// Steps of an event's own transmit time and position, holding the clocks, at a published
/// estimate.
pub const EVENT_STEPS: usize = 8;
/// Huber-weighted steps before those.
pub const EVENT_HUBER_STEPS: usize = 3;

struct SiteInfo {
    timebase: Timebase,
    mm: [i64; 3],
    ecef: Vec3,
    sigma_mm: i64,
}

struct Rx<'a> {
    id: ObservationId,
    receiver: PublicKey,
    epoch: u32,
    raw: u64,
    linear: i64,
    wall_ms: u64,
    data: &'a [u8],
}

#[derive(Clone)]
struct Event {
    prior: Vec3,
    basis: [Vec3; 3],
    /// The prior on its aircraft's horizontal bias, per axis.
    sigma_h: f64,
    sigma_v: f64,
    address: u32,
    /// What its altitude's bias is.
    vertical: BiasKind,
    rx: Vec<usize>,
}

fn site_table(sites: &[Site]) -> BTreeMap<PublicKey, SiteInfo> {
    sites
        .iter()
        .filter(|site| site.usable())
        .filter_map(|site| {
            let timebase = Timebase::of(site.clock)?;
            let mm = site.mm();
            Some((
                site.receiver,
                SiteInfo {
                    timebase,
                    mm,
                    ecef: geo::from_mm(mm),
                    sigma_mm: site.sigma_mm(),
                },
            ))
        })
        .collect()
}

/// Deduplicates by identity, drops receptions of unusable receivers, and linearizes counters: a
/// GPS epoch whose times of day span more than half a day crossed midnight, and its times before
/// noon move forward a day.
fn linearize<'a>(
    sites: &BTreeMap<PublicKey, SiteInfo>,
    receptions: impl Iterator<Item = &'a Reception>,
) -> Vec<Rx<'a>> {
    // Unique by identity (of copies the earliest wall clock), in identity order: so each
    // receiver's epoch is one run.
    let mut unique: Vec<(ObservationId, &'a Reception)> = receptions
        .filter(|reception| sites.contains_key(&reception.receiver))
        .map(|reception| (reception.id(), reception))
        .collect();
    unique.sort_by(|a, b| a.0.cmp(&b.0).then(a.1.wall_ms.cmp(&b.1.wall_ms)));
    unique.dedup_by(|later, earlier| later.0 == earlier.0);
    let mut out: Vec<Rx<'a>> = Vec::with_capacity(unique.len());
    let mut start = 0;
    while start < unique.len() {
        let (receiver, epoch) = (unique[start].1.receiver, unique[start].1.epoch);
        let end = start
            + unique[start..]
                .iter()
                .take_while(|(_, r)| r.receiver == receiver && r.epoch == epoch)
                .count();
        let Some(site) = sites.get(&receiver) else {
            start = end;
            continue;
        };
        let values: Vec<Option<i64>> = unique[start..end]
            .iter()
            .map(|(_, r)| site.timebase.linear(r.observation.timestamp))
            .collect();
        let low = values.iter().flatten().min().copied().unwrap_or(0);
        let high = values.iter().flatten().max().copied().unwrap_or(0);
        let wrapped = high - low > DAY_NS / 2;
        let gps = site.timebase == Timebase::GpsNanos;
        for ((id, reception), value) in unique[start..end].iter().zip(values) {
            let Some(value) = value else { continue };
            out.push(Rx {
                id: *id,
                receiver,
                epoch,
                raw: reception.observation.timestamp,
                linear: if gps && wrapped && value < DAY_NS / 2 {
                    value + DAY_NS
                } else {
                    value
                },
                wall_ms: reception.wall_ms,
                data: &reception.observation.data,
            });
        }
        start = end;
    }
    out
}

/// A position message one receiver heard: (linear count, bytes, odd).
type Heard<'a> = (i64, &'a [u8], bool);
/// A CPR pair candidate: (even bytes, odd bytes, the odd one is later).
type Pair<'a> = (&'a [u8], &'a [u8], bool);

/// The sync events of the window (crate docs, § Sync references).
fn sync_events(sites: &BTreeMap<PublicKey, SiteInfo>, rxs: &[Rx<'_>]) -> Vec<Event> {
    // Every distinct position message, with the receptions of it.
    let mut messages: BTreeMap<&[u8], Vec<usize>> = BTreeMap::new();
    let mut nacp: BTreeMap<u32, u8> = BTreeMap::new();
    for (index, rx) in rxs.iter().enumerate() {
        let Some(address) = modes::address(rx.data) else {
            continue;
        };
        if let Some(value) = modes::nacp(rx.data) {
            let entry = nacp.entry(address).or_insert(value);
            *entry = (*entry).min(value);
        }
        if modes::type_code(rx.data).is_some() && modes::airborne_position(rx.data).is_some() {
            messages.entry(rx.data).or_default().push(index);
        }
    }
    // The CPR reference of each address: the first, in (even bytes, odd bytes, odd latest)
    // order, of the even and odd pairs one receiver heard within ten seconds that decodes.
    let mut heard: BTreeMap<(u32, PublicKey, u32), Vec<Heard<'_>>> = BTreeMap::new();
    for (data, indices) in &messages {
        let (Some(address), Some(position)) =
            (modes::address(data), modes::airborne_position(data))
        else {
            continue;
        };
        for index in indices {
            let rx = &rxs[*index];
            heard
                .entry((address, rx.receiver, rx.epoch))
                .or_default()
                .push((rx.linear, data, position.odd));
        }
    }
    let mut pairs: BTreeMap<u32, BTreeSet<Pair<'_>>> = BTreeMap::new();
    for ((address, receiver, _), list) in &heard {
        let Some(site) = sites.get(receiver) else {
            continue;
        };
        let window = site.timebase.pair_counts();
        for (even_time, even, even_odd) in list {
            if *even_odd {
                continue;
            }
            for (odd_time, odd, odd_odd) in list {
                if *odd_odd && (odd_time - even_time).abs() <= window {
                    pairs
                        .entry(*address)
                        .or_default()
                        .insert((even, odd, odd_time > even_time));
                }
            }
        }
    }
    let mut references: BTreeMap<u32, modes::LatLon> = BTreeMap::new();
    for (address, candidates) in &pairs {
        for (even, odd, odd_latest) in candidates {
            let (Some(even), Some(odd)) = (
                modes::airborne_position(even),
                modes::airborne_position(odd),
            ) else {
                continue;
            };
            if let Some(position) = modes::cpr_global(
                (even.lat_cpr, even.lon_cpr),
                (odd.lat_cpr, odd.lon_cpr),
                *odd_latest,
            ) {
                references.insert(*address, position);
                break;
            }
        }
    }
    let mut events = Vec::new();
    for (data, indices) in messages {
        let (Some(address), Some(position)) =
            (modes::address(data), modes::airborne_position(data))
        else {
            continue;
        };
        let (Some(reference), Some(altitude)) = (references.get(&address), position.altitude)
        else {
            continue;
        };
        let decoded = modes::cpr_local(
            (position.lat_cpr, position.lon_cpr),
            position.odd,
            *reference,
        );
        let at = |lat_deg: f64, lon_deg: f64| {
            geo::to_ecef(Geodetic {
                lat_deg,
                lon_deg,
                height_m: 0.0,
            })
        };
        if linalg::norm(linalg::sub(
            at(decoded.lat_deg, decoded.lon_deg),
            at(reference.lat_deg, reference.lon_deg),
        )) > MAX_LOCAL_DECODE_M
        {
            continue;
        }
        let declared = nacp
            .get(&address)
            .and_then(|value| modes::epu_m(*value))
            .or_else(|| modes::containment_m(position.type_code));
        let Some(declared) = declared else {
            continue;
        };
        let sigma_h = (declared / R95).max(MIN_PRIOR_SIGMA_M);
        if sigma_h > MAX_PRIOR_SIGMA_M {
            continue;
        }
        let prior = geo::to_ecef(Geodetic {
            lat_deg: decoded.lat_deg,
            lon_deg: decoded.lon_deg,
            height_m: altitude.metres(),
        });
        let mut receivers = BTreeSet::new();
        let mut duplicate = false;
        let mut kept = Vec::new();
        for index in indices {
            let rx = &rxs[index];
            if !receivers.insert(rx.receiver) {
                duplicate = true;
            }
            let Some(site) = sites.get(&rx.receiver) else {
                continue;
            };
            if linalg::norm(linalg::sub(prior, site.ecef)) <= MAX_RANGE_M {
                kept.push(index);
            }
        }
        if duplicate || kept.len() < 2 {
            continue;
        }
        events.push(Event {
            prior,
            basis: geo::enu_basis(decoded.lat_deg, decoded.lon_deg),
            sigma_h,
            sigma_v: VERTICAL_SIGMA_M,
            address,
            vertical: if altitude.kind == modes::AltitudeKind::Barometric {
                BiasKind::Barometric
            } else {
                BiasKind::GnssHeight
            },
            rx: kept,
        });
    }
    events
}

type Boundaries = BTreeMap<(PublicKey, u32), Vec<i64>>;

fn clock_key(boundaries: &Boundaries, receiver: PublicKey, epoch: u32, linear: i64) -> ClockKey {
    let piece = boundaries
        .get(&(receiver, epoch))
        .map_or(0, |list| list.partition_point(|at| *at <= linear) as u16);
    ClockKey {
        receiver,
        epoch,
        piece,
    }
}

fn boundaries_of(jumps: &[Jump]) -> Boundaries {
    let mut boundaries: Boundaries = BTreeMap::new();
    for jump in jumps {
        boundaries
            .entry((jump.receiver, jump.epoch))
            .or_default()
            .push(jump.at);
    }
    for list in boundaries.values_mut() {
        list.sort_unstable();
    }
    boundaries
}

/// One clock of a fit: which counter, where its knots are.
#[derive(Clone, Debug, PartialEq, Eq)]
struct ClockShape {
    key: ClockKey,
    timebase: Timebase,
    begins: Option<i64>,
    ends: Option<i64>,
    base: i64,
    first: i32,
    end: i32,
}

/// The clocks of a fit and its gauge (crate docs, § Clocks, the gauge and the knots).
#[derive(Clone, Debug, PartialEq, Eq)]
struct Shape {
    gauge: ClockKey,
    /// The wall clock of the gauge's anchor reception.
    anchor_wall_ms: u64,
    /// Sorted by key; the gauge among them.
    clocks: Vec<ClockShape>,
}

impl Shape {
    fn of_model(model: &ClockModel) -> Self {
        Self {
            gauge: model.gauge,
            anchor_wall_ms: 0,
            clocks: model
                .pieces
                .iter()
                .map(|piece| ClockShape {
                    key: piece.key,
                    timebase: piece.timebase,
                    begins: piece.begins,
                    ends: piece.ends,
                    base: piece.base,
                    first: piece.first,
                    end: piece.end(),
                })
                .collect(),
        }
    }

    /// A reception's clock (index), and its nominal picoseconds since that clock's knot 0, as
    /// `ClockModel::time` places it.
    fn place(&self, receiver: &PublicKey, epoch: u32, raw: u64) -> Option<(usize, i128)> {
        let start = self
            .clocks
            .partition_point(|clock| (clock.key.receiver, clock.key.epoch) < (*receiver, epoch));
        let end = self
            .clocks
            .partition_point(|clock| (clock.key.receiver, clock.key.epoch) <= (*receiver, epoch));
        let first = self.clocks.get(start).filter(|_| start < end)?;
        let linear = first.timebase.linear_near(raw, first.base)?;
        let index = (start..end).find(|index| {
            let clock = &self.clocks[*index];
            clock.begins.is_none_or(|begins| linear >= begins)
                && clock.ends.is_none_or(|ends| linear < ends)
        })?;
        let clock = &self.clocks[index];
        Some((
            index,
            clock
                .timebase
                .elapsed_ps(i128::from(linear) - i128::from(clock.base)),
        ))
    }
}

fn find(parent: &mut [usize], mut x: usize) -> usize {
    while parent[x] != x {
        parent[x] = parent[parent[x]];
        x = parent[x];
    }
    x
}

fn lower_median(mut values: Vec<i64>) -> Option<i64> {
    values.sort_unstable();
    let middle = values.len().checked_sub(1)? / 2;
    Some(values[middle])
}

/// The clocks, the gauge, the coarse offsets and the knot ranges of a fit (crate docs, § Clocks,
/// the gauge and the knots).
fn shape(
    sites: &BTreeMap<PublicKey, SiteInfo>,
    rxs: &[Rx<'_>],
    events: &[Event],
    boundaries: &Boundaries,
    hearers: &BTreeSet<PublicKey>,
    forced_gauge: Option<PublicKey>,
) -> Result<Shape, FitError> {
    let key_of = |rx: &Rx<'_>| clock_key(boundaries, rx.receiver, rx.epoch, rx.linear);
    let keys: Vec<ClockKey> = events
        .iter()
        .flat_map(|event| event.rx.iter().map(|index| key_of(&rxs[*index])))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    let index_of: BTreeMap<ClockKey, usize> =
        keys.iter().enumerate().map(|(i, key)| (*key, i)).collect();
    let mut parent: Vec<usize> = (0..keys.len()).collect();
    for event in events {
        let clocks: Vec<usize> = event
            .rx
            .iter()
            .map(|index| index_of[&key_of(&rxs[*index])])
            .collect();
        for clock in &clocks[1..] {
            let a = find(&mut parent, clocks[0]);
            let b = find(&mut parent, *clock);
            if a != b {
                let (low, high) = if a < b { (a, b) } else { (b, a) };
                parent[high] = low;
            }
        }
    }
    let mut components: BTreeMap<usize, Vec<usize>> = BTreeMap::new();
    for clock in 0..keys.len() {
        let root = find(&mut parent, clock);
        components.entry(root).or_default().push(clock);
    }
    // The component holding the most of the aircraft's hearers; of equals, the one whose first
    // clock has the lowest key (components are keyed by their lowest member).
    let mut chosen: Option<(usize, &Vec<usize>)> = None;
    for members in components.values().filter(|members| members.len() >= 2) {
        let receivers: BTreeSet<PublicKey> = members
            .iter()
            .map(|clock| keys[*clock].receiver)
            .filter(|receiver| hearers.contains(receiver))
            .collect();
        if chosen.is_none_or(|(count, _)| receivers.len() > count) {
            chosen = Some((receivers.len(), members));
        }
    }
    let Some((_, members)) = chosen else {
        return Err(FitError::NoSyncEvents);
    };
    let members: BTreeSet<usize> = members.iter().copied().collect();
    let timebase_of = |clock: usize| {
        sites
            .get(&keys[clock].receiver)
            .map_or(Timebase::Mhz12, |site| site.timebase)
    };
    let gauge = match forced_gauge {
        Some(receiver) => members
            .iter()
            .copied()
            .find(|clock| keys[*clock].receiver == receiver),
        None => members
            .iter()
            .copied()
            .find(|clock| timebase_of(*clock).disciplined())
            .or_else(|| members.iter().next().copied()),
    }
    .ok_or(FitError::Shape("no gauge"))?;
    // Every event's receptions by clock, for the walk.
    // Shared events by ordered pair of clocks, as one table of n x n lists.
    let n = keys.len();
    let mut shared: Vec<Vec<(i64, i64)>> = vec![Vec::new(); n * n];
    let mut anchor: Option<(i64, u64)> = None;
    for event in events {
        let list: Vec<(usize, &Rx<'_>)> = event
            .rx
            .iter()
            .map(|index| (index_of[&key_of(&rxs[*index])], &rxs[*index]))
            .filter(|(clock, _)| members.contains(clock))
            .collect();
        for (clock, rx) in &list {
            if *clock == gauge {
                anchor = Some(match anchor {
                    Some((at, wall)) if at < rx.linear => (at, wall),
                    Some((at, wall)) if at == rx.linear => (at, wall.min(rx.wall_ms)),
                    _ => (rx.linear, rx.wall_ms),
                });
            }
            for (other, other_rx) in &list {
                if clock != other {
                    shared[clock * n + other].push((rx.linear, other_rx.linear));
                }
            }
        }
    }
    let (anchor, anchor_wall_ms) = anchor.ok_or(FitError::Shape("no gauge anchor"))?;
    // The walk from the gauge: the unmapped clock of lowest key that shares an event with a
    // mapped one takes its base from the mapped one it shares most events with (of equals, the
    // lowest key), as the lower median of the count differences.
    let mut bases: BTreeMap<usize, i64> = BTreeMap::new();
    bases.insert(gauge, anchor);
    loop {
        let mut next: Option<(usize, usize, usize)> = None;
        for clock in &members {
            if bases.contains_key(clock) {
                continue;
            }
            for mapped in bases.keys() {
                let list = &shared[mapped * n + clock];
                if list.is_empty() {
                    continue;
                }
                match next {
                    Some((c, _, _)) if c < *clock => {}
                    Some((c, _, n)) if c == *clock && n >= list.len() => {}
                    _ => next = Some((*clock, *mapped, list.len())),
                }
            }
            if next.is_some_and(|(c, _, _)| c == *clock) {
                break;
            }
        }
        let Some((clock, mapped, _)) = next else {
            break;
        };
        let (from, to) = (timebase_of(mapped), timebase_of(clock));
        let base = bases[&mapped];
        let differences: Vec<i64> = shared[mapped * n + clock]
            .iter()
            .map(|(there, here)| {
                here - to.counts_of_ps(from.elapsed_ps(i128::from(*there) - i128::from(base)))
            })
            .collect();
        bases.insert(
            clock,
            lower_median(differences).ok_or(FitError::Shape("no shared event"))?,
        );
    }
    let mut clocks: Vec<ClockShape> = members
        .iter()
        .filter_map(|clock| {
            let key = keys[*clock];
            let list = boundaries.get(&(key.receiver, key.epoch));
            let piece = usize::from(key.piece);
            Some(ClockShape {
                key,
                timebase: timebase_of(*clock),
                begins: piece
                    .checked_sub(1)
                    .and_then(|index| list.and_then(|list| list.get(index)).copied()),
                ends: list.and_then(|list| list.get(piece)).copied(),
                base: *bases.get(clock)?,
                first: 0,
                end: 0,
            })
        })
        .collect();
    let mut shape = Shape {
        gauge: keys[gauge],
        anchor_wall_ms,
        clocks: clocks.clone(),
    };
    // Knots: from the interval of the earliest to that of the latest reception of a sync event
    // each clock has, one knot past it.
    let mut spans: BTreeMap<usize, (i128, i128)> = BTreeMap::new();
    for rx in events
        .iter()
        .flat_map(|event| event.rx.iter().map(|index| &rxs[*index]))
    {
        if let Some((clock, elapsed)) = shape.place(&rx.receiver, rx.epoch, rx.raw) {
            let entry = spans.entry(clock).or_insert((elapsed, elapsed));
            entry.0 = entry.0.min(elapsed);
            entry.1 = entry.1.max(elapsed);
        }
    }
    for (index, clock) in clocks.iter_mut().enumerate() {
        let (low, high) = spans.get(&index).copied().unwrap_or((0, 0));
        clock.first =
            i32::try_from(low.div_euclid(KNOT_PS)).map_err(|_| FitError::Shape("knot"))?;
        clock.end =
            i32::try_from(high.div_euclid(KNOT_PS) + 2).map_err(|_| FitError::Shape("knot"))?;
    }
    shape.clocks = clocks;
    Ok(shape)
}

/// A reception row: its clock, the interval it is in, how far in, and its nominal time.
struct Row {
    rx: usize,
    clock: usize,
    knot: i32,
    fraction: f64,
    nominal_m: f64,
    /// The places of the knots either side, `None` for the gauge.
    places: Option<(At, At)>,
    /// The receiver's antenna, ECEF metres.
    site: Vec3,
}

struct EventUse {
    event: usize,
    rows: Vec<Row>,
    /// Its first row's nominal time, metres: the gauge rate's lever is model time less this, so
    /// its column is a time difference within the event, not the time since the anchor (the
    /// event's own transmit time absorbs the rest exactly).
    reference_m: f64,
}

/// A parameter of the border: the gauge's rate, and the sync aircraft's biases.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Param {
    Rate,
    Bias(u32, BiasKind),
}

/// Where every parameter of a fit sits in the banded system.
struct Layout {
    shape: Shape,
    sizes: Vec<usize>,
    /// (clock, knot) to its place, for every clock but the gauge.
    places: BTreeMap<(usize, i32), At>,
    /// The border's parameters, to their places: the rate first, then the biases by (address,
    /// kind).
    border: BTreeMap<Param, usize>,
    /// Each bias's prior, metres.
    priors: BTreeMap<Param, f64>,
    events: Vec<EventUse>,
}

impl Layout {
    fn rate(&self) -> At {
        At::Border(self.border.get(&Param::Rate).copied().unwrap_or(0))
    }

    fn bias(&self, address: u32, kind: BiasKind) -> Option<At> {
        self.border
            .get(&Param::Bias(address, kind))
            .map(|slot| At::Border(*slot))
    }
}

impl Layout {
    fn new(
        shape: Shape,
        sites: &BTreeMap<PublicKey, SiteInfo>,
        rxs: &[Rx<'_>],
        events: &[Event],
    ) -> Self {
        let gauge = shape.gauge;
        let first_knot = shape
            .clocks
            .iter()
            .filter(|clock| clock.key != gauge)
            .map(|clock| clock.first)
            .min()
            .unwrap_or(0);
        let last_knot = shape
            .clocks
            .iter()
            .filter(|clock| clock.key != gauge)
            .map(|clock| clock.end)
            .max()
            .unwrap_or(0);
        let slices = usize::try_from(last_knot - first_knot).unwrap_or(0);
        let mut sizes = vec![0usize; slices];
        let mut places = BTreeMap::new();
        // Slices in time order; within one, clocks in key order.
        for knot in first_knot..last_knot {
            let slice = (knot - first_knot) as usize;
            for (index, clock) in shape.clocks.iter().enumerate() {
                if clock.key != gauge && knot >= clock.first && knot < clock.end {
                    places.insert((index, knot), At::Slice(slice, sizes[slice]));
                    sizes[slice] += 1;
                }
            }
        }
        let mut uses = Vec::new();
        let mut priors: BTreeMap<Param, f64> = BTreeMap::new();
        for (event_index, event) in events.iter().enumerate() {
            let rows: Vec<Row> = event
                .rx
                .iter()
                .filter_map(|index| {
                    let rx = &rxs[*index];
                    let (clock, elapsed) = shape.place(&rx.receiver, rx.epoch, rx.raw)?;
                    let knot = i32::try_from(elapsed.div_euclid(KNOT_PS)).ok()?;
                    let into = elapsed - i128::from(knot) * KNOT_PS;
                    Some(Row {
                        rx: *index,
                        clock,
                        knot,
                        fraction: into as f64 / KNOT_PS as f64,
                        nominal_m: elapsed as f64 * 1e-12 * C,
                        places: places
                            .get(&(clock, knot))
                            .copied()
                            .zip(places.get(&(clock, knot + 1)).copied()),
                        site: sites.get(&rx.receiver).map_or([0.0; 3], |site| site.ecef),
                    })
                })
                .collect();
            // Two receptions, and every reception's interval within one of every other's, so
            // the event couples knots no more than `BAND` apart.
            let low = rows.iter().map(|row| row.knot).min();
            let high = rows.iter().map(|row| row.knot).max();
            let within = rows.iter().all(|row| {
                let clock = &shape.clocks[row.clock];
                row.knot >= clock.first && row.knot + 1 < clock.end
            });
            if rows.len() < 2 || !within || high.zip(low).is_none_or(|(h, l)| h - l > 1) {
                continue;
            }
            // An aircraft's bias prior is its weakest event's: the declared accuracy at its
            // worst in the window.
            let mut widen = |param: Param, sigma: f64| {
                let held = priors.entry(param).or_insert(sigma);
                *held = held.max(sigma);
            };
            widen(Param::Bias(event.address, BiasKind::East), event.sigma_h);
            widen(Param::Bias(event.address, BiasKind::North), event.sigma_h);
            widen(
                Param::Bias(event.address, event.vertical),
                match event.vertical {
                    BiasKind::Barometric => BARO_BIAS_SIGMA_M,
                    _ => GNSS_HEIGHT_FACTOR * event.sigma_h,
                },
            );
            let reference_m = rows[0].nominal_m;
            uses.push(EventUse {
                event: event_index,
                rows,
                reference_m,
            });
        }
        let border: BTreeMap<Param, usize> = std::iter::once(Param::Rate)
            .chain(priors.keys().copied())
            .enumerate()
            .map(|(slot, param)| (param, slot))
            .collect();
        Self {
            shape,
            sizes,
            places,
            border,
            priors,
            events: uses,
        }
    }
}

/// Every clock's reception standard deviation (`sigma_m`), by clock index.
fn sigmas_of(problem: &Problem<'_>, noise: &BTreeMap<ClockKey, f64>) -> Vec<f64> {
    let shape = &problem.layout.shape;
    (0..shape.clocks.len())
        .map(|clock| sigma_m(shape, problem.sites, noise, clock))
        .collect()
}

fn noise_s(shape: &Shape, noise: &BTreeMap<ClockKey, f64>, clock: usize) -> f64 {
    let info = &shape.clocks[clock];
    noise
        .get(&info.key)
        .copied()
        .unwrap_or_else(|| info.timebase.default_noise_s())
}

/// One reception's standard deviation, metres: timing noise and antenna position.
fn sigma_m(
    shape: &Shape,
    sites: &BTreeMap<PublicKey, SiteInfo>,
    noise: &BTreeMap<ClockKey, f64>,
    clock: usize,
) -> f64 {
    let timing = noise_s(shape, noise, clock) * C;
    let site = sites
        .get(&shape.clocks[clock].key.receiver)
        .map_or(0.0, |site| site.sigma_mm as f64 / 1000.0);
    (timing * timing + site * site).sqrt()
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Weighting {
    Unit,
    Huber,
    Final,
}

impl Weighting {
    fn weight(self, z: f64) -> f64 {
        let z = z.abs();
        match self {
            Self::Unit => 1.0,
            Self::Huber if z <= HUBER_K => 1.0,
            Self::Huber => HUBER_K / z,
            Self::Final if z <= HUBER_K => 1.0,
            Self::Final if z <= SYNC_CUTOFF => HUBER_K / z,
            Self::Final => 0.0,
        }
    }
}

/// Parameter values: knot offsets and biases in metres, and each event's transmit time (metres
/// of light time) and position (ECEF metres).
struct State {
    theta: Vector,
    locals: Vec<[f64; 4]>,
}

/// A row's global Jacobian entries: at most three (a reception's two knots and the gauge rate, or
/// a bias).
#[derive(Clone, Copy)]
struct Entries {
    items: [(At, f64); 3],
    len: usize,
}

impl Entries {
    const NONE: Self = Self {
        items: [(At::Border(0), 0.0); 3],
        len: 0,
    };

    fn one(at: At, value: f64) -> Self {
        let mut entries = Self::NONE;
        entries.push(at, value);
        entries
    }

    fn push(&mut self, at: At, value: f64) {
        self.items[self.len] = (at, value);
        self.len += 1;
    }

    fn as_slice(&self) -> &[(At, f64)] {
        &self.items[..self.len]
    }
}

/// A row of a least-squares problem: residual, weight, local and global Jacobian entries.
struct LocalRow {
    residual: f64,
    weight: f64,
    local: [f64; 4],
    global: Entries,
}

/// What everything the fit and the calibration share needs: the sites, receptions and events.
struct Problem<'a> {
    sites: &'a BTreeMap<PublicKey, SiteInfo>,
    rxs: &'a [Rx<'a>],
    events: &'a [Event],
    layout: &'a Layout,
}

impl State {
    /// The state a published model states, its events settled, and its noise.
    fn at(model: &ClockModel, problem: &Problem<'_>) -> (Self, BTreeMap<ClockKey, f64>) {
        let layout = problem.layout;
        let mut state = Self::start(problem);
        for (index, piece) in model.pieces.iter().enumerate() {
            for (at, offset) in (piece.first..).zip(&piece.offsets_ps) {
                if let Some(place) = layout.places.get(&(index, at)) {
                    state.theta.add(*place, *offset as f64 * 1e-12 * C);
                }
            }
        }
        for bias in &model.biases {
            if let Some(at) = layout.bias(bias.address, bias.kind) {
                state.theta.add(at, bias.mm as f64 / 1000.0);
            }
        }
        state
            .theta
            .add(layout.rate(), model.gauge_rate as f64 * PPM_PER_RATE);
        let noise: BTreeMap<ClockKey, f64> = model
            .pieces
            .iter()
            .map(|piece| (piece.key, piece.noise_ps as f64 * 1e-12))
            .collect();
        state.settle_events(problem, &noise);
        (state, noise)
    }

    fn start(problem: &Problem<'_>) -> Self {
        let layout = problem.layout;
        Self {
            theta: Vector::zeros(&layout.sizes, layout.border.len()),
            locals: layout
                .events
                .iter()
                .map(|event| {
                    let prior = problem.events[event.event].prior;
                    [0.0, prior[0], prior[1], prior[2]]
                })
                .collect(),
        }
    }

    /// Model time of a row, metres, and its Jacobian over the knots and the gauge rate: the
    /// clock's time `t` (nominal plus offset) times `1 + rate`, less `rate` times the event's
    /// reference (which its transmit time absorbs).
    fn model(&self, layout: &Layout, row: &Row, reference_m: f64) -> (f64, Entries) {
        let rate_at = layout.rate();
        let rate = self.theta.get(rate_at) * 1e-6;
        let mut entries = Entries::NONE;
        let t = match row.places {
            Some((left, right)) => {
                let f = row.fraction;
                entries.push(left, (1.0 + rate) * (1.0 - f));
                entries.push(right, (1.0 + rate) * f);
                row.nominal_m + (1.0 - f) * self.theta.get(left) + f * self.theta.get(right)
            }
            None => row.nominal_m,
        };
        entries.push(rate_at, (t - reference_m) * 1e-6);
        (t + rate * (t - reference_m), entries)
    }

    /// One event's rows at the current parameters: receptions first, then the position prior.
    fn rows(
        &self,
        problem: &Problem<'_>,
        event_use: &EventUse,
        local: &[f64; 4],
        sigmas: &[f64],
        weighting: Weighting,
    ) -> Vec<LocalRow> {
        let layout = problem.layout;
        let event = &problem.events[event_use.event];
        let x = [local[1], local[2], local[3]];
        let mut rows = Vec::with_capacity(event_use.rows.len() + 3);
        for row in &event_use.rows {
            let (model, global) = self.model(layout, row, event_use.reference_m);
            let delta = linalg::sub(x, row.site);
            let range = linalg::norm(delta);
            let unit = linalg::scale(delta, 1.0 / range);
            let residual = model - local[0] - range;
            let sigma = sigmas[row.clock];
            rows.push(LocalRow {
                residual,
                weight: weighting.weight(residual / sigma) / (sigma * sigma),
                local: [-1.0, -unit[0], -unit[1], -unit[2]],
                global,
            });
        }
        let offset = linalg::sub(x, event.prior);
        for (axis, basis) in event.basis.iter().enumerate() {
            let (kind, sigma) = match axis {
                0 => (BiasKind::East, MESSAGE_SIGMA_M),
                1 => (BiasKind::North, MESSAGE_SIGMA_M),
                _ => (event.vertical, event.sigma_v),
            };
            let mut global = Entries::NONE;
            let mut residual = linalg::dot(*basis, offset);
            if let Some(at) = layout.bias(event.address, kind) {
                residual -= self.theta.get(at);
                global = Entries::one(at, -1.0);
            }
            rows.push(LocalRow {
                residual,
                weight: 1.0 / (sigma * sigma),
                local: [0.0, basis[0], basis[1], basis[2]],
                global,
            });
        }
        rows
    }

    /// The normal equations of every parameter at the current values, the event parameters
    /// eliminated by Schur complement, and the step that solves them.
    /// The reduced normal equations and gradient at the current values, and the events as
    /// eliminated.
    fn normal_equations(
        &self,
        problem: &Problem<'_>,
        noise: &BTreeMap<ClockKey, f64>,
        weighting: Weighting,
    ) -> Result<(Banded, Vector, Vec<Eliminated>), FitError> {
        let layout = problem.layout;
        let mut normal = Banded::zeros(layout.sizes.clone(), layout.border.len());
        let mut gradient = Vector::zeros(&layout.sizes, layout.border.len());
        let mut eliminated = Vec::with_capacity(layout.events.len());
        let sigmas = sigmas_of(problem, noise);
        for (event_use, local) in layout.events.iter().zip(&self.locals) {
            let rows = self.rows(problem, event_use, local, &sigmas, weighting);
            eliminated.push(eliminate(rows, &mut normal, &mut gradient)?);
        }
        self.priors(problem, &mut normal, &mut gradient)?;
        Ok((normal, gradient, eliminated))
    }

    fn system(
        &self,
        problem: &Problem<'_>,
        noise: &BTreeMap<ClockKey, f64>,
        weighting: Weighting,
    ) -> Result<Step, FitError> {
        let (normal, gradient, eliminated) = self.normal_equations(problem, noise, weighting)?;
        let uninformed = uninformed(problem.layout, &eliminated);
        if !uninformed.is_empty() {
            return Err(FitError::Uninformed(uninformed));
        }
        let factor = normal.factor().ok_or(FitError::Singular)?;
        let mut rhs = gradient.clone();
        rhs.slices
            .iter_mut()
            .flatten()
            .chain(rhs.border.iter_mut())
            .for_each(|value| *value = -*value);
        let delta = factor.solve(&rhs);
        Ok(Step {
            factor,
            gradient,
            delta,
            events: eliminated,
        })
    }

    /// The clocks' priors (crate docs, § The least-squares problem) and the biases'.
    fn priors(
        &self,
        problem: &Problem<'_>,
        normal: &mut Banded,
        gradient: &mut Vector,
    ) -> Result<(), FitError> {
        let layout = problem.layout;
        let shape = &layout.shape;
        let gauge = shape
            .clocks
            .iter()
            .find(|clock| clock.key == shape.gauge)
            .ok_or(FitError::Shape("no gauge"))?;
        let spacing_s = KNOT_PS as f64 * 1e-12;
        let theta = |at: At| self.theta.get(at);
        // Curvature: every clock, the gauge too, wanders as an integrated random walk of its own;
        // an offset is from the gauge, so at each knot the second differences of the offsets
        // there share the gauge's (crate docs, § The least-squares problem).
        let first = shape
            .clocks
            .iter()
            .map(|clock| clock.first)
            .min()
            .unwrap_or(0);
        let last = shape
            .clocks
            .iter()
            .map(|clock| clock.end)
            .max()
            .unwrap_or(0);
        let gauge_sigma = gauge.timebase.curvature_sigma_s() * C;
        for knot in first + 1..last - 1 {
            let mut terms: Vec<Curvature> = Vec::new();
            for (index, clock) in shape.clocks.iter().enumerate() {
                if clock.key == shape.gauge {
                    continue;
                }
                let at = |knot: i32| layout.places.get(&(index, knot)).copied();
                let (Some(a), Some(b), Some(c)) = (at(knot - 1), at(knot), at(knot + 1)) else {
                    continue;
                };
                terms.push((
                    [(a, 1.0), (b, -2.0), (c, 1.0)],
                    theta(a) - 2.0 * theta(b) + theta(c),
                    clock.timebase.curvature_sigma_s() * C,
                ));
            }
            add_curvature(normal, gradient, &terms, gauge_sigma)?;
        }
        for (index, clock) in shape.clocks.iter().enumerate() {
            if clock.key == shape.gauge {
                continue;
            }
            let at = |knot: i32| layout.places.get(&(index, knot)).copied();
            if let (Some(a), Some(b)) = (at(clock.first), at(clock.first + 1)) {
                add_prior(
                    normal,
                    gradient,
                    &[(b, 1.0), (a, -1.0)],
                    theta(b) - theta(a),
                    RATE_PRIOR_PPM * 1e-6 * C * spacing_s,
                )?;
            }
        }
        for (param, sigma) in &layout.priors {
            if let Some(slot) = layout.border.get(param) {
                let at = At::Border(*slot);
                add_prior(normal, gradient, &[(at, 1.0)], theta(at), *sigma)?;
            }
        }
        // The gauge's rate: free running, as any clock's first interval; disciplined, held.
        let rate = layout.rate();
        let sigma = if gauge.timebase.disciplined() {
            GNSS_GAUGE_RATE_PPM
        } else {
            RATE_PRIOR_PPM
        };
        add_prior(normal, gradient, &[(rate, 1.0)], theta(rate), sigma)?;
        Ok(())
    }

    fn apply(&mut self, step: &Step) {
        for (values, changes) in self.theta.slices.iter_mut().zip(&step.delta.slices) {
            for (value, change) in values.iter_mut().zip(changes) {
                *value += change;
            }
        }
        for (value, change) in self.theta.border.iter_mut().zip(&step.delta.border) {
            *value += change;
        }
        for (local, event) in self.locals.iter_mut().zip(&step.events) {
            if event.hll.is_none() {
                continue;
            }
            for i in 0..4 {
                let mut change = -event.kg[i];
                for (column, global) in event.globals.iter().enumerate() {
                    change -= event.k[i][column] * step.delta.get(*global);
                }
                local[i] += change;
            }
        }
    }

    fn step(
        &mut self,
        problem: &Problem<'_>,
        noise: &BTreeMap<ClockKey, f64>,
        weighting: Weighting,
    ) -> Result<Step, FitError> {
        let step = self.system(problem, noise, weighting)?;
        self.apply(&step);
        Ok(step)
    }

    /// Each event's transmit time and position at the clocks and biases held fixed: what a
    /// published model leaves out. From its prior position and the lower median of its
    /// receptions' model times less their ranges from it, `EVENT_HUBER_STEPS` Huber-weighted and
    /// then `EVENT_STEPS` final-weighted Gauss-Newton steps of the event's own four parameters.
    fn settle_events(&mut self, problem: &Problem<'_>, noise: &BTreeMap<ClockKey, f64>) {
        let layout = problem.layout;
        let sigmas = sigmas_of(problem, noise);
        for (index, event_use) in layout.events.iter().enumerate() {
            let prior = problem.events[event_use.event].prior;
            let mut starts: Vec<f64> = event_use
                .rows
                .iter()
                .map(|row| {
                    self.model(layout, row, event_use.reference_m).0
                        - linalg::norm(linalg::sub(prior, row.site))
                })
                .collect();
            starts.sort_by(f64::total_cmp);
            let transmit = starts
                .get(starts.len().saturating_sub(1) / 2)
                .copied()
                .unwrap_or(0.0);
            let mut local = [transmit, prior[0], prior[1], prior[2]];
            let schedule = std::iter::repeat_n(Weighting::Huber, EVENT_HUBER_STEPS)
                .chain(std::iter::repeat_n(Weighting::Final, EVENT_STEPS));
            for weighting in schedule {
                let rows = self.rows(problem, event_use, &local, &sigmas, weighting);
                let mut hll = Small::zeros();
                let mut gl = [0.0; 4];
                for row in &rows {
                    for i in 0..4 {
                        gl[i] += row.weight * row.local[i] * row.residual;
                        for j in 0..4 {
                            hll.a[i][j] += row.weight * row.local[i] * row.local[j];
                        }
                    }
                }
                let Some(factor) = hll.cholesky() else {
                    break;
                };
                let step = factor.solve(&gl);
                for i in 0..4 {
                    local[i] -= step[i];
                }
            }
            self.locals[index] = local;
        }
    }

    /// Every reception row's residual, by event.
    fn residuals(&self, problem: &Problem<'_>) -> Vec<Vec<f64>> {
        let layout = problem.layout;
        layout
            .events
            .iter()
            .zip(&self.locals)
            .map(|(event, local)| {
                event
                    .rows
                    .iter()
                    .map(|row| {
                        let (model, _) = self.model(layout, row, event.reference_m);
                        let x = [local[1], local[2], local[3]];
                        model - local[0] - linalg::norm(linalg::sub(x, row.site))
                    })
                    .collect()
            })
            .collect()
    }
}

/// A 4 x 4 symmetric positive definite system: an event's own parameters. Factored in place,
/// solved without allocating.
#[derive(Clone, Copy)]
struct Small {
    a: [[f64; 4]; 4],
}

impl Small {
    fn zeros() -> Self {
        Self { a: [[0.0; 4]; 4] }
    }

    /// The lower Cholesky factor, `None` when not positive definite.
    fn cholesky(&self) -> Option<Self> {
        let mut l = [[0.0; 4]; 4];
        for j in 0..4 {
            let mut diagonal = self.a[j][j];
            for k in 0..j {
                diagonal -= l[j][k] * l[j][k];
            }
            if diagonal.is_nan() || diagonal <= 0.0 {
                return None;
            }
            let root = diagonal.sqrt();
            l[j][j] = root;
            for i in j + 1..4 {
                let mut value = self.a[i][j];
                for k in 0..j {
                    value -= l[i][k] * l[j][k];
                }
                l[i][j] = value / root;
            }
        }
        Some(Self { a: l })
    }

    /// `x` with `L Lᵀ x = b`, `self` the factor.
    fn solve(&self, b: &[f64; 4]) -> [f64; 4] {
        let l = &self.a;
        let mut y = [0.0; 4];
        for i in 0..4 {
            let mut value = b[i];
            for k in 0..i {
                value -= l[i][k] * y[k];
            }
            y[i] = value / l[i][i];
        }
        let mut x = [0.0; 4];
        for i in (0..4).rev() {
            let mut value = y[i];
            for k in i + 1..4 {
                value -= l[k][i] * x[k];
            }
            x[i] = value / l[i][i];
        }
        x
    }
}

/// One event after elimination: its global places, `K = Hll⁻¹ Hlg` (four rows, one column per
/// place), `Hll⁻¹ gl`, the factor of `Hll`, and its rows.
struct Eliminated {
    globals: Vec<At>,
    k: Vec<Vec<f64>>,
    kg: [f64; 4],
    hll: Option<Small>,
    rows: Vec<LocalRow>,
}

/// One Gauss-Newton system: its factor, gradient and step, and the events as eliminated.
struct Step {
    factor: Factor,
    gradient: Vector,
    delta: Vector,
    events: Vec<Eliminated>,
}

/// The clocks (receiver and epoch, ascending) other than the gauge that no reception with weight
/// in a used event places: every reception of theirs is beyond the robust cutoff, or in events
/// whose own parameters nothing else fixes. Their offsets are then free (only the curvature and
/// first rate priors bind them, which say nothing of a level), so the normal equations are
/// singular; a real receiver whose stamps are garbage, or a fit that leaves one clock with no
/// partner, does this. Such a clock costs the tile that receiver, never the tile.
fn uninformed(layout: &Layout, eliminated: &[Eliminated]) -> Vec<(PublicKey, u32)> {
    let clock_of: BTreeMap<At, usize> = layout
        .places
        .iter()
        .map(|((clock, _), at)| (*at, *clock))
        .collect();
    let mut informed: BTreeSet<usize> = BTreeSet::new();
    for event in eliminated.iter().filter(|event| event.hll.is_some()) {
        for row in event.rows.iter().filter(|row| row.weight > 0.0) {
            for (at, value) in row.global.as_slice() {
                if *value != 0.0
                    && let Some(clock) = clock_of.get(at)
                {
                    informed.insert(*clock);
                }
            }
        }
    }
    let mut out: BTreeSet<(PublicKey, u32)> = BTreeSet::new();
    for (index, clock) in layout.shape.clocks.iter().enumerate() {
        if clock.key != layout.shape.gauge && !informed.contains(&index) {
            out.insert((clock.key.receiver, clock.key.epoch));
        }
    }
    out.into_iter().collect()
}

/// Accumulates one event's rows into the reduced normal equations, eliminating its four local
/// parameters, and returns what back-substitution needs. An event left with no reception of
/// weight above zero cannot fix its transmit time; it contributes nothing and stays where it is.
fn eliminate(
    rows: Vec<LocalRow>,
    normal: &mut Banded,
    gradient: &mut Vector,
) -> Result<Eliminated, FitError> {
    let mut globals: Vec<At> = rows
        .iter()
        .flat_map(|row| row.global.as_slice().iter().map(|(at, _)| *at))
        .collect();
    globals.sort_unstable();
    globals.dedup();
    let m = globals.len();
    // Each row's entries as (slot, value), found once.
    let slots: Vec<[(usize, f64); 3]> = rows
        .iter()
        .map(|row| {
            let mut out = [(usize::MAX, 0.0); 3];
            for (i, (at, value)) in row.global.as_slice().iter().enumerate() {
                out[i] = (globals.partition_point(|g| g < at), *value);
            }
            out
        })
        .collect();
    let mut hll = Small::zeros();
    let mut gl = [0.0; 4];
    // Hlg as four rows of m, Hgg as m x m.
    let mut hlg = vec![0.0; 4 * m];
    let mut hgg = vec![0.0; m * m];
    let mut gg = vec![0.0; m];
    for (row, entries) in rows.iter().zip(&slots) {
        let w = row.weight;
        if w == 0.0 {
            continue;
        }
        for i in 0..4 {
            gl[i] += w * row.local[i] * row.residual;
            for j in 0..4 {
                hll.a[i][j] += w * row.local[i] * row.local[j];
            }
        }
        for (s, value) in entries.iter().filter(|(s, _)| *s != usize::MAX) {
            gg[*s] += w * value * row.residual;
            for i in 0..4 {
                hlg[i * m + s] += w * row.local[i] * value;
            }
            for (t, other) in entries.iter().filter(|(t, _)| *t != usize::MAX) {
                hgg[s * m + t] += w * value * other;
            }
        }
    }
    let Some(factor) = hll.cholesky() else {
        return Ok(Eliminated {
            globals: Vec::new(),
            k: vec![Vec::new(); 4],
            kg: [0.0; 4],
            hll: None,
            rows,
        });
    };
    let kg = factor.solve(&gl);
    let mut k = vec![vec![0.0; m]; 4];
    for column in 0..m {
        let rhs = [
            hlg[column],
            hlg[m + column],
            hlg[2 * m + column],
            hlg[3 * m + column],
        ];
        let solved = factor.solve(&rhs);
        for i in 0..4 {
            k[i][column] = solved[i];
        }
    }
    for a in 0..m {
        let mut g = gg[a];
        for i in 0..4 {
            g -= hlg[i * m + a] * kg[i];
        }
        gradient.add(globals[a], g);
        let row = &mut hgg[a * m..(a + 1) * m];
        for i in 0..4 {
            let h = hlg[i * m + a];
            for (value, kib) in row[a..].iter_mut().zip(&k[i][a..]) {
                *value -= h * kib;
            }
        }
    }
    if !normal.add_dense(&globals, &hgg) {
        return Err(FitError::Shape("an event outside the band"));
    }
    Ok(Eliminated {
        globals,
        k,
        kg: [kg[0], kg[1], kg[2], kg[3]],
        hll: Some(factor),
        rows,
    })
}

/// One offset's second difference at a knot: its three entries, its value, its own sigma.
type Curvature = ([(At, f64); 3], f64, f64);

/// The second differences `r` of several offsets at one knot, under the covariance
/// `diag(sigma_j^2) + sigma_g^2 1 1ᵀ` (each clock's own wander, and the gauge's, which every
/// offset carries): its precision by Sherman-Morrison,
/// `D⁻¹ - u uᵀ / (sigma_g⁻² + Σ u_j)` with `u_j = sigma_j⁻²`.
fn add_curvature(
    normal: &mut Banded,
    gradient: &mut Vector,
    terms: &[Curvature],
    gauge_sigma: f64,
) -> Result<(), FitError> {
    // Jᵀ P J = Σ u_j J_jᵀ J_j - w wᵀ / s, with w = Σ u_j J_j; and Jᵀ P r likewise.
    let u: Vec<f64> = terms
        .iter()
        .map(|(_, _, sigma)| 1.0 / (sigma * sigma))
        .collect();
    let s = 1.0 / (gauge_sigma * gauge_sigma) + u.iter().sum::<f64>();
    let mut shared = 0.0;
    let mut w: Vec<(At, f64)> = Vec::with_capacity(3 * terms.len());
    for ((entries, residual, _), weight) in terms.iter().zip(&u) {
        shared += weight * residual;
        let mut own = [0.0; 9];
        for (i, (_, vi)) in entries.iter().enumerate() {
            for (j, (_, vj)) in entries.iter().enumerate() {
                own[i * 3 + j] = weight * vi * vj;
            }
        }
        let mut places = [entries[0].0, entries[1].0, entries[2].0];
        // The three knots of one clock ascend with time.
        places.sort_unstable();
        let order: Vec<usize> = places
            .iter()
            .filter_map(|at| entries.iter().position(|(x, _)| x == at))
            .collect();
        let mut sorted = [0.0; 9];
        for (i, a) in order.iter().enumerate() {
            for (j, b) in order.iter().enumerate() {
                sorted[i * 3 + j] = own[a * 3 + b];
            }
        }
        if !normal.add_dense(&places, &sorted) {
            return Err(FitError::Shape("a prior outside the band"));
        }
        for (at, value) in entries {
            gradient.add(*at, weight * residual * value);
            w.push((*at, weight * value));
        }
    }
    w.sort_unstable_by_key(|entry| entry.0);
    let places: Vec<At> = w.iter().map(|(at, _)| *at).collect();
    let m = places.len();
    let mut dense = vec![0.0; m * m];
    for i in 0..m {
        gradient.add(places[i], -shared / s * w[i].1);
        for j in i..m {
            dense[i * m + j] = -w[i].1 * w[j].1 / s;
        }
    }
    if !normal.add_dense(&places, &dense) {
        return Err(FitError::Shape("a prior outside the band"));
    }
    Ok(())
}

fn add_prior(
    normal: &mut Banded,
    gradient: &mut Vector,
    entries: &[(At, f64)],
    residual: f64,
    sigma: f64,
) -> Result<(), FitError> {
    let weight = 1.0 / (sigma * sigma);
    for (i, (a, va)) in entries.iter().enumerate() {
        gradient.add(*a, weight * va * residual);
        for (b, vb) in &entries[i..] {
            // Two entries on one place (never here) would need their sum; each pair once.
            if !normal.add(*a, *b, weight * va * vb) {
                return Err(FitError::Shape("a prior outside the band"));
            }
        }
    }
    Ok(())
}

/// The most significant step in any clock's residuals (crate docs, § Jumps), whatever its size,
/// in standard deviations of the clock's nominal timing noise (`Timebase::default_noise_s`) and
/// its site: never its estimated noise, which a jump left in would inflate and so hide.
fn strongest_jump(problem: &Problem<'_>, state: &State) -> Option<(f64, Jump)> {
    let layout = problem.layout;
    let residuals = state.residuals(problem);
    let mut per_clock: BTreeMap<usize, Vec<(i64, ObservationId, f64)>> = BTreeMap::new();
    for (event, rows) in layout.events.iter().zip(&residuals) {
        for (row, residual) in event.rows.iter().zip(rows) {
            let rx = &problem.rxs[row.rx];
            per_clock
                .entry(row.clock)
                .or_default()
                .push((rx.linear, rx.id, *residual));
        }
    }
    let mut best: Option<(f64, Jump)> = None;
    for (clock, mut list) in per_clock {
        list.sort_by(|a, b| a.0.cmp(&b.0).then(a.1.cmp(&b.1)));
        let n = list.len();
        if n < 2 * JUMP_SIDE {
            continue;
        }
        // The clock's noise as its own residuals show it, robustly: 1.4826 times the median
        // absolute consecutive difference, over the square root of two (a difference of two
        // noises; a jump moves one difference only). Never below the nominal.
        let site = problem
            .sites
            .get(&layout.shape.clocks[clock].key.receiver)
            .map_or(0.0, |site| site.sigma_mm as f64 / 1000.0);
        let differences: Vec<f64> = list
            .windows(2)
            .map(|pair| (pair[1].2 - pair[0].2).abs())
            .collect();
        let robust = 1.4826 * median(differences) / std::f64::consts::SQRT_2;
        let floor = (MIN_NOISE_S * C).hypot(site);
        let sigma = robust.max(floor);
        for m in JUMP_SIDE..=n - JUMP_SIDE {
            if list[m].0 == list[m - 1].0 {
                continue;
            }
            let before: Vec<f64> = list[m - JUMP_SIDE..m].iter().map(|x| x.2).collect();
            let after: Vec<f64> = list[m..m + JUMP_SIDE].iter().map(|x| x.2).collect();
            let step = median(after) - median(before);
            let score = step.abs() / sigma;
            if best.as_ref().is_none_or(|(top, _)| score > *top) {
                let key = layout.shape.clocks[clock].key;
                best = Some((
                    score,
                    Jump {
                        receiver: key.receiver,
                        epoch: key.epoch,
                        at: list[m].0,
                        step_ps: (step / C * 1e12).round() as i64,
                    },
                ));
            }
        }
    }
    best
}

fn find_jump(problem: &Problem<'_>, state: &State) -> Option<Jump> {
    strongest_jump(problem, state)
        .filter(|(score, _)| *score > JUMP_THRESHOLD)
        .map(|(_, jump)| jump)
}

fn median(mut values: Vec<f64>) -> f64 {
    values.sort_by(f64::total_cmp);
    let n = values.len();
    if n == 0 {
        return 0.0;
    }
    if n % 2 == 1 {
        values[n / 2]
    } else {
        0.5 * (values[n / 2 - 1] + values[n / 2])
    }
}

/// Each clock's timing noise from its residuals (crate docs, § Noise): `sum r^2 / sum (1 - h)`
/// over its receptions of weight above zero, `h` each reception's exact leverage in the step's
/// system (through the event's own block and the selected inverse of the reduced system), less
/// its site variance, floored.
/// Each clock's noise as its residuals show it before any is estimated, robustly: 1.4826 times
/// their median absolute value, less its site's variance, floored at `MIN_NOISE_S`. Where the
/// rounds start from: a clock far noisier than the nominal (500 ns against 100 ns) would
/// otherwise see most of its receptions beyond the cut-off and never be estimated at all.
fn robust_noise(problem: &Problem<'_>, state: &State) -> BTreeMap<ClockKey, f64> {
    let layout = problem.layout;
    let residuals = state.residuals(problem);
    let mut per_clock: BTreeMap<usize, Vec<f64>> = BTreeMap::new();
    for (event_use, rows) in layout.events.iter().zip(&residuals) {
        for (row, residual) in event_use.rows.iter().zip(rows) {
            per_clock.entry(row.clock).or_default().push(residual.abs());
        }
    }
    per_clock
        .into_iter()
        .filter(|(_, list)| list.len() >= MIN_NOISE_RECEPTIONS)
        .map(|(clock, list)| {
            let info = &layout.shape.clocks[clock];
            let site = problem
                .sites
                .get(&info.key.receiver)
                .map_or(0.0, |site| site.sigma_mm as f64 / 1000.0);
            let scale = 1.4826 * median(list);
            let variance = scale * scale - site * site;
            let floor = MIN_NOISE_S * C;
            (info.key, variance.max(floor * floor).sqrt() / C)
        })
        .collect()
}

fn estimate_noise(
    problem: &Problem<'_>,
    state: &State,
    step: &Step,
    inverse: &Banded,
) -> BTreeMap<ClockKey, f64> {
    let layout = problem.layout;
    let residuals = state.residuals(problem);
    let mut per_clock: BTreeMap<usize, (f64, f64, usize)> = BTreeMap::new();
    for ((event_use, rows), eliminated) in layout.events.iter().zip(&residuals).zip(&step.events) {
        let Some(hll) = &eliminated.hll else {
            continue;
        };
        let slot = |at: At| eliminated.globals.partition_point(|g| *g < at);
        // The event's block of the selected inverse, A; B = A Kᵀ; Q = K A Kᵀ. A row's fitted
        // value has the global part v = e - Kᵀ l (e its own sparse entries, l its local ones),
        // so vᵀ A v = eᵀ A e - 2 eᵀ B l + lᵀ Q l, a few terms a row.
        let m = eliminated.globals.len();
        let block = inverse.gather(&eliminated.globals);
        let mut b_matrix = vec![[0.0; 4]; m];
        for (a, row) in b_matrix.iter_mut().enumerate() {
            for (i, entry) in row.iter_mut().enumerate() {
                let mut sum = 0.0;
                for c in 0..m {
                    sum += block[a * m + c] * eliminated.k[i][c];
                }
                *entry = sum;
            }
        }
        let mut q = [[0.0; 4]; 4];
        for i in 0..4 {
            for j in 0..4 {
                let mut sum = 0.0;
                for c in 0..m {
                    sum += eliminated.k[i][c] * b_matrix[c][j];
                }
                q[i][j] = sum;
            }
        }
        for ((row, residual), local_row) in event_use.rows.iter().zip(rows).zip(&eliminated.rows) {
            if local_row.weight == 0.0 {
                continue;
            }
            let local = hll.solve(&local_row.local);
            let l = &local_row.local;
            let mut variance: f64 = l.iter().zip(&local).map(|(a, b)| a * b).sum();
            for (x, vx) in local_row.global.as_slice() {
                let a = slot(*x);
                for (y, vy) in local_row.global.as_slice() {
                    variance += vx * block[a * m + slot(*y)] * vy;
                }
                for i in 0..4 {
                    variance -= 2.0 * vx * b_matrix[a][i] * l[i];
                }
            }
            for i in 0..4 {
                for j in 0..4 {
                    variance += l[i] * q[i][j] * l[j];
                }
            }
            let leverage = (local_row.weight * variance).clamp(0.0, 0.99);
            let entry = per_clock.entry(row.clock).or_insert((0.0, 0.0, 0));
            entry.0 += residual * residual;
            entry.1 += 1.0 - leverage;
            entry.2 += 1;
        }
    }
    let mut estimates = BTreeMap::new();
    for (clock, (squares, freedom, count)) in per_clock {
        if count < MIN_NOISE_RECEPTIONS {
            continue;
        }
        let info = &layout.shape.clocks[clock];
        let site = problem
            .sites
            .get(&info.key.receiver)
            .map_or(0.0, |site| site.sigma_mm as f64 / 1000.0);
        let variance = squares / freedom - site * site;
        let floor = MIN_NOISE_S * C;
        // `NOISE_MARGIN` standard errors up: an estimate from a few dozen receptions is low as
        // often as high, and a low one makes every solution through the clock overconfident, a
        // high one only conservative (the variance's relative standard error is
        // sqrt(2 / freedom)).
        let upper = 1.0 + NOISE_MARGIN * (2.0 / freedom.max(1.0)).sqrt();
        estimates.insert(
            info.key,
            variance.max(floor * floor).sqrt() * upper.sqrt() / C,
        );
    }
    estimates
}

/// The inputs as the fit and the calibration read them.
struct Read<'a> {
    sites: BTreeMap<PublicKey, SiteInfo>,
    rxs: Vec<Rx<'a>>,
    events: Vec<Event>,
    hearers: BTreeSet<PublicKey>,
}

fn read(inputs: &Inputs) -> Read<'_> {
    let sites = site_table(&inputs.scope);
    // The component holding the most members is the tile's.
    let hearers: BTreeSet<PublicKey> = sites.keys().copied().collect();
    let rxs = linearize(&sites, inputs.sync.iter());
    let events = sync_events(&sites, &rxs);
    Read {
        sites,
        rxs,
        events,
        hearers,
    }
}

/// Fits the clock model of `inputs` (crate docs, § The clock model).
pub fn fit(inputs: &Inputs) -> Result<ClockModel, FitError> {
    fit_with_gauge(inputs, None)
}

/// Fits the clock model of `inputs` and calibrates it in one: the fit's own read of the inputs,
/// and one factorisation at the published (rounded) estimate, kept with its selected inverse.
/// What `calibrate` of the published model would give, without reading the inputs again; an
/// engine solves under its own model through this, and anyone else checks it with
/// `verify::verify_model`.
pub fn fit_calibrated(inputs: &Inputs) -> Result<(ClockModel, Calibrated), FitError> {
    fit_read(inputs, &read(inputs), None, MAX_JUMPS)
}

/// As `fit_calibrated`, warm started from `prior` (the same tile's model of an earlier window, an
/// engine's own): its clocks' offsets carried into this window's frame, its biases, gauge rate
/// and noise as the start, and the cold start's unit and Huber steps skipped. The protocol would
/// allow it (it asks that a model be an optimum of its cited inputs within the verifier's
/// tolerance, not that it be particular bytes), and one whose result is not an optimum is thrown
/// away for a cold fit. Measured (`tests::warm_start_bound`), it does not pay: begun at its own
/// converged model a fit would take 8 ms instead of 55, but begun at the previous stride's model
/// (four bins of new raw, often another jump or noise estimate) it took 94 ms against 62 cold,
/// the jump scan and the noise rounds re-run either way. The engine fits cold.
#[cfg(test)]
pub(crate) fn fit_calibrated_from(
    inputs: &Inputs,
    prior: Option<&ClockModel>,
) -> Result<(ClockModel, Calibrated), FitError> {
    let read = read(inputs);
    if let Some(prior) = prior.filter(|prior| prior.tile == inputs.tile)
        && let Ok((model, _)) = fit_read_from(inputs, &read, None, MAX_JUMPS, Some(prior))
        && let Ok((calibrated, assessment)) = calibrate_read(&model, &read)
        && assessment.distance <= crate::verify::MODEL_OPTIMALITY_TOLERANCE / 10.0
    {
        return Ok((model, calibrated));
    }
    fit_read(inputs, &read, None, MAX_JUMPS)
}

/// A prior model's offset of one of its pieces at linear count `linear`, picoseconds: the
/// interpolation `ClockModel::time` makes, held at the end knots beyond them.
fn offset_at(piece: &ClockPiece, linear: i64) -> i128 {
    let elapsed = piece
        .timebase
        .elapsed_ps(i128::from(linear) - i128::from(piece.base));
    let last = piece.end() - 1;
    let knot = i32::try_from(elapsed.div_euclid(KNOT_PS))
        .unwrap_or(piece.first)
        .clamp(piece.first, last.max(piece.first));
    let at = (knot - piece.first) as usize;
    let left = i128::from(piece.offsets_ps[at]);
    let Some(right) = piece.offsets_ps.get(at + 1).map(|value| i128::from(*value)) else {
        return left;
    };
    let into = (elapsed - i128::from(knot) * KNOT_PS).clamp(0, KNOT_PS);
    left + ((right - left) * into).div_euclid(KNOT_PS)
}

impl State {
    /// The start a prior model gives, in this layout's frame: each clock's offsets carried over
    /// (`o_new = o_prior + e(base_new - base_prior) - D`, `D` the gauge's anchor moved, in its
    /// nominal time), the biases and the gauge rate as they were. `None` when the prior's gauge
    /// is not this fit's.
    fn warm(prior: &ClockModel, problem: &Problem<'_>) -> Option<Self> {
        let layout = problem.layout;
        let shape = &layout.shape;
        if prior.gauge != shape.gauge {
            return None;
        }
        let gauge_new = shape.clocks.iter().find(|clock| clock.key == shape.gauge)?;
        let gauge_prior = prior.gauge_piece()?;
        let shift = gauge_new
            .timebase
            .elapsed_ps(i128::from(gauge_new.base) - i128::from(gauge_prior.base));
        let mut state = Self::start(problem);
        for (index, clock) in shape.clocks.iter().enumerate() {
            let Some(piece) = prior.pieces.iter().find(|piece| piece.key == clock.key) else {
                continue;
            };
            let moved = clock
                .timebase
                .elapsed_ps(i128::from(clock.base) - i128::from(piece.base));
            for knot in clock.first..clock.end {
                let Some(place) = layout.places.get(&(index, knot)) else {
                    continue;
                };
                let linear = clock.base + i64::from(knot) * clock.timebase.knot_counts();
                let offset = offset_at(piece, linear) + moved - shift;
                state.theta.add(*place, offset as f64 * 1e-12 * C);
            }
        }
        for bias in &prior.biases {
            if let Some(at) = layout.bias(bias.address, bias.kind) {
                state.theta.add(at, bias.mm as f64 / 1000.0);
            }
        }
        state
            .theta
            .add(layout.rate(), prior.gauge_rate as f64 * PPM_PER_RATE);
        Some(state)
    }
}

/// As `fit`, with the gauge forced to `gauge`'s clock instead of chosen by the rule: model time
/// is then another clock's, and everything published from it should agree within its
/// uncertainty, which is what checking the gauge rule's arbitrariness needs.
pub fn fit_with_gauge(inputs: &Inputs, gauge: Option<PublicKey>) -> Result<ClockModel, FitError> {
    fit_inner(inputs, gauge, MAX_JUMPS)
}

/// A fit that looks for no jumps at all: what an engine that skipped the jump rule would
/// publish, which a verifier must refuse when the raw shows one.
#[cfg(test)]
pub(crate) fn fit_ignoring_jumps(inputs: &Inputs) -> Result<ClockModel, FitError> {
    fit_inner(inputs, None, 0)
}

fn fit_inner(
    inputs: &Inputs,
    gauge: Option<PublicKey>,
    max_jumps: usize,
) -> Result<ClockModel, FitError> {
    fit_read(inputs, &read(inputs), gauge, max_jumps).map(|(model, _)| model)
}

fn fit_read(
    inputs: &Inputs,
    read: &Read<'_>,
    gauge: Option<PublicKey>,
    max_jumps: usize,
) -> Result<(ClockModel, Calibrated), FitError> {
    fit_read_from(inputs, read, gauge, max_jumps, None)
}

fn fit_read_from(
    inputs: &Inputs,
    read: &Read<'_>,
    gauge: Option<PublicKey>,
    max_jumps: usize,
    prior: Option<&ClockModel>,
) -> Result<(ClockModel, Calibrated), FitError> {
    if read.events.is_empty() {
        return Err(FitError::NoSyncEvents);
    }
    let mut jumps: Vec<Jump> = Vec::new();
    let mut dropped: BTreeSet<(PublicKey, u32)> = BTreeSet::new();
    loop {
        match attempt(inputs, read, gauge, max_jumps, prior, &jumps, &dropped) {
            Ok(Attempt::Done(done)) => return Ok(*done),
            Ok(Attempt::Jump(jump)) => admit(&mut jumps, &mut dropped, jump, max_jumps)?,
            // Clocks nothing places are dropped, their jumps with them, and the fit starts over:
            // each pass drops at least one, so it ends.
            Err(FitError::Uninformed(clocks)) => {
                let before = dropped.len();
                dropped.extend(clocks);
                if dropped.len() == before {
                    return Err(FitError::Singular);
                }
                jumps.retain(|jump| !dropped.contains(&(jump.receiver, jump.epoch)));
            }
            Err(error) => return Err(error),
        }
    }
}

/// What one pass of a fit ends in: a model, or a jump to declare before the next.
enum Attempt {
    Done(Box<(ClockModel, Calibrated)>),
    Jump(Jump),
}

/// One pass of `fit_read_from` with the jumps and dropped clocks so far.
fn attempt(
    inputs: &Inputs,
    read: &Read<'_>,
    gauge: Option<PublicKey>,
    max_jumps: usize,
    prior: Option<&ClockModel>,
    jumps: &[Jump],
    dropped: &BTreeSet<(PublicKey, u32)>,
) -> Result<Attempt, FitError> {
    let events = without(&read.events, &read.rxs, dropped);
    let boundaries = boundaries_of(jumps);
    let shape = shape(
        &read.sites,
        &read.rxs,
        &events,
        &boundaries,
        &read.hearers,
        gauge,
    )?;
    let layout = Layout::new(shape, &read.sites, &read.rxs, &events);
    if layout.events.is_empty() {
        return Err(FitError::NoSyncEvents);
    }
    let problem = Problem {
        sites: &read.sites,
        rxs: &read.rxs,
        events: &events,
        layout: &layout,
    };
    let mut noise = BTreeMap::new();
    let warm = prior.and_then(|prior| {
        let state = State::warm(prior, &problem)?;
        let known: BTreeMap<ClockKey, f64> = prior
            .pieces
            .iter()
            .map(|piece| (piece.key, piece.noise_ps as f64 * 1e-12))
            .collect();
        Some((state, known))
    });
    let mut state = match warm {
        Some((mut state, known)) => {
            noise.extend(known);
            state.settle_events(&problem, &noise);
            state
        }
        None => {
            let mut state = State::start(&problem);
            state.step(&problem, &noise, Weighting::Unit)?;
            for _ in 0..HUBER_STEPS {
                state.step(&problem, &noise, Weighting::Huber)?;
            }
            state
        }
    };
    if max_jumps > 0
        && let Some(jump) = find_jump(&problem, &state)
    {
        return Ok(Attempt::Jump(jump));
    }
    noise.extend(robust_noise(&problem, &state));
    for round in 1..=NOISE_ROUNDS.1 {
        let step = state.step(&problem, &noise, Weighting::Final)?;
        let inverse = step.factor.selected_inverse();
        let estimates = estimate_noise(&problem, &state, &step, &inverse);
        let settled = estimates.iter().all(|(key, value)| {
            noise
                .get(key)
                .is_some_and(|old: &f64| (value - old).abs() <= NOISE_SETTLED * old)
        });
        noise.extend(estimates);
        if round >= NOISE_ROUNDS.0 && settled {
            break;
        }
    }
    // Final steps until one moves the estimate by less than `CONVERGED` squared standard
    // deviations, at least `FINAL_STEPS` and at most `MAX_FINAL_STEPS`.
    for taken in 1..=MAX_FINAL_STEPS {
        let step = state.step(&problem, &noise, Weighting::Final)?;
        let moved = -step.delta.dot(&step.gradient);
        if taken >= FINAL_STEPS && moved <= CONVERGED {
            break;
        }
    }
    // A jump the final estimate still shows is split too, and the fit starts over: so a
    // model that is published shows none above the threshold, which a verifier checks.
    if max_jumps > 0
        && let Some(jump) = find_jump(&problem, &state)
    {
        return Ok(Attempt::Jump(jump));
    }
    let mut jumps = jumps.to_vec();
    jumps.sort_unstable();
    let mut fixups = 0;
    loop {
        let mut model = build_model(inputs, &problem, &state, &noise, jumps.clone())?;
        // The estimate as a verifier will see it: the published model, its events settled
        // from their priors with the clocks held (`State::at`). Under robust weights an event
        // can settle into another of its optima than the joint iteration left it in; then the
        // fit goes on from there, so what is published is an optimum of what anyone rebuilds.
        // The step at the published estimate that shows it converged is its calibration too:
        // its factor's selected inverse is what solving under the model needs (folded, not
        // formed again).
        model.dropped = dropped.iter().copied().collect();
        let mut at_estimate: Option<(State, Step)> = None;
        for _ in 0..RESETTLE_PASSES {
            let (mut settled, published) = State::at(&model, &problem);
            let step = settled.system(&problem, &published, Weighting::Final)?;
            if -step.delta.dot(&step.gradient) <= CONVERGED {
                at_estimate = Some((settled, step));
                break;
            }
            settled.apply(&step);
            for taken in 2..=MAX_FINAL_STEPS {
                let step = settled.step(&problem, &published, Weighting::Final)?;
                if taken >= FINAL_STEPS && -step.delta.dot(&step.gradient) <= CONVERGED {
                    break;
                }
            }
            model = build_model(inputs, &problem, &settled, &published, jumps.clone())?;
            model.dropped = dropped.iter().copied().collect();
        }
        let (settled, step) = match at_estimate {
            Some(found) => found,
            None => {
                let (settled, published) = State::at(&model, &problem);
                let step = settled.system(&problem, &published, Weighting::Final)?;
                (settled, step)
            }
        };
        // What a verifier scans for undeclared jumps is the published estimate, so that is what
        // is scanned last: a step there is split as one the joint estimate shows (a clock whose
        // stamps are noise can show a step only once its events are settled from their priors).
        if max_jumps > 0
            && let Some(jump) = find_jump(&problem, &settled)
        {
            return Ok(Attempt::Jump(jump));
        }
        let inverse = step.factor.selected_inverse();
        // The noise the rule estimates at the published estimate: a clock published well
        // below it would be refused (understated noise), so the noise is taken from there and
        // the final steps run again, at most `NOISE_FIXUPS` times.
        let estimates = estimate_noise(&problem, &settled, &step, &inverse);
        let understated = model.pieces.iter().any(|piece| {
            estimates.get(&piece.key).is_some_and(|estimate| {
                (piece.noise_ps as f64) * 1e-12 < (1.0 - crate::verify::NOISE_BAND / 2.0) * estimate
            })
        });
        if understated && fixups < NOISE_FIXUPS {
            fixups += 1;
            noise.extend(estimates);
            state = settled;
            for taken in 1..=MAX_FINAL_STEPS {
                let step = state.step(&problem, &noise, Weighting::Final)?;
                if taken >= FINAL_STEPS && -step.delta.dot(&step.gradient) <= CONVERGED {
                    break;
                }
            }
            continue;
        }
        let calibrated = Calibrated {
            model: model.clone(),
            places: layout.places.clone(),
            rate: layout.rate(),
            inverse,
        };
        return Ok(Attempt::Done(Box::new((model, calibrated))));
    }
}

/// Times the noise is re-taken at the published estimate when the rule there finds a clock's
/// published noise understated (`fit_read`).
pub const NOISE_FIXUPS: usize = 2;

/// Times the published estimate is settled again before the fit gives up making it the optimum
/// a verifier rebuilds (`fit_read`).
pub const RESETTLE_PASSES: usize = 3;

/// The most a warm start could save (measured by `tests::warm_start_bound`): the fit begun at a
/// converged model of the very same inputs, its noise and shape taken as given, run to the same
/// convergence. A warm start from the previous stride's model of the tile starts further away
/// than this, so saves less.
#[cfg(test)]
pub(crate) fn fit_from_converged(
    inputs: &Inputs,
    model: &ClockModel,
) -> Result<ClockModel, FitError> {
    let read = read(inputs);
    let dropped: BTreeSet<(PublicKey, u32)> = model.dropped.iter().copied().collect();
    let events = without(&read.events, &read.rxs, &dropped);
    let layout = Layout::new(Shape::of_model(model), &read.sites, &read.rxs, &events);
    let problem = Problem {
        sites: &read.sites,
        rxs: &read.rxs,
        events: &events,
        layout: &layout,
    };
    let (mut state, noise) = State::at(model, &problem);
    for taken in 1..=MAX_FINAL_STEPS {
        let step = state.step(&problem, &noise, Weighting::Final)?;
        if taken >= FINAL_STEPS && -step.delta.dot(&step.gradient) <= CONVERGED {
            break;
        }
    }
    build_model(inputs, &problem, &state, &noise, model.jumps.clone())
}

/// Takes a jump the scan found: declared while the fit has fewer than `max_jumps`; beyond that
/// the clock that misbehaves most (the most jumps, this one counted; of equals, the lowest key)
/// is dropped from the tile with its jumps, and the fit goes on without it. One bad receiver
/// costs the tile that receiver, never the tile.
fn admit(
    jumps: &mut Vec<Jump>,
    dropped: &mut BTreeSet<(PublicKey, u32)>,
    jump: Jump,
    max_jumps: usize,
) -> Result<(), FitError> {
    if jumps.len() < max_jumps {
        jumps.push(jump);
        return Ok(());
    }
    let mut counts: BTreeMap<(PublicKey, u32), usize> = BTreeMap::new();
    for one in jumps.iter().chain(std::iter::once(&jump)) {
        *counts.entry((one.receiver, one.epoch)).or_default() += 1;
    }
    let worst = counts
        .iter()
        .fold(
            None,
            |best: Option<((PublicKey, u32), usize)>, (clock, count)| match best {
                Some((_, top)) if *count <= top => best,
                _ => Some((*clock, *count)),
            },
        )
        .map(|(clock, _)| clock)
        .ok_or(FitError::UndeclaredJump)?;
    if !dropped.insert(worst) {
        return Err(FitError::UndeclaredJump);
    }
    jumps.retain(|one| (one.receiver, one.epoch) != worst);
    Ok(())
}

/// The events without the receptions of dropped clocks (an event left with fewer than two is
/// gone).
fn without(events: &[Event], rxs: &[Rx<'_>], dropped: &BTreeSet<(PublicKey, u32)>) -> Vec<Event> {
    if dropped.is_empty() {
        return events.to_vec();
    }
    events
        .iter()
        .filter_map(|event| {
            let mut event = event.clone();
            event
                .rx
                .retain(|index| !dropped.contains(&(rxs[*index].receiver, rxs[*index].epoch)));
            (event.rx.len() >= 2).then_some(event)
        })
        .collect()
}

fn build_model(
    inputs: &Inputs,
    problem: &Problem<'_>,
    state: &State,
    noise: &BTreeMap<ClockKey, f64>,
    jumps: Vec<Jump>,
) -> Result<ClockModel, FitError> {
    let layout = problem.layout;
    let shape = &layout.shape;
    let mut pieces = Vec::with_capacity(shape.clocks.len());
    for (index, clock) in shape.clocks.iter().enumerate() {
        let offsets_ps = (clock.first..clock.end)
            .map(|knot| {
                layout
                    .places
                    .get(&(index, knot))
                    .map_or(0, |at| (state.theta.get(*at) / C * 1e12).round() as i64)
            })
            .collect();
        let site = problem.sites.get(&clock.key.receiver);
        pieces.push(ClockPiece {
            key: clock.key,
            timebase: clock.timebase,
            begins: clock.begins,
            ends: clock.ends,
            site_mm: site.map_or([0; 3], |site| site.mm),
            site_sigma_mm: site.map_or(0, |site| site.sigma_mm),
            noise_ps: (noise_s(shape, noise, index) * 1e12).round() as i64,
            base: clock.base,
            first: clock.first,
            offsets_ps,
        });
    }
    let biases = layout
        .border
        .iter()
        .filter_map(|(param, slot)| match param {
            Param::Bias(address, kind) => Some(Bias {
                address: *address,
                kind: *kind,
                mm: (state.theta.get(At::Border(*slot)) * 1000.0).round() as i64,
            }),
            Param::Rate => None,
        })
        .collect();
    let gauge_rate = (state.theta.get(layout.rate()) / PPM_PER_RATE).round() as i64;
    let gauge = shape
        .clocks
        .iter()
        .find(|clock| clock.key == shape.gauge)
        .ok_or(FitError::Shape("no gauge"))?;
    let origin_unix_ns = origin_unix_ns(
        gauge.timebase,
        gauge.base,
        shape.anchor_wall_ms.saturating_mul(1_000_000),
    )
    .ok_or(FitError::Shape("no origin"))?;
    Ok(ClockModel {
        spec: SPEC_VERSION,
        tile: inputs.tile,
        window: inputs.window,
        scope: inputs.scope.clone(),
        input: inputs.citation,
        gauge: shape.gauge,
        origin_unix_ns,
        gauge_rate,
        pieces,
        biases,
        jumps,
        dropped: Vec::new(),
    })
}

/// The Unix time of model time zero, given the wall clock (Unix nanoseconds) of the gauge's
/// signed batch that carried its anchor reception. A GNSS-disciplined gauge's linear count is
/// nanoseconds of the UTC day, so the wall clock only picks the day (the one that puts the anchor
/// within half a day of it) and the origin is exact; a free-running gauge has no absolute time,
/// and the wall clock is the origin.
pub fn origin_unix_ns(timebase: Timebase, anchor: i64, wall_unix_ns: u64) -> Option<u64> {
    match timebase {
        Timebase::Mhz12 => Some(wall_unix_ns),
        Timebase::GpsNanos => {
            let day = i128::from(DAY_NS);
            let wall = i128::from(wall_unix_ns);
            let anchor = i128::from(anchor);
            let start = (wall - anchor + day / 2).div_euclid(day) * day;
            u64::try_from(start + anchor).ok()
        }
    }
}

/// A published model with what solving under it needs and the model itself does not carry: the
/// covariance of its knots, from one factorisation of its normal equations at its estimate.
#[derive(Clone, Debug)]
pub struct Calibrated {
    pub model: ClockModel,
    /// (piece, knot) to its place in `inverse`.
    places: BTreeMap<(usize, i32), At>,
    /// The gauge rate's place (parts per million).
    rate: At,
    /// The selected inverse, metres squared.
    inverse: Banded,
}

/// What a model's estimate shows when its normal equations are formed there (crate docs,
/// § Verifying a model).
#[derive(Clone, Debug, PartialEq)]
pub struct Assessment {
    /// The squared Mahalanobis length of the Gauss-Newton step from the estimate.
    pub distance: f64,
    /// Each clock's noise as the rule estimates it at the estimate, picoseconds.
    pub noise_ps: BTreeMap<ClockKey, i64>,
    /// The strongest step in any clock's residuals, in its standard deviations.
    pub jump: Option<f64>,
}

impl Calibrated {
    /// The covariance, seconds squared, of the clock error of two receptions mapped through the
    /// model, about `reference_ps` (a model time of the same transmission: the gauge rate's error
    /// moves a time by its distance from there, and what it moves every reception by alike the
    /// transmit time takes), or `None` when their knots are further apart than the selected
    /// inverse holds.
    pub fn clock_covariance(
        &self,
        a: &ModelTime,
        b: &ModelTime,
        reference_ps: i128,
    ) -> Option<f64> {
        self.clock_cross_covariance((a, reference_ps), (b, reference_ps))
    }

    /// One standard deviation of the gauge's rate, parts per million (from the selected inverse).
    pub fn gauge_rate_sigma_ppm(&self) -> Option<f64> {
        self.inverse.get(self.rate, self.rate).map(f64::sqrt)
    }

    /// As `clock_covariance`, each time about its own reference: two transmissions' receptions
    /// under one model, for the covariance between their solutions.
    pub fn clock_cross_covariance(
        &self,
        (a, reference_a): (&ModelTime, i128),
        (b, reference_b): (&ModelTime, i128),
    ) -> Option<f64> {
        let weights = |time: &ModelTime, reference_ps: i128| -> Vec<(At, f64)> {
            let f = time.fraction();
            let lever_m = (time.ps - reference_ps) as f64 * 1e-12 * C;
            [(time.knot, 1.0 - f), (time.knot + 1, f)]
                .into_iter()
                .filter_map(|(knot, weight)| {
                    self.places.get(&(time.piece, knot)).map(|at| (*at, weight))
                })
                .chain(std::iter::once((self.rate, lever_m * 1e-6)))
                .collect()
        };
        let mut sum = 0.0;
        for (x, wx) in weights(a, reference_a) {
            for (y, wy) in weights(b, reference_b) {
                sum += wx * wy * self.inverse.get(x, y)?;
            }
        }
        let fitted = sum / (C * C);
        if a.carried_ps > 0 || b.carried_ps > 0 {
            return Some(fitted + self.carried_covariance(a, b));
        }
        Some(fitted)
    }

    /// What carrying the model past its knots adds to the clock covariance of two receptions,
    /// seconds squared (crate docs, § Provisional solutions). Past its last knot a clock's offset
    /// follows its last interval's line, and its true offset wanders from that line by the
    /// curvature prior's integrated random walk: with `n` the knot intervals carried (fractional)
    /// and `d` the independent second differences of standard deviation `sigma` (the clock's
    /// curvature, `Timebase::curvature_sigma_s`), the offset `n` intervals on is off by
    /// `sum_{j <= n} (n - j + 1) d_j`, so two receptions of one clock carried `m <= M` intervals
    /// covary by `sigma^2 (m (m + 1) (2m + 1) / 6 + (M - m) m (m + 1) / 2)`. An offset is from the
    /// gauge, whose own walk moves every other clock's offset alike: every pair of receptions on
    /// clocks other than the gauge adds the same term with the gauge's curvature, a pair on one
    /// clock adds its own as well, and a reception on the gauge adds nothing.
    fn carried_covariance(&self, a: &ModelTime, b: &ModelTime) -> f64 {
        let model = &self.model;
        let on_gauge = |time: &ModelTime| {
            model
                .pieces
                .get(time.piece)
                .is_none_or(|piece| piece.key == model.gauge)
        };
        if on_gauge(a) || on_gauge(b) {
            return 0.0;
        }
        let intervals = |time: &ModelTime| time.carried_ps.max(0) as f64 / KNOT_PS as f64;
        let (first, second) = (intervals(a), intervals(b));
        let (m, most) = if first <= second {
            (first, second)
        } else {
            (second, first)
        };
        let walk = m * (m + 1.0) * (2.0 * m + 1.0) / 6.0 + (most - m) * m * (m + 1.0) / 2.0;
        let curvature =
            |piece: Option<&ClockPiece>| piece.map_or(0.0, |p| p.timebase.curvature_sigma_s());
        let gauge = curvature(model.gauge_piece());
        let mut variance = gauge * gauge;
        if a.piece == b.piece {
            let own = curvature(model.pieces.get(a.piece));
            variance += own * own;
        }
        variance * walk
    }
}

/// Forms the normal equations of `model` at its estimate from the raw it cites, once: the
/// covariance solutions need, and what a verifier checks (`Assessment`).
pub fn calibrate(
    model: &ClockModel,
    inputs: &Inputs,
) -> Result<(Calibrated, Assessment), FitError> {
    calibrate_read(model, &read(inputs))
}

fn calibrate_read(
    model: &ClockModel,
    read: &Read<'_>,
) -> Result<(Calibrated, Assessment), FitError> {
    let layout = Layout::new(Shape::of_model(model), &read.sites, &read.rxs, &read.events);
    if layout.events.is_empty() {
        return Err(FitError::NoSyncEvents);
    }
    let problem = Problem {
        sites: &read.sites,
        rxs: &read.rxs,
        events: &read.events,
        layout: &layout,
    };
    let (state, noise) = State::at(model, &problem);
    let step = state.system(&problem, &noise, Weighting::Final)?;
    let inverse = step.factor.selected_inverse();
    let distance = -step.delta.dot(&step.gradient);
    let noise_ps = estimate_noise(&problem, &state, &step, &inverse)
        .into_iter()
        .map(|(key, seconds)| (key, (seconds * 1e12).round() as i64))
        .collect();
    let jump = strongest_jump(&problem, &state).map(|(score, _)| score);
    Ok((
        Calibrated {
            model: model.clone(),
            places: layout.places.clone(),
            rate: layout.rate(),
            inverse,
        },
        Assessment {
            distance,
            noise_ps,
            jump,
        },
    ))
}

/// Whether `model`'s clocks, gauge, knots and sites are the ones the rules derive from `inputs`
/// (with its declared jumps): `None` when they are, else what differs.
pub fn check_shape(model: &ClockModel, inputs: &Inputs) -> Option<&'static str> {
    let read = read(inputs);
    let boundaries = boundaries_of(&model.jumps);
    let dropped: BTreeSet<(PublicKey, u32)> = model.dropped.iter().copied().collect();
    let events = without(&read.events, &read.rxs, &dropped);
    let Ok(derived) = shape(
        &read.sites,
        &read.rxs,
        &events,
        &boundaries,
        &read.hearers,
        None,
    ) else {
        return Some("no clocks");
    };
    if derived.gauge != model.gauge {
        return Some("gauge");
    }
    if derived.clocks != Shape::of_model(model).clocks {
        return Some("clocks or knots");
    }
    for piece in &model.pieces {
        let Some(site) = read.sites.get(&piece.key.receiver) else {
            return Some("site");
        };
        if site.mm != piece.site_mm || site.sigma_mm != piece.site_sigma_mm {
            return Some("site");
        }
    }
    let Some(gauge) = model.gauge_piece() else {
        return Some("gauge");
    };
    if origin_unix_ns(
        gauge.timebase,
        gauge.base,
        derived.anchor_wall_ms.saturating_mul(1_000_000),
    ) != Some(model.origin_unix_ns)
    {
        return Some("origin");
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::linalg::Matrix;
    use crate::scope::{Sites, Window, WindowIndex};
    use crate::sim::{self, Scenario};

    /// A clock none of whose receptions carries weight has a free offset: the system is singular
    /// (in floating point it may still factor, on a vanishing pivot, which is worse: the free
    /// offset is solved to noise), and `uninformed` names that clock and no other, so the fit drops it and goes on
    /// (`fit_read_from`) instead of failing the tile. Real receivers do this (OpenSky's LocaRDS:
    /// clocks left with no usable event, and clocks every reception of which is beyond the
    /// cut-off); here one honest clock is given a noise so small that every reception of it is.
    #[test]
    fn a_clock_with_no_weight_is_named_uninformed_and_nothing_else_is() -> Result<(), String> {
        let simulation = sim::run(&Scenario {
            duration_s: 12.0,
            ..Scenario::new(3)
        });
        let bins: Vec<_> = crate::held::bins_of(&simulation.receptions)
            .into_values()
            .collect();
        let sites = Sites::new(&simulation.sites());
        let bin = bins.last().ok_or("no bins")?.bin;
        let index = WindowIndex::new(Window::canonical(bin), &bins, &sites);
        let plan = index.plan();
        let tile = plan.tiles().into_iter().next().ok_or("no tile")?;
        let inputs = index
            .inputs(tile, &plan.members[&tile])
            .ok_or("no inputs")?;
        let model = fit(&inputs).map_err(|e| e.to_string())?;
        let read = read(&inputs);
        let layout = Layout::new(
            Shape::of_model(&model),
            &read.sites,
            &read.rxs,
            &read.events,
        );
        let problem = Problem {
            sites: &read.sites,
            rxs: &read.rxs,
            events: &read.events,
            layout: &layout,
        };
        let (state, mut noise) = State::at(&model, &problem);
        let (_, _, eliminated) = state
            .normal_equations(&problem, &noise, Weighting::Final)
            .map_err(|e| e.to_string())?;
        assert!(uninformed(&layout, &eliminated).is_empty());
        let silenced = layout
            .shape
            .clocks
            .iter()
            .find(|clock| clock.key != layout.shape.gauge)
            .ok_or("one clock")?
            .key;
        noise.insert(silenced, 1e-15);
        let (_, _, eliminated) = state
            .normal_equations(&problem, &noise, Weighting::Final)
            .map_err(|e| e.to_string())?;
        assert_eq!(
            uninformed(&layout, &eliminated),
            vec![(silenced.receiver, silenced.epoch)]
        );
        assert!(matches!(
            state.system(&problem, &noise, Weighting::Final),
            Err(FitError::Uninformed(_))
        ));
        Ok(())
    }

    /// (a) A scope's time-banded system solves and selectively inverts as the same system dense:
    /// every step and every block of the selected inverse to within 1e-12, relative.
    #[test]
    fn a_scopes_banded_system_agrees_with_the_dense_reference() -> Result<(), String> {
        let simulation = sim::run(&Scenario {
            duration_s: 12.0,
            ..Scenario::new(3)
        });
        let bins: Vec<_> = crate::held::bins_of(&simulation.receptions)
            .into_values()
            .collect();
        let sites = Sites::new(&simulation.sites());
        let bin = bins.last().ok_or("no bins")?.bin;
        let index = WindowIndex::new(Window::canonical(bin), &bins, &sites);
        let plan = index.plan();
        let mut checked = 0;
        for tile in plan.tiles().into_iter().take(3) {
            let inputs = index
                .inputs(tile, &plan.members[&tile])
                .ok_or("no inputs")?;
            let model = fit(&inputs).map_err(|e| e.to_string())?;
            let read = read(&inputs);
            let layout = Layout::new(
                Shape::of_model(&model),
                &read.sites,
                &read.rxs,
                &read.events,
            );
            let problem = Problem {
                sites: &read.sites,
                rxs: &read.rxs,
                events: &read.events,
                layout: &layout,
            };
            let (state, noise) = State::at(&model, &problem);
            let (normal, gradient, _) = state
                .normal_equations(&problem, &noise, Weighting::Final)
                .map_err(|e| e.to_string())?;
            let places: Vec<At> = layout
                .sizes
                .iter()
                .enumerate()
                .flat_map(|(s, size)| (0..*size).map(move |r| At::Slice(s, r)))
                .chain((0..layout.border.len()).map(At::Border))
                .collect();
            let n = places.len();
            let mut dense = Matrix::zeros(n);
            for (i, a) in places.iter().enumerate() {
                for (j, b) in places.iter().enumerate() {
                    dense.set(i, j, normal.get(*a, *b).unwrap_or(0.0));
                }
            }
            let factor = normal.factor().ok_or("not positive definite")?;
            let reference = dense.cholesky().ok_or("dense not positive definite")?;
            let rhs: Vec<f64> = places.iter().map(|at| -gradient.get(*at)).collect();
            let mut vector = Vector::zeros(&layout.sizes, layout.border.len());
            for (at, value) in places.iter().zip(&rhs) {
                vector.add(*at, *value);
            }
            let banded = factor.solve(&vector);
            let want = reference.solve(&rhs);
            let scale = want.iter().fold(0.0f64, |m, v| m.max(v.abs()));
            for (i, at) in places.iter().enumerate() {
                assert!(
                    (banded.get(*at) - want[i]).abs() <= 1e-12 * scale.max(1e-30),
                    "step at {at:?}"
                );
            }
            let selected = factor.selected_inverse();
            let inverse = reference.inverse();
            for (i, a) in places.iter().enumerate() {
                for (j, b) in places.iter().enumerate() {
                    if let Some(value) = selected.get(*a, *b) {
                        let want = inverse.get(i, j);
                        let scale = (inverse.get(i, i) * inverse.get(j, j)).sqrt();
                        assert!(
                            (value - want).abs() <= 1e-12 * scale,
                            "{a:?} {b:?}: {value} against {want}"
                        );
                        checked += 1;
                    }
                }
            }
        }
        assert!(checked > 1000, "{checked}");
        Ok(())
    }
}
