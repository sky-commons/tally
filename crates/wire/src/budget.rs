//! The clocks' error budget (RFC-0171 §3.6): every source of time error named once, and every
//! window and tolerance a relay or a feeder judges a signed time by derived from them, each term
//! saying which error it absorbs. Nothing outside this module can make a [`Tolerance`] or a
//! [`Window`] (their constructors are private to it), so a window cannot be written from a
//! literal elsewhere: a new one is a new derivation here, beside the others, under the same
//! compile-time checks.
//!
//! | term | value | what it absorbs |
//! | --- | --- | --- |
//! | [`E`] | 7.5 s | a judging relay's (or a synced host's) clock against true time |
//! | [`CLOCK_BOUND_MARGIN`] | 418 ms | what ClockBound's word may leave unsaid of `E`: `J`'s whole milliseconds and its documented gaps |
//! | [`U_M`] | 1 s | a feeder's measurement of one relay's clock |
//! | [`TRANSIT`] (`δ`) | 1 s | one way, feeder to relay or relay to feeder |
//! | [`ANCHOR_PERIOD`] (`P`) | 1 s | how often a relay signs a new anchor |
//! | [`ANCHOR_HELD`] | 2 s | how long a feeder signs by an anchor after it first heard it |
//! | [`F`] | 10 s | a feeder's signed time ahead of its relay's clock |
//! | [`B`] | 64 s | how long a feeder may hold a batch, gathered to sent |
//! | [`SEAL_PERIOD`] | 1 s | how often a feeder seals a batch |
//! | [`CEILING_BURST`] | 1 s | what a feeder's ceiling, or a session's pace, lets through at once |
//! | [`BACKLOG_DRAIN`] | 2 s | what a feeder's released backlog adds to a batch's way out: `SEAL_PERIOD + CEILING_BURST` |
//! | [`ANCHOR_WAIT`] | 62 s | how long a feeder holds a batch for an anchor: `B - BACKLOG_DRAIN` |
//! | [`REPAIR_TRANSIT`] | 2 s | a repaired copy's way to the member that asked |
//! | [`K`] | 15 s | two relays' clocks apart: `2E` |
//! | [`SELECTION_LAG`] | 17 s | a trusted reference's width, so how far below true time its low end, which a feeder signs at, may be: `2(E + U_m)` |
//! | [`ANCHOR_AGE`] | 4 s | an honest anchor's age as a batch is signed by it: `P + δ + 2P` |
//! | [`MLAT_BATCHING`] | 2 s | a receiver's raw of a moment, gathered and on its way |
//! | [`FIX_SOLVE`] | 4 s | an MLAT fix's way out of its engine, its first reception in |
//! | [`FIX_SETTLE`] | 1.1 s | how long the engine waits for a transmission's later receptions after its first |
//! | [`ARRIVED_SLICE`] | 1 s | the slices the engine seals what has arrived in |
//! | [`MODEL_KNOT`] | 5 s | a pair's knot spacing |
//! | [`REFIT_EVERY`] | 2 s | how often an area's pair model is refit: the refit grid |
//! | [`FIT_LAG`] | 2 s | how far a model's trailing edge trails its refit's clock: `MLAT_BATCHING` |
//! | [`TRAILING_WINDOW`] | 15 s | the sync raw a trailing-window model is fitted over |
//!
//! What follows from them is each derived below with the error each term absorbs: the feeder's,
//! peers' and anchors' windows, [`OWN_ANCHOR_OLDEST`] (blame, measured on the origin's raw
//! monotonic clock), the hosted MLAT's [`MLAT_AHEAD`], and of its one class of fix (RFC-0171
//! §3.8.1 as amended 2026-10-24) the signed lag of the receptions it is solved from
//! ([`SIGNED_LAG`]), when it has been offered where it was heard ([`FIX_LEAVES`]), when it has
//! surely arrived wherever it is read ([`FIX_ARRIVED`], the world's settle and a fix's standing's)
//! and how far its model is carried ([`MAX_CARRY`]), the feeder
//! figures' [`Window::FIGURES`] and [`Window::FIGURES_POSITIONS`], when a relay restates its clock
//! to a feeder ([`RESTATE_BEYOND`]), and the strike tables' [`FALLBACK_FLOOR`]. A signed time
//! compared against a clock is compared through [`Tolerance`]'s methods or a [`Window`], never by
//! hand.
//! [`ACARS_MESSAGE_SKEW`], [`EVIDENCE_AGE`], [`EVIDENCE_AWAITED`], [`FIGURES_SERVED`],
//! [`ADSB_HORIZON`], [`ADSB_REMEMBERED`], [`LEASE`], [`expired`], [`reached`] and [`passed`] are
//! the exemptions, each stated where it is: a choice of how long a thing is kept
//! or held, not a clock's error, stated here because each is compared with a clock.
//!
//! What is not here is not a clock's error but a choice of how old a thing may be served or
//! counted, measured on one machine's own clock: a product's age at the API, a station's
//! "online", the world product's history before its first seal, a fan-out queue's lag. Those
//! are policies of their own modules, and none is a tolerance of one clock against another. A
//! policy that moves or measures a reading is a [`Span`] of that reading's clock, made by
//! [`policy`] from a constant, so no number read at run time (a reading of another clock) is ever
//! one.
//!
//! What comparing by hand, or across clocks, would look like, refused by the compiler:
//!
//! ```compile_fail,E0277
//! # use tally_wire::budget::K;
//! # use tally_wire::clocks::Judged;
//! // A window's edge is a reading of the clock it is on, never a number.
//! fn hand_cmp(signed: u64, now: Judged) -> bool { signed > K.after(now.ms()) }
//! ```
//!
//! ```compile_fail,E0308
//! # use tally_wire::budget::K;
//! # use tally_wire::clocks::Judged;
//! // Nor is a signed time compared with one by hand.
//! fn hand_cmp(signed: u64, now: Judged) -> bool { signed > K.after(now) }
//! ```
//!
//! ```compile_fail,E0308
//! # use tally_wire::budget::Window;
//! # use tally_wire::clocks::Mono;
//! // A signed time is judged by the judging clock, never the monotonic one.
//! fn window_on_mono(signed: u64, m: Mono) -> bool { Window::PEER.holds(signed, m) }
//! ```
//!
//! ```compile_fail,E0308
//! # use tally_wire::budget::Window;
//! // A window's horizon is a span of the judging clock, never a raw duration.
//! fn horizon() -> Window { Window::sharing(std::time::Duration::from_secs(30)) }
//! ```
//!
//! ```compile_fail,E0435
//! # use tally_wire::budget::policy;
//! # use tally_wire::clocks::{Judged, Mono, Span};
//! // A policy is a constant: a reading's milliseconds never become one.
//! fn span_of(m: Mono) -> Span<Judged> { policy::<Judged, { m.ms() }>() }
//! ```
//!
//! ```compile_fail,E0308
//! # use tally_wire::budget::K;
//! # use tally_wire::clocks::{Mono, Raw};
//! // A tolerance measures a span on one clock, both ends its readings.
//! fn mixed(since: Mono, now: Raw) -> bool { K.past(since, now) }
//! ```

/// A span of milliseconds in the clocks' error budget. Only this module makes one, so every
/// tolerance is one of its terms or derived from them here. It is a true span, measured on no
/// clock in particular: it becomes a span of one ([`Span`], `Span<Judged>`, ...) where a reading
/// of that clock is moved or measured by it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Tolerance(u64);

impl Tolerance {
    /// Its milliseconds: this module's alone, so a span is compared with a clock only through the
    /// methods below and never by hand.
    const fn ms(self) -> u64 {
        self.0
    }

    /// The span, for a timer, a timeout or a size reckoned from it (how many of a thing one
    /// period of it holds). Never a comparison with a clock: those are the methods below.
    pub const fn duration(self) -> std::time::Duration {
        std::time::Duration::from_millis(self.0)
    }

    /// This span on the clock `C`: what moves a reading of it ([`crate::clocks::Mono::later`],
    /// ...), sizes what a window of it holds, or is stated (in a greeting, a figure).
    pub const fn span<C>(self) -> Span<C> {
        Span::of(self.0)
    }

    /// The reading this span after `at`, on `at`'s own clock: the edge of a window, for building
    /// one.
    pub fn after<R: Reading>(self, at: R) -> R {
        at.moved(TOKEN, self.0, 0)
    }

    /// The reading this span before `at`, on `at`'s own clock, never below its start.
    pub fn before<R: Reading>(self, at: R) -> R {
        at.moved(TOKEN, 0, self.0)
    }

    const fn plus(self, other: Self) -> Self {
        Self(self.0 + other.0)
    }

    const fn minus(self, other: Self) -> Self {
        Self(self.0 - other.0)
    }

    const fn times(self, n: u64) -> Self {
        Self(self.0 * n)
    }

    const fn halved(self) -> Self {
        Self(self.0 / 2)
    }

    const fn most(self, other: Self) -> Self {
        if self.0 >= other.0 { self } else { other }
    }

    /// This span as a clock off true time by up to [`DRIFT_PPM`] may measure it: lengthened by
    /// that rate, rounded up.
    const fn drifted(self) -> Self {
        Self(self.0 + (self.0 * DRIFT_PPM).div_ceil(1_000_000))
    }

    /// Whether a time signed (or stated) at `signed_ms` is more than this ahead of the judging
    /// clock reading `now`. Every comparison of a signed time against a clock goes through this
    /// module: this, [`Tolerance::older`], [`Tolerance::apart_from`], or a [`Window`].
    pub const fn ahead(self, signed_ms: u64, now: Judged) -> bool {
        signed_ms > now.ms().saturating_add(self.0)
    }

    /// Whether a time signed (or stated) at `signed_ms` is more than this behind the judging
    /// clock reading `now`: too old.
    pub const fn older(self, signed_ms: u64, now: Judged) -> bool {
        now.ms().saturating_sub(signed_ms) > self.0
    }

    /// Whether the judging clock reading `now` has reached this span after a time stated at
    /// `stated_ms` (a transmission's): exactly at the edge, so a time this span old has settled.
    pub const fn settled(self, stated_ms: u64, now: Judged) -> bool {
        now.ms() >= stated_ms.saturating_add(self.0)
    }

    /// Whether a time stated at `later_ms` is more than this after one stated at `earlier_ms`, by
    /// the same signer's clock (an aircraft's newest position against a reception's time): two
    /// stated times, so no clock's error between them.
    pub const fn beyond(self, earlier_ms: u64, later_ms: u64) -> bool {
        later_ms.saturating_sub(earlier_ms) > self.0
    }

    /// Whether a time signed at `signed_ms` is more than this from the judging clock reading
    /// `now`, either way.
    pub const fn apart_from(self, signed_ms: u64, now: Judged) -> bool {
        signed_ms.abs_diff(now.ms()) > self.0
    }

    /// Whether more than this has passed on one clock from its reading `since` to its reading
    /// `now`: a span measured from it run out. Both readings are the same clock's.
    pub fn past<R: Reading>(self, since: R, now: R) -> bool {
        now.ms().saturating_sub(since.ms()) > self.0
    }

    /// Whether a signed whole `second` is more than this span's whole seconds behind the judging
    /// clock reading `now`, counted in whole seconds: too old, for a record kept by its second.
    pub const fn older_second(self, second: u64, now: Judged) -> bool {
        now.ms() / 1000 > second.saturating_add(self.0 / 1000)
    }

    /// Whether an error a clock's keeper states, `ms` (ClockBound's bound, a measurement's
    /// uncertainty: a number it reports, not a span measured here), is within this.
    pub const fn covers(self, ms: u64) -> bool {
        ms <= self.0
    }

    /// The most bytes a source held to `bytes_per_sec` gathers over this span, rounded up. Of
    /// [`B`], what a feeder at its upload ceiling gathers into the batches it holds for an anchor
    /// at once ([`ANCHOR_WAIT`], the seal that releases them and its ceiling's burst:
    /// `tally_feed`'s `batches_held` and `held_bytes`), which sizes that hold's memory.
    pub const fn gathered(self, bytes_per_sec: u64) -> u64 {
        bytes_per_sec.saturating_mul(self.0).div_ceil(1_000)
    }
}

impl<C> From<Tolerance> for Span<C> {
    fn from(tolerance: Tolerance) -> Self {
        tolerance.span()
    }
}

impl<C> PartialEq<Tolerance> for Span<C> {
    fn eq(&self, other: &Tolerance) -> bool {
        self.ms() == other.0
    }
}

impl<C> PartialOrd<Tolerance> for Span<C> {
    fn partial_cmp(&self, other: &Tolerance) -> Option<std::cmp::Ordering> {
        Some(self.ms().cmp(&other.0))
    }
}

/// A module's own span of `MS` milliseconds on the clock `C`: how long it holds, waits for or
/// remembers a thing (a verified address, a credential's life, an orphan's wait), a choice of its
/// own and no clock's error, so stated beside its module and not derived here. A const parameter,
/// so only a constant becomes one: a reading's milliseconds never can (they are no constant), and
/// no span is made from a number at run time but here, by the terms above.
pub const fn policy<C, const MS: u64>() -> Span<C> {
    Span::of(MS)
}

use crate::clocks::sealed::TOKEN;
use crate::clocks::{Judged, Reading, Span};

// The sources: each measured, configured or allowed once.

/// `E`, 7.5 s: the most a judging relay's clock may be from true time, the cap past which it
/// counts itself unsynced and signs nothing (its host's NTP daemon keeps it within, its host's
/// ClockBound says by how much, `crate::clock_bound`); and the most a synced host's bound may be
/// for a feeder to trust it.
pub const E: Tolerance = Tolerance(7_500);

/// `U_m`, 1 s: the most a feeder's measurement of one relay's clock may be off (half the round
/// trip of the heartbeat that measured it, and the drift since at [`DRIFT_PPM`]); a sample past it
/// is discarded.
pub const U_M: Tolerance = Tolerance(1_000);

/// `δ`, 1 s: one way between a feeder and a relay, either direction: a batch from its signing to
/// its relay's judgment, an anchor from its relay to the feeder.
pub const TRANSIT: Tolerance = Tolerance(1_000);

/// `P`, 1 s: how often a relay signs a new anchor and states it to its feeder sessions.
pub const ANCHOR_PERIOD: Tolerance = Tolerance(1_000);

/// `2P`, 2 s: how long after it first heard an anchor a feeder still signs a batch by it; the
/// same anchor stated again is not heard anew.
pub const ANCHOR_HELD: Tolerance = ANCHOR_PERIOD.times(2);

/// `F`, 10 s: how far a feeder's signed time may be ahead of the relay it publishes to and still
/// be used there. A feeder signs at the low end of a trusted reference, never ahead of true time,
/// and its relay is within `E` of it, measured within `U_m` and sent within `δ`:
/// `F >= E + U_m + δ` (asserted). Stated to feeders in the greeting.
pub const F: Tolerance = Tolerance(10_000);

/// `B`, 64 s: how long a feeder may hold a batch, from gathering it to sending it (a wait for its
/// first anchor, a backoff, a stall), its way out of the feeder's backlog included
/// ([`ANCHOR_WAIT`] and [`BACKLOG_DRAIN`]). A batch held longer is late.
pub const B: Tolerance = Tolerance(64_000);

/// 1 s: how often a feeder seals a batch, at most (`tally_feed`'s `SEAL_EVERY`), and the most one
/// waits from its gathering to its sealing.
pub const SEAL_PERIOD: Tolerance = Tolerance(1_000);

/// 1 s: the most a feeder gathers at once beyond its upload ceiling's rate, and the most a session
/// sends at once beyond the rate it is paced at: each bucket holds a second of its rate.
pub const CEILING_BURST: Tolerance = Tolerance(1_000);

/// `B_d`, `SEAL_PERIOD + CEILING_BURST`, 2 s: the most a feeder's backlog adds to a batch's hold on
/// its way out, every session sending at least what the feeder signs a second at its ceiling
/// (`tally_feed`'s `signed_most`), as each does unless its relay states less. The held batches are
/// released at the first seal once an anchor is heard, or once the oldest has waited
/// [`ANCHOR_WAIT`]: a seal's wait. From then a session sends without a pause until the backlog
/// is gone, at least as fast as the feeder signs, so a batch gathered `x` after the oldest held
/// waits behind what was signed in those `x`, at most `x` and a burst's second of sending: so it
/// is sent at most `ANCHOR_WAIT + B_d` after it was gathered, however long the backlog takes to
/// drain while new batches join it.
pub const BACKLOG_DRAIN: Tolerance = SEAL_PERIOD.plus(CEILING_BURST);

/// `B_h`, `B - B_d`, 62 s: how long a feeder holds a batch for an anchor before it signs it with
/// none (a relay holds an unanchored batch, passes it on and uses it nowhere): what is left of
/// `B` once the backlog's way out ([`BACKLOG_DRAIN`]) is paid for, so a batch released after the
/// longest hold is still sent within `B`.
pub const ANCHOR_WAIT: Tolerance = B.minus(BACKLOG_DRAIN);

/// 2 s: how long a repaired copy may take to reach the member that asked for it, past the second
/// it was asked in: the answer's page queued behind a link's other sends and its way there. An
/// allowance, not a measurement.
pub const REPAIR_TRANSIT: Tolerance = Tolerance(2_000);

/// 2 s: how long after a moment a receiver's raw of it reaches its relay, its batch gathered (a
/// feeder seals one every second) and on its way: the hosted MLAT's own share of
/// [`SIGNED_LAG`] before the clocks' errors. An allowance, not a measurement.
pub const MLAT_BATCHING: Tolerance = Tolerance(2_000);

/// 4 s: the engine's share of an MLAT fix's way out (RFC-0171 §3.8.1, as amended 2026-10-24),
/// counted from its transmission's first reception reaching the engine's relay (its stamp) to the
/// fix's records taken for the network: the transmission due [`FIX_SETTLE`] after, kept a second
/// more while too few receivers have come, weighed by the first step after that, and published
/// within that step's own deadline. The hosted MLAT asserts its steps fit it (`tally_relay`'s
/// `mlat_host`) and refuses a step's records past it, counted. The engine's design, not a clock's
/// error.
pub const FIX_SOLVE: Tolerance = Tolerance(4_000);

/// 1.1 s: how long after a transmission's first reception reaches the engine's relay the engine
/// weighs it (`tally_mlat`'s `SETTLE_MS`, which asserts it is this): long enough for the other
/// receivers' batches of the same second, sealed every [`SEAL_PERIOD`], to come. The engine's
/// design, not a clock's error.
pub const FIX_SETTLE: Tolerance = Tolerance(1_100);

/// 1 s: the slices the engine seals what has arrived in (`tally_mlat_solver`'s `arrived`, which
/// asserts it is this): a refit sees what was sealed, so its trailing edge is up to a slice below
/// the clock it runs at. The engine's design, not a clock's error.
pub const ARRIVED_SLICE: Tolerance = Tolerance(1_000);

/// 5 s: a pair's knot spacing (`tally_mlat_solver`'s `KNOT_PS`, which asserts it is this): what a
/// trailing window must hold several of to fit a rate. The solver's design, not a clock's
/// error.
pub const MODEL_KNOT: Tolerance = Tolerance(5_000);

/// 2 s: how often the engine refits each area's pair model (RFC-0171 §3.8.1, as amended
/// 2026-10-24), warm from the last, at the edges of one grid every relay shares (multiples of this
/// at least [`FIT_LAG`] below its clock, `tally_mlat_solver::Trailing::fitted_at`), so
/// neighbouring areas' models share the edges a fix citing several needs: one refit every second
/// step, its fixes solved every step ([`ARRIVED_SLICE`]) under the newest edge's models. The
/// engine's design, not a clock's error.
pub const REFIT_EVERY: Tolerance = Tolerance(2_000);

/// [`REFIT_EVERY`] in milliseconds, for the engine's refit cadence.
pub const REFIT_EVERY_MS: u64 = REFIT_EVERY.0;

/// [`MLAT_BATCHING`], 2 s: how far a model's trailing edge trails the clock its refit runs at
/// (`tally_mlat_solver`'s `scope::Trailing::fitted_at`): by then an honest receiver's raw of the
/// edge, its signed clock on the relay's, has arrived, so two relays holding the same raw fit the
/// same inputs at the same edge, whatever their paths' delays, and a model's inputs are a function
/// of its edge and not of when a batch happened to arrive. A feeder whose signed clock lags the
/// relay's by more ([`SIGNED_LAG`] allows it `E + 2U_m`) may be cited differently by two relays.
/// The engine's design, not a clock's error.
pub const FIT_LAG: Tolerance = MLAT_BATCHING;

/// [`FIT_LAG`] in milliseconds, for the engine's trailing edge.
pub const FIT_LAG_MS: u64 = FIT_LAG.0;

/// 15 s: the span of sync raw, by its signed wall clocks, a trailing-window model is fitted over,
/// ending at its edge (`tally_mlat_solver`'s `Trailing`): long against the fit's time constant
/// (about 12 s) and at least three knots ([`MODEL_KNOT`], asserted). Chosen by the pair path's
/// sweep (`tally_mlat_solver`'s `pairwise_path_sweep`, run at 15, 20 and 25 s, RFC-0171 §3.8.1):
/// a longer window moved coverage within 0.03 either way and the median error within a metre,
/// declared no false jump at any, and cost more to refit (at world density 0.851, 1.124 and
/// 1.450 ms a feeder-second), so the shortest. The solver's design, not a clock's error.
pub const TRAILING_WINDOW: Tolerance = Tolerance(15_000);

/// [`TRAILING_WINDOW`] in milliseconds: a model's `span_ms`, which every party states the same.
pub const TRAILING_WINDOW_MS: u64 = TRAILING_WINDOW.0;

/// `ρ`, 500 ppm: how fast a clock may drift between measurements, the kernel's most frequency
/// correction (`MAXFREQ`). A rate, not a span: it ages a measurement's uncertainty.
pub const DRIFT_PPM: u64 = 500;

/// 300 s: how far an ACARS message's own time may be from its arrival at the collector
/// (`tally_acars_collect`'s `MAX_SKEW`). Exempt from the clocks' budget, and written here so the
/// exemption is stated where every tolerance is: the time is the aircraft's or its ground
/// station's, set by no clock of ours and bound by none of these errors, so it is an allowance for
/// those clocks, not a derivation from ours.
pub const ACARS_MESSAGE_SKEW: Tolerance = Tolerance(300_000);

/// Whether an ACARS message timed at Unix second `second` is more than [`ACARS_MESSAGE_SKEW`] from
/// the collector's host clock at Unix second `now_second`: the exemption's one comparison, in the
/// whole seconds the collector keeps (its host's clock, not a relay's judging one).
pub const fn acars_skewed(second: u64, now_second: u64) -> bool {
    second.abs_diff(now_second) > ACARS_MESSAGE_SKEW.0 / 1000
}

/// 6 h: how old the evidence a relay's credit counts may be by its issued time
/// (`tally_relay`'s `credit`). Exempt from the clocks' budget, and written
/// here so the exemption is stated where every tolerance is: it is how long credit remembers what
/// a relay did (a feeder re-signs its description every ten minutes, so six hours is many missed
/// renewals), hours beyond any clock's error, so no error of ours sets it.
pub const EVIDENCE_AGE: Tolerance = Tolerance(6 * 60 * 60 * 1000);

/// An exemption, 6 min: how long a relay's directory holds another relay's evidence by its issued
/// time while that relay's offer has not come (`tally_relay`'s `directory`): two of the bundles a
/// relay signs every tenth of credit's half-life (`OWN_EVIDENCE_EVERY_MS`, three minutes). How long
/// a thing is held for an offer under way, not a clock's error.
pub const EVIDENCE_AWAITED: Tolerance = Tolerance(2 * 3 * 60 * 1000);

/// An exemption, 2 h: how long the API serves a receiver's feeder figure by its issued time
/// (`tally_api`'s `feeders`, `STALE_MS`): two of a relay's hourly publishing intervals, so one
/// missed publish is carried and a relay gone is dropped within two hours. How long a figure is
/// served, not a clock's error.
pub const FIGURES_SERVED: Tolerance = Tolerance(2 * 60 * 60 * 1000);

/// An exemption, 65 s: how long after an aircraft's newest ADS-B position (its feeder's signed
/// time) the hosted MLAT engine leaves it alone, and how many seconds back what it solved of an
/// aircraft is remembered (`tally_mlat`'s `ADSB_HORIZON_MS`, which asserts it is this). Not a clock's error: a choice of how long one aircraft's own signed
/// times say something, stated here because each is compared with the judging clock.
pub const ADSB_HORIZON: Tolerance = Tolerance(65_000);

/// An exemption, twice [`ADSB_HORIZON`]: how long the MLAT engine remembers an aircraft's
/// newest ADS-B position by the judging clock, so one heard within the horizon of a reception is
/// still known however late that reception's step runs.
pub const ADSB_REMEMBERED: Tolerance = ADSB_HORIZON.times(2);

/// An exemption, none: a signed expiry (a provider's offer's) is held exactly against the judging
/// clock. Its signer chose the lifetime, so no error is added: an offer lives a moment less on a
/// relay whose clock is ahead, which costs nothing but its renewal a little sooner.
pub const fn expired(expires_ms: u64, now: Judged) -> bool {
    now.ms() >= expires_ms
}

/// An exemption, none: whether the judging clock reading `now` has reached `stated_ms`, a time on
/// its own grid that the one stepping by it states from its own readings (a slice's end, a
/// refit's due time, a deadline it set): exactly, since no other clock stated it. A signed time
/// from elsewhere is compared with a tolerance or a [`Window`], never here.
pub const fn reached(stated_ms: u64, now: Judged) -> bool {
    now.ms() >= stated_ms
}

/// As [`reached`], strictly past `stated_ms`.
pub const fn passed(stated_ms: u64, now: Judged) -> bool {
    now.ms() > stated_ms
}

/// chrony's fastest slew (`maxslewrate`), parts per million: the most the tick may be biased by
/// a chronyd that died mid-slew.
const CHRONY_SLEW_PPM: u64 = 83_333;

/// ClockBound's grace (`CHRONY_RESTART_GRACE_PERIOD`): how long after its last sample a stopped
/// ClockBound's segment still reads `Synchronized` to a client.
const CLOCKBOUND_GRACE_MS: u64 = 5_000;

/// How long ClockBound's poll of a hung chronyd waits (its 1 s query timeout) after its 100 ms
/// poll period before it writes `FreeRunning`.
const CHRONY_HUNG_MS: u64 = 1_100;

/// The most the tick runs off, unbounded, over `ms` at chrony's fastest slew, rounded up.
const fn slewed(ms: u64) -> u64 {
    (ms * CHRONY_SLEW_PPM).div_ceil(1_000_000)
}

/// What ClockBound's word on the clock may leave unsaid, 418 ms (`crate::clock_bound`'s residual
/// gaps): a judging reading of `J` is whole milliseconds truncated (1 ms), and its bound may
/// understate the error by the slew of a chronyd that died mid-slew for as long as the status
/// still says `Synchronized`: up to about 92 ms while ClockBound polls a hung chronyd (1.1 s), and
/// up to about 417 ms when ClockBound stops with chronyd (its segment read `Synchronized` for 5 s
/// after its last sample). The two do not add: a ClockBound that polls writes `FreeRunning` once
/// its poll fails, and one that stopped stops polling, so the slew runs unsaid at most the longer
/// of the two. So a bound judges only within `E` less this ([`judging_bound`]), and a judging
/// clock is within `E` of true time even across those gaps.
pub const CLOCK_BOUND_MARGIN: Tolerance = Tolerance(
    1 + if slewed(CLOCKBOUND_GRACE_MS) > slewed(CHRONY_HUNG_MS) {
        slewed(CLOCKBOUND_GRACE_MS)
    } else {
        slewed(CHRONY_HUNG_MS)
    },
);

/// Whether ClockBound's stated bound, `ms`, leaves the clock within [`E`] even past what it may
/// leave unsaid ([`CLOCK_BOUND_MARGIN`]): the one test of a bound's width.
pub const fn judging_bound(ms: u64) -> bool {
    E.minus(CLOCK_BOUND_MARGIN).covers(ms)
}

/// [`E`] in milliseconds, as a protocol constant: the error a relay that states none is taken to
/// have (`tally_feed`'s relay clocks), since a relay that judges states at most this.
pub const E_MS: u64 = E.0;

// What follows from them.

/// `K`, 15 s: how far two judging relays' clocks may be apart, each within `E` of true time
/// either way.
pub const K: Tolerance = E.times(2);

/// `K`, 15 s: how far ahead of a relay's clock a credit receipt's issued time may be and still be
/// counted (`tally_relay`'s `credit`): the receipt is issued by another judging relay's clock and
/// judged by this one's, each within `E` of true time, so at most `K` apart.
pub const RECEIPT_AHEAD: Tolerance = K;

/// `K`, 15 s: how far ahead of the API's clock a world second's seal may be and still be served
/// (`tally_api`'s `mlat`): second `s` is sealed no earlier than `(s + 1) * 1000 + FIX_ARRIVED`
/// by its relay's judging clock, and judged by the API's, each within `E` of true time either
/// way, so they are at most `K` apart.
pub const PRODUCT_AHEAD: Tolerance = K;

/// `2(E + U_m)`, 17 s: the widest trusted reference a feeder signs by, so how far below true time
/// its low end may be. A selection of configured relays is the span of the points more than half
/// their intervals cover, each interval at most `E + U_m` either side of its relay's clock: any
/// two points of the span are covered by one interval in common, so the span is no wider than one
/// interval, `2(E + U_m)`, and while honest relays are a majority it holds true time. A synced
/// host's is its own bound either side, within `2E`. A feeder signs at the low end of it (never
/// ahead of true time), so its signed time lags true by up to this. Two lawful relays' intervals
/// always overlap within it, so a majority of them meets.
pub const SELECTION_LAG: Tolerance = E.plus(U_M).times(2).most(K);

/// `3P + δ`, 4 s: the oldest an honest relay's anchor is as a feeder signs a batch by it: up to
/// `P` old as its relay states it, `δ` on its way, and [`ANCHOR_HELD`] held.
pub const ANCHOR_AGE: Tolerance = ANCHOR_PERIOD.plus(TRANSIT).plus(ANCHOR_HELD);

/// `E`, 7.5 s: how far above the high end of a feeder's trusted reference an honest relay's
/// anchor may read as it is heard: the reference holds true time, and the relay's clock is at
/// most `E` ahead of it.
pub const ANCHOR_ABOVE_REFERENCE: Tolerance = E;

/// `E + P + δ`, 9.5 s: how far below the low end of a feeder's trusted reference an honest
/// relay's anchor may read as it is heard: its clock up to `E` behind true time, and the anchor up
/// to `P` old as it was stated and `δ` on its way.
pub const ANCHOR_BELOW_REFERENCE: Tolerance = E.plus(ANCHOR_PERIOD).plus(TRANSIT);

/// `F + B + 2(E + U_m)`, 91 s: how old by its relay's clock a feeder's batch may be where it
/// publishes and still be used there. An honest feeder's signed time lags true time by up to
/// [`SELECTION_LAG`]; the batch is held up to `B` and sent within `δ`; the relay's clock is up to
/// `E` ahead: `E + δ <= F` covers the last two (asserted).
pub const FEEDER_BEHIND: Tolerance = F.plus(B).plus(SELECTION_LAG);

/// `F`: how far ahead of its relay's clock a feeder's batch may be signed and still be used
/// there: signed at its reference's low end, never ahead of true time, and the relay within `E`.
pub const FEEDER_AHEAD: Tolerance = F;

/// `U_p`, `FEEDER_BEHIND - K`, 76 s: how old any other copy of a feeder's batch may be and still
/// be used. A relay's clock is at most `K` from the origin's, so a batch the origin found too old
/// is too old here (`U_p + K == FEEDER_BEHIND`, asserted), and nothing travels with a copy to
/// say so.
pub const PEER_BEHIND: Tolerance = FEEDER_BEHIND.minus(K);

/// `S`, `F + K`, 25 s: how far ahead of a relay's clock any copy of a feeder's batch may be and
/// still be used: at most `F` ahead of its origin's clock, which is at most `K` ahead of this one.
pub const PEER_AHEAD: Tolerance = F.plus(K);

/// `W_a`, `FEEDER_BEHIND + E + P + δ + 2P`, 102.5 s: how old by a hop's clock a feeder's batch's
/// oldest known anchor may be and the batch still be used: `J - A = (J - t) + (t - A)`. The first
/// is at most [`FEEDER_BEHIND`] wherever its signed time `t` is usable. The second, for a feeder
/// with a trusted reference: it signs at the reference's low end as it signs, and carries only
/// anchors at most [`ANCHOR_BELOW_REFERENCE`] below that low end as it stood when each was heard,
/// at most [`ANCHOR_HELD`] before (`tally_feed`'s `RelayClocks::anchors` judges each against the
/// reference now, shifted back by the time since it was heard). An honest relay's anchor is the
/// same bound by another road: its relay up to `E` behind true time, the anchor up to
/// [`ANCHOR_AGE`] old, the feeder never ahead of true time. So no batch of a feeder with a trusted
/// reference whose signed time a hop may use is ever stale there by an anchor it carries. Without
/// a reference nothing ties its signed time to its anchors (its clock may be hours off), so the
/// claim is not made for it: its batches are judged by both windows, and the anchors' guarantee
/// (RFC-0171 §3.6) still holds.
pub const ANCHOR_BEHIND: Tolerance = FEEDER_BEHIND.plus(ANCHOR_BELOW_REFERENCE).plus(ANCHOR_HELD);

/// `2(E + U_m) + K`, 32 s: how far ahead of a hop's clock a feeder's batch's oldest known anchor
/// may be and the batch still be used: an anchor a feeder carries reads at most
/// [`ANCHOR_ABOVE_REFERENCE`] above a reference whose high end is at most [`SELECTION_LAG`]
/// above true time, and the hop is at most `E` behind: `SELECTION_LAG + 2E`.
pub const ANCHOR_AHEAD: Tolerance = SELECTION_LAG.plus(ANCHOR_ABOVE_REFERENCE).plus(E);

/// `P + δ + 2P + B + δ`, 69 s (and the drift of the clock that measures it): how long after
/// the origin relay issued its own anchor an honest feeder's batch carrying it reaches it at the
/// most: the anchor stated up to `P` after it was signed, `δ` to the feeder, held up to `2P`, then
/// the batch held up to `B` and `δ` on its way. Measured by the origin on its raw monotonic clock
/// from the anchor's issue (`tally_relay`'s `anchors::Anchors::issued_by`, `clock::RelayClock::
/// raw`: `CLOCK_MONOTONIC_RAW`, which no time daemon slews or steps), never by its judging
/// clock, which a daemon may slew (chrony at up to 83,333 ppm) or step within `E` meanwhile. The
/// raw clock's own rate is off true by at most [`DRIFT_PPM`] (the most an NTP daemon corrects it
/// by), counted in. A batch the origin finds older than this by its own anchor, and too old by
/// its signed time, is blamed on its receiver (`strikes::blame`). The origin keeps a ring of its
/// recent issues: an anchor the ring has let go is aged from the newest issue it let go, which
/// it was issued no later than, and an earlier run's from this run's first issue, so its age is
/// never overstated; a batch carrying none of its anchors is never blamed
/// (`strikes::OwnAnchor::Absent`).
pub const OWN_ANCHOR_OLDEST: Tolerance = ANCHOR_AGE.plus(B).plus(TRANSIT).drifted();

/// `E`, 7.5 s: how far above the judging clock it arrives by a reception of the hosted MLAT may be
/// signed and still be gathered for a fix: a feeder with a trusted reference signs at or below
/// true time, and the relay's clock is at most `E` behind it.
pub const MLAT_AHEAD: Tolerance = E;

/// `MLAT_BATCHING + E + 2U_m`, 11.5 s: how far below a relay's judging clock an honest receiver's
/// raw of a moment may be signed and still be in when the hosted MLAT looks for it
/// (`tally_relay`'s `mlat_host`): its batch gathered and on its way ([`MLAT_BATCHING`]), and its
/// signed time at most `E + 2U_m` below this relay's clock when its feeder's selection holds this
/// relay (its seeds, the relays it is configured with): its reference's low end at most this
/// relay's stated error and twice its measurement below this relay's clock. A feeder whose
/// reference leaves this relay out may lag by up to [`SELECTION_LAG`] and `E` more: its raw past
/// this is late for MLAT, counted and blamed on nobody. Why it is left out is seat cost: covering
/// it would reserve every seat's open raw over a span `LAG + E` longer, and the world relay's seats
/// (`mlat-seats` in `tally/crates/relay/tests/world-relay.txt`, held by the relay's `check` test)
/// have no such margin over their 2,000 floor. What it gives up is small: its raw lands seconds away
/// from its peers' receptions of the same transmissions, so MLAT pairs little of it anyway.
pub const SIGNED_LAG: Tolerance = MLAT_BATCHING.plus(E).plus(U_M.times(2));

/// [`SIGNED_LAG`] in milliseconds, for the engine's arrival hold.
pub const SIGNED_LAG_MS: u64 = SIGNED_LAG.0;

/// `SIGNED_LAG + FIX_SOLVE`, 15.5 s: how long after a transmission its MLAT fix has been offered
/// by the relay that heard it, by that relay's judging clock (the feeder path), as a live world
/// fix's: its receptions are signed at most `E + 2U_m` below that clock and their batch is on its
/// way within [`MLAT_BATCHING`] ([`SIGNED_LAG`]), and its fix leaves within [`FIX_SOLVE`]: its
/// engine, or an ADS-B position's regional batch, signed at its epoch's end, a second at most. A
/// fix whose receptions a feeder signed lower than that (its reference leaving its relay out,
/// [`SIGNED_LAG`] says why) may miss its second, counted late.
pub const FIX_LEAVES: Tolerance = SIGNED_LAG.plus(FIX_SOLVE);

/// `FIX_LEAVES + K + REPAIR_TRANSIT`, 32.5 s: how long after a transmission its MLAT fix has
/// surely arrived, wherever it is read: the live world's seal of a second (`tally_relay`'s
/// `products::WORLD_SETTLE_MS`) and when a fix's standing settles (`tally_mlat_solver`'s
/// `standing`). A fix leaves where it was heard within [`FIX_LEAVES`] by that relay's clock, the
/// reader's is at most `K` from that one, and the fix's way through a relay or two is
/// [`REPAIR_TRANSIT`]. It covers the feeder path, a fix read where it was heard, too.
pub const FIX_ARRIVED: Tolerance = FIX_LEAVES.plus(K).plus(REPAIR_TRANSIT);

/// [`FIX_ARRIVED`] in milliseconds, as a protocol constant every party states the same: stated,
/// and compared with a clock only through the tolerance.
pub const FIX_ARRIVED_MS: u64 = FIX_ARRIVED.0;

/// `2 REFIT_EVERY + FIT_LAG + MLAT_AHEAD + FIX_SETTLE`, 14.6 s: the most a fix's transmit time
/// may be past the trailing edge of the models it is solved under (`tally_mlat_solver`'s
/// `MAX_CARRY_PS`, which asserts it is this), so how far a model is ever carried. Every area is
/// refit on one grid of edges, each a multiple of [`REFIT_EVERY`] at least [`FIT_LAG`] below the
/// clock its refit runs at (`tally_mlat_solver`'s `scope::Trailing::fitted_at`), so the newest
/// edge at a step is less than `REFIT_EVERY + FIT_LAG` below its clock, whatever the step's phase;
/// a fix citing a neighbouring area's model may be solved one edge further back, while that area's
/// relays' model of the newest edge is still on its way (one more [`REFIT_EVERY`]); the fix's
/// receptions are signed at most [`MLAT_AHEAD`] above the judging clock they arrive by, which is
/// no later than the step's. [`FIX_SETTLE`] is counted though a due transmission's first reception
/// has already waited it (which would take it off): so the bound holds of a fix weighed as soon as
/// its first reception is in, and is a hard bound, not a tight one. A fix carried further is not
/// solved, counted.
pub const MAX_CARRY: Tolerance = REFIT_EVERY
    .plus(REFIT_EVERY)
    .plus(FIT_LAG)
    .plus(MLAT_AHEAD)
    .plus(FIX_SETTLE);

/// [`MAX_CARRY`] in milliseconds, for the solver's carry bound.
pub const MAX_CARRY_MS: u64 = MAX_CARRY.0;

/// `F / 2`, 5 s: how far a feeder's signed time may be from its relay's clock, either way, before
/// the relay states its clock to it again at its next heartbeat (`tally_relay`'s `hub`,
/// `ingest::Refusal::drifted`): half of what the relay allows ahead, so a feeder drifting is told
/// well before its batches reach [`F`].
pub const RESTATE_BEYOND: Tolerance = F.halved();

/// An exemption, `L`, 2 s: how far past the newest signed time it has used a relay's strike table
/// leases signed time on disk (`tally_relay`'s `durable::Lease`): what a restart costs beyond the
/// records it used, and how often a busy table writes its lease. A choice of how often to write,
/// not a clock's error; under `S` ([`PEER_AHEAD`], asserted), so a lease never reaches past what
/// [`FALLBACK_FLOOR`] already allows for.
pub const LEASE: Tolerance = Tolerance(2_000);

/// `S + L`, 27 s: how far ahead of a synced judging clock a lease's bound is a quick restart's: a
/// run takes records up to `S` ahead of its clock, and its bound is [`LEASE`] past the newest it
/// took. A bound further ahead was left by a run whose clock ran ahead (`durable::Lease::begin`).
pub const LEASE_REACH: Tolerance = PEER_AHEAD.plus(LEASE);

/// How long a sender held to `bytes_per_sec` takes to send `bytes`, rounded down (none at no
/// rate): the least time after it began it can have sent them, so a moment put that long after its
/// start is never later than they were sent (`tally_relay`'s `ceiling::Ceiling::sending`).
pub const fn sending<C>(bytes: u64, bytes_per_sec: u64) -> Span<C> {
    match bytes_per_sec {
        0 => Span::ZERO,
        rate => Span::of(bytes.saturating_mul(1_000) / rate),
    }
}

/// The bound a lease writes to cover a record signed at `signed_ms`: [`LEASE`] past it.
pub const fn lease_bound(signed_ms: u64) -> u64 {
    signed_ms.saturating_add(LEASE.0)
}

/// Whether a record signed at `signed_ms`, inside its lease's bound `held_ms`, is within half a
/// [`LEASE`] of it (`H - L/2`), so the lease is renewed ahead: standard lease renewal, so a take
/// waits on a write only when the renewal fell behind.
pub const fn lease_renews(signed_ms: u64, held_ms: u64) -> bool {
    signed_ms.saturating_add(LEASE.halved().0) > held_ms
}

/// `S + K`, 40 s: the floor a relay's strike table starts at with no state: the process before
/// may have used records up to `S` ahead of its clock, which may have been `K` ahead of this one's
/// (RFC 8446 §8.2's rule for a server with no state).
pub const FALLBACK_FLOOR: Tolerance = PEER_AHEAD.plus(K);

const _: () = assert!(F.ms() >= E.ms() + U_M.ms() + TRANSIT.ms());
// ClockBound's gaps leave a judging clock within `E`: the larger gap, and `J`'s truncation.
const _: () = assert!(
    CLOCK_BOUND_MARGIN.ms() == 418
        && slewed(CHRONY_HUNG_MS) == 92
        && slewed(CLOCKBOUND_GRACE_MS) == 417
        && CLOCK_BOUND_MARGIN.ms() < E.ms()
);
// A batch held the longest for an anchor, then sent through the backlog it was released into,
// is sent within `B`, so it is within `FEEDER_BEHIND` where it publishes.
const _: () = assert!(
    ANCHOR_WAIT.ms() + BACKLOG_DRAIN.ms() == B.ms()
        && BACKLOG_DRAIN.ms() == SEAL_PERIOD.ms() + CEILING_BURST.ms()
        && ANCHOR_WAIT.ms() + BACKLOG_DRAIN.ms() + SELECTION_LAG.ms() + E.ms() + TRANSIT.ms()
            <= FEEDER_BEHIND.ms()
);
// A lease reaches less far than the fallback floor allows for, so a lease is never costlier than
// no state.
const _: () = assert!(LEASE.ms() < PEER_AHEAD.ms() && LEASE_REACH.ms() == 27_000);
const _: () =
    assert!(SELECTION_LAG.ms() == 2 * (E.ms() + U_M.ms()) && SELECTION_LAG.ms() >= K.ms());
const _: () = assert!(PEER_BEHIND.ms() + K.ms() == FEEDER_BEHIND.ms());
// An honest relay's anchor is within the same bound as an agreeing one.
const _: () = assert!(E.ms() + ANCHOR_AGE.ms() == ANCHOR_BELOW_REFERENCE.ms() + ANCHOR_HELD.ms());
// An honest anchor never makes a batch its feeder holds the most it may stale.
const _: () = assert!(K.ms() + ANCHOR_AGE.ms() + B.ms() + TRANSIT.ms() <= ANCHOR_BEHIND.ms());
const _: () = assert!(ANCHOR_AHEAD.ms() == SELECTION_LAG.ms() + K.ms());
const _: () = assert!(
    OWN_ANCHOR_OLDEST.ms() >= ANCHOR_AGE.ms() + B.ms() + TRANSIT.ms()
        && OWN_ANCHOR_OLDEST.ms() <= ANCHOR_AGE.ms() + B.ms() + TRANSIT.ms() + 100
);
const _: () = assert!(ANCHOR_AGE.ms() == 3 * ANCHOR_PERIOD.ms() + TRANSIT.ms());
// One fix class (RFC-0171 §3.8.1 as amended 2026-10-24): a fix leaves its engine its signed lag
// and its solve after its transmission, and has arrived `K` and a repair's way later; a trailing
// window holds three knots, and a model is carried less than its own window.
const _: () = assert!(
    SIGNED_LAG.ms() == MLAT_BATCHING.ms() + E.ms() + 2 * U_M.ms()
        && FIX_LEAVES.ms() == SIGNED_LAG.ms() + FIX_SOLVE.ms()
        && FIX_ARRIVED.ms() == FIX_LEAVES.ms() + K.ms() + REPAIR_TRANSIT.ms()
        && TRAILING_WINDOW.ms() >= 3 * MODEL_KNOT.ms()
        && MAX_CARRY.ms()
            == 2 * REFIT_EVERY.ms() + FIT_LAG.ms() + MLAT_AHEAD.ms() + FIX_SETTLE.ms()
        && MAX_CARRY.ms() < TRAILING_WINDOW.ms()
);
// The figures RFC-0171 quotes.
const _: () = assert!(
    E.ms() == 7_500
        && K.ms() == 15_000
        && SELECTION_LAG.ms() == 17_000
        && ANCHOR_AGE.ms() == 4_000
        && FEEDER_BEHIND.ms() == 91_000
        && PEER_BEHIND.ms() == 76_000
        && PEER_AHEAD.ms() == 25_000
        && ANCHOR_BEHIND.ms() == 102_500
        && ANCHOR_AHEAD.ms() == 32_000
        && OWN_ANCHOR_OLDEST.ms() == 69_035
        && MLAT_AHEAD.ms() == 7_500
        && SIGNED_LAG.ms() == 11_500
        && FIX_LEAVES.ms() == 15_500
        && FIX_ARRIVED.ms() == 32_500
        && MAX_CARRY.ms() == 14_600
        && RESTATE_BEYOND.ms() == 5_000
        && FALLBACK_FLOOR.ms() == 40_000
        && ANCHOR_WAIT.ms() == 62_000
);

/// What a feeder's selection `[lo_ms, hi_ms]` (offsets from its raw monotonic clock) holds true
/// time in `age_ms` later on that clock, held over once its sources are gone (NTP's holdover):
/// widened either side by the raw clock's drift over the age at [`DRIFT_PPM`], rounded up, so its
/// low end, which the feeder signs at, is never ahead of true time. None once it is wider than
/// [`SELECTION_LAG`], the widest reference a feeder signs by, so a held offset never lags true
/// time more than a live selection may, which every window allows for.
pub fn held_over(lo_ms: i64, hi_ms: i64, age_ms: u64) -> Option<(i64, i64)> {
    let drift = (u128::from(age_ms) * u128::from(DRIFT_PPM)).div_ceil(1_000_000);
    let drift = i64::try_from(drift).unwrap_or(i64::MAX);
    let (lo, hi) = (lo_ms.saturating_sub(drift), hi_ms.saturating_add(drift));
    u64::try_from(hi.saturating_sub(lo))
        .is_ok_and(|width| SELECTION_LAG.covers(width))
        .then_some((lo, hi))
}

/// Whether an anchor reading `j_ms` agrees with a trusted reference that held `[lo_ms, hi_ms]`
/// as it was heard: at most [`ANCHOR_BELOW_REFERENCE`] below its low end and
/// [`ANCHOR_ABOVE_REFERENCE`] above its high end, as an honest relay's must. None while it
/// agrees; else how far outside it is, positive when the reference is ahead of it (the anchor
/// below), negative when behind.
pub fn anchor_outside(lo_ms: i128, hi_ms: i128, j_ms: u64) -> Option<i64> {
    let j = i128::from(j_ms);
    let below = lo_ms - i128::from(ANCHOR_BELOW_REFERENCE.ms()) - j;
    let above = j - hi_ms - i128::from(ANCHOR_ABOVE_REFERENCE.ms());
    let clamp =
        |value: i128| i64::try_from(value).unwrap_or(if value < 0 { i64::MIN } else { i64::MAX });
    if below > 0 {
        Some(clamp(below))
    } else if above > 0 {
        Some(clamp(-above))
    } else {
        None
    }
}

/// A window of a relay's clock within which a copy's signed time must be for it to be used:
/// some span behind and some ahead. Only this module makes one, and a signed time is compared with
/// it only through [`Window::holds`], [`Window::ahead`], [`Window::stale`] and
/// [`Window::holds_second`]; its spans
/// ([`Window::behind_span`], [`Window::ahead_span`]) size what is kept for it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Window {
    behind_ms: u64,
    ahead_ms: u64,
}

impl Window {
    const fn of(behind: Tolerance, ahead: Tolerance) -> Self {
        Self {
            behind_ms: behind.ms(),
            ahead_ms: ahead.ms(),
        }
    }

    /// A feeder's own copy where it publishes: [`FEEDER_BEHIND`] behind, [`FEEDER_AHEAD`] ahead.
    pub const FEEDER: Self = Self::of(FEEDER_BEHIND, FEEDER_AHEAD);

    /// Any other copy of a feeder's batch: [`PEER_BEHIND`] behind, [`PEER_AHEAD`] ahead.
    pub const PEER: Self = Self::of(PEER_BEHIND, PEER_AHEAD);

    /// A feeder's batch's oldest known freshness anchor: [`ANCHOR_BEHIND`] behind,
    /// [`ANCHOR_AHEAD`] ahead.
    pub const ANCHOR: Self = Self::of(ANCHOR_BEHIND, ANCHOR_AHEAD);

    /// What the feeder figures count of a feeder's batch or a position it placed, by its own
    /// signed clock (`tally_relay`'s `figures`): the most behind any copy of a feeder's batch is
    /// used anywhere ([`FEEDER_BEHIND`]), and the most ahead ([`PEER_AHEAD`]).
    pub const FIGURES: Self = Self::of(FEEDER_BEHIND, PEER_AHEAD);

    /// What the feeder figures count of an MLAT fix, by its transmit time: as old as a fix may
    /// arrive ([`FIX_ARRIVED`]), and no further ahead than any copy of the batches it was solved
    /// from ([`PEER_AHEAD`]).
    pub const FIGURES_POSITIONS: Self = Self::of(FIX_ARRIVED, PEER_AHEAD);

    /// A record a relay signs (an engine's positions, clock models, a regional batch, a bundle
    /// index), for a relay whose groups keep a horizon of `horizon` and whose engine signs
    /// within `engine_lag` of its step's signed time. Its first copy is its signer's own, never
    /// ahead of the signer's clock; a member may ask for it until the horizon's whole seconds after
    /// the second it was signed in, and the second it may be signed before its own ends, its
    /// answer taking [`REPAIR_TRANSIT`], to a relay whose clock is `K` from the signer's. Behind:
    /// the lag, the horizon and a second, the transit and `K`; ahead, `K`.
    pub const fn relay_signed(engine_lag: Span<Judged>, horizon: Span<Judged>) -> Self {
        Self::of(
            Tolerance(engine_lag.ms() + horizon.ms() + 1_000)
                .plus(REPAIR_TRANSIT)
                .plus(K),
            K,
        )
    }

    /// A fault proof, by the newer of the two records it carries: one may carry a feeder's batch,
    /// usable [`FEEDER_BEHIND`] behind its origin's clock and signed up to `F` ahead of it, and a
    /// proof travels its group's horizon (`horizon`) after it is made as any record does,
    /// to a relay `K` from the origin. Behind: `FEEDER_BEHIND`, the horizon and a second, the
    /// transit and `K`; ahead, `S`.
    pub const fn proofs(horizon: Span<Judged>) -> Self {
        Self::of(
            FEEDER_BEHIND
                .plus(Tolerance(horizon.ms() + 1_000))
                .plus(REPAIR_TRANSIT)
                .plus(K),
            PEER_AHEAD,
        )
    }

    /// What a sharing group holds by its signed whole second (a manifest's, a parity's, a
    /// receipt's), for a group that keeps a horizon of `horizon`: the horizon behind, since a
    /// member may ask for it that long, and `K` ahead, the most two relays' clocks differ. Anything
    /// later is refused, so what is held is bounded by the horizon behind and `K` ahead. Compared in
    /// whole seconds ([`Window::holds_second`]).
    pub const fn sharing(horizon: Span<Judged>) -> Self {
        Self::of(Tolerance(horizon.ms()), K)
    }

    /// Feeder figures beside the relay-signed window `relay`: a relay signs its figures as of an
    /// hour's start (their `issued_ms`) at any time within that hour
    /// ([`crate::FIGURES_BUCKET_MS`]), so a copy is as young as one signed that much later, and is
    /// held to `relay` from then.
    pub const fn figures(relay: Self) -> Self {
        Self {
            behind_ms: relay.behind_ms + crate::FIGURES_BUCKET_MS,
            ahead_ms: relay.ahead_ms,
        }
    }

    /// How far behind the clock a signed time may be.
    pub const fn behind_span(self) -> Tolerance {
        Tolerance(self.behind_ms)
    }

    /// How far ahead of the clock a signed time may be.
    pub const fn ahead_span(self) -> Tolerance {
        Tolerance(self.ahead_ms)
    }

    /// Whether a record signed at `signed_ms` is signed further ahead of the judging clock
    /// reading `now` than the window allows.
    pub const fn ahead(self, signed_ms: u64, now: Judged) -> bool {
        signed_ms > now.ms().saturating_add(self.ahead_ms)
    }

    /// Whether a record signed at `signed_ms` is further behind the judging clock reading `now`
    /// than the window allows.
    pub const fn stale(self, signed_ms: u64, now: Judged) -> bool {
        signed_ms.saturating_add(self.behind_ms) < now.ms()
    }

    /// Whether a record signed at `signed_ms` is inside the window at the judging clock reading
    /// `now`: neither [`Window::ahead`] nor [`Window::stale`].
    pub const fn holds(self, signed_ms: u64, now: Judged) -> bool {
        !self.ahead(signed_ms, now) && !self.stale(signed_ms, now)
    }

    /// Whether a record signed in the whole `second` is inside the window at the judging clock
    /// reading `now`, counted in whole seconds: the window's whole seconds behind `now`'s second
    /// at most, and its whole seconds ahead at most. Overflow-free for any `second`.
    pub const fn holds_second(self, second: u64, now: Judged) -> bool {
        let now_second = now.ms() / 1000;
        second.saturating_add(self.behind_ms / 1000) >= now_second
            && second <= now_second.saturating_add(self.ahead_ms / 1000)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::disallowed_methods, reason = "a test's scripted readings")]
    use super::*;

    /// What a source gathers over a span is its rate for that span, rounded up, and saturates
    /// rather than overflows: `B` at a feeder's default ceiling is 64 s of it.
    #[test]
    fn a_span_gathers_its_rate_for_its_length() {
        assert_eq!(B.gathered(64_000), 64 * 64_000);
        assert_eq!(SEAL_PERIOD.gathered(1), 1);
        assert_eq!(Tolerance(1).gathered(1), 1);
        assert_eq!(B.gathered(0), 0);
        assert_eq!(B.gathered(u64::MAX), u64::MAX.div_ceil(1_000));
    }

    /// A sharing window holds a second from its horizon's whole seconds behind the clock's second
    /// to `K`'s ahead, and neither one second further, nor overflows at the ends.
    #[test]
    fn a_sharing_window_holds_its_seconds_and_not_one_past() {
        let window = Window::sharing(policy::<Judged, 30_000>());
        let now = crate::clocks::recorded::judged(1_000_500);
        let skew = K.duration().as_secs();
        assert!(window.holds_second(1_000 - 30, now));
        assert!(!window.holds_second(1_000 - 31, now));
        assert!(window.holds_second(1_000 + skew, now));
        assert!(!window.holds_second(1_000 + skew + 1, now));
        assert!(!window.holds_second(u64::MAX, now));
        assert!(window.holds_second(0, crate::clocks::recorded::judged(0)));
    }

    /// A window's edges are its own: a time signed exactly its spans behind or ahead holds, and
    /// one a millisecond further is stale or ahead, and only that.
    #[test]
    fn a_windows_edges_hold_and_a_millisecond_past_them_does_not() {
        let window = Window::PEER;
        let at = 1_000_000_000;
        let now = crate::clocks::recorded::judged(at);
        let behind = window.behind_span().before(now).ms();
        let ahead = window.ahead_span().after(now).ms();
        for signed in [behind, at, ahead] {
            assert!(window.holds(signed, now), "{signed}");
            assert!(
                !window.stale(signed, now) && !window.ahead(signed, now),
                "{signed}"
            );
        }
        assert!(window.stale(behind - 1, now) && !window.ahead(behind - 1, now));
        assert!(window.ahead(ahead + 1, now) && !window.stale(ahead + 1, now));
        assert!(!window.holds(behind - 1, now) && !window.holds(ahead + 1, now));
    }

    /// An anchor agrees with a reference's whole interval, not a point of it: an honest relay
    /// `E` ahead of true time against a reference whose low end is `2(E + U_m)` below it agrees.
    /// Past either edge by a millisecond, it does not, and says by how far.
    #[test]
    fn an_anchor_agrees_with_the_references_whole_interval() {
        let (lo, hi) = (1_000_000_i128, 1_017_000_i128);
        let above = u64::try_from(hi).unwrap_or(0) + ANCHOR_ABOVE_REFERENCE.ms();
        let below = u64::try_from(lo).unwrap_or(0) - ANCHOR_BELOW_REFERENCE.ms();
        assert_eq!(anchor_outside(lo, hi, above), None);
        assert_eq!(anchor_outside(lo, hi, below), None);
        assert_eq!(anchor_outside(lo, hi, above + 1), Some(-1));
        assert_eq!(anchor_outside(lo, hi, below - 1), Some(1));
        // The round 20 case: the reference's low end 14.4 s below true time, an honest relay
        // 7 s ahead of it. Against the low end alone, it was 21.4 s ahead and left out.
        let truth = 1_014_400_u64;
        assert_eq!(anchor_outside(lo, hi, truth + 7_000), None);
    }

    /// A held selection widens by the raw clock's drift either side as it ages, rounded up, and
    /// is dropped the millisecond it is wider than `SELECTION_LAG`. Before, the offset was held
    /// as selected for ever, ahead of true time once the raw clock had drifted under it.
    #[test]
    fn a_held_selection_widens_by_drift_and_is_dropped_past_the_selection_lag() {
        assert_eq!(held_over(-1_000, 1_000, 0), Some((-1_000, 1_000)));
        assert_eq!(held_over(-1_000, 1_000, 2_000_000), Some((-2_000, 2_000)));
        assert_eq!(held_over(-1_000, 1_000, 1), Some((-1_001, 1_001)));
        // 2 s wide, it reaches 17 s once 7.5 s has drifted either side: 15,000 s at 500 ppm.
        assert_eq!(held_over(-1_000, 1_000, 15_000_000), Some((-8_500, 8_500)));
        assert_eq!(held_over(-1_000, 1_000, 15_000_001), None);
        assert_eq!(held_over(0, 17_000, 0), Some((0, 17_000)));
        assert_eq!(held_over(0, 17_001, 0), None);
    }

    /// Each comparison is strict at its edge: a time exactly the tolerance ahead, past or apart is
    /// within it, a millisecond more is not; and a span is drifted up, never down.
    #[test]
    fn the_comparisons_hold_their_edges() {
        use crate::clocks::recorded;
        let at = 1_000_000;
        let now = recorded::judged(at);
        assert!(!K.ahead(at + K.ms(), now) && K.ahead(at + K.ms() + 1, now));
        assert!(!K.older(at - K.ms(), now) && K.older(at - K.ms() - 1, now));
        assert!(
            !K.older(at + 5, now),
            "a time after the reading is not older than it"
        );
        let ms = policy::<_, 1>();
        assert!(!K.past(now, now.later(K)) && K.past(now, now.later(K).later(ms)));
        assert!(
            !K.past(now.later(ms), now),
            "a reading before the time is not past it"
        );
        let raw = recorded::raw(at);
        assert!(!K.past(raw, raw.later(K)) && K.past(raw, raw.later(K).later(policy::<_, 1>())));
        assert!(!K.settled(at, now.later(K).earlier(ms)) && K.settled(at, now.later(K)));
        assert!(!K.apart_from(at + K.ms(), now) && K.apart_from(at + K.ms() + 1, now));
        assert!(!K.apart_from(at - K.ms(), now) && K.apart_from(at - K.ms() - 1, now));
        assert!(K.covers(K.ms()) && !K.covers(K.ms() + 1));
        assert!(!K.beyond(at, at + K.ms()) && K.beyond(at, at + K.ms() + 1));
        // A stated time is reached at it and passed only after it.
        assert!(!reached(at + 1, now) && reached(at, now));
        assert!(!passed(at, now) && passed(at - 1, now));
        // A lease reaches `L` past the time it was signed at, and renews within half of it.
        assert_eq!(lease_bound(at), at + LEASE.ms());
        let held = lease_bound(at);
        assert!(
            !lease_renews(held - LEASE.ms() / 2, held)
                && lease_renews(held - LEASE.ms() / 2 + 1, held)
        );
        assert_eq!(
            (K.after(now).ms(), K.before(now).ms()),
            (at + K.ms(), at - K.ms())
        );
        assert_eq!(K.before(recorded::judged(5)).ms(), 0);
        assert_eq!(raw.later(K).since(raw), K);
        assert!(raw.later(K).since(raw) > ANCHOR_AGE && now.since(now.later(K)) < K);
        assert_eq!(K.duration(), std::time::Duration::from_millis(K.ms()));
        assert_eq!(Tolerance(1_000_000).drifted().ms(), 1_000_500);
        assert_eq!(Tolerance(1).drifted().ms(), 2);
        let window = Window::PEER;
        assert!(
            window.holds(at - PEER_BEHIND.ms(), now)
                && !window.holds(at - PEER_BEHIND.ms() - 1, now)
        );
        assert!(
            window.holds(at + PEER_AHEAD.ms(), now) && !window.holds(at + PEER_AHEAD.ms() + 1, now)
        );
    }
}
