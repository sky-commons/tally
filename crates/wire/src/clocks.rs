//! A host's clocks as types (RFC-0171 §3.6), so a reading of one can never be passed where another
//! belongs: the compiler refuses it.
//!
//! - [`Mono`]: the monotonic clock `M`, what arrivals, durations, epochs and MLAT steps are timed
//!   by. Nothing signed is compared with it.
//! - [`Judged`]: the judging clock `J`, the host's wall clock as its time daemon keeps it: what a
//!   signed time, the MLAT bin grid and a model's life are compared with, and what is signed.
//! - [`Raw`]: the raw monotonic clock (`CLOCK_MONOTONIC_RAW`), which no daemon slews or steps:
//!   what a relay ages its own anchors by.
//! - [`Moment`]: one instant read on `M` and `J` together, as one pair (a stamp's, a
//!   watermark's): what a step names by its monotonic time and signs by its judging one.
//! - [`Span`]: a span on one of them, `Span<Mono>`, `Span<Judged>` or `Span<Raw>`, so a span
//!   measured on one clock never moves a reading of another.
//!
//! **Only a reader makes a reading.** A reading's field is private, and the one way to make one
//! is to read a clock: [`MonoReader`], [`JudgedReader`] and [`RawReader`], distinct types, each
//! made from what yields its own clock's readings, so a reader of one clock is never handed where
//! another's belongs either. No reading has a default. A reading is moved only by a span on its
//! own clock ([`Mono::later`], [`Judged::earlier`], ...), and a span is made only by the clocks'
//! budget (`crate::budget`: its terms, and the constants a module states through
//! `crate::budget::policy`) or by measuring between two readings of one clock ([`Mono::since`]):
//! never from a number, so no reading's milliseconds become a span or a reading of another
//! clock. A reading is read out as milliseconds to be stated (signed into a record, binned on the
//! grid), but a number is never made into a reading again but by [`recorded`]: a reading a reader
//! took before, given back by a trace or a test's script. Clippy refuses those constructors
//! outside the code that replays (`clippy.toml`), so a relay's own code reads its clocks and
//! nothing else.
//!
//! What mixing them would look like, refused by the compiler:
//!
//! ```compile_fail,E0599
//! # use tally_wire::clocks::Judged;
//! // A reading has no default to start from.
//! fn start() -> Judged { Judged::default() }
//! ```
//!
//! ```compile_fail,E0277
//! # use tally_wire::clocks::{Judged, Mono};
//! // A span of one clock never moves another's reading.
//! fn moved(m: Mono, earlier: Mono, j: Judged) -> Judged { j.later(m.since(earlier)) }
//! ```
//!
//! ```compile_fail,E0277
//! # use tally_wire::clocks::{Judged, Mono};
//! // A reading's milliseconds are no span.
//! fn moved(m: Mono, j: Judged) -> Judged { j.later(m.ms()) }
//! ```
//!
//! ```compile_fail,E0599
//! # use tally_wire::clocks::Moment;
//! // An instant has no default either.
//! fn start() -> Moment { Moment::default() }
//! ```
//!
//! ```compile_fail,E0308
//! # use tally_wire::clocks::{JudgedReader, MonoReader};
//! // A reader of `J` reads `J`, never another clock's milliseconds.
//! fn reader_mix(m: MonoReader) -> JudgedReader { JudgedReader::of(move || m.read().ms()) }
//! ```
//!
//! ```compile_fail,E0308
//! # use tally_wire::clocks::{JudgedReader, MonoReader};
//! // Nor another clock's readings.
//! fn reader_mix(m: MonoReader) -> JudgedReader { JudgedReader::of(move || m.read()) }
//! ```
//!
//! ```compile_fail,E0624
//! # use tally_wire::clocks::{Judged, Moment, Mono};
//! // An instant is read, both clocks together, never paired by hand.
//! fn moment_mix(m: Mono, j: Judged) -> Moment { Moment::of(m, j) }
//! ```
//!
//! A time a record states (its signed time, a bin's start on the grid) is a number, not a
//! reading: it is compared with a reading only through `crate::budget` (with the error its
//! clocks allow), never by hand.

use std::marker::PhantomData;
use std::sync::Arc;

/// A span of milliseconds on the clock `C` (`Span<Mono>`, `Span<Judged>`, `Span<Raw>`): what a
/// reading of `C` is moved by. Made only by the clocks' budget (`crate::budget`'s terms, and a
/// module's constants through `crate::budget::policy`) or by measuring between two readings of
/// `C` ([`Mono::since`], ...), so a span is never made from a reading's number, and one measured
/// on one clock never moves another's reading.
pub struct Span<C>(u64, PhantomData<fn() -> C>);

impl<C> Span<C> {
    /// The span of `ms`: this crate's alone (`crate::budget`).
    pub(crate) const fn of(ms: u64) -> Self {
        Self(ms, PhantomData)
    }

    /// No time at all.
    pub const ZERO: Self = Self::of(0);

    /// Its milliseconds, to be stated (in a record, a log, a figure) or to size what it holds.
    pub const fn ms(self) -> u64 {
        self.0
    }

    /// The two spans end to end, on the same clock.
    #[must_use]
    pub const fn plus(self, other: Self) -> Self {
        Self::of(self.0.saturating_add(other.0))
    }

    /// This span less `other`, on the same clock, never below none.
    #[must_use]
    pub const fn minus(self, other: Self) -> Self {
        Self::of(self.0.saturating_sub(other.0))
    }

    /// This span rounded up to whole seconds.
    #[must_use]
    pub const fn whole_seconds(self) -> Self {
        Self::of(self.0.div_ceil(1000).saturating_mul(1000))
    }

    /// This span `n` times over.
    #[must_use]
    pub const fn times(self, n: u64) -> Self {
        Self::of(self.0.saturating_mul(n))
    }
}

impl<C> Clone for Span<C> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<C> Copy for Span<C> {}

impl<C> PartialEq for Span<C> {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl<C> Eq for Span<C> {}

impl<C> PartialOrd for Span<C> {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl<C> Ord for Span<C> {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.0.cmp(&other.0)
    }
}

impl<C> std::hash::Hash for Span<C> {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.0.hash(state);
    }
}

impl<C> std::fmt::Debug for Span<C> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} ms", self.0)
    }
}

macro_rules! reading {
    ($(#[$doc:meta])* $name:ident) => {
        $(#[$doc])*
        #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name(u64);

        impl $name {
            /// Its milliseconds, to be stated (signed, binned, logged).
            pub const fn ms(self) -> u64 {
                self.0
            }

            /// The reading `span` later on the same clock.
            #[must_use]
            pub fn later(self, span: impl Into<Span<Self>>) -> Self {
                Self(self.0.saturating_add(span.into().ms()))
            }

            /// The reading `span` earlier on the same clock, never below its start.
            #[must_use]
            pub fn earlier(self, span: impl Into<Span<Self>>) -> Self {
                Self(self.0.saturating_sub(span.into().ms()))
            }

            /// The span from `earlier` to this reading on the same clock, none when it is later.
            pub const fn since(self, earlier: Self) -> Span<Self> {
                Span::of(self.0.saturating_sub(earlier.0))
            }

            /// The start of the cell of `step` on this clock's own grid (its multiples from the
            /// clock's start) that holds this reading: itself for no step.
            #[must_use]
            pub fn floor(self, step: impl Into<Span<Self>>) -> Self {
                match step.into().ms() {
                    0 => self,
                    step => Self(self.0 - self.0 % step),
                }
            }

            /// The later of the two readings.
            #[must_use]
            pub fn latest(self, other: Self) -> Self {
                self.max(other)
            }

            /// Whether this reading has reached `at`, a reading of the same clock (a deadline set
            /// from one): exactly, with no error allowed.
            pub const fn reached(self, at: Self) -> bool {
                self.0 >= at.0
            }

            /// Whether this reading is past `at`, a reading of the same clock: strictly later.
            pub const fn passed(self, at: Self) -> bool {
                self.0 > at.0
            }

            const fn read(ms: u64) -> Self {
                Self(ms)
            }
        }

        impl crate::clocks::Reading for $name {
            fn ms(self) -> u64 {
                self.0
            }
        }

        impl crate::clocks::sealed::Sealed for $name {
            fn moved(self, _: crate::clocks::sealed::Token, later_ms: u64, earlier_ms: u64) -> Self {
                Self(self.0.saturating_add(later_ms).saturating_sub(earlier_ms))
            }
        }
    };
}

reading!(
    /// A reading of the monotonic clock `M`, in milliseconds.
    Mono
);
reading!(
    /// A reading of the judging clock `J`, in milliseconds.
    Judged
);
reading!(
    /// A reading of the raw monotonic clock, in milliseconds.
    Raw
);

pub(crate) mod sealed {
    /// What only this crate can make, so only it can call [`Sealed::moved`]: a bound on
    /// [`super::Reading`] elsewhere reaches the method, but cannot pass it one.
    #[derive(Clone, Copy)]
    pub struct Token(());

    /// The one token.
    pub(crate) const TOKEN: Token = Token(());

    /// What only this module's readings are: unnameable outside this crate.
    pub trait Sealed: Copy {
        /// The reading `later_ms` later and `earlier_ms` earlier, for `crate::budget`'s spans.
        fn moved(self, token: Token, later_ms: u64, earlier_ms: u64) -> Self;
    }
}

/// A reading of one of a host's clocks: what `crate::budget` measures a span on, both ends on the
/// same clock. Sealed: only this module's readings are one.
pub trait Reading: Copy + sealed::Sealed {
    /// Its milliseconds.
    fn ms(self) -> u64;
}

/// What reads a clock: a host's, or a test's script, yielding that clock's own readings.
type Read<R> = Arc<dyn Fn() -> R + Send + Sync>;

macro_rules! reader {
    ($(#[$doc:meta])* $name:ident, $reading:ident) => {
        $(#[$doc])*
        #[derive(Clone)]
        pub struct $name(Read<$reading>);

        impl $name {
            /// The reader of the clock `read` reads: a host's clock, where the host's readers are
            /// made (`tally_relay::clock`), or a test's script. It yields that clock's own
            /// readings, so a reader of one clock is never made from another's.
            pub fn of(read: impl Fn() -> $reading + Send + Sync + 'static) -> Self {
                Self(Arc::new(read))
            }

            /// The clock now.
            pub fn read(&self) -> $reading {
                (self.0)()
            }
        }

        impl std::fmt::Debug for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.debug_tuple(stringify!($name)).finish_non_exhaustive()
            }
        }
    };
}

reader!(
    /// What reads the monotonic clock `M`.
    MonoReader,
    Mono
);
reader!(
    /// What reads the judging clock `J`.
    JudgedReader,
    Judged
);
reader!(
    /// What reads the raw monotonic clock.
    RawReader,
    Raw
);

/// Readings a reader took before, given back: a trace replayed, a test's script, the instants a
/// reference engine is stepped at, a host's clock read where its readers are made. Clippy refuses
/// these outside the code that replays or reads a host's clock (`clippy.toml`): a relay reads its
/// clocks through its readers.
#[allow(
    clippy::disallowed_methods,
    reason = "where the recorded readings are made"
)]
pub mod recorded {
    use super::{Judged, Moment, Mono, Raw};

    /// The monotonic reading `ms` taken before.
    pub const fn mono(ms: u64) -> Mono {
        Mono::read(ms)
    }

    /// The judging reading `ms` taken before.
    pub const fn judged(ms: u64) -> Judged {
        Judged::read(ms)
    }

    /// The raw reading `ms` taken before.
    pub const fn raw(ms: u64) -> Raw {
        Raw::read(ms)
    }

    /// The instant read as `mono` on `M` and `judged` on `J`.
    pub const fn moment(mono: u64, judged: u64) -> Moment {
        Moment {
            mono: Mono::read(mono),
            judged: Judged::read(judged),
        }
    }

    /// An instant whose two clocks read alike: a trace's or a test's, on a host whose clock never
    /// stepped.
    pub const fn aligned(ms: u64) -> Moment {
        moment(ms, ms)
    }
}

/// One instant on `M` and `J`, read together. Made only by reading both at once (a stamp's, a
/// watermark's) or from one by [`Moment::at`]; never paired by hand, and with no default.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Moment {
    mono: Mono,
    judged: Judged,
}

impl Moment {
    /// Both clocks read at one instant, by their readers.
    pub fn read(mono: &MonoReader, judged: &JudgedReader) -> Self {
        Self {
            mono: mono.read(),
            judged: judged.read(),
        }
    }

    /// Two readings taken together, as one instant: this crate's alone, for [`Moment::at`].
    const fn of(mono: Mono, judged: Judged) -> Self {
        Self { mono, judged }
    }

    /// Its monotonic reading.
    pub const fn mono(self) -> Mono {
        self.mono
    }

    /// Its judging reading.
    pub const fn judged(self) -> Judged {
        self.judged
    }

    /// How far `J` stands from `M` at this instant.
    pub fn offset_ms(self) -> i64 {
        let offset = i128::from(self.judged.0) - i128::from(self.mono.0);
        i64::try_from(offset).unwrap_or(if offset < 0 { i64::MIN } else { i64::MAX })
    }

    /// The instant `mono` on `M`, its `J` by this instant's offset: a step the pipeline names by
    /// its monotonic time, signed by the judging clock as this instant read it.
    pub fn at(self, mono: Mono) -> Self {
        let judged = i128::from(mono.0) + i128::from(self.offset_ms());
        Self::of(
            mono,
            Judged(u64::try_from(judged.max(0)).unwrap_or(u64::MAX)),
        )
    }

    /// As [`Moment::at`], at `mono_ms` on the monotonic clock's own grid (an epoch's end, a step):
    /// a time the pipeline states on `M`, never a reading of any other clock. Clippy refuses it
    /// but where the pipeline steps by its grid (`clippy.toml`), which says so.
    pub fn at_ms(self, mono_ms: u64) -> Self {
        self.at(Mono(mono_ms))
    }
}

#[cfg(test)]
#[allow(clippy::disallowed_methods, reason = "a test's scripted readings")]
mod tests {
    use super::*;

    #[test]
    fn an_instant_carries_its_offset_to_another_monotonic_time() {
        let ahead = recorded::moment(10_000, 70_000);
        assert_eq!(ahead.offset_ms(), 60_000);
        assert_eq!(
            ahead.at(recorded::mono(11_000)),
            recorded::moment(11_000, 71_000)
        );
        let behind = recorded::moment(70_000, 10_000);
        assert_eq!(
            behind.at(recorded::mono(71_000)),
            recorded::moment(71_000, 11_000)
        );
        assert_eq!(
            behind.at(recorded::mono(1_000)).judged(),
            recorded::judged(0)
        );
        assert_eq!(ahead.at_ms(11_000), ahead.at(recorded::mono(11_000)));
        assert_eq!(
            recorded::aligned(5).at(recorded::mono(9)),
            recorded::aligned(9)
        );
    }

    #[test]
    fn a_reader_reads_its_own_clock_and_a_reading_moves_on_it() {
        let reader = JudgedReader::of(|| recorded::judged(42));
        let now = reader.read();
        assert_eq!(now.ms(), 42);
        let eight = recorded::judged(50).since(now);
        assert_eq!(eight.ms(), 8);
        assert_eq!(now.later(eight).since(now), eight);
        assert_eq!(now.earlier(eight.times(100)).ms(), 0);
        assert_eq!(now.since(now.later(eight)), Span::ZERO);
        assert!(now.reached(recorded::judged(42)) && !now.reached(recorded::judged(43)));
        assert!(now.passed(recorded::judged(41)) && !now.passed(recorded::judged(42)));
        assert_eq!(eight.plus(eight).minus(eight), eight);
        assert_eq!(eight.minus(eight.times(2)), Span::ZERO);
        assert_eq!(recorded::judged(50).floor(eight), recorded::judged(48));
        assert_eq!(eight.whole_seconds().ms(), 1_000);
        assert_eq!(eight.times(125).whole_seconds().ms(), 1_000);
        assert_eq!(Span::<Judged>::ZERO.whole_seconds(), Span::ZERO);
        assert_eq!(now.floor(Span::ZERO), now);
    }
}
