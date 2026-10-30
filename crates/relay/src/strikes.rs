//! What a relay took in, which decides whether a copy of a record is new (RFC-0171 §3.6): the
//! strike register of RFC 8446 §8.2 (which QUIC keeps, RFC 9001 §9.2) and the replay cache of
//! Kerberos (RFC 4120 §3.2.3), a window of time plus the set of what was seen within it, and the
//! most it may have forgotten.
//!
//! **Two questions, never one.** Whether a relay *holds* a copy of a record (holds it in its
//! group, pushes it on down its stripe, receipts it, credits whoever delivered it, tags it for the
//! delivery checks) and whether it *uses* it (forwards it, gives it to its products, its
//! subscribers or its MLAT) are separate, and each is a pure function of the record's signed bytes
//! and this relay's own clock. Possession never reads a clock: nobody refuses a link, files a
//! shortfall or withholds credit over usability. Usability is this module's, and nothing a record
//! carries or a sender says changes it: no verdict travels with a copy.
//!
//! **What it covers.** Every record a relay uses once by its hash, each judged by the signed time
//! its kind carries: a feeder's batch by its `wall_ms` (the raw batches of each ingest shard);
//! positions, clock models and their client form by their engine's
//! `issued_ms`; a regional batch, its client form and a bundle index by the time their relay
//! signed (what is passed on by hash); feeder figures by their `issued_ms` in a window stretched
//! by the hour they are signed for ([`Usable::figures`]); and a fault proof by the newer of the
//! records it carries (`hub::proof_time`). What it does not cover is held by rules of its own: a
//! clock model's parts by the manifest that lists them (`parts`), a receiver's description and
//! site by the newest of each (`stations`), the sharing groups' manifests, receipts and asks by
//! their seconds' horizon (`sharing::member`), the world products by the second they seal
//! (`products`), offers by their expiry (`directory`), and the relay's own deduplicated stream by
//! the message exchange's generations (`exchange`).
//!
//! - **Usable within a window of this relay's clock** ([`Usable`]). A feeder's own copy, where it
//!   publishes, is usable while `now - t <= F + B + LAG` (91 s, [`Window::FEEDER`]); one signed more
//!   than `F` ahead is held there unused ([`feeder_clock`]) and passed on all the same, and
//!   nothing anywhere is refused for a clock. Any other copy of a feeder's batch (a member's, one
//!   rebuilt from parity) is usable while `now - t <= F + B + LAG - K` (76 s) and
//!   `t - now <= F + K` (25 s, [`Window::PEER`]); every window is derived in `tally_wire::budget`
//!   (RFC-0171 §3.6's error budget). The edges meet exactly: every copy's first
//!   relay is the one its feeder published to, which judges it before anyone else holds it, and
//!   every later relay's clock is within `K` of that one's, so a batch too old at its origin
//!   (`> 91` there) is too old everywhere (`> 76` at any relay), whatever version or honesty its
//!   origin has: no mark is needed to say so. The relay-signed kinds keep windows derived the same
//!   way from where their first copy is made ([`relay_signed`], [`proofs`]).
//!   Ahead, each copy is judged where it is held: one its origin held unused a peer may use, if
//!   its own clock finds it within `S`, and that peer's table remembers it for its own window.
//! - **New above a floor, unless its fingerprint is held.** A usable record is new iff its signed
//!   time is above the table's floor and its fingerprint is not held ([`Strikes`]). A fingerprint
//!   is held until the bucket of time holding its record's `t + R` has passed, `R` the longest any
//!   copy of it is usable ([`Usable::retained_ms`]: 91 s for a batch); dropping a generation
//!   raises the floor to the newest signed time it held, the most the table has forgotten. So a
//!   record is never new twice, whatever the clock does in between: a step back leaves the floor
//!   where it was (nothing was dropped), and a step or glitch forward forgets only what was taken,
//!   so the floor never passes what was really used. The floor outlives a restart (`durable`): a
//!   lease of signed time, synced ahead of use, so a restarted relay uses nothing it used before.
//! - **Remembered only once kept.** A record is judged first without being remembered
//!   ([`Strikes::judge`]) and remembered only when it is kept ([`Strikes::take`], judged again in
//!   the same step), so one dropped for load is no record seen and a member's copy of it is new.
//! - **Budgeted and closed when full.** Every table keeps a ring of generations for each class of
//!   deliverer ([`Class`]: the feeders, the peers, the relay's own), each charged what it
//!   allocates to its class's store (`Store::FeederStrikes`, `Store::PeerStrikes`,
//!   `Store::OwnStrikes`, planned as [`PLANNED_ENTRY_BYTES`] for each record a second the plan
//!   carries, its set at its growing peak, over the longest an entry delivered that way lives:
//!   [`Usable::feeder_life_seconds`], [`Usable::own_life_seconds`], [`Usable::life_seconds`]),
//!   and each entry to the share of whoever delivered it ([`Shares`]: a feeder's, the feeders'
//!   together, the peers' together, the relay's own, each planned from the records a second the
//!   plan carries for it). A record whose deliverer's share, or its class's store, is full is let
//!   go ([`Verdict::Full`]): not used, not remembered and not counted had, so its group asks for
//!   it again, its deliverer credited for delivering it. Nothing is ever evicted to make room, and
//!   no class's sets ever take another's store, so a flood fills only its own share and can never
//!   make another's record new twice or let it go.
//!
//! **Why a fingerprint of eight bytes.** A table keeps of each record a 64-bit SipHash of its hash
//! under a secret ([`Shares`]'s key: the process's, or the state directory's, `durable`), never the
//! hash's own bytes, so no sender can choose records that meet in a table or crowd one run of its
//! slots. Two records meet only by chance, in the one generation a copy is looked for in: with `n`
//! fingerprints in it, a new record is mistaken for a copy with probability `n / 2^64`. A
//! generation holds a second of one table's records, some 30,000 at the most a relay admits
//! (`cores::RECORDS_PER_PLANNED_FEEDER` at `R_max`), so a relay judging that many records a second
//! for a year makes about 1.5e-3 such mistakes. A mistake costs one record one use: it is a
//! duplicate (held in its group, counted had, its deliverer credited), not used by this relay, and
//! every other relay judges it under its own secret. Four bytes would make it about one every five
//! seconds; sixteen, the 2^64 work of the hash itself, would double what every entry costs to buy
//! nothing a relay can see.
//!
//! The message exchange keeps fingerprints over a window too (`exchange::Fingerprints`), and they
//! are not this table: its one table a thread is allocated once at a fixed capacity for the
//! window's epochs on that thread, each epoch counted before any is decided, and carries the epochs
//! and areas each message was kept for; a strike generation holds whatever a second's records were
//! taken, grows as they come, carries nothing but the fingerprint, and is dropped whole. One
//! structure for both would carry the other's fields for every entry.

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use tally_wire::batch::Hash;
use tally_wire::clocks::{Judged, Raw, Span};
use tally_wire::{FingerprintKey, PublicKey};

use crate::budget::{Charge, Gauge, Store};
use crate::durable::{Durable, Lease, Log, Prior, StateDir};
use crate::sharing::Deadlines;

/// How long after its signed `issued_ms` (its step) an engine may sign a record: a step runs for
/// up to `mlat_host::STEP_BUDGET_MS` before what it solved is signed. An engine's deadline, not a
/// clock's error: the windows are `tally_wire::budget`'s.
pub const ENGINE_LAG_MS: u64 = crate::mlat_host::STEP_BUDGET_MS;

/// The windows of time a relay judges signed times by, every one derived in the clocks' error
/// budget (`tally_wire::budget`, RFC-0171 §3.6), the one place a window can be made.
pub use tally_wire::budget::Window;

/// A record a relay signs, for a relay whose groups keep `deadlines`
/// (`tally_wire::budget::Window::relay_signed`): 32 s behind, `K` ahead.
pub const fn relay_signed(deadlines: Deadlines) -> Window {
    Window::relay_signed(
        tally_wire::budget::policy::<_, ENGINE_LAG_MS>(),
        deadlines.horizon(),
    )
}

/// A fault proof, for a relay whose groups keep `deadlines`
/// (`tally_wire::budget::Window::proofs`): 122 s behind, `S` ahead.
pub const fn proofs(deadlines: Deadlines) -> Window {
    Window::proofs(deadlines.horizon())
}

const _: () = assert!(
    relay_signed(Deadlines::RELAY)
        .behind_span()
        .span::<Judged>()
        .ms()
        == 32_000
);
const _: () = assert!(proofs(Deadlines::RELAY).behind_span().span::<Judged>().ms() == 122_000);

/// A table's windows: the one its first relay judges its origin's copy by (a feeder's batch from
/// its feeder) and the one every other copy is judged by, and the buckets of time its
/// fingerprints expire in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Usable {
    pub origin: Window,
    pub copy: Window,
    pub bucket_ms: u64,
}

const fn most(a: u64, b: u64) -> u64 {
    if a > b { a } else { b }
}

impl Usable {
    /// A feeder's batches: [`Window::FEEDER`] where its feeder publishes, [`Window::PEER`] for
    /// every other copy.
    pub const BATCHES: Self = Self {
        origin: Window::FEEDER,
        copy: Window::PEER,
        bucket_ms: 1000,
    };

    /// A kind judged alike wherever it comes from.
    pub const fn alike(window: Window) -> Self {
        Self {
            origin: window,
            copy: window,
            bucket_ms: 1000,
        }
    }

    /// The relay-signed kinds of a relay whose groups keep `deadlines` ([`Window::relay_signed`]).
    pub const fn relay_signed(deadlines: Deadlines) -> Self {
        Self::alike(crate::strikes::relay_signed(deadlines))
    }

    /// Fault proofs ([`Window::proofs`]).
    pub const fn proofs(deadlines: Deadlines) -> Self {
        Self::alike(crate::strikes::proofs(deadlines))
    }

    /// Feeder figures beside the relay-signed window `relay` (`Window::figures`: signed as of an
    /// hour's start at any time within it, `figures::Figures::sign`). Bucketed by the minute:
    /// figures are a few records an area an hour.
    pub const fn figures(relay: Window) -> Self {
        Self {
            origin: Window::figures(relay),
            copy: Window::figures(relay),
            bucket_ms: 60_000,
        }
    }

    /// The window a copy `who` delivered is judged by.
    pub fn window_for(self, who: Deliverer) -> Window {
        match who {
            Deliverer::Feeder(_) => self.origin,
            Deliverer::Peer(_) | Deliverer::Relay | Deliverer::Restored(_) => self.copy,
        }
    }

    /// How long after its signed time a fingerprint is held (`R`): the longest any copy of its
    /// record is usable, so nothing between is new twice.
    pub const fn retained_ms(self) -> u64 {
        most(
            self.origin
                .behind_span()
                .span::<tally_wire::clocks::Judged>()
                .ms(),
            self.copy
                .behind_span()
                .span::<tally_wire::clocks::Judged>()
                .ms(),
        )
    }

    /// How far ahead of the clock a held record may be signed.
    pub const fn ahead_ms(self) -> u64 {
        most(
            self.origin
                .ahead_span()
                .span::<tally_wire::clocks::Judged>()
                .ms(),
            self.copy
                .ahead_span()
                .span::<tally_wire::clocks::Judged>()
                .ms(),
        )
    }

    /// The whole seconds an entry may be remembered at the longest: from a copy signed as far
    /// ahead as any is used to `R` after it, and the bucket its expiry is rounded up to. What a
    /// peer's copy lives (100 s for a batch).
    pub const fn life_seconds(self) -> u64 {
        (self.retained_ms()
            + self
                .copy
                .ahead_span()
                .span::<tally_wire::clocks::Judged>()
                .ms()
            + self.bucket_ms)
            .div_ceil(1000)
    }

    /// The whole seconds an entry a feeder delivered lives at the longest: its relay uses no
    /// batch signed more than [`tally_wire::budget::F`] ahead of its clock (85 s).
    pub const fn feeder_life_seconds(self) -> u64 {
        (self.retained_ms()
            + self
                .origin
                .ahead_span()
                .span::<tally_wire::clocks::Judged>()
                .ms()
            + self.bucket_ms)
            .div_ceil(1000)
    }

    /// The whole seconds an entry of the relay's own making lives at the longest: what it signs
    /// is signed no later than its own clock reads (its products as of an epoch's end, its
    /// engine's as of a step), so it lives `R` and its bucket.
    pub const fn own_life_seconds(self) -> u64 {
        (self.retained_ms() + self.bucket_ms).div_ceil(1000)
    }

    /// The buckets an entry may be remembered over, as `life_seconds`.
    pub const fn life_buckets(self) -> u64 {
        (self.retained_ms() + self.ahead_ms()).div_ceil(self.bucket_ms) + 1
    }
}

/// What the relay a feeder publishes to makes of its batch's signed clock ([`feeder_clock`]).
/// Usability only: every one of them is possessed (held in its group, tagged for the delivery
/// checks, pushed down its stripe to the peers, who judge it by their own clocks), and none ends
/// or refuses anything (RFC-0171 §3.6, "nobody refuses a link over a clock").
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FeederClock {
    /// Within [`Window::FEEDER`]: usable, judged new or not by its table.
    Usable,
    /// Signed longer ago than the feeder's clock and its backlog allow: a batch it held too long
    /// (a session that waited out a backoff, a stall) or a clock behind, which look the same:
    /// possession only, never used here, counted late against its receiver where its owner reads
    /// it (`stations::StationReport`'s `late_batches`), and its feeder told the relay's clock
    /// again.
    TooOld,
    /// Signed more than `F` ahead of this relay's clock: a clock ahead (a Pi that has not synced,
    /// a host set by hand), or this relay's own stepped back. Possession only, never used here
    /// and counted against nobody (`Hub`'s `ahead_records`), its feeder told the relay's clock
    /// again; a peer judges its copy by its own clock.
    Ahead,
    /// Any batch while this relay's clock is not judging: possession only, counted against
    /// nobody, since the clock that cannot judge it is this relay's.
    Unjudged,
}

/// Whether a feeder's batch too old by its signed time where it publishes
/// ([`FeederClock::TooOld`]) is older than an honest batch can be by this relay's own anchor in
/// it: the youngest of this relay's own anchors it carries was issued [`OwnAnchor::Aged`] before
/// it arrived by this relay's raw monotonic clock (`Hub::own_anchor_age`), longer than an honest
/// batch's can be (`tally_wire::budget::OWN_ANCHOR_OLDEST`: the anchor's age as it is signed by,
/// `B` and `δ`). The signed time's half of the rule is [`feeder_clock`]'s alone ([`blame`]'s
/// `too_old`). The origin signed that anchor and timed it on a clock no daemon slews or steps, so
/// the age is exact whatever its judging clock did meanwhile, and whatever the feeder's clock
/// says. No other relay's anchor moves it, so the blame is the same whatever else the batch
/// carries. A batch a feeder held waiting for its first anchor, or signed by a clock behind true
/// time, carries this relay's anchor younger than that, so neither the hold nor the clock is
/// blamed. A batch that carries none of this relay's anchors ([`OwnAnchor::Absent`]) is never
/// blamed: an honest feeder sends such batches (a reconnect's backlog anchored by another relay
/// alone, its batches anchored by another relay while this relay's judging clock stepped ahead, a
/// relay with no signer, which issues none), so its signed time alone proves nothing against it.
fn own_anchor_too_old(own: OwnAnchor) -> bool {
    match own {
        OwnAnchor::Aged(age) => age > tally_wire::budget::OWN_ANCHOR_OLDEST,
        OwnAnchor::Absent => false,
    }
}

/// This relay's own freshness anchor in a feeder's batch, as blame reads it ([`blame`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OwnAnchor {
    /// The youngest it carries was issued no later than this long before the batch arrived, by
    /// this relay's raw monotonic clock (`Hub::own_anchor_age`): never overstated, whether the
    /// relay remembers that issue or only one it was issued no later than
    /// (`anchors::Anchors::issued_by`), or the batch came in its link's backlog
    /// (`link::Drained`).
    Aged(Span<Raw>),
    /// It carries none of this relay's that verifies, or this relay has issued none this run
    /// (none it can age): never blamed.
    Absent,
}

/// A feeder's batch's lateness blamed on its receiver (`stations::StationReport`'s
/// `late_batches`): what `Hub::late_from_feeder` takes, so nothing counts a batch against its
/// receiver but [`blame`], and no path of the hub can skip its rule.
pub struct Blame(());

/// The one rule a feeder's batch is blamed by: too old by its own signed time where its feeder
/// published it (`too_old`, `feeder_clock`), judged there for the first time (`first`, so a
/// resend or an audit's owed copy is never blamed again), and older than an honest batch can be
/// by this relay's own anchor in it ([`own_anchor_too_old`]), so only a batch that carries this
/// relay's own anchor is ever blamed. Late for any other reason (its table's floor raised past it
/// before it was kept, a stale anchor, a clock not judging, none of this relay's anchors) is
/// counted late, never blamed.
pub fn blame(too_old: bool, first: bool, own: OwnAnchor) -> Option<Blame> {
    (too_old && first && own_anchor_too_old(own)).then_some(Blame(()))
}

/// What the relay a feeder publishes to makes of its batch signed at `signed_ms`, by its own
/// judging clock `now` as its stamp read it, with whether that clock judged then
/// (`clock::RelayClock::judging`).
/// Usability only: whatever it answers, the batch is possessed and passed on, and nothing is
/// refused for it. While the relay's clock is not judging, nothing is judged
/// ([`FeederClock::Unjudged`]); otherwise a batch more than `F` ahead is
/// [`FeederClock::Ahead`], one older than `tally_wire::budget::FEEDER_BEHIND` is
/// [`FeederClock::TooOld`], and the rest is
/// [`FeederClock::Usable`].
pub fn feeder_clock(signed_ms: u64, now: Now) -> FeederClock {
    if !now.judges() {
        return FeederClock::Unjudged;
    }
    if tally_wire::budget::F.ahead(signed_ms, now.judged()) {
        return FeederClock::Ahead;
    }
    if Window::FEEDER.holds(signed_ms, now.judged()) {
        FeederClock::Usable
    } else {
        FeederClock::TooOld
    }
}

/// The judging clock as a table is asked by it ([`Strikes::judge`], [`Strikes::take`]): its
/// reading, and whether it judged as it was read (`clock::RelayClock::judging`: synced, its error
/// within `E`), the two taken together (a stamp's, `ingest::Stamp`). So no record is judged by a
/// clock that was not judging when its reading was taken.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Now {
    judged: Judged,
    judging: bool,
}

impl Now {
    /// The judging reading `judged`, and whether it judged as it was read: a test's. Everything
    /// else takes the two as they were read together (a stamp's, a sharing tick's: the `From`s
    /// below), so no reading is paired with a judging bit read at another instant.
    #[cfg(test)]
    pub const fn new(judged: Judged, judging: bool) -> Self {
        Self { judged, judging }
    }

    /// A test's reading `ms` of a clock that judges.
    #[cfg(test)]
    #[allow(clippy::disallowed_methods, reason = "a test's scripted readings")]
    pub const fn judging(ms: u64) -> Self {
        Self::new(tally_wire::clocks::recorded::judged(ms), true)
    }

    /// The judging reading.
    pub const fn judged(self) -> Judged {
        self.judged
    }

    /// Whether the clock judged as it was read.
    pub const fn judges(self) -> bool {
        self.judging
    }
}

impl From<crate::ingest::Stamp> for Now {
    fn from(stamp: crate::ingest::Stamp) -> Self {
        Self {
            judged: stamp.judged(),
            judging: stamp.judging(),
        }
    }
}

impl From<crate::sharing::Now> for Now {
    fn from(now: crate::sharing::Now) -> Self {
        Self {
            judged: now.judged(),
            judging: now.judging(),
        }
    }
}

/// What a table's fingerprint of a record is planned to cost at most, at its set's peak: its
/// eight bytes in its generation's set, which doubles past 3/4 full and is never shrunk (it is
/// dropped whole as its second passes), so at least 3/8 full, 8 x 8/3 (21.3) a fingerprint; and
/// while a set grows it holds its old slots and its new at once (`Generation::insert`), three
/// times the old slots for the 3/4 of them full and the one more, under 8 x 4 (32) a
/// fingerprint of the generation growing. Any number of a class's generations may be growing at
/// once (one in each table) and one generation may hold every entry of its class (all signed in
/// one bucket), so each class's store is planned at the peak for every entry: before, the plan
/// took the 3/8 floor alone, and a store filled to its plan had no room for the set's growth, so
/// every record of that bucket was let go. Beside what every class's ring in a table allocates
/// whatever it holds ([`Strikes::fixed_bytes`]), and its deliverer's count of it
/// ([`PLANNED_PAIR_BYTES`]).
///
/// What each class's store (`Store::FeederStrikes`, `Store::PeerStrikes`, `Store::OwnStrikes`)
/// is planned at for each record a second over its life; a test holds the tables to it as records
/// come and go (`a_tables_bytes_are_within_what_it_is_planned`).
pub const PLANNED_ENTRY_BYTES: usize = 32;

/// What a deliverer's count of its entries expiring in one second costs ([`Shares`]): a second
/// and a count (eight bytes) in its list, which is kept at least half full. A deliverer that
/// delivers records each second holds one for each second its entries live.
pub const PLANNED_PAIR_BYTES: usize = 16;

/// What the places in the shares cost at most ([`Shares`]) for `places` deliverers holding
/// entries, their counts apart: the table of places, which is never more than four times the
/// places it holds once it is past [`PLACES_KEPT`] of them
/// (`footprint::table_planned`). What a plan takes for them: [`PLACES_FIXED_BYTES`] and
/// [`PLACE_BYTES`] for each.
pub const fn places_bytes(places: usize) -> usize {
    crate::footprint::table_planned::<Deliverer, Place>(PLACES_KEPT + 4 * places)
}

/// The places a table of places keeps room for however few hold entries: it is never shrunk below
/// them ([`Shares`]).
pub const PLACES_KEPT: usize = 64;

/// What [`places_bytes`] costs whatever it holds: the table kept for [`PLACES_KEPT`], and a
/// bucket's rounding.
pub const PLACES_FIXED_BYTES: usize =
    places_bytes(0) + std::mem::size_of::<(Deliverer, Place)>() + 1;

/// What [`places_bytes`] costs for each place more, at most: four entries' sixteen sevenths of a
/// bucket each, and the bucket's control byte.
pub const PLACE_BYTES: usize = (64 * (std::mem::size_of::<(Deliverer, Place)>() + 1)).div_ceil(7);

/// What a feeder's place costs at most beside the table ([`PLACE_BYTES`]): its counts, one for
/// each second its entries may expire in over the longest a feeder's entry lives, the list kept at
/// least half full ([`PLANNED_PAIR_BYTES`] each).
pub const fn feeder_place_bytes(usable: Usable) -> usize {
    PLACE_BYTES + (usable.feeder_life_seconds() as usize + 1) * PLANNED_PAIR_BYTES
}

/// What a peer's or the relay's own place costs at most beside the table: its counts over the
/// longest a peer's copy lives, and those of the figures it delivers, which expire by the minute
/// over their own window's buckets ([`Usable::figures`]).
pub const fn place_bytes(usable: Usable, figures: Usable) -> usize {
    PLACE_BYTES
        + (usable.life_seconds() as usize + 1 + figures.life_buckets() as usize)
            * PLANNED_PAIR_BYTES
}

/// What a feeder's place costs its kind's share, in entries ([`PLANNED_ENTRY_BYTES`] each): its
/// bytes beside the table ([`feeder_place_bytes`]), rounded up. A feeder holding entries is
/// charged this once beside its entries against the feeders' share together ([`Shares::take`]),
/// so feeders churning fresh keys, each a place of its own, fill the feeders' share with their
/// places as with their entries, and no more: before, a place was planned once a connection and
/// charged to no share, and a churn of fresh keys each sending one tiny batch filled the store
/// for the peers and the relay's own.
pub const FEEDER_PLACE_ENTRIES: usize =
    feeder_place_bytes(Usable::BATCHES).div_ceil(PLANNED_ENTRY_BYTES);

/// What a peer's place costs the peers' share, in entries, as [`FEEDER_PLACE_ENTRIES`]: its bytes
/// beside the table ([`place_bytes`]), rounded up.
pub const PEER_PLACE_ENTRIES: usize = place_bytes(
    Usable::BATCHES,
    Usable::figures(crate::strikes::relay_signed(
        crate::sharing::Deadlines::RELAY,
    )),
)
.div_ceil(PLANNED_ENTRY_BYTES);

// A place charged in entries is charged at least what it allocates.
const _: () = assert!(
    FEEDER_PLACE_ENTRIES * PLANNED_ENTRY_BYTES >= feeder_place_bytes(Usable::BATCHES)
        && PEER_PLACE_ENTRIES * PLANNED_ENTRY_BYTES
            >= place_bytes(
                Usable::BATCHES,
                Usable::figures(crate::strikes::relay_signed(
                    crate::sharing::Deadlines::RELAY
                ))
            )
);

// A fresh key's place costs the store no more than the least its first record is charged in the
// ingest pool (`ingest::CHARGE_FLOOR`, what a tiny batch is charged), so the ingest rate that
// meters a churn of fresh keys' tiny batches meters what their places hold too.
const _: () = assert!(feeder_place_bytes(Usable::BATCHES) <= crate::ingest::CHARGE_FLOOR);

const _: () = {
    let mut places = 0;
    while places < 1 << 21 {
        assert!(places_bytes(places) <= PLACES_FIXED_BYTES + places * PLACE_BYTES);
        places = places * 3 + 1;
    }
};

/// The fingerprints of the records one table took that expire in one bucket of time: open
/// addressing with linear probing over one allocation of `u64`s, its probes started from the
/// fingerprint's own bits (a keyed hash, so no sender chooses where it lands). At most 3/4 full,
/// doubled past it; never shrunk and never removed from: dropped whole as its bucket passes, the
/// newest signed time it held raising its table's floor.
#[derive(Default)]
struct Generation {
    bucket: u64,
    slots: Vec<u64>,
    len: usize,
    /// The newest signed time among its records: the most its table forgets when it is dropped.
    newest_ms: u64,
}

impl Generation {
    const LEAST: usize = 1;

    fn bytes(&self) -> usize {
        self.slots.capacity() * std::mem::size_of::<u64>()
    }

    /// The slots it holds `len` fingerprints in: its own while they fit, else doubled.
    fn slots_for(&self, len: usize) -> usize {
        let mut slots = self.slots.len().max(Self::LEAST);
        while len * 4 > slots * 3 {
            slots *= 2;
        }
        slots
    }

    /// The slot holding `fp`, or the empty one ending its run.
    fn find(&self, fp: u64) -> (usize, bool) {
        let mask = self.slots.len() - 1;
        let mut at = (fp as usize) & mask;
        loop {
            let held = self.slots[at];
            if held == fp {
                return (at, true);
            }
            if held == 0 {
                return (at, false);
            }
            at = (at + 1) & mask;
        }
    }

    fn contains(&self, fp: u64) -> bool {
        !self.slots.is_empty() && self.find(fp).1
    }

    /// Holds `fp` of a record signed at `signed_ms`, its slots already grown to
    /// `slots_for(len + 1)` by the caller's charge, which covers the old slots and the new while
    /// both are held (`Strikes::make_room`).
    fn insert(&mut self, fp: u64, signed_ms: u64) {
        let wanted = self.slots_for(self.len + 1);
        if wanted != self.slots.len() {
            let old = std::mem::replace(&mut self.slots, vec![0; wanted]);
            for held in old.into_iter().filter(|held| *held != 0) {
                let (at, _) = self.find(held);
                self.slots[at] = held;
            }
        }
        let (at, held) = self.find(fp);
        if !held {
            self.slots[at] = fp;
            self.len += 1;
        }
        self.newest_ms = self.newest_ms.max(signed_ms);
    }

    /// Forgets everything, giving back what it allocated.
    fn drop_all(&mut self) {
        self.slots = Vec::new();
        self.len = 0;
        self.newest_ms = 0;
    }
}

/// A record's fingerprint in a table: its hash's SipHash under `key` (module docs). Never zero,
/// which marks an empty slot.
fn fingerprint(key: &FingerprintKey, hash: &Hash) -> u64 {
    let keyed = key.fingerprint(tally_wire::decoded::keyed::STRIKE, hash);
    (keyed as u64).max(1)
}

/// Where a fingerprint may go ([`Strikes::make_room`]).
enum Room {
    /// In this generation's slot, charged.
    At(usize),
    /// Its slot holds a newer bucket's records still owed (only after a clock stepped back).
    Collides,
    /// The store has no room.
    Full,
}

/// A table's floor and every generation each class's ring holds, appended to `out`: what a stop's
/// dump and a table's checkpoint hold, under its shares' key. The floor, then for each class in
/// [`Class::ALL`]'s order its generations holding anything, each its bucket, its newest signed
/// time, its length and its fingerprints.
fn dump_into(floor_ms: Option<u64>, rings: &[Ring; 3], out: &mut Vec<u8>) {
    // The floor one past itself, so a table that has forgotten nothing writes zero.
    let floor = floor_ms.map_or(0, |floor| floor.saturating_add(1));
    out.extend_from_slice(&floor.to_le_bytes());
    for ring in rings {
        let held: Vec<&Generation> = ring
            .generations
            .iter()
            .filter(|generation| generation.len > 0)
            .collect();
        out.extend_from_slice(&(held.len() as u64).to_le_bytes());
        for generation in held {
            out.extend_from_slice(&generation.bucket.to_le_bytes());
            out.extend_from_slice(&generation.newest_ms.to_le_bytes());
            out.extend_from_slice(&(generation.len as u64).to_le_bytes());
            for fp in generation.slots.iter().filter(|fp| **fp != 0) {
                out.extend_from_slice(&fp.to_le_bytes());
            }
        }
    }
}

/// What a table says of a record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// Usable, above the floor, its fingerprint not held: used, held in its group, its deliverer
    /// credited.
    New,
    /// Usable, its fingerprint held: not used again, but held in its group (counted as had) and
    /// its deliverer credited, since it did deliver it.
    Duplicate,
    /// Not usable here: outside its window ([`Usable`]), or at or below the floor (signed no later
    /// than the newest record the table may have forgotten). Never used, never remembered (counted
    /// apart, `MemoryReport::late_records`); held in its group as every copy is, its deliverer
    /// credited, since possession never reads a clock.
    Late,
    /// Not usable yet: the relay's clock has not yet been synced since it started, so the table
    /// has no floor and no window it may judge by (`Strikes::begin`). Held in its group as every
    /// copy is and its deliverer credited, never used, never remembered, and never counted against
    /// anyone (counted apart, `MemoryReport::unjudged_records`).
    Unjudged,
    /// Not usable at this copy's arrival here: a feeder's batch signed further ahead of this
    /// relay's clock than its window allows (`Strikes::judge_batch`). Held in its group as every
    /// copy is, its deliverer credited, never used, counted against nobody (counted apart,
    /// `MemoryReport::ahead_records`): this relay's clock may be the one behind. A copy that
    /// arrives once its signed time has come is judged by its anchors (`anchors`), so a batch held
    /// back until then is too old by them.
    Ahead,
    /// Not usable here: a feeder's batch with no freshness anchor this relay can check (a format
    /// without them, an older feeder's; or one whose anchor does not verify under a relay this
    /// relay knows, `anchors`). Held in its group as every copy is, its deliverer credited, never
    /// used, counted apart (`MemoryReport::unanchored_records`).
    Unanchored,
    /// New, but its deliverer's share or the store is full, or its table could not make sure a
    /// restart would know it was used (`durable::Lease`): let go, not used, not remembered and not
    /// counted had, so its group asks for it again (counted apart, `MemoryReport::strikes_full`).
    /// Its deliverer is credited all the same, since it did deliver it: this relay's room is no
    /// fault of the member that sent it.
    Full,
}

/// Who delivered a record, whose share its entry is charged to.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Deliverer {
    /// A feeder publishing its receiver's batches, by its receiver's key.
    Feeder(PublicKey),
    /// A peer: a member's link, a relay's, an engine's, by its key. Whatever a peer sent is its,
    /// the products it passes on among them.
    Peer(PublicKey),
    /// This relay: what it made itself (its products, its engine's records, its figures) and what
    /// it rebuilt from its groups' parity. Nothing a peer sent.
    Relay,
    /// What a restart read back of a class (a dump, a table's checkpoint and log): one holder of
    /// that class's share, so a restored fingerprint is counted as every other is
    /// ([`Shares::take`]). Nobody delivered it in this process.
    Restored(Class),
}

/// The records a second the relay signs as its products for each planned feeder's worth of load
/// (`products::Sealer::seal_copies`): each epoch (`seal::EPOCH_MS`, a second), each area with
/// copies in it gets a regional batch and its client form, and one more of each for every chunk
/// its copies overflow into (`products::cut`). An area holds the receptions of the receivers in
/// it, and a planned feeder's epoch of them fits one record, so an area of `k` planned feeders
/// overflows into fewer than `k` chunks: two records an epoch for each planned feeder, which
/// sparse coverage (each feeder alone in its area) reaches.
pub const OWN_PRODUCTS_PER_FEEDER: u64 = 2;

/// The records a second hosted MLAT signs for each planned feeder's worth of load, beside the
/// engine's own ([`ENGINE_RECORDS_FIXED`]): its fixes as positions, each raw and tagged
/// (`tally_mlat::fix`'s step), packed to a record's bytes (`Positions::fitting`), and its areas'
/// clock models with their client form. A fix needs three receivers at the least, so a feeder's
/// planned notes (`mlat_host::PLANNED_NOTES_PER_SEC`, 300) make at most 100 transmissions a
/// second, each solved twice at most (when it settles, and once more if its set grew); a fix of a
/// few receivers is about 110 bytes, so a record carries some 580; the two forms of 200 are under
/// one record a second, and an area's model and its client form, once a refit
/// (`tally_wire::budget::REFIT_EVERY`), a few hundredths.
pub const ENGINE_RECORDS_PER_FEEDER: u64 = 1;

/// The records a second hosted MLAT signs whatever its load: the last record of each form a step
/// packs (raw and tagged, a step a second), each part filled, and the last model's client form.
pub const ENGINE_RECORDS_FIXED: u64 = 3;

/// The records a second the relay itself delivers for each planned feeder's worth of load, of its
/// own making: its products and, where it hosts MLAT, its engine's.
pub const fn own_records_per_feeder(holds_raw: bool) -> u64 {
    if holds_raw {
        OWN_PRODUCTS_PER_FEEDER + ENGINE_RECORDS_PER_FEEDER
    } else {
        OWN_PRODUCTS_PER_FEEDER
    }
}

/// The feeder figures records the relay holds an entry of for each planned feeder's worth of load
/// (`Usable::figures`): an area's figures are signed once an hour, a record for each
/// `tally_wire::figures::MAX_FEEDER_FIGURES` receivers and an area holding one at least, so this
/// hour's and the last's, while a record is remembered for an hour and a relay's window.
pub const FIGURES_HELD_PER_FEEDER: u64 = 2;

/// The entries each kind of deliverer may hold across every table ([`Shares`]), from the plan's
/// own quantities (`budget::Plan::strike_entries`): one feeder's session's, the feeders' together,
/// one peer's, the peers' together, and the relay's own. A kind's share together counts its
/// holders' places among its entries ([`FEEDER_PLACE_ENTRIES`], [`PEER_PLACE_ENTRIES`]); one
/// deliverer's counts its entries alone.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Entries {
    pub feeder: usize,
    pub feeders: usize,
    pub peer: usize,
    pub peers: usize,
    pub relay: usize,
}

/// The three classes of deliverer, each with a store of its own (`Store::FeederStrikes`,
/// `Store::PeerStrikes`, `Store::OwnStrikes`, [`StrikeStores`]), a ring of generations of its own
/// in every table, and a table of places of its own in the shares: so whatever one class holds,
/// and however its sets grow, it never takes room another class is planned. Before, every class
/// shared one store and one set a second, and one generation's growth, filled by feeders, refused
/// a peer's record and the relay's own.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Class {
    Feeders,
    Peers,
    Own,
}

impl Class {
    pub const ALL: [Self; 3] = [Self::Feeders, Self::Peers, Self::Own];

    const fn index(self) -> usize {
        self as usize
    }

    /// The class written in a dump or a log as `byte`, if any.
    const fn of_byte(byte: u8) -> Option<Self> {
        match byte {
            0 => Some(Self::Feeders),
            1 => Some(Self::Peers),
            2 => Some(Self::Own),
            _ => None,
        }
    }

    /// The store its entries are charged to.
    pub const fn store(self) -> Store {
        match self {
            Self::Feeders => Store::FeederStrikes,
            Self::Peers => Store::PeerStrikes,
            Self::Own => Store::OwnStrikes,
        }
    }
}

impl Deliverer {
    /// The class it delivers as ([`Class`]).
    pub const fn class(self) -> Class {
        match self {
            Self::Feeder(_) => Class::Feeders,
            Self::Peer(_) => Class::Peers,
            Self::Relay => Class::Own,
            Self::Restored(class) => class,
        }
    }
}

/// The stores what is taken is charged to, one for each [`Class`].
#[derive(Clone)]
pub struct StrikeStores {
    gauges: [Arc<Gauge>; 3],
}

impl StrikeStores {
    /// The budget's three stores.
    pub fn of(budget: &crate::budget::Budget) -> Self {
        Self {
            gauges: Class::ALL.map(|class| budget.gauge(class.store())),
        }
    }

    /// Three stores of no bound: a part built without a budget (a test's).
    pub fn unlimited() -> Self {
        Self::limited([usize::MAX; 3])
    }

    /// Three stores of `limits`, the feeders', the peers' and the relay's own: a test's.
    pub fn limited(limits: [usize; 3]) -> Self {
        let [feeders, peers, own] = limits;
        Self {
            gauges: [
                Gauge::new(Store::FeederStrikes, feeders),
                Gauge::new(Store::PeerStrikes, peers),
                Gauge::new(Store::OwnStrikes, own),
            ],
        }
    }

    /// One store for every class: a test's, which looks at one class at a time.
    #[cfg(test)]
    pub(crate) fn sharing(gauge: &Arc<Gauge>) -> Self {
        Self {
            gauges: [Arc::clone(gauge), Arc::clone(gauge), Arc::clone(gauge)],
        }
    }

    /// The store of `class`.
    pub fn gauge(&self, class: Class) -> &Arc<Gauge> {
        &self.gauges[class.index()]
    }

    /// What the three hold now, together.
    pub fn held(&self) -> usize {
        self.gauges.iter().map(|gauge| gauge.held()).sum()
    }
}

/// Each deliverer's entries across every table, against its share ([`Entries`]), so a flood by
/// any deliverer, the relay's own included, fills its own share and no more. A feeder's share is
/// its own and its part of the feeders' together, as a peer's is of the peers': feeders churning
/// fresh keys fill the feeders' share and no more, never another class's store. A deliverer
/// holding entries has a place of its own in its class's table of places and a count of its
/// entries by the second they expire in, its list of them kept at least half full
/// ([`PLANNED_PAIR_BYTES`] each); both are charged to its class's store as they allocate
/// (`footprint`): the table as its buckets grow, before the insert that grows it, and each list's
/// capacity. Its entries leave its share as their seconds pass, as their generations leave the
/// tables (each swept by the relay's tick, `Hub::sweep_strikes`), and a table of places is shrunk
/// once it is past four times the places it holds and [`PLACES_KEPT`]. It holds the tables'
/// fingerprint key too, the process's or the state directory's (`durable`), so a dump and a
/// persisted table are read back under the key they were written under.
pub struct Shares {
    /// Each class's places, by [`Class::index`].
    held: Mutex<[Held; 3]>,
    key: FingerprintKey,
    feeder: AtomicUsize,
    feeders: AtomicUsize,
    peer: AtomicUsize,
    peers: AtomicUsize,
    relay: AtomicUsize,
    /// Set once the relay is stopping (`Shares::close`): nothing more is taken, so a stop's dump
    /// holds everything used.
    closed: std::sync::atomic::AtomicBool,
    /// Each table taking into these shares, by how far it has swept (`Strikes::sweep`, in
    /// milliseconds: it holds nothing that expires before): entries are let go only below the
    /// least of them ([`Shares::expire`]).
    tables: Mutex<Vec<std::sync::Weak<AtomicU64>>>,
}

/// One deliverer's place: its entries, and how many expire in each second, in order.
struct Place {
    entries: usize,
    expiring: VecDeque<(u32, u32)>,
}

impl Place {
    /// What its counts allocate.
    fn bytes(&self) -> usize {
        crate::footprint::vec::<(u32, u32)>(self.expiring.capacity())
    }
}

/// One class's places, charged to its store.
struct Held {
    places: HashMap<Deliverer, Place>,
    /// The buckets `places` allocates (`footprint::Table`).
    table: crate::footprint::Table,
    /// What the places' counts allocate together (`Place::bytes`).
    counts: usize,
    /// The deliverers holding entries, their entries together, and their places in entries
    /// ([`place_entries`]) together.
    holders: usize,
    entries: usize,
    place_units: usize,
    /// Every second before this has been let go.
    expired: u32,
    charge: Charge,
}

impl Held {
    fn new(gauge: &Arc<Gauge>) -> Self {
        Self {
            places: HashMap::new(),
            table: crate::footprint::Table::default(),
            counts: 0,
            holders: 0,
            entries: 0,
            place_units: 0,
            expired: 0,
            charge: gauge.empty(),
        }
    }
}

/// What `who`'s place costs its kind's share, in entries ([`FEEDER_PLACE_ENTRIES`],
/// [`PEER_PLACE_ENTRIES`]); the relay's own is one deliverer, its place planned apart. A restored
/// holder's place is a peer's (its counts may span every second a copy lives, and a figure's).
const fn place_entries(who: Deliverer) -> usize {
    match who {
        Deliverer::Feeder(_) => FEEDER_PLACE_ENTRIES,
        Deliverer::Peer(_) | Deliverer::Restored(_) => PEER_PLACE_ENTRIES,
        Deliverer::Relay => 0,
    }
}

/// The second a record's entry expires in: the second its bucket ends, as a table drops it.
fn second_of(expires_ms: u64) -> u32 {
    u32::try_from(expires_ms.div_ceil(1000)).unwrap_or(u32::MAX)
}

impl Shares {
    /// Shares of `entries`, each class's places charged to its store in `stores`, under a key of
    /// the process's own.
    pub fn new(stores: &StrikeStores, entries: Entries) -> Arc<Self> {
        Self::keyed(stores, entries, FingerprintKey::random())
    }

    /// Shares of `entries`, charged to `stores`, its tables' fingerprints under `key`.
    pub fn keyed(stores: &StrikeStores, entries: Entries, key: FingerprintKey) -> Arc<Self> {
        Arc::new(Self {
            held: Mutex::new(Class::ALL.map(|class| Held::new(stores.gauge(class)))),
            key,
            feeder: AtomicUsize::new(entries.feeder),
            feeders: AtomicUsize::new(entries.feeders),
            peer: AtomicUsize::new(entries.peer),
            peers: AtomicUsize::new(entries.peers),
            relay: AtomicUsize::new(entries.relay),
            closed: std::sync::atomic::AtomicBool::new(false),
            tables: Mutex::new(Vec::new()),
        })
    }

    /// A new table's place among those taking into these shares: how far it has swept, nothing
    /// yet. It goes with the table.
    fn register(&self) -> Arc<AtomicU64> {
        let swept = Arc::new(AtomicU64::new(0));
        if let Ok(mut tables) = self.tables.lock() {
            tables.retain(|table| table.strong_count() > 0);
            tables.push(Arc::downgrade(&swept));
        }
        swept
    }

    /// The least any live table has swept through, in milliseconds (none taking: `now_ms`).
    fn swept_by_all(&self, now: Judged) -> u64 {
        let now_ms = now.ms();
        self.tables.lock().map_or(0, |tables| {
            tables
                .iter()
                .filter_map(std::sync::Weak::upgrade)
                .map(|swept| swept.load(Ordering::SeqCst))
                .min()
                .map_or(now_ms, |least| least.min(now_ms))
        })
    }

    /// Nothing more is taken by any table: every record from now is [`Verdict::Full`]. What a
    /// graceful stop does before it dumps the tables (`Hub::stop`), so a record used after the
    /// dump cannot be new again after the restart that reads it back.
    pub fn close(&self) {
        self.closed.store(true, Ordering::SeqCst);
    }

    /// The shares set again, as the relay's plan is.
    pub fn set(&self, entries: Entries) {
        self.feeder.store(entries.feeder, Ordering::Relaxed);
        self.feeders.store(entries.feeders, Ordering::Relaxed);
        self.peer.store(entries.peer, Ordering::Relaxed);
        self.peers.store(entries.peers, Ordering::Relaxed);
        self.relay.store(entries.relay, Ordering::Relaxed);
    }

    /// The entries one `who` may hold, those its class may hold together, and whether `who` may
    /// take past them to its fair part (a feeder and a peer, one of many holders of their kind).
    /// The relay's own class holds the relay's share together, and a restored holder's class
    /// holds its share together, never past it: what a restart read back is counted in the share
    /// of the class that took it, so a class's store holds what its share plans and nothing
    /// beside.
    fn shares_of(&self, who: Deliverer) -> (usize, usize, bool) {
        let feeders = || self.feeders.load(Ordering::Relaxed);
        let peers = || self.peers.load(Ordering::Relaxed);
        let relay = || self.relay.load(Ordering::Relaxed);
        match who {
            Deliverer::Feeder(_) => (self.feeder.load(Ordering::Relaxed), feeders(), true),
            Deliverer::Peer(_) => (self.peer.load(Ordering::Relaxed), peers(), true),
            Deliverer::Relay => (relay(), relay(), false),
            Deliverer::Restored(Class::Feeders) => (usize::MAX, feeders(), false),
            Deliverer::Restored(Class::Peers) => (usize::MAX, peers(), false),
            Deliverer::Restored(Class::Own) => (usize::MAX, relay(), false),
        }
    }

    /// One more entry for `who`, expiring at `expires_ms`; false when its share or its class's
    /// store is full. Nothing is let go here: entries leave the shares only once every table has
    /// dropped them ([`Shares::expire`], after every table's sweep).
    /// A feeder's and a peer's kind share theirs together, counted in entries with each holder's
    /// place among them ([`FEEDER_PLACE_ENTRIES`], [`PEER_PLACE_ENTRIES`]): one takes an entry
    /// while it holds less than its own share, and while its kind would hold no more than theirs
    /// with it, or it would hold no more than its fair part of it (theirs over the holders of its
    /// kind, rounded down) and its kind no more than twice theirs. So one that floods fills its
    /// kind's share and no more, and never keeps another from its part, and a kind holds at most
    /// twice its share however its holders come: before, the fair part alone bounded a holder past
    /// the share, and holders that came one after another, each filling its fair part of the
    /// holders then, held a harmonic sum of the share past twice it. A crowd of fresh keys
    /// (feeders churning keys, each a holder of its own) makes every fair part smaller, never the
    /// kind's bound larger.
    fn take(&self, who: Deliverer, expires_ms: u64) -> bool {
        if self.closed.load(Ordering::SeqCst) {
            return false;
        }
        let (share, together, fair) = self.shares_of(who);
        let Ok(mut all) = self.held.lock() else {
            return false;
        };
        let held = &mut all[who.class().index()];
        let entries = held.places.get(&who).map_or(0, |place| place.entries);
        // A class's share is counted in entries, each holder's place among them
        // (`place_entries`): one more entry for `who` is one entry, and its place's too when it
        // holds none yet.
        let place = place_entries(who);
        let first = entries == 0;
        let holders = held.holders + usize::from(first);
        let kind_after = held.entries + 1 + held.place_units + if first { place } else { 0 };
        let own_after = entries + 1 + place;
        let within = entries < share
            && (kind_after <= together
                || (fair
                    && own_after <= together / holders.max(1)
                    && kind_after <= together.saturating_mul(2)));
        if !within {
            return false;
        }
        let second = second_of(expires_ms);
        // A new place: its table may grow, and its list of counts is a new one of two. Each
        // allocation charged at its peak before it is made (`reallocated`).
        if !held.places.contains_key(&who) {
            let Held {
                places,
                table,
                charge,
                ..
            } = &mut *held;
            let peak = table.growth::<Deliverer, Place>(places.len(), places.capacity())
                + crate::footprint::vec::<(u32, u32)>(2);
            let old_table = table.bytes::<Deliverer, Place>();
            if !reallocated(charge, peak, || {
                let buckets = table.buckets();
                let mut expiring = VecDeque::new();
                expiring.reserve_exact(2);
                places.insert(
                    who,
                    Place {
                        entries: 0,
                        expiring,
                    },
                );
                // A table that grew freed the one it moved out of. Whether it grew is the
                // table's buckets' to say (`footprint::Table::inserted`), never its capacity: an
                // insert into a slot a removed entry left raises the capacity it reads by one
                // with no new table made. Before, that was taken for a growth and the old table
                // given back while still held, so the shares were charged a table short.
                table.inserted(places.capacity());
                if table.buckets() == buckets {
                    0
                } else {
                    old_table
                }
            }) {
                return false;
            }
            held.counts += crate::footprint::vec::<(u32, u32)>(2);
        }
        let Held { places, charge, .. } = &mut *held;
        let Some(place) = places.get_mut(&who) else {
            return false;
        };
        let before = place.bytes();
        let at = place.expiring.partition_point(|(s, _)| *s < second);
        if place.expiring.get(at).is_some_and(|(s, _)| *s == second) {
            place.expiring[at].1 += 1;
        } else {
            // A new second in a full list: doubled, so it is at least half full as it grows.
            if place.expiring.len() == place.expiring.capacity() {
                let to = (place.expiring.capacity() * 2).max(2);
                let expiring = &mut place.expiring;
                if !reallocated(charge, crate::footprint::vec::<(u32, u32)>(to), || {
                    let old = crate::footprint::vec::<(u32, u32)>(expiring.capacity());
                    expiring.reserve_exact(to - expiring.len());
                    old
                }) {
                    // A place that holds nothing yet goes again, its counts with it.
                    if place.entries == 0 {
                        let gone = place.bytes();
                        places.remove(&who);
                        held.counts -= gone;
                        settle(held);
                    }
                    return false;
                }
            }
            place.expiring.insert(at, (second, 1));
        }
        let after = place.bytes();
        let first = place.entries == 0;
        place.entries += 1;
        held.counts = held.counts + after - before;
        // What it allocated is charged, and the peak above it given back.
        charged_down(held);
        held.holders += usize::from(first);
        held.place_units += if first { place_entries(who) } else { 0 };
        held.entries += 1;
        true
    }

    /// The entry `take` just gave `who` at `expires_ms`, given back: its table had no room for it.
    fn untake(&self, who: Deliverer, expires_ms: u64) {
        let Ok(mut all) = self.held.lock() else {
            return;
        };
        let held = &mut all[who.class().index()];
        let second = second_of(expires_ms);
        let Some(place) = held.places.get_mut(&who) else {
            return;
        };
        let before = place.bytes();
        let at = place.expiring.partition_point(|(s, _)| *s < second);
        let mut gave_back = false;
        if place.expiring.get(at).is_some_and(|(s, _)| *s == second) {
            place.expiring[at].1 -= 1;
            if place.expiring[at].1 == 0 {
                place.expiring.remove(at);
            }
            place.entries -= 1;
            gave_back = true;
        }
        let gone = place.entries == 0;
        let after = if gone {
            held.places.remove(&who);
            0
        } else {
            place.bytes()
        };
        held.entries -= usize::from(gave_back);
        held.holders -= usize::from(gone);
        held.place_units -= if gone { place_entries(who) } else { 0 };
        held.counts -= before - after;
        settle(held);
    }

    /// Every entry whose second has passed at `now_ms` let go, in every class: called once every
    /// table that takes into these shares has been swept at `now_ms` or later
    /// (`Hub::sweep_strikes`), so an entry leaves its share only once no table holds it. Before,
    /// each take and each table's own sweep let entries go, and the entries of a table not yet
    /// swept (another ingest shard's) left the shares while their fingerprints still held its
    /// store: the shares then allowed more than the store planned for them could hold.
    ///
    /// And never past what the least swept table has dropped (`swept_by_all`), read under the
    /// shares' lock: a table judging by a clock older than this expiry's (a judge's reading taken
    /// before the tick's, a clock stepped back) sweeps back before it takes, and says so before
    /// its take reaches the shares, so what it takes then is let go only once it sweeps past it
    /// again. Before, such a take, its bucket already swept, left the shares at once while its
    /// table held it for a whole window.
    pub fn expire(&self, now: Judged) {
        if let Ok(mut all) = self.held.lock() {
            let through = self.swept_by_all(now);
            for held in all.iter_mut() {
                expire(held, through);
            }
        }
    }

    /// The entries `who` holds now.
    #[cfg(test)]
    pub(crate) fn held_by(&self, who: Deliverer) -> usize {
        self.held.lock().ok().map_or(0, |all| {
            all[who.class().index()]
                .places
                .get(&who)
                .map_or(0, |place| place.entries)
        })
    }

    /// The entries and the holders of `class` now, together.
    #[cfg(test)]
    pub(crate) fn held_of(&self, class: Class) -> (usize, usize) {
        self.held.lock().ok().map_or((0, 0), |all| {
            let held = &all[class.index()];
            (held.entries, held.holders)
        })
    }

    /// What the shares are charged now.
    #[cfg(test)]
    pub(crate) fn charged(&self) -> usize {
        self.held
            .lock()
            .ok()
            .map_or(0, |all| all.iter().map(|held| held.charge.bytes()).sum())
    }

    /// What the shares allocate now, reckoned afresh from the places themselves: what they must be
    /// charged.
    #[cfg(test)]
    pub(crate) fn counted(&self) -> usize {
        self.held.lock().ok().map_or(0, |all| {
            all.iter()
                .map(|held| {
                    held.table.bytes::<Deliverer, Place>()
                        + held.places.values().map(Place::bytes).sum::<usize>()
                })
                .sum()
        })
    }

    /// The places held now.
    #[cfg(test)]
    pub(crate) fn places(&self) -> usize {
        self.held
            .lock()
            .ok()
            .map_or(0, |all| all.iter().map(|held| held.places.len()).sum())
    }
}

/// The places' table shrunk once it is past four times the places and [`PLACES_KEPT`] (charged at
/// its peak, `reallocated`: kept as it is when its store has no room for the copy), and the charge
/// brought down to what the shares allocate now: the table and the counts.
fn settle(held: &mut Held) {
    let len = held.places.len();
    if crate::footprint::capacity_of(held.table.buckets()) > (4 * len).max(PLACES_KEPT) {
        let to = (2 * len).max(PLACES_KEPT);
        let Held {
            places,
            table,
            charge,
            ..
        } = &mut *held;
        let copy = table.shrinking::<Deliverer, Place>(len, to);
        // The old table is freed only if a new one is made.
        let old_table = if copy > 0 {
            table.bytes::<Deliverer, Place>()
        } else {
            0
        };
        if reallocated(charge, copy, || {
            places.shrink_to(to);
            old_table
        }) {
            table.shrunk::<Deliverer, Place>(len, to);
        }
    }
    charged_down(held);
}

/// The charge brought down to what the shares allocate now: the places' table and their counts.
fn charged_down(held: &mut Held) {
    held.charge
        .shrink_to(held.table.bytes::<Deliverer, Place>() + held.counts);
}

/// Runs `resize`, which moves an allocation into a new one of `new_bytes` and answers the bytes
/// of the old one it freed, charged at its peak (RFC-0181, "Memory is charged once"): while one
/// is copied into the other both are live, so `new_bytes` is charged on top of what `charge`
/// holds (the old allocation among it) before it runs, and what it freed is given back the moment
/// it returns. False, and nothing resized, when the store has no room for it. Every allocation of
/// the shares' places that grows or shrinks goes through it, so none is charged at less than its
/// peak, and none past it: a pass that resizes many (`expire`) holds one copy's room at a time.
/// Before, a list of counts that grew was charged only what it added, and a shrink nothing; then
/// each shrink was charged its new list and its old one given back only once the whole pass was
/// over, so the pass held every copy's room at once and a take beside it found its store full.
fn reallocated(charge: &mut Charge, new_bytes: usize, resize: impl FnOnce() -> usize) -> bool {
    if !charge.try_grow(new_bytes) {
        return false;
    }
    let freed = resize();
    charge.shrink_to(charge.bytes().saturating_sub(freed));
    true
}

/// A clock this far behind the second the shares last let go through is a clock stepped back,
/// from which they let go as it passes (`expire`); less is the stamps of records taken in a
/// different order than they were stamped, which lets nothing go.
const STEPPED_BACK_SECONDS: u32 = 2;

/// Every entry of `held` whose second a table has passed at `now_ms` (its bucket's end before
/// `now_ms`, as `Strikes::sweep` drops it) let go, and each deliverer's place given back once it
/// holds none. Once a second, whatever it is asked: a pass over the places holding entries. An
/// entry is let go once, since its count is taken off as it goes; after a clock stepped back
/// ([`STEPPED_BACK_SECONDS`]) the seconds are let go from the new clock, so what is taken after
/// the step goes as that clock passes it. Before, the seconds only moved forward, and after a
/// step back nothing taken was let go until the clock passed where it had been.
fn expire(held: &mut Held, now_ms: u64) {
    // A second `s` has passed once `s * 1000 < now_ms`.
    let through = u32::try_from(now_ms.div_ceil(1000)).unwrap_or(u32::MAX);
    if through.saturating_add(STEPPED_BACK_SECONDS) < held.expired {
        held.expired = through;
        return;
    }
    if through <= held.expired {
        return;
    }
    held.expired = through;
    let (mut holders, mut entries, mut freed, mut units) = (0usize, 0usize, 0usize, 0usize);
    let Held { places, charge, .. } = &mut *held;
    places.retain(|who, place| {
        if place.expiring.front().is_none_or(|(s, _)| *s >= through) {
            return true;
        }
        let before = place.bytes();
        let mut gone = 0;
        while place.expiring.front().is_some_and(|(s, _)| *s < through) {
            if let Some((_, count)) = place.expiring.pop_front() {
                gone += count as usize;
            }
        }
        let gone = gone.min(place.entries);
        place.entries -= gone;
        entries += gone;
        if place.entries == 0 {
            holders += 1;
            units += place_entries(*who);
            freed += before;
            return false;
        }
        // Kept at least half full, so a count costs at most what it is planned at: shrunk when
        // its store has room for the copy (`reallocated`).
        if place.expiring.len() * 2 < place.expiring.capacity() {
            let to = place.expiring.len().max(2);
            let expiring = &mut place.expiring;
            let _ = reallocated(charge, crate::footprint::vec::<(u32, u32)>(to), || {
                let old = crate::footprint::vec::<(u32, u32)>(expiring.capacity());
                expiring.shrink_to(to);
                old
            });
        }
        freed += before - place.bytes();
        true
    });
    held.holders -= holders.min(held.holders);
    held.entries -= entries.min(held.entries);
    held.place_units -= units.min(held.place_units);
    held.counts -= freed;
    settle(held);
}

/// Where a table keeps what a restart must know (`durable`).
enum Kept {
    /// Nothing: a hub with no state (`Durable::Off`, `Durable::Fresh`).
    Nothing,
    /// A lease of signed time, shared with the tables of its kind (`durable::Lease`).
    Lease(Arc<Lease>),
    /// Its fingerprints themselves, in a checkpoint and a log (a table of few records,
    /// `durable::Log`): the log once the table has begun, its directory and name until then.
    Log(Arc<StateDir>, String, Option<Log>),
}

/// What a table waits for the clock to settle before it judges anything (`Strikes::begin`): the
/// fallback floor, computed only from a synced clock, or a check of the bound it started from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Pending {
    /// No state it may trust: the fallback floor, from the clock once synced.
    Fallback,
    /// Its lease's bound when it is trusted (`durable::Lease::begin`): the bound covers every
    /// record the run before used, so it is the floor even below the fallback; the higher of the
    /// bound and the fallback floor when the bound is past `S + L` ahead of the synced clock; the
    /// fallback floor when the bound is not there or not trusted.
    Leased,
    /// A stop's dump read back beside its lease (`resume`): the dump's floor, never below what the
    /// lease proves (the bound of a lease another run wrote), and the bound when it is past
    /// `S + L` ahead of the synced clock.
    Resumed,
    /// A checkpoint and log it read back: its floor is theirs.
    Restored,
}

/// One class's generations in a table ([`Class`]): a generation of fingerprints for each bucket of
/// time its records expire in, bucket `b` at `b % len`, made at the class's first entry, and
/// charged to its class's store, so one class's sets, however they grow, never take room from
/// another's.
struct Ring {
    generations: Vec<Generation>,
    /// What the generations' sets allocate.
    set_bytes: usize,
    charge: Charge,
}

impl Ring {
    fn new(gauge: &Arc<Gauge>) -> Self {
        Self {
            generations: Vec::new(),
            set_bytes: 0,
            charge: gauge.empty(),
        }
    }

    /// What it allocates now.
    fn bytes(&self) -> usize {
        self.generations.capacity() * std::mem::size_of::<Generation>() + self.set_bytes
    }

    /// The fingerprints it holds.
    fn len(&self) -> usize {
        self.generations
            .iter()
            .map(|generation| generation.len)
            .sum()
    }

    /// Whether `fp` expiring in bucket `expires` is held.
    fn contains(&self, expires: u64, fp: u64) -> bool {
        let ring = self.generations.len() as u64;
        ring > 0 && {
            let generation = &self.generations[(expires % ring) as usize];
            generation.bucket == expires && generation.contains(fp)
        }
    }

    /// Whether `fp` is held in any generation.
    fn contains_any(&self, fp: u64) -> bool {
        self.generations
            .iter()
            .any(|generation| generation.len > 0 && generation.contains(fp))
    }

    /// Room for one more fingerprint expiring in bucket `expires` in a ring of `ring`
    /// generations, charged before it is allocated: the ring made, and its generation's set grown
    /// as it would grow, the old slots and the new both charged while both are held. A slot
    /// holding another bucket's records (which only a clock stepped back leaves: every bucket live
    /// at one clock fits the ring) collides: never overwritten unforgotten.
    fn make_room(&mut self, ring: usize, expires: u64) -> Room {
        let at = (expires % ring as u64) as usize;
        if self
            .generations
            .get(at)
            .is_some_and(|generation| generation.bucket != expires && generation.len > 0)
        {
            return Room::Collides;
        }
        let (held, wanted) = match self.generations.get(at) {
            Some(generation) => (
                generation.bytes(),
                generation.slots_for(generation.len + 1) * std::mem::size_of::<u64>(),
            ),
            None => (
                0,
                Generation::default().slots_for(1) * std::mem::size_of::<u64>(),
            ),
        };
        let ring_bytes = ring * std::mem::size_of::<Generation>();
        // At its peak, while a set grows, both its old slots and its new are held.
        let grows = wanted > held;
        let peak = ring_bytes + self.set_bytes + if grows { wanted } else { 0 };
        if !self
            .charge
            .try_grow(peak.saturating_sub(self.charge.bytes()))
        {
            return Room::Full;
        }
        if self.generations.is_empty() {
            self.generations.reserve_exact(ring);
            self.generations.resize_with(ring, Generation::default);
        }
        Room::At(at)
    }

    /// `fp` of a record signed at `signed_ms` held in slot `at` for bucket `expires`, its room
    /// made (`make_room`), the charge brought down to what it allocates.
    fn insert(&mut self, at: usize, expires: u64, fp: u64, signed_ms: u64) {
        let generation = &mut self.generations[at];
        if generation.bucket != expires {
            // Its last bucket was dropped (`sweep`), or it never held one.
            debug_assert!(generation.len == 0);
            generation.bucket = expires;
        }
        let before = generation.bytes();
        generation.insert(fp, signed_ms);
        self.set_bytes = self.set_bytes - before + self.generations[at].bytes();
        self.charge.shrink_to(self.bytes());
    }

    /// The generation in slot `at`, if it holds bucket `bucket`, dropped whole: the newest signed
    /// time it held.
    fn drop_bucket(&mut self, at: usize, bucket: u64) -> Option<u64> {
        let generation = self.generations.get_mut(at)?;
        if generation.bucket != bucket {
            return None;
        }
        let newest = generation.newest_ms;
        self.set_bytes -= generation.bytes();
        generation.drop_all();
        self.charge.shrink_to(self.bytes());
        Some(newest)
    }

    /// Every generation of a bucket from `from` to before `through` dropped whole: the newest
    /// signed time any of them held.
    fn sweep(&mut self, from: u64, through: u64) -> Option<u64> {
        let ring = self.generations.len() as u64;
        if ring == 0 {
            return None;
        }
        let mut newest: Option<u64> = None;
        for passed in from..through {
            let generation = &mut self.generations[(passed % ring) as usize];
            if generation.bucket >= through || generation.slots.capacity() == 0 {
                continue;
            }
            newest = Some(newest.unwrap_or(0).max(generation.newest_ms));
            self.set_bytes -= generation.bytes();
            generation.drop_all();
        }
        self.charge.shrink_to(self.bytes());
        newest
    }
}

/// One table of what was taken (see the module): for each class of deliverer its own ring of
/// generations ([`Ring`], charged to its class's store, [`StrikeStores`]), each record's
/// fingerprint in the generation of its own `t + R` in the ring of the class that delivered it,
/// and the floor: the newest signed time it may have forgotten, one for the table, whatever class
/// forgot it. A record is held once its fingerprint is in any class's ring, so a copy one class
/// took is a duplicate from every other.
pub struct Strikes {
    usable: Usable,
    /// Each class's generations, by [`Class::index`].
    rings: [Ring; 3],
    /// The bucket the last sweep dropped everything before: a later sweep drops what passed since.
    /// Set back with a clock stepped back, so what is taken after the step is dropped as that
    /// clock passes it (`sweep`).
    swept: u64,
    /// `swept` in milliseconds, told to its shares (`Shares::expire` lets nothing go past what
    /// any table has swept).
    swept_ms: Arc<AtomicU64>,
    /// No record signed at or before it is new: the newest signed time of any generation it
    /// dropped, or what a restart started it at (`durable`); none while it has forgotten nothing.
    /// Only moves forward.
    floor_ms: Option<u64>,
    shares: Arc<Shares>,
    kept: Kept,
    /// What it waits for before it judges anything; none once begun, or for a table that keeps
    /// nothing and assumes nothing (`Durable::Off`).
    pending: Option<Pending>,
    /// Looks in every generation (`contains_hash`) since it was made: what a test counts.
    #[cfg(test)]
    scans: std::sync::atomic::AtomicU64,
}

/// Where a table starts (`Strikes::starting`), from what the relay kept (`durable`).
#[derive(Clone, Debug)]
pub enum Start {
    /// With no floor (nothing forgotten), keeping nothing: `Durable::Off`.
    Empty,
    /// At the fallback floor once the clock is synced, keeping nothing: `Durable::Fresh`.
    Fallback,
    /// At a floor, keeping nothing: a test's.
    At(u64),
    /// Keeping a lease of signed time ahead of use, at the bound it held when that is trusted,
    /// else at the fallback floor; either once the clock is synced (`durable::Lease::begin`).
    Leased(Arc<Lease>),
}

impl Start {
    /// Where a table of the lease named `name` starts, its relay keeping `durable`: with no floor
    /// keeping nothing; at the fallback floor with no state ([`tally_wire::budget::FALLBACK_FLOOR`], from the
    /// clock once it is synced); with a state directory, at the bound its lease last held when the
    /// lease is trusted, else at the fallback floor, keeping it from now.
    pub fn of(durable: &Durable, name: &str) -> Self {
        match durable {
            Durable::Off => Self::Empty,
            Durable::Fresh => Self::Fallback,
            Durable::Dir(dir) => Self::Leased(dir.lease(name).0),
        }
    }
}

/// What a table's [`Strikes::begin`] found: its start's bound trusted, or refused for being past
/// what a synced clock allows.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Begun {
    /// Nothing to begin: begun before, or a table that assumes nothing.
    Already,
    /// At the bound it started from, or the fallback floor.
    Begun,
    /// Its lease's bound was past `S` ahead of the synced clock (a run whose clock ran ahead,
    /// unsynced, left it): the floor all the same, so nothing it used is used again, and nothing
    /// new is used until the clock passes it.
    LeaseAhead { held_ms: u64, now_ms: u64 },
}

/// What a table restored from a dump or its own file says of itself (`Strikes::restore`).
#[derive(Debug, PartialEq, Eq)]
pub enum Restored {
    /// Everything it held, held again.
    Whole,
    /// Some generations had no room and were dropped, the floor raised past them.
    Partly,
}

impl Strikes {
    /// An empty table judging by `usable`, each class's ring charged to its store in `stores`,
    /// its entries to `shares`, with no floor and nothing kept across a restart.
    pub fn new(usable: Usable, stores: &StrikeStores, shares: Arc<Shares>) -> Self {
        Self {
            usable,
            rings: Class::ALL.map(|class| Ring::new(stores.gauge(class))),
            swept: 0,
            swept_ms: shares.register(),
            floor_ms: None,
            shares,
            kept: Kept::Nothing,
            pending: None,
            #[cfg(test)]
            scans: std::sync::atomic::AtomicU64::new(0),
        }
    }

    /// As `new`, starting as `start` says (`Start::of`).
    pub fn starting(
        usable: Usable,
        stores: &StrikeStores,
        shares: Arc<Shares>,
        start: &Start,
    ) -> Self {
        let mut table = Self::new(usable, stores, shares);
        match start {
            Start::Empty => {}
            Start::Fallback => table.pending = Some(Pending::Fallback),
            Start::At(floor_ms) => table.floor_ms = Some(*floor_ms),
            Start::Leased(lease) => {
                table.kept = Kept::Lease(Arc::clone(lease));
                table.pending = Some(Pending::Leased);
            }
        }
        table
    }

    /// As `new`, a table of few records that keeps its fingerprints themselves in `dir` as
    /// `name` (its checkpoint and log, `durable::Log`), read back now: a restart forgets none of
    /// them, and so starts with no floor of signed time to suppress records signed long before
    /// they are sent. One whose checkpoint is missing or not trusted starts at the fallback floor
    /// once the clock is synced, as any table with no state does; either way it judges nothing
    /// until then (`begin`), and writes its first checkpoint as it begins.
    pub fn persisted(
        usable: Usable,
        stores: &StrikeStores,
        shares: Arc<Shares>,
        dir: &Arc<StateDir>,
        name: &str,
    ) -> Self {
        let mut table = Self::new(usable, stores, shares);
        let layout = table.layout(name);
        table.pending = Some(match dir.open_table(name, &layout) {
            Prior::Valid(state) => match table.restore(&state.dump) {
                Ok(_) => {
                    let mut whole = true;
                    for (class, signed_ms, fp) in state.records {
                        match Class::of_byte(class) {
                            Some(class) => table.hold(class, fp, signed_ms),
                            None => whole = false,
                        }
                    }
                    if whole {
                        Pending::Restored
                    } else {
                        eprintln!(
                            "tally-relay: {name}: a logged record of no class: the table starts at the fallback floor"
                        );
                        table.drop_everything();
                        Pending::Fallback
                    }
                }
                Err(_) => Pending::Fallback,
            },
            Prior::Missing => Pending::Fallback,
            Prior::Refused(why) => {
                eprintln!("tally-relay: {why}: the table starts at the fallback floor");
                Pending::Fallback
            }
        });
        table.kept = Kept::Log(Arc::clone(dir), name.to_owned(), None);
        table
    }

    /// A fingerprint `class` took, read back from a log, held again, charged to its class's store
    /// and to its class's share as a restored holder ([`Deliverer::Restored`]); one with no room in
    /// either raises the floor past it instead, as a restore does.
    fn hold(&mut self, class: Class, fp: u64, signed_ms: u64) {
        let expires = self.expires(signed_ms);
        let expires_ms = expires.saturating_mul(self.usable.bucket_ms);
        let restored = Deliverer::Restored(class);
        if !self.shares.take(restored, expires_ms) {
            self.raise_floor(signed_ms);
            return;
        }
        let ring = self.ring();
        let held = &mut self.rings[class.index()];
        match held.make_room(ring, expires) {
            Room::At(at) => held.insert(at, expires, fp.max(1), signed_ms),
            Room::Collides | Room::Full => {
                self.shares.untake(restored, expires_ms);
                self.raise_floor(signed_ms);
            }
        }
    }

    /// Everything held dropped, as a table refused starts: nothing it read back is trusted.
    fn drop_everything(&mut self) {
        for ring in &mut self.rings {
            for generation in &mut ring.generations {
                generation.drop_all();
            }
            ring.set_bytes = 0;
            let made = ring.bytes();
            ring.charge.shrink_to(made);
        }
        self.floor_ms = None;
    }

    /// Whether it waits for the clock to be synced before it judges anything.
    pub fn is_pending(&self) -> bool {
        self.pending.is_some()
    }

    /// The table begun by a synced clock reading `now_ms` (RFC-0171 §3.6: nothing is derived from
    /// the clock before it is synced): with no state it may trust, at the fallback floor
    /// `now_ms + tally_wire::budget::FALLBACK_FLOOR`; else at its lease's bound, which covers every record the run
    /// before used (`durable::Lease::begin`), even below the fallback floor. A bound past `S + L`
    /// ahead of `now_ms` is named (the caller says so loudly) and the floor is the higher of it and
    /// the fallback: nothing new is used until the clock passes it. A table of few records then writes its first
    /// checkpoint; one that cannot takes nothing until it can.
    pub fn begin(&mut self, now: Judged) -> Begun {
        let now_ms = now.ms();
        let Some(pending) = self.pending.take() else {
            return Begun::Already;
        };
        let fallback = tally_wire::budget::FALLBACK_FLOOR.after(now).ms();
        let mut begun = Begun::Begun;
        match pending {
            Pending::Fallback => self.raise_floor(fallback),
            Pending::Leased | Pending::Resumed => {
                if let Kept::Lease(lease) = &self.kept {
                    let start = lease.begin(now, fallback);
                    if pending == Pending::Leased || start.ahead.is_some() {
                        self.raise_floor(start.floor_ms);
                    }
                    if let Some(held_ms) = start.ahead {
                        begun = Begun::LeaseAhead { held_ms, now_ms };
                    }
                } else {
                    self.raise_floor(fallback);
                }
            }
            Pending::Restored => {}
        }
        let layout = match &self.kept {
            Kept::Log(_, name, _) => self.layout(name),
            Kept::Nothing | Kept::Lease(_) => String::new(),
        };
        if let Kept::Log(dir, name, log) = &mut self.kept {
            let mut dump = Vec::new();
            dump_into(self.floor_ms, &self.rings, &mut dump);
            *log = dir.begin_table(name, &layout, &dump).ok();
        }
        begun
    }

    fn raise_floor(&mut self, floor_ms: u64) {
        self.floor_ms = Some(self.floor_ms.unwrap_or(0).max(floor_ms));
    }

    /// How often it has looked for a hash in every generation (`contains_hash`).
    #[cfg(test)]
    pub fn scans(&self) -> u64 {
        self.scans.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// The newest signed time it may have forgotten: no record signed at or before it is new.
    pub fn floor_ms(&self) -> Option<u64> {
        self.floor_ms
    }

    /// What one class's ring in a table judging by `usable` allocates whatever it holds, once
    /// the class holds anything there: its ring of generations. What each class's store holds
    /// for each table it may take in before any feeder (`budget::Plan::strike_tables_bytes`).
    pub const fn fixed_bytes(usable: Usable) -> usize {
        (usable.life_buckets() as usize + 1) * std::mem::size_of::<Generation>()
    }

    fn ring(&self) -> usize {
        usize::try_from(self.usable.life_buckets() + 1).unwrap_or(usize::MAX)
    }

    /// The fingerprints remembered.
    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.held_len()
    }

    #[cfg(test)]
    pub(crate) fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The bucket a record signed at `signed_ms` expires in.
    fn expires(&self, signed_ms: u64) -> u64 {
        signed_ms
            .saturating_add(self.usable.retained_ms())
            .div_ceil(self.usable.bucket_ms)
    }

    fn fingerprint(&self, hash: &Hash) -> u64 {
        fingerprint(&self.shares.key, hash)
    }

    /// Whether a record signed at `signed_ms` with `hash` was taken and is remembered still.
    pub fn contains(&self, hash: &Hash, signed_ms: u64) -> bool {
        let expires = self.expires(signed_ms);
        let fp = self.fingerprint(hash);
        self.rings.iter().any(|ring| ring.contains(expires, fp))
    }

    /// Whether a record with `hash` was taken and is remembered still, whatever its signed time:
    /// what a reader that names it by its hash alone asks (positions citing a clock model by its
    /// id, once each as they come, `Hub::forward_positions`). It looks in every generation, so it
    /// is asked once a record that needs it, never again while that record waits.
    pub fn contains_hash(&self, hash: &Hash) -> bool {
        #[cfg(test)]
        self.scans
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let fp = self.fingerprint(hash);
        self.rings.iter().any(|ring| ring.contains_any(fp))
    }

    /// What a record signed at `signed_ms` with `hash`, delivered by `who`, is at `now`,
    /// remembering nothing: usable by its window for `who`, above the floor, and not held. While
    /// the clock is not judging (not synced since the start, `begin`, or its error past `E` since:
    /// `now.judging`), nothing is judged: [`Verdict::Unjudged`], possessed and credited, never
    /// used.
    pub fn judge(&mut self, hash: &Hash, signed_ms: u64, now: Now, who: Deliverer) -> Verdict {
        if self.pending.is_some() || !now.judges() {
            return Verdict::Unjudged;
        }
        self.sweep(now.judged());
        // A copy of one taken is a duplicate first, however old: a feeder's resend of a batch
        // this relay used is no batch too old to use, and never counted against its receiver.
        if self.contains(hash, signed_ms) {
            Verdict::Duplicate
        } else if self.floor_ms.is_some_and(|floor| signed_ms <= floor)
            || !self.usable.window_for(who).holds(signed_ms, now.judged())
        {
            Verdict::Late
        } else {
            Verdict::New
        }
    }

    /// As `judge`, for a feeder's batch: [`Verdict::Ahead`] where it is signed further ahead of
    /// `now` than `who`'s window allows, which `judge` calls late.
    pub fn judge_batch(
        &mut self,
        hash: &Hash,
        signed_ms: u64,
        now: Now,
        who: Deliverer,
    ) -> Verdict {
        match self.judge(hash, signed_ms, now, who) {
            Verdict::Late if self.usable.window_for(who).ahead(signed_ms, now.judged()) => {
                Verdict::Ahead
            }
            verdict => verdict,
        }
    }

    /// As `take`, for a feeder's batch, judged as `judge_batch` judges it.
    pub fn take_batch(&mut self, hash: &Hash, signed_ms: u64, now: Now, who: Deliverer) -> Verdict {
        match self.judge_batch(hash, signed_ms, now, who) {
            Verdict::New => self.take(hash, signed_ms, now, who),
            verdict => verdict,
        }
    }

    /// As `judge`, and a new record remembered until its `signed_ms + R`, charged to `who`'s
    /// share, a restart told first (`durable`); one that has no room, or that a restart could
    /// not be told of, is [`Verdict::Full`] and remembered nothing.
    pub fn take(&mut self, hash: &Hash, signed_ms: u64, now: Now, who: Deliverer) -> Verdict {
        let verdict = self.judge(hash, signed_ms, now, who);
        if verdict != Verdict::New {
            return verdict;
        }
        // Its deliverer's share first: a share refused (a stopping relay's, `Shares::close`, among
        // them) moves nothing a restart reads, so nothing is used after a stop's dump.
        let expires = self.expires(signed_ms);
        let expires_ms = expires.saturating_mul(self.usable.bucket_ms);
        if !self.shares.take(who, expires_ms) {
            return Verdict::Full;
        }
        let class = who.class();
        let ring = self.ring();
        let at = match self.rings[class.index()].make_room(ring, expires) {
            Room::At(at) => at,
            // Its slot holds a newer bucket's records still owed (only after a clock stepped
            // back): never overwritten, and this record not remembered, so not used. The slot
            // frees as the clock passes that bucket again.
            Room::Collides => {
                self.shares.untake(who, expires_ms);
                return Verdict::Late;
            }
            Room::Full => {
                self.shares.untake(who, expires_ms);
                return Verdict::Full;
            }
        };
        let fp = self.fingerprint(hash);
        // A restart told before the record is used: its lease made to cover it, or the record
        // appended to its log. One that cannot be is let go, remembered nothing.
        let told = match &self.kept {
            Kept::Nothing => Ok(()),
            Kept::Lease(lease) => lease.cover(signed_ms),
            Kept::Log(..) => self.logged(class, signed_ms, fp),
        };
        let held = &mut self.rings[class.index()];
        if told.is_err() {
            self.shares.untake(who, expires_ms);
            let made = held.bytes();
            held.charge.shrink_to(made);
            return Verdict::Full;
        }
        held.insert(at, expires, fp, signed_ms);
        if let Kept::Log(_, _, Some(log)) = &self.kept
            && log.records() > crate::durable::LOG_COMPACT_RECORDS.max(2 * self.held_len() as u64)
        {
            // Folded once the log outgrows the table: a fold that fails leaves the log as it was
            // (or stale, folded again before the next record).
            let mut dump = Vec::new();
            dump_into(self.floor_ms, &self.rings, &mut dump);
            if let Kept::Log(_, _, Some(log)) = &mut self.kept {
                let _ = log.fold(&dump);
            }
        }
        Verdict::New
    }

    /// A record of a table of few records appended to its log before it is used: the log folded
    /// first when it is stale. An error means it must not be used.
    fn logged(&mut self, class: Class, signed_ms: u64, fp: u64) -> std::io::Result<()> {
        let stale = matches!(&self.kept, Kept::Log(_, _, Some(log)) if log.is_stale());
        if stale {
            let mut dump = Vec::new();
            dump_into(self.floor_ms, &self.rings, &mut dump);
            if let Kept::Log(_, _, Some(log)) = &mut self.kept {
                log.fold(&dump)?;
            }
        }
        let layout = match &self.kept {
            Kept::Log(_, name, _) => self.layout(name),
            Kept::Nothing | Kept::Lease(_) => String::new(),
        };
        match &mut self.kept {
            Kept::Log(dir, name, log) => {
                if log.is_none() {
                    let mut dump = Vec::new();
                    dump_into(self.floor_ms, &self.rings, &mut dump);
                    *log = Some(dir.begin_table(name, &layout, &dump)?);
                }
                match log {
                    Some(log) => log.append(class as u8, signed_ms, fp),
                    None => Err(std::io::Error::other("no log")),
                }
            }
            Kept::Nothing | Kept::Lease(_) => Ok(()),
        }
    }

    /// The records its log holds since its checkpoint: a test's.
    #[cfg(test)]
    pub(crate) fn logged_records(&self) -> u64 {
        match &self.kept {
            Kept::Log(_, _, Some(log)) => log.records(),
            _ => 0,
        }
    }

    /// The fingerprints it holds.
    fn held_len(&self) -> usize {
        self.rings.iter().map(Ring::len).sum()
    }

    /// Drops every generation the clock `now_ms` has passed, whole, raising the floor to the
    /// newest signed time each held. Its deliverers' entries leave the shares once every table is
    /// swept ([`Shares::expire`], `Hub::sweep_strikes`). A clock that went back
    /// drops nothing, and what is taken after it is dropped as that clock passes it; one that went
    /// forward drops what it passed, and the floor rises only to what was really taken. The
    /// relay's tick sweeps every table (`Hub::sweep_strikes`), so an idle one gives its entries
    /// back as they pass.
    pub fn sweep(&mut self, now: Judged) {
        let now_ms = now.ms();
        // Nothing swept by a clock not yet synced since the start (`begin`).
        if self.pending.is_some() {
            return;
        }
        // Every bucket `b` with `b * bucket_ms < now_ms` is past: a record expiring in it was
        // signed more than `R` before now, and its window refuses its copies itself.
        let through = now_ms.div_ceil(self.usable.bucket_ms);
        if through <= self.swept {
            // Back: everything before `through` was dropped already, and what comes after the
            // step is dropped from here as the clock passes it. Told before anything is taken by
            // this clock, so the shares keep what it takes until this table drops it.
            self.swept = through;
            self.swept_ms.store(
                through.saturating_mul(self.usable.bucket_ms),
                Ordering::SeqCst,
            );
            return;
        }
        // The slots of the buckets since the last sweep: every slot, once the clock has moved a
        // whole ring or more (an idle table, a clock stepped forward), whatever bucket each
        // holds. A slot holding a bucket at or past `through` holds entries still owed.
        let ring = self.ring() as u64;
        let from = if through - self.swept >= ring {
            through - ring
        } else {
            self.swept
        };
        for held in &mut self.rings {
            if let Some(newest) = held.sweep(from, through) {
                self.floor_ms = Some(self.floor_ms.unwrap_or(0).max(newest));
            }
        }
        self.swept = through;
        self.swept_ms.store(
            through.saturating_mul(self.usable.bucket_ms),
            Ordering::SeqCst,
        );
    }

    /// Its floor and every generation it holds, appended to `out`: what a stop's dump holds,
    /// under its shares' key. A table that has not begun (`begin`: its clock never synced) has no
    /// floor of its own to state (the one its lease proves was never taken up), so it writes
    /// nothing and says so: false, and the caller writes no dump.
    pub fn dump(&self, out: &mut Vec<u8>) -> bool {
        if self.pending.is_some() {
            return false;
        }
        dump_into(self.floor_ms, &self.rings, out);
        true
    }

    /// What a dump or a checkpoint of this table must name as its layout, so one of other
    /// windows is never read into it: `name`, how long it keeps a record, its bucket, its ring and
    /// the classes it keeps a ring for.
    pub fn layout(&self, name: &str) -> String {
        format!(
            "{name}: retained {} ms, bucket {} ms, ring {}, classes {}",
            self.usable.retained_ms(),
            self.usable.bucket_ms,
            self.ring(),
            Class::ALL.len()
        )
    }

    /// What `dump` wrote, held again: its floor, raised past any generation the store has no
    /// room for, and every generation that fits, each in the ring of the class that took it,
    /// charged to that class's store and to its class's share as one restored holder
    /// ([`Deliverer::Restored`]: nobody delivered them in this process, but a class's store holds
    /// only what its share allows, so they are counted in it as every entry is). Its shape is checked first, holding nothing (every generation's length within
    /// the bytes), then each fingerprint is held, and charged, as it is read: nothing the dump
    /// says is allocated before the store has taken it. The bytes it read, or why they are no
    /// dump.
    pub fn restore(&mut self, bytes: &[u8]) -> Result<(usize, Restored), String> {
        let word = |at: usize| -> Result<u64, String> {
            let chunk = at
                .checked_add(8)
                .and_then(|end| bytes.get(at..end))
                .ok_or("a dump cut short")?;
            let mut word = [0u8; 8];
            word.copy_from_slice(chunk);
            Ok(u64::from_le_bytes(word))
        };
        let floor = word(0)?;
        let mut at = 8usize;
        for _ in Class::ALL {
            let count = word(at)?;
            at += 8;
            for _ in 0..count {
                let len =
                    usize::try_from(word(at + 16)?).map_err(|_| "a generation past memory")?;
                at = len
                    .checked_mul(8)
                    .and_then(|fps| at.checked_add(24 + fps))
                    .filter(|end| *end <= bytes.len())
                    .ok_or("a dump cut short")?;
            }
        }
        let read = at;
        if let Some(floor) = floor.checked_sub(1) {
            self.raise_floor(floor);
        }
        let mut whole = Restored::Whole;
        let ring = self.ring();
        let mut at = 8usize;
        for class in Class::ALL {
            let count = word(at)?;
            at += 8;
            for _ in 0..count {
                let (bucket, newest) = (word(at)?, word(at + 8)?);
                let len =
                    usize::try_from(word(at + 16)?).map_err(|_| "a generation past memory")?;
                at += 24;
                let fps = at;
                at += len * 8;
                let slot = (bucket % ring as u64) as usize;
                let expires_ms = bucket.saturating_mul(self.usable.bucket_ms);
                let restored = Deliverer::Restored(class);
                let held = &mut self.rings[class.index()];
                let (mut fits, mut taken) = (true, 0);
                for index in 0..len {
                    let fp = word(fps + index * 8)?;
                    // Counted in its class's share as a restored holder's, then charged to its
                    // class's store: either full, the generation is dropped whole.
                    if !self.shares.take(restored, expires_ms) {
                        fits = false;
                        break;
                    }
                    taken += 1;
                    let Room::At(room) = held.make_room(ring, bucket) else {
                        fits = false;
                        break;
                    };
                    debug_assert_eq!(room, slot);
                    held.insert(room, bucket, fp.max(1), newest);
                }
                if !fits {
                    whole = Restored::Partly;
                    for _ in 0..taken {
                        self.shares.untake(restored, expires_ms);
                    }
                    held.drop_bucket(slot, bucket);
                    self.raise_floor(newest);
                }
            }
        }
        Ok((read, whole))
    }

    /// What a stop's `dump` wrote, read back into a table that has used nothing since (its
    /// lease's bound unchanged, `Hub::durable`): its floor is the dump's own, which may be below
    /// the lease's, since the dump holds every fingerprint above it; but never below `proven`, the
    /// floor its lease proves on its own (`Hub::restore_dump`: the bound of a lease the dump's run
    /// never wrote, so that run used nothing of it past the bound and started no lower). No file
    /// lowers a floor a lease proves. What it reads, or why it is no dump, the table's floor then
    /// as it was.
    pub fn resume(
        &mut self,
        bytes: &[u8],
        proven: Option<u64>,
    ) -> Result<(usize, Restored), String> {
        let floor = self.floor_ms;
        self.floor_ms = None;
        let resumed = self.restore(bytes);
        match &resumed {
            Ok(_) => {
                if let Some(proven) = proven {
                    self.raise_floor(proven);
                }
                if self.pending == Some(Pending::Leased) {
                    self.pending = Some(Pending::Resumed);
                }
            }
            Err(_) => self.floor_ms = floor,
        }
        resumed
    }

    /// Swept at `now_ms`, then its shares: as the relay's tick sweeps every table and then the
    /// shares (`Hub::sweep_strikes`), for a test whose table is the only one taking into them.
    #[cfg(test)]
    pub(crate) fn swept(&mut self, now: Judged) {
        self.sweep(now);
        self.shares.expire(now);
    }

    /// What it allocates now, every class's ring together.
    #[cfg(test)]
    pub(crate) fn bytes(&self) -> usize {
        self.rings.iter().map(Ring::bytes).sum()
    }

    /// What it is charged now, every class's ring together.
    #[cfg(test)]
    pub fn charged(&self) -> usize {
        self.rings.iter().map(|ring| ring.charge.bytes()).sum()
    }

    /// What `class`'s ring is charged now.
    #[cfg(test)]
    pub fn charged_of(&self, class: Class) -> usize {
        self.rings[class.index()].charge.bytes()
    }
}
#[cfg(test)]
mod tests {
    #![allow(clippy::disallowed_methods, reason = "a test's scripted readings")]
    use super::*;
    use crate::budget::Store;
    use crate::durable::tests::Scratch;
    use tally_wire::clocks::recorded::judged;

    const BASE_MS: u64 = 1_791_244_800_000;

    fn hash(n: u64) -> Hash {
        let mut hash = [0; 32];
        hash[..8].copy_from_slice(&n.to_be_bytes());
        hash[16..24].copy_from_slice(&n.to_le_bytes());
        hash
    }

    fn peer(n: u8) -> Deliverer {
        Deliverer::Peer(tally_wire::Identity::from_seed([n; 32]).public())
    }

    fn feeder(n: u64) -> Deliverer {
        let mut seed = [0u8; 32];
        seed[..8].copy_from_slice(&n.to_be_bytes());
        seed[31] = 0xfe;
        Deliverer::Feeder(tally_wire::Identity::from_seed(seed).public())
    }

    /// Shares of `feeder` entries a feeder, `feeders` the feeders together and `peer` a peer and
    /// the peers together, each kind's beside the places of two holders of it (charged among its
    /// entries, `Shares::take`), and the relay's as a peer's.
    fn entries(feeder: usize, feeders: usize, peer: usize) -> Entries {
        Entries {
            feeder,
            feeders: feeders.saturating_add(2 * FEEDER_PLACE_ENTRIES),
            peer,
            peers: peer.saturating_add(2 * PEER_PLACE_ENTRIES),
            relay: peer,
        }
    }

    /// A batches table on a store of `limit` bytes, its shares `entries` on a store of their own.
    fn table(limit: usize, entries: Entries) -> (Strikes, Arc<Gauge>, Arc<Shares>) {
        let gauge = Gauge::new(Store::PeerStrikes, limit);
        let shares = Shares::new(&StrikeStores::unlimited(), entries);
        (
            Strikes::new(
                Usable::BATCHES,
                &StrikeStores::sharing(&gauge),
                Arc::clone(&shares),
            ),
            gauge,
            shares,
        )
    }

    fn unbounded() -> Entries {
        entries(usize::MAX, usize::MAX, usize::MAX)
    }

    /// RFC-0171 §3.6: the windows and lives the RFC quotes, from the constants alone: a feeder's
    /// own copy 91 s behind and 10 s ahead, any other 76 s and 25 s, the relay-signed kinds 32 s
    /// and 15 s, fault proofs 122 s and 25 s; a batch's fingerprint held 91 s past its signed
    /// time, so an entry lives 117 s at most (a peer's copy 25 s ahead) and 102 s a feeder's; the
    /// relay's own records (the relay-signed kinds, held 32 s past their signed time) 33 s.
    #[test]
    fn the_windows_are_the_figures_the_rfc_quotes() {
        assert_eq!(Deadlines::RELAY.horizon_seconds(), 13);
        assert_eq!(
            (
                tally_wire::budget::K
                    .span::<tally_wire::clocks::Judged>()
                    .ms(),
                tally_wire::budget::F
                    .span::<tally_wire::clocks::Judged>()
                    .ms(),
                tally_wire::budget::B
                    .span::<tally_wire::clocks::Judged>()
                    .ms(),
                ENGINE_LAG_MS,
                tally_wire::budget::REPAIR_TRANSIT
                    .span::<tally_wire::clocks::Judged>()
                    .ms(),
                tally_wire::budget::FALLBACK_FLOOR
                    .span::<tally_wire::clocks::Judged>()
                    .ms(),
            ),
            (15_000, 10_000, 64_000, 1_000, 2_000, 40_000)
        );
        let window = |window: Window| {
            (
                window
                    .behind_span()
                    .span::<tally_wire::clocks::Judged>()
                    .ms(),
                window
                    .ahead_span()
                    .span::<tally_wire::clocks::Judged>()
                    .ms(),
            )
        };
        assert_eq!(window(Window::FEEDER), (91_000, 10_000));
        assert_eq!(window(Window::PEER), (76_000, 25_000));
        assert_eq!(window(relay_signed(Deadlines::RELAY)), (32_000, 15_000));
        assert_eq!(window(proofs(Deadlines::RELAY)), (122_000, 25_000));
        let batches = Usable::BATCHES;
        assert_eq!(batches.retained_ms(), 91_000);
        assert_eq!(
            (
                batches.life_seconds(),
                batches.feeder_life_seconds(),
                batches.own_life_seconds()
            ),
            (117, 102, 92)
        );
        assert_eq!(
            Usable::relay_signed(Deadlines::RELAY).own_life_seconds(),
            33
        );
        // A member asks for a relay-signed record until the horizon's seconds after the second
        // it was signed in; the answer's way and the clocks apart are inside its window.
        let deadlines = Deadlines::RELAY;
        let last_ask = (deadlines.horizon_seconds() + 1) * 1000
            + tally_wire::budget::REPAIR_TRANSIT
                .span::<tally_wire::clocks::Judged>()
                .ms();
        assert!(
            crate::strikes::relay_signed(deadlines)
                .behind_span()
                .duration()
                .as_millis() as u64
                >= ENGINE_LAG_MS
                    + last_ask
                    + tally_wire::budget::K
                        .span::<tally_wire::clocks::Judged>()
                        .ms()
        );
    }

    /// RFC-0171 §3.6: a batch too old where its feeder published it is too old at every relay,
    /// whatever its origin's version or honesty: the origin judges first, every later relay's
    /// clock is within `K` of the origin's, and `U_p + K == FEEDER_BEHIND`. So no mark need travel
    /// with a copy. Each case is an origin clock, a later relay's offset from it, and how much
    /// later that relay judges.
    #[test]
    fn too_old_at_the_origin_is_too_old_everywhere() {
        let signed = BASE_MS;
        let edge = tally_wire::budget::FEEDER_BEHIND
            .span::<tally_wire::clocks::Judged>()
            .ms();
        for origin_age in [edge + 1, edge + 500, edge + 6_000, 200_000] {
            let origin_now = signed + origin_age;
            assert!(!Window::FEEDER.holds(signed, judged(origin_now)));
            for offset in [-15_000i64, -7_000, 0, 7_000, 15_000] {
                for later in [0u64, 1, 1_000, 60_000] {
                    let relay_now = origin_now.saturating_add_signed(offset) + later;
                    assert!(
                        !Window::PEER.holds(signed, judged(relay_now)),
                        "{origin_age} {offset} {later}"
                    );
                }
            }
        }
        // And usable at the origin is usable at a relay within the skew when it arrives at once.
        let origin_now = signed
            + tally_wire::budget::PEER_BEHIND
                .span::<tally_wire::clocks::Judged>()
                .ms()
            - tally_wire::budget::K
                .span::<tally_wire::clocks::Judged>()
                .ms();
        assert!(Window::FEEDER.holds(signed, judged(origin_now)));
        assert!(Window::PEER.holds(signed, judged(origin_now + 15_000)));
    }

    /// RFC-0171 §3.6, the round-20 sweep's cases: an honest feeder is blamed neither for its
    /// reference's lag nor for its backlog. Its batch signed at the low end of a configured
    /// reference 14.4 s below true time, held its whole backlog for an anchor that never came and
    /// sent unanchored, reaches an origin 7 s ahead usable and unblamed; one signed by a clock an
    /// hour behind, carrying the origin's own anchor, is not blamed while that anchor's age since
    /// its issue is within an honest batch's (`OWN_ANCHOR_OLDEST`), and is past it; one carrying
    /// none of the origin's own anchors is never blamed, however old. Before, the first was too
    /// old (a 74 s window with no room for the lag), the second blamed (an allowance that
    /// subtracted the wrong term), and the third blamed by its signed time alone, though an honest
    /// reconnect's backlog anchored by another relay is such a batch.
    #[test]
    fn an_honest_feeder_is_blamed_neither_for_its_references_lag_nor_its_backlog() {
        use tally_wire::budget::{ANCHOR_AGE, B, OWN_ANCHOR_OLDEST, TRANSIT};
        let truth = BASE_MS;
        let signed = truth - 14_400;
        let origin = truth
            + B.span::<tally_wire::clocks::Judged>().ms()
            + 1
            + TRANSIT.span::<tally_wire::clocks::Judged>().ms()
            + 7_000;
        assert!(matches!(
            feeder_clock(signed, Now::new(judged(origin), true)),
            FeederClock::Usable
        ));
        let blamed = |signed: u64, own_age: Option<u64>, now: u64| {
            let too_old = matches!(
                feeder_clock(signed, Now::new(judged(now), true)),
                FeederClock::TooOld
            );
            let raw = tally_wire::clocks::recorded::raw;
            let own = own_age.map_or(OwnAnchor::Absent, |ms| {
                OwnAnchor::Aged(raw(ms).since(raw(0)))
            });
            blame(too_old, true, own).is_some()
        };
        assert!(!blamed(signed, None, origin));
        let behind = truth - 3_600_000;
        let now = truth + 70_000;
        assert!(!blamed(
            behind,
            Some(
                ANCHOR_AGE.span::<tally_wire::clocks::Judged>().ms()
                    + B.span::<tally_wire::clocks::Judged>().ms()
                    + TRANSIT.span::<tally_wire::clocks::Judged>().ms()
            ),
            now
        ));
        assert!(!blamed(
            behind,
            Some(OWN_ANCHOR_OLDEST.span::<tally_wire::clocks::Judged>().ms()),
            now
        ));
        assert!(blamed(
            behind,
            Some(OWN_ANCHOR_OLDEST.span::<tally_wire::clocks::Judged>().ms() + 1),
            now
        ));
        // None of this relay's anchors in it (another relay's alone, a relay with no signer):
        // never blamed, however old its signed time. An own anchor the ring has let go, or one of
        // an earlier run, is no such batch: it is aged from the newest issue let go, or this
        // run's first (`anchors::Anchors::issued_by`), and blamed by that age.
        assert!(!blamed(behind, None, now));
        // Usable by its signed time: never blamed, whatever its anchor's age.
        assert!(!blamed(now - 1_000, Some(u64::MAX), now));
        assert!(!blamed(now - 1_000, None, now));
        // Judged before (a resend, an audit's owed copy): never blamed again.
        let raw = tally_wire::clocks::recorded::raw;
        let aged = OwnAnchor::Aged(raw(u64::MAX).since(raw(0)));
        assert!(blame(true, true, aged).is_some());
        assert!(blame(true, false, aged).is_none());
    }

    /// A table begun by a synced clock judges nothing while the clock is not judging (its error
    /// past `E` after the start): a fresh record is unjudged, remembered nothing and charged to
    /// no one, and judged new once the clock judges again. Before, a table judged by whatever the
    /// clock read once it had begun.
    #[test]
    fn a_table_judges_nothing_while_its_clock_is_not_judging() {
        let now = BASE_MS;
        let (mut table, _gauge, _shares) = table(usize::MAX, unbounded());
        let unjudging = Now::new(judged(now), false);
        assert_eq!(
            table.judge(&hash(1), now, unjudging, peer(1)),
            Verdict::Unjudged
        );
        assert_eq!(
            table.take(&hash(1), now, unjudging, peer(1)),
            Verdict::Unjudged
        );
        assert_eq!(table.held_len(), 0);
        assert_eq!(
            table.take(&hash(1), now, Now::judging(now), peer(1)),
            Verdict::New
        );
        // Not even a duplicate is judged while the clock is not.
        assert_eq!(
            table.take(&hash(1), now, unjudging, peer(2)),
            Verdict::Unjudged
        );
    }

    /// The relay a feeder publishes to judges its clock for usability alone: within `F` ahead and
    /// `F + B` behind it is usable, further ahead it is held unjudged at this hop, older it is
    /// late, and while the relay's clock is not judging nothing is judged. No answer refuses
    /// anything. Before, a batch more than `F` ahead was refused and its feeder sent away.
    #[test]
    fn a_feeders_clock_decides_its_usability_and_nothing_else() {
        let now = BASE_MS;
        assert_eq!(
            feeder_clock(now, Now::new(judged(now), true)),
            FeederClock::Usable
        );
        assert_eq!(
            feeder_clock(
                now + tally_wire::budget::F
                    .span::<tally_wire::clocks::Judged>()
                    .ms(),
                Now::new(judged(now), true)
            ),
            FeederClock::Usable
        );
        assert_eq!(
            feeder_clock(
                now + tally_wire::budget::F
                    .span::<tally_wire::clocks::Judged>()
                    .ms()
                    + 1,
                Now::new(judged(now), true)
            ),
            FeederClock::Ahead
        );
        assert_eq!(
            feeder_clock(now + 3_600_000, Now::new(judged(now), true)),
            FeederClock::Ahead
        );
        assert_eq!(
            feeder_clock(u64::MAX, Now::new(judged(now), true)),
            FeederClock::Ahead
        );
        let behind = tally_wire::budget::FEEDER_BEHIND
            .span::<tally_wire::clocks::Judged>()
            .ms();
        assert_eq!(
            feeder_clock(now - behind, Now::new(judged(now), true)),
            FeederClock::Usable
        );
        assert_eq!(
            feeder_clock(now - behind - 1, Now::new(judged(now), true)),
            FeederClock::TooOld
        );
        assert_eq!(
            feeder_clock(0, Now::new(judged(now), true)),
            FeederClock::TooOld
        );
        // Not judging (unsynced, or its error past `E` since), it judges nothing: every batch is
        // possession only, blamed on no one, even one inside the window.
        for signed in [now + 3_600_000, now - 3_600_000, now] {
            assert_eq!(
                feeder_clock(signed, Now::new(judged(now), false)),
                FeederClock::Unjudged
            );
        }
    }

    /// A fingerprint taken is a duplicate for as long as a copy's window holds its record, and a
    /// copy is too late the millisecond after: never forgotten early and never new twice. Ahead,
    /// a copy signed `S` ahead is taken and one past it is late. A feeder's own copy is judged by
    /// its own window.
    #[test]
    fn a_hash_is_a_duplicate_until_its_record_leaves_the_window_and_late_after() {
        let (mut taken, _, _) = table(usize::MAX, unbounded());
        let window = Window::PEER;
        let signed = BASE_MS + 123;
        assert_eq!(
            taken.take(&hash(1), signed, Now::judging(signed), peer(1)),
            Verdict::New
        );
        let edge = signed
            + window
                .behind_span()
                .span::<tally_wire::clocks::Judged>()
                .ms();
        assert_eq!(
            taken.take(&hash(1), signed, Now::judging(edge), peer(1)),
            Verdict::Duplicate
        );
        assert!(taken.contains(&hash(1), signed));
        // Another record signed then is late the millisecond after the window.
        assert_eq!(
            taken.take(&hash(2), signed, Now::judging(edge + 1), peer(1)),
            Verdict::Late
        );
        // A copy of the one taken stays a duplicate while its fingerprint is held, past the
        // window too: a resend is no record too old. Before, it was counted late, and a feeder's
        // resend late against its receiver.
        let origin_edge = signed
            + Window::FEEDER
                .behind_span()
                .span::<tally_wire::clocks::Judged>()
                .ms();
        assert_eq!(
            taken.judge(&hash(1), signed, Now::judging(origin_edge), feeder(1)),
            Verdict::Duplicate
        );
        assert_eq!(
            taken.judge(&hash(1), signed, Now::judging(origin_edge + 1), feeder(1)),
            Verdict::Duplicate
        );
        assert_eq!(
            taken.judge(&hash(2), signed, Now::judging(origin_edge + 1), feeder(1)),
            Verdict::Late
        );
        // Once the bucket its fingerprint expires in has passed, a copy is late.
        let gone = (signed + Usable::BATCHES.retained_ms()).div_ceil(1000) * 1000 + 1000;
        assert_eq!(
            taken.judge(&hash(1), signed, Now::judging(gone), feeder(1)),
            Verdict::Late
        );
        let (mut early, _, _) = table(usize::MAX, unbounded());
        let ahead = signed
            + window
                .ahead_span()
                .span::<tally_wire::clocks::Judged>()
                .ms();
        assert_eq!(
            early.take(&hash(4), ahead, Now::judging(signed), peer(1)),
            Verdict::New
        );
        assert_eq!(
            early.take(&hash(5), ahead + 1, Now::judging(signed), peer(1)),
            Verdict::Late
        );
        assert_eq!(
            early.take(
                &hash(6),
                signed
                    + tally_wire::budget::F
                        .span::<tally_wire::clocks::Judged>()
                        .ms()
                    + 1,
                Now::judging(signed),
                feeder(1)
            ),
            Verdict::Late
        );
        // Remembered until its own expiry, however far ahead it was signed.
        assert_eq!(
            early.take(
                &hash(4),
                ahead,
                Now::judging(
                    ahead
                        + window
                            .behind_span()
                            .span::<tally_wire::clocks::Judged>()
                            .ms()
                ),
                peer(1)
            ),
            Verdict::Duplicate
        );
    }

    /// RFC 4120 §3.2.3: dropping a generation raises the floor to the newest signed time it held,
    /// and no record at or below the floor is new, whatever its window says. So a clock that steps
    /// forward past a record and back again never makes it new twice: before, the step forward
    /// dropped the record and the step back judged a copy new.
    #[test]
    fn a_clock_stepped_forward_and_back_makes_nothing_new_twice() {
        let (mut table, _, _) = table(usize::MAX, unbounded());
        let signed = BASE_MS;
        assert_eq!(
            table.take(&hash(1), signed, Now::judging(signed), peer(1)),
            Verdict::New
        );
        assert_eq!(table.floor_ms(), None);
        // A step forward of an hour: everything passed is dropped and the floor raised past it.
        table.sweep(judged(signed + 3_600_000));
        assert!(!table.contains(&hash(1), signed));
        assert_eq!(table.floor_ms(), Some(signed));
        // Back again: the copy is in its window, and at the floor, so late, never new, whether
        // asked or taken.
        assert_eq!(
            table.judge(&hash(1), signed, Now::judging(signed + 1_000), peer(2)),
            Verdict::Late
        );
        assert_eq!(
            table.take(&hash(1), signed, Now::judging(signed + 1_000), peer(2)),
            Verdict::Late
        );
        // A record signed after the floor is new.
        assert_eq!(
            table.take(&hash(2), signed + 1, Now::judging(signed + 1_000), peer(2)),
            Verdict::New
        );
        // The floor only moves forward.
        table.sweep(judged(signed));
        assert_eq!(table.floor_ms(), Some(signed));
    }

    /// A window bucketed coarser than a second (feeder figures', by the minute) still remembers
    /// each fingerprint to its record's edge of the window and never forgets it earlier, and is
    /// late just past it: figures signed an hour and a relay's window ago are refused.
    #[test]
    fn a_coarse_bucket_remembers_to_the_edge_of_the_window() {
        let usable = Usable::figures(crate::strikes::relay_signed(Deadlines::RELAY));
        let window = usable.copy;
        assert_eq!(
            window
                .behind_span()
                .span::<tally_wire::clocks::Judged>()
                .ms(),
            32_000 + 3_600_000
        );
        for (n, signed) in [(1, BASE_MS), (2, BASE_MS + 59_999), (3, BASE_MS + 1)] {
            let gauge = Gauge::new(Store::PeerStrikes, usize::MAX);
            let shares = Shares::new(&StrikeStores::unlimited(), entries(1, 1, 1 << 20));
            let mut table =
                Strikes::new(usable, &StrikeStores::sharing(&gauge), Arc::clone(&shares));
            let who = Deliverer::Relay;
            assert_eq!(
                table.take(&hash(n), signed, Now::judging(signed), who),
                Verdict::New
            );
            let edge = signed
                + window
                    .behind_span()
                    .span::<tally_wire::clocks::Judged>()
                    .ms();
            assert_eq!(
                table.judge(&hash(n), signed, Now::judging(edge), who),
                Verdict::Duplicate
            );
            assert_eq!(shares.held_by(who), 1);
            // Past the edge another record signed then is late; a copy of this one is a
            // duplicate while its fingerprint is held.
            assert_eq!(
                table.judge(&hash(9), signed, Now::judging(edge + 1), who),
                Verdict::Late
            );
            assert_eq!(
                table.judge(&hash(n), signed, Now::judging(edge + 1), who),
                Verdict::Duplicate
            );
            // Its deliverer's entry left with its generation, as the minute it expires in passes
            // (the table swept, then the shares, as the relay's tick does).
            let passes = edge.div_ceil(60_000) * 60_000;
            let _ = table.judge(&hash(n), signed, Now::judging(passes), who);
            shares.expire(judged(passes));
            assert_eq!(shares.held_by(who), 1);
            let _ = table.judge(&hash(n), signed, Now::judging(passes + 1), who);
            shares.expire(judged(passes + 1));
            assert_eq!(shares.held_by(who), 0);
            assert!(!table.contains(&hash(n), signed));
        }
        assert!(Strikes::fixed_bytes(usable) < 4_096);
    }

    /// A record judged and not kept is remembered nothing: a later copy is new.
    #[test]
    fn a_record_judged_and_not_kept_is_no_record_seen() {
        let (mut table, _, _) = table(usize::MAX, unbounded());
        assert_eq!(
            table.judge(&hash(1), BASE_MS, Now::judging(BASE_MS), peer(1)),
            Verdict::New
        );
        assert_eq!(
            table.take(&hash(1), BASE_MS, Now::judging(BASE_MS), peer(1)),
            Verdict::New
        );
    }

    /// A copy is looked for in the generation of its own signed time alone, so the same hash under
    /// another signed time is another record, and a record is found whichever second of its
    /// window it is judged in.
    #[test]
    fn a_copy_is_looked_for_in_the_generation_of_its_signed_time() {
        let (mut table, _, _) = table(usize::MAX, unbounded());
        for n in 0..2_000u64 {
            let signed = BASE_MS + (n % 50) * 1_000 + n;
            assert_eq!(
                table.take(&hash(n), signed, Now::judging(signed), peer(1)),
                Verdict::New
            );
        }
        let now = BASE_MS + 55_000;
        for n in 0..2_000u64 {
            let signed = BASE_MS + (n % 50) * 1_000 + n;
            assert_eq!(
                table.judge(&hash(n), signed, Now::judging(now), peer(2)),
                Verdict::Duplicate,
                "{n}"
            );
        }
        assert_eq!(table.len(), 2_000);
    }

    /// A flood from one deliverer fills its own share and no more: past it its records are let go
    /// (`Full`), and nothing the flood or anyone else had taken is forgotten to make room, so every
    /// copy of it stays a duplicate. The peers' share is theirs together: a flooding peer fills
    /// what the others leave of it, and another peer is still taken up to its fair part of it. A
    /// feeder's share is a feeder's and the relay's own the relay's. A share comes back as its
    /// entries expire.
    #[test]
    fn a_flood_fills_only_its_own_share_and_evicts_nothing() {
        let (mut table, _, shares) = table(usize::MAX, entries(8, 16, 16));
        let honest = peer(2);
        assert_eq!(
            table.take(&hash(0), BASE_MS, Now::judging(BASE_MS), honest),
            Verdict::New
        );
        let flood = peer(1);
        for n in 1..=15 {
            assert_eq!(
                table.take(&hash(n), BASE_MS, Now::judging(BASE_MS), flood),
                Verdict::New
            );
        }
        assert_eq!(
            table.take(&hash(16), BASE_MS, Now::judging(BASE_MS), flood),
            Verdict::Full
        );
        assert_eq!(shares.held_by(flood), 15);
        for n in 0..=15 {
            assert_eq!(
                table.judge(&hash(n), BASE_MS, Now::judging(BASE_MS), honest),
                Verdict::Duplicate,
                "{n} was forgotten to make room"
            );
        }
        // The honest peer is taken to its half of the share, the flood having filled the rest.
        for n in 20..27 {
            assert_eq!(
                table.take(&hash(n), BASE_MS, Now::judging(BASE_MS), honest),
                Verdict::New
            );
        }
        assert_eq!(
            table.take(&hash(27), BASE_MS, Now::judging(BASE_MS), honest),
            Verdict::Full
        );
        // A third peer's place is no part of a share planned for two (`entries`): its third of
        // it, rounded down, does not hold its place beside an entry, so it is let go. Before, a
        // place was charged to no share, and it was taken to its third.
        let third = peer(3);
        const _: () = assert!((16 + 2 * PEER_PLACE_ENTRIES) / 3 < 1 + PEER_PLACE_ENTRIES);
        assert_eq!(
            table.take(&hash(30), BASE_MS, Now::judging(BASE_MS), third),
            Verdict::Full
        );
        // A feeder's share is a feeder's.
        for n in 100..108 {
            assert_eq!(
                table.take(&hash(n), BASE_MS, Now::judging(BASE_MS), feeder(3)),
                Verdict::New
            );
        }
        assert_eq!(
            table.take(&hash(108), BASE_MS, Now::judging(BASE_MS), feeder(3)),
            Verdict::Full
        );
        // And the relay's own is the relay's: its records past it are let go too.
        for n in 200..216 {
            assert_eq!(
                table.take(&hash(n), BASE_MS, Now::judging(BASE_MS), Deliverer::Relay),
                Verdict::New
            );
        }
        assert_eq!(
            table.take(&hash(216), BASE_MS, Now::judging(BASE_MS), Deliverer::Relay),
            Verdict::Full
        );
        assert_eq!(
            table.take(&hash(109), BASE_MS, Now::judging(BASE_MS), feeder(4)),
            Verdict::New
        );
        // Once the flood's records leave the window (every table swept, then the shares), its
        // share is its own again.
        let later = BASE_MS + Usable::BATCHES.retained_ms() + 1_000;
        table.swept(judged(later));
        assert_eq!(
            table.take(&hash(17), later, Now::judging(later), flood),
            Verdict::New
        );
        assert_eq!(shares.held_by(flood), 1);
    }

    /// Feeders churning fresh keys, each a deliverer with a share of its own, fill the feeders'
    /// share together and at most twice it, never their store: thousands of keys each sending one
    /// batch take no more than twice the feeders' share, and the feeders' store, sized past that,
    /// is never what refuses them. A peer's record is taken, its store its own. Before, a fair
    /// part was rounded up, so every fresh key took an entry past the feeders' share, and enough
    /// keys filled the store for everyone.
    #[test]
    fn feeders_churning_fresh_keys_fill_their_share_and_never_the_store() {
        let shares_of = entries(64, 200, 64);
        let together = shares_of.feeders;
        // Room for more than twice the feeders' share, and not for every key.
        let limit = Strikes::fixed_bytes(Usable::BATCHES)
            + PLACES_FIXED_BYTES
            + (2 * together + 100) * PLANNED_ENTRY_BYTES;
        let stores = StrikeStores::limited([limit, usize::MAX, usize::MAX]);
        let shares = Shares::new(&stores, shares_of);
        let mut table = Strikes::new(Usable::BATCHES, &stores, Arc::clone(&shares));
        let mut taken = 0;
        for n in 0..5_000u64 {
            match table.take(&hash(n), BASE_MS, Now::judging(BASE_MS), feeder(n)) {
                Verdict::New => taken += 1,
                Verdict::Full => {}
                other => panic!("{other:?}"),
            }
        }
        // Each key's place is charged among its entries: one entry and its place each.
        let units = taken * (1 + FEEDER_PLACE_ENTRIES);
        assert!(units + 1 + FEEDER_PLACE_ENTRIES > together, "{taken}");
        assert!(units <= 2 * together, "{taken} taken by fresh keys");
        assert!(stores.gauge(Class::Feeders).held() <= limit);
        assert_eq!(
            table.take(&hash(1 << 40), BASE_MS, Now::judging(BASE_MS), peer(1)),
            Verdict::New
        );
        assert!(shares.held_by(peer(1)) == 1);
    }

    /// Each class's store as the relay plans it (`budget::Plan::strike_tables_bytes` and
    /// `PerFeeder`'s: the feeders' and the peers' shares each twice, places charged among their
    /// entries, the relay's own whole and its place, each class's ring and table of places), for
    /// `shares_of`.
    fn planned_stores(shares_of: Entries) -> (StrikeStores, [usize; 3]) {
        let figures = Usable::figures(crate::strikes::relay_signed(
            crate::sharing::Deadlines::RELAY,
        ));
        let ring = Strikes::fixed_bytes(Usable::BATCHES) + PLACES_FIXED_BYTES;
        let limits = [
            ring + 2 * shares_of.feeders * PLANNED_ENTRY_BYTES,
            ring + 2 * shares_of.peers * PLANNED_ENTRY_BYTES,
            ring + shares_of.relay * PLANNED_ENTRY_BYTES + place_bytes(Usable::BATCHES, figures),
        ];
        (StrikeStores::limited(limits), limits)
    }

    /// The entries a share of `connections` planned feeders' worth allows each class, as the
    /// relay plans them (`budget::Plan::strike_entries`): a feeder ten planned feeders' records.
    fn realistic(connections: usize) -> Entries {
        let life = Usable::BATCHES.feeder_life_seconds() as usize;
        let records = crate::cores::RECORDS_PER_PLANNED_FEEDER as usize;
        Entries {
            feeder: 10 * records * life,
            feeders: connections * (records * life + FEEDER_PLACE_ENTRIES),
            peer: life,
            peers: life + PEER_PLACE_ENTRIES,
            relay: life,
        }
    }

    /// Stores planned as the relay plans them hold the peers' and the relay's records whatever
    /// the feeders do: a churn of fresh keys each sending one tiny batch, and one feeder flooding,
    /// leave every record a peer and the relay deliver within their shares taken. Before, a place
    /// was charged to no share, and fresh keys filled the store with places while the feeders'
    /// share still had room.
    #[test]
    fn a_churn_of_fresh_feeder_keys_leaves_the_peers_and_the_relay_their_room() {
        let shares_of = realistic(4);
        let (stores, limits) = planned_stores(shares_of);
        let shares = Shares::new(&stores, shares_of);
        let mut table = Strikes::new(Usable::BATCHES, &stores, Arc::clone(&shares));
        let now = Now::judging(BASE_MS);
        let mut n = 0u64;
        // Thousands of fresh keys, one batch each, and one key flooding.
        for key in 0..5_000u64 {
            let _ = table.take(&hash(n), BASE_MS, now, feeder(key));
            n += 1;
        }
        for _ in 0..5_000 {
            let _ = table.take(&hash(n), BASE_MS, now, feeder(1 << 32));
            n += 1;
        }
        takes_every_peer_and_relay_record(&mut table, &shares, &stores, shares_of, &mut n);
        for class in Class::ALL {
            assert!(stores.gauge(class).held() <= limits[class.index()]);
        }
    }

    /// Every record a peer and the relay deliver within their shares, all in one bucket, taken.
    fn takes_every_peer_and_relay_record(
        table: &mut Strikes,
        shares: &Shares,
        stores: &StrikeStores,
        shares_of: Entries,
        n: &mut u64,
    ) {
        let now = Now::judging(BASE_MS);
        for (who, count) in [
            (peer(1), shares_of.peer),
            (Deliverer::Relay, shares_of.relay),
        ] {
            for _ in 0..count {
                assert_eq!(
                    table.take(&hash(*n), BASE_MS, now, who),
                    Verdict::New,
                    "{who:?} refused after {} of {count}: {} held",
                    shares.held_by(who),
                    stores.gauge(who.class()).held()
                );
                *n += 1;
            }
        }
    }

    /// The round 12 sweep's realistic overshoot, at the size a relay of 200 connections plans:
    /// feeders flooding with key after key, each filling its fair part, all signed in one bucket,
    /// so the feeders' one generation holds tens of thousands of fingerprints and grows past them
    /// (its old slots and its new held at once); and then, their shares opened wide, flooding on
    /// until their own store refuses them, a growth step among what it refuses. The peers' and the
    /// relay's records are taken all the same: their rings and their places are in stores of their
    /// own. Before, every class shared one store, and the feeders' generation, growing in it, took
    /// the room the peers and the relay were planned.
    #[test]
    fn one_generations_growth_by_feeders_never_refuses_a_peer_or_the_relay() {
        let shares_of = realistic(200);
        let (stores, limits) = planned_stores(shares_of);
        let shares = Shares::new(&stores, shares_of);
        let mut table = Strikes::new(Usable::BATCHES, &stores, Arc::clone(&shares));
        let now = Now::judging(BASE_MS);
        let mut n = 0u64;
        for key in 0..800u64 {
            while table.take(&hash(n), BASE_MS, now, feeder(key)) == Verdict::New {
                n += 1;
            }
            n += 1;
        }
        let (entries, _) = shares.held_of(Class::Feeders);
        // One generation, grown at least once past the first slots.
        assert!(entries > shares_of.feeders / 2, "{entries} held");
        assert!(entries * 4 > (1 << 14) * 3);
        // The feeders' shares opened wide: they flood until their store refuses them.
        shares.set(Entries {
            feeder: usize::MAX / 4,
            feeders: usize::MAX / 4,
            ..shares_of
        });
        let feeders = stores.gauge(Class::Feeders);
        while table.take(&hash(n), BASE_MS, now, feeder(1 << 33)) == Verdict::New {
            n += 1;
        }
        n += 1;
        let (full, _) = shares.held_of(Class::Feeders);
        assert!(full > entries, "{full} held");
        // What refused them was a growth: its set's new slots, twice its old (each 3/4 full),
        // beside the old, past what is left.
        assert!(
            feeders.held() + (full * 8 * 8).div_ceil(3) > limits[0],
            "{} held, {full} entries, {} planned",
            feeders.held(),
            limits[0]
        );
        // And every other second of the window filled until nothing more fits: the feeders' store
        // is full to its last generation's first slots.
        for back in 1..60 {
            let signed = BASE_MS - back * 1_000;
            while table.take(&hash(n), signed, now, feeder(1 << 33)) == Verdict::New {
                n += 1;
            }
            n += 1;
        }
        assert!(feeders.held() + Strikes::fixed_bytes(Usable::BATCHES) > limits[0]);
        takes_every_peer_and_relay_record(&mut table, &shares, &stores, shares_of, &mut n);
        for class in Class::ALL {
            assert!(stores.gauge(class).held() <= limits[class.index()]);
        }
    }

    /// The feeders' store as the relay plans it ([`PLANNED_ENTRY_BYTES`] for every entry, at a
    /// set's growing peak) never refuses a feeder's record its share would take: the same flood
    /// into a store of no bound takes exactly as much, though the feeders' one generation grows
    /// while it holds close to twice their share. Before, an entry was planned at the 3/8 floor
    /// of a set (22 bytes), and a store filled to it had no room for the growth: every record of
    /// that bucket was let go while the share had room.
    #[test]
    fn the_planned_store_holds_a_growing_generation_the_shares_allow() {
        let shares_of = realistic(200);
        let (planned, _) = planned_stores(shares_of);
        let mut held = Vec::new();
        for stores in [planned, StrikeStores::unlimited()] {
            let shares = Shares::new(&stores, shares_of);
            let mut table = Strikes::new(Usable::BATCHES, &stores, Arc::clone(&shares));
            let now = Now::judging(BASE_MS);
            let mut n = 0u64;
            for key in 0..4_000u64 {
                while table.take(&hash(n), BASE_MS, now, feeder(key)) == Verdict::New {
                    n += 1;
                }
                n += 1;
            }
            held.push(shares.held_of(Class::Feeders));
        }
        assert_eq!(
            held[0], held[1],
            "the planned store refused what the shares allow"
        );
        let (entries, holders) = held[0];
        assert!(entries + holders * FEEDER_PLACE_ENTRIES > shares_of.feeders);
    }

    /// Two tables sharing the shares, as the ingest shards do: one fills the feeders' share at one
    /// time, and the other takes at a time past that one's records' life, before the first is
    /// swept. Its entries are still in the first table's store, so they are still in the share:
    /// the store planned as the relay plans it takes exactly what a store of no bound takes. Once
    /// every table is swept and then the shares (`Hub::sweep_strikes`), they leave both, and the
    /// second table takes the share whole. The round 13 sweep's sizes: a generation just past a
    /// growth step at 2^11 and 2^12 slots, and a relay of 20 connections. Before, a take and each
    /// table's own sweep let the entries go from the shares while another table still held them,
    /// and the planned store refused what the shares then allowed.
    #[test]
    fn entries_leave_the_shares_only_once_every_table_has_dropped_them() {
        // Each size and the keys that fill it: one key fills a share it may hold whole.
        let mut sizes: Vec<(Entries, u64)> = Vec::new();
        for k in [11u32, 12] {
            for extra in [1usize, 50, 400] {
                let together = 3 * (1usize << k) / 4 + extra + FEEDER_PLACE_ENTRIES + 1;
                let shares_of = Entries {
                    feeder: usize::MAX / 4,
                    feeders: together,
                    peer: 64,
                    peers: 64 + PEER_PLACE_ENTRIES,
                    relay: 64,
                };
                sizes.push((shares_of, 3));
            }
        }
        sizes.push((realistic(20), 40));
        for (shares_of, keys) in sizes {
            let mut out = Vec::new();
            for planned in [true, false] {
                let stores = if planned {
                    planned_stores(shares_of).0
                } else {
                    StrikeStores::unlimited()
                };
                let shares = Shares::new(&stores, shares_of);
                let mut a = Strikes::new(Usable::BATCHES, &stores, Arc::clone(&shares));
                let mut b = Strikes::new(Usable::BATCHES, &stores, Arc::clone(&shares));
                let now = Now::judging(BASE_MS);
                let mut n = 0u64;
                for key in 0..keys {
                    while b.take(&hash(n), BASE_MS, now, feeder(key)) == Verdict::New {
                        n += 1;
                    }
                    n += 1;
                }
                let held = b.len();
                let later = BASE_MS + Usable::BATCHES.retained_ms() + 2_000;
                let take_all = |table: &mut Strikes, n: &mut u64, from: u64| {
                    let mut taken = 0usize;
                    for key in from..from + keys {
                        while table.take(&hash(*n), later, Now::judging(later), feeder(key))
                            == Verdict::New
                        {
                            taken += 1;
                            *n += 1;
                        }
                        *n += 1;
                    }
                    taken
                };
                // The first table not swept: its entries are still the share's.
                let before = take_all(&mut a, &mut n, 10_000);
                assert_eq!(b.len(), held);
                // Every table swept, then the shares: all of the first table's entries gone.
                b.sweep(judged(later));
                a.sweep(judged(later));
                shares.expire(judged(later));
                let after = take_all(&mut a, &mut n, 20_000);
                out.push((before, after));
            }
            assert_eq!(
                out[0], out[1],
                "{shares_of:?}: the planned store refused what the shares allow"
            );
            assert!(out[0].1 > 0);
        }
    }

    /// A table judging by a clock older than the shares' expiry (a judge's reading taken before
    /// the tick's, or a clock stepped back) sweeps back before it takes, so the shares keep what
    /// it takes until that table sweeps past it again: an entry leaves a share only once no table
    /// holds it, however the clocks interleave. Before, the expiry by the tick's clock let it go
    /// at once, while its table held it for a whole window.
    #[test]
    fn an_entry_a_stale_judge_takes_stays_in_the_share_while_its_table_holds_it() {
        let stores = StrikeStores::unlimited();
        let shares = Shares::new(&stores, realistic(20));
        let mut a = Strikes::new(Usable::BATCHES, &stores, Arc::clone(&shares));
        let mut b = Strikes::new(Usable::BATCHES, &stores, Arc::clone(&shares));
        let tick = BASE_MS + 1_000_000;
        a.sweep(judged(tick));
        b.sweep(judged(tick));
        shares.expire(judged(tick));
        // The next tick sweeps every table; then, before its expiry, a judge whose clock reads
        // 200 s before the tick's takes a record signed then: its bucket ends before the tick.
        let tick = tick + 1_000;
        a.sweep(judged(tick));
        b.sweep(judged(tick));
        let stale = tick - 200_000;
        assert!(stale + Usable::BATCHES.retained_ms() + 1_000 < tick);
        assert_eq!(
            a.take(&hash(1), stale, Now::judging(stale), feeder(1)),
            Verdict::New
        );
        // The tick's expiry, by its own clock, after that take: the table holds it, so the share
        // does.
        shares.expire(judged(tick));
        assert!(a.contains(&hash(1), stale));
        assert_eq!(
            shares.held_by(feeder(1)),
            1,
            "the share let go what a table holds"
        );
        // Once the table sweeps past it, both let it go.
        let past = tick + 1_000;
        a.sweep(judged(past));
        b.sweep(judged(past));
        shares.expire(judged(past));
        assert!(!a.contains(&hash(1), stale));
        assert_eq!(shares.held_by(feeder(1)), 0);
    }

    /// Every resize of the shares' places is charged at its peak, the old allocation and the new
    /// together, before it is made (`reallocated`): a list of counts that doubles from two to four
    /// needs room for both, and is refused without it; one that would shrink with no room for the
    /// copy is kept as it is. Before, a list that grew was charged only what it added, and a
    /// shrink nothing, so the store held past its limit while either was copied.
    #[test]
    fn a_resize_of_the_shares_is_charged_at_its_peak() -> Result<(), String> {
        let who = feeder(1);
        let first = BASE_MS / 1_000;
        let at = |second: u64| (first + second) * 1_000;
        let fill = |shares: &Shares, seconds: u64| {
            for second in 0..seconds {
                assert!(shares.take(who, at(second)), "second {second}");
            }
        };
        let list = crate::footprint::vec::<(u32, u32)>;
        // What the shares hold with a full list of two.
        let gauge = Gauge::unlimited(Store::FeederStrikes);
        let shares = Shares::new(&StrikeStores::sharing(&gauge), unbounded());
        fill(&shares, 2);
        let full = gauge.held();
        // Room for what it adds and not for both lists at once: refused; room for both: taken.
        for (limit, taken) in [(full + list(4) - 1, false), (full + list(4), true)] {
            let gauge = Gauge::new(Store::FeederStrikes, limit);
            let shares = Shares::new(&StrikeStores::sharing(&gauge), unbounded());
            fill(&shares, 2);
            assert_eq!(shares.take(who, at(2)), taken, "limit {limit}");
            assert!(gauge.peak() <= limit);
            assert_eq!(shares.charged(), shares.counted());
        }
        // Eight seconds held, six let go: its list of eight would move into one of two. With no
        // room left in its store for the copy (the rest of the store taken by another charge) it
        // is kept as it is; with room, it shrinks.
        for (room, shrunk) in [(0, false), (list(2), true)] {
            let limited = Gauge::new(Store::FeederStrikes, 1 << 20);
            let shares = Shares::new(&StrikeStores::sharing(&limited), unbounded());
            fill(&shares, 8);
            let rest = limited.limit() - limited.held() - room;
            let _taken = limited.try_charge(rest).ok_or("no room for the rest")?;
            let before = shares.counted();
            shares.expire(judged(at(6)));
            assert_eq!(shares.held_by(who), 2);
            let freed = if shrunk { list(8) - list(2) } else { 0 };
            assert_eq!(before - shares.counted(), freed, "room {room}");
            assert!(limited.held() <= limited.limit());
            assert_eq!(shares.charged(), shares.counted());
        }
        Ok(())
    }

    /// A pass that shrinks many places' lists (`expire`) gives back each old list the moment its
    /// copy is made (`reallocated`), so it holds one copy's room at a time: a store with room for
    /// one copy beside everything else shrinks every list, and a take beside the pass (here,
    /// another charge on the same store, as a concurrent take's) never finds more than one copy's
    /// room taken. Before, each shrink's old list was given back only when the pass was over, so
    /// the copies stacked up: with room for one, only the first list shrank, and the store's peak
    /// rose by a copy for every list shrunk.
    #[test]
    fn a_pass_of_shrinks_holds_one_copys_room_at_a_time() -> Result<(), String> {
        let first = BASE_MS / 1_000;
        let at = |second: u64| (first + second) * 1_000;
        let list = crate::footprint::vec::<(u32, u32)>;
        let holders = 16u64;
        let limited = Gauge::new(Store::FeederStrikes, 1 << 20);
        let shares = Shares::new(&StrikeStores::sharing(&limited), unbounded());
        for key in 0..holders {
            for second in 0..8 {
                assert!(shares.take(feeder(key), at(second)), "{key} at {second}");
            }
        }
        // Room for one copy of a list of two, the rest of the store taken by another charge.
        let rest = limited.limit() - limited.held() - list(2);
        let beside = limited.try_charge(rest).ok_or("no room for the rest")?;
        let (held_before, peak_before) = (limited.held(), limited.peak());
        let counted = shares.counted();
        shares.expire(judged(at(6)));
        assert_eq!(
            counted - shares.counted(),
            holders as usize * (list(8) - list(2)),
            "not every list shrank"
        );
        assert!(
            limited.peak() <= peak_before.max(held_before + list(2)),
            "the pass held {} past the store's level before it",
            limited.peak() - held_before
        );
        assert_eq!(shares.charged(), shares.counted());
        // The charge beside it is still whole, and a take after the pass finds the room freed.
        assert_eq!(beside.bytes(), rest);
        assert!(limited.fits(list(8) - list(2)));
        Ok(())
    }

    /// The round 12 sweep's sequential keys at a relay's size: key after key, each filling its
    /// fair part of the feeders' share (theirs over the holders then), hold at most twice the
    /// share. Before, the fair part alone bounded a holder past the share, and holders that came
    /// one after another each filled their fair part of the holders then: a harmonic sum of the
    /// share, past twice it.
    #[test]
    fn keys_filling_their_fair_part_one_after_another_hold_at_most_twice_the_share() {
        for together in [20_000usize, realistic(200).feeders] {
            let shares_of = Entries {
                feeder: together,
                feeders: together,
                peer: 64,
                peers: 64 + 2 * PEER_PLACE_ENTRIES,
                relay: 64,
            };
            let stores = StrikeStores::unlimited();
            let shares = Shares::new(&stores, shares_of);
            let mut table = Strikes::new(Usable::BATCHES, &stores, Arc::clone(&shares));
            let now = Now::judging(BASE_MS);
            let mut n = 0u64;
            for key in 0..2_000u64 {
                while table.take(&hash(n), BASE_MS, now, feeder(key)) == Verdict::New {
                    n += 1;
                }
                n += 1;
            }
            let (entries, holders) = shares.held_of(Class::Feeders);
            let units = entries + holders * FEEDER_PLACE_ENTRIES;
            assert!(
                units > together,
                "{units} of {together}: the fair part took nothing"
            );
            assert!(units <= 2 * together, "{units} held past twice {together}");
        }
    }

    /// The store full lets a new record go and forgets nothing.
    #[test]
    fn a_full_store_lets_a_record_go_and_forgets_nothing() {
        let (mut table, gauge, _) = table(16_384, unbounded());
        let mut taken = Vec::new();
        let mut n = 0;
        loop {
            match table.take(&hash(n), BASE_MS, Now::judging(BASE_MS), peer(1)) {
                Verdict::New => taken.push(n),
                Verdict::Full => break,
                other => panic!("{other:?}"),
            }
            n += 1;
        }
        assert!(!taken.is_empty());
        assert!(gauge.held() <= 16_384);
        assert_eq!(table.charged(), gauge.held());
        for n in taken {
            assert_eq!(
                table.judge(&hash(n), BASE_MS, Now::judging(BASE_MS), peer(1)),
                Verdict::Duplicate
            );
        }
    }

    /// A generation's set grows by allocating its new slots while it still holds the old, so the
    /// store is charged both before it grows: a store with room for the grown set alone, and not
    /// for both at once, lets the record go. Before, only the grown set was charged, and the peak
    /// passed the store.
    #[test]
    fn a_growing_set_is_charged_its_old_and_new_slots_at_once() {
        let ring = Strikes::fixed_bytes(Usable::BATCHES);
        let slot = std::mem::size_of::<u64>();
        // One fingerprint holds two slots; the second grows the set to four.
        let peak = ring + 2 * slot + 4 * slot;
        for (limit, second) in [(peak - 1, Verdict::Full), (peak, Verdict::New)] {
            let (mut table, gauge, _) = table(limit, unbounded());
            assert_eq!(
                table.take(&hash(1), BASE_MS, Now::judging(BASE_MS), peer(1)),
                Verdict::New
            );
            assert_eq!(
                table.take(&hash(2), BASE_MS, Now::judging(BASE_MS), peer(1)),
                second
            );
            assert!(gauge.held() <= limit);
        }
    }

    /// What a table allocates is charged, and within what it is planned at: [`PLANNED_ENTRY_BYTES`]
    /// for each entry it holds, beside its ring (`fixed_bytes`), while records keep coming and
    /// leaving at a rate that rises and falls (so its generations fill, and drop as they pass);
    /// and what its deliverers' places and counts allocate charged, within [`places_bytes`] and
    /// [`PLANNED_PAIR_BYTES`] for each second they count; all given back once every entry has
    /// expired, but the table of places kept for [`PLACES_KEPT`].
    #[test]
    fn a_tables_bytes_are_within_what_it_is_planned() {
        let gauge = Gauge::new(Store::PeerStrikes, usize::MAX);
        let shares = Shares::new(&StrikeStores::sharing(&gauge), unbounded());
        let mut table = Strikes::new(
            Usable::BATCHES,
            &StrikeStores::sharing(&gauge),
            Arc::clone(&shares),
        );
        let fixed = Strikes::fixed_bytes(Usable::BATCHES);
        let deliverers = 8;
        let mut n = 0u64;
        let mut fell = false;
        let mut previous = 0;
        // Eight minutes, a second at a time, the rate four hundred a second for two minutes and
        // one a second for the next two (each longer than an entry lives), spread over eight
        // peers: the live entries rise to their window's worth and fall away to almost none,
        // twice.
        const SECONDS: u64 = 480;
        const PHASE: u64 = 120;
        const _: () = assert!(PHASE * 1_000 > Usable::BATCHES.retained_ms());
        for second in 0..SECONDS {
            let now = BASE_MS + second * 1_000;
            // The relay's tick: every table swept, then the shares.
            table.swept(judged(now));
            let rate = if (second / PHASE).is_multiple_of(2) {
                400
            } else {
                1
            };
            for _ in 0..rate {
                let who = peer((n % deliverers) as u8);
                assert_eq!(
                    table.take(&hash(n), now, Now::judging(now), who),
                    Verdict::New
                );
                n += 1;
            }
            fell |= table.len() < previous;
            previous = table.len();
            assert_eq!(table.charged(), table.bytes());
            assert!(
                table.bytes() <= fixed + table.len() * PLANNED_ENTRY_BYTES,
                "{} bytes at second {second}, {} held",
                table.bytes(),
                table.len()
            );
            let counted = (0..deliverers)
                .filter(|d| shares.held_by(peer(*d as u8)) > 0)
                .count();
            let life = Usable::BATCHES.life_seconds() as usize;
            assert_eq!(shares.charged(), shares.counted());
            assert!(
                shares.charged()
                    <= places_bytes(counted) + counted * (life + 1) * PLANNED_PAIR_BYTES,
                "{} bytes of counts at second {second}",
                shares.charged()
            );
            assert_eq!(gauge.held(), table.bytes() + shares.charged());
        }
        assert!(fell, "nothing left the table, so nothing churned");
        // Every entry expired gives back all but the ring.
        let after = BASE_MS + SECONDS * 1_000 + Usable::BATCHES.retained_ms() + 1_000;
        table.swept(judged(after));
        assert!(table.is_empty());
        assert_eq!(table.charged(), table.bytes());
        assert!(table.charged() <= fixed);
        assert_eq!(shares.charged(), shares.counted());
        assert!(shares.charged() <= PLACES_FIXED_BYTES);
    }

    /// The table of places is charged what it allocates as deliverers come and go in their
    /// thousands (`footprint::Table`): before it grows, for its buckets as they are, never shrunk
    /// past four times the places it holds and [`PLACES_KEPT`], and so within [`places_bytes`] of
    /// them.
    #[test]
    fn the_places_are_charged_what_they_allocate_as_deliverers_come_and_go() {
        let gauge = Gauge::new(Store::PeerStrikes, usize::MAX);
        let shares = Shares::new(&StrikeStores::sharing(&gauge), unbounded());
        let feeders: Vec<Deliverer> = (0..5_000u64).map(feeder).collect();
        let mut most = 0;
        // Each minute a different number of feeders, up to five thousand, each taking an entry
        // that lives a second: the places rise and fall, and the table grows and shrinks.
        for minute in 0..40u64 {
            let now = BASE_MS + minute * 60_000;
            let count = [5_000, 3, 1_200, 0, 4_000, 70, 2_500, 1][minute as usize % 8];
            for each in &feeders[..count] {
                assert!(shares.take(*each, now + 1_000));
                assert_eq!(shares.charged(), shares.counted());
            }
            most = most.max(shares.places());
            assert!(
                shares.charged()
                    <= places_bytes(shares.places()) + shares.places() * 2 * PLANNED_PAIR_BYTES
            );
            shares.expire(judged(now + 30_000));
            assert_eq!(shares.places(), 0);
            assert_eq!(shares.charged(), shares.counted());
            assert!(shares.charged() <= PLACES_FIXED_BYTES);
            assert_eq!(gauge.held(), shares.charged());
        }
        assert_eq!(most, 5_000);
    }

    /// The table of places is charged what it holds when new places land in slots that places
    /// gone left behind: half the places live long and half a second, and each round the short
    /// ones go and new ones come, so the table, never shrunk, fills its removed entries' slots.
    /// Such an insert raises the capacity the table reads by one with no new table made, and
    /// the charge must follow its buckets, not that capacity. Before, it was taken for a growth
    /// and the old table given back while still held, so the shares were charged a table short
    /// whenever the hasher's seed put a new place in such a slot (one run in eight of the test
    /// above).
    #[test]
    fn a_place_in_a_removed_entrys_slot_is_no_growth() {
        let gauge = Gauge::new(Store::PeerStrikes, usize::MAX);
        for _ in 0..8 {
            let shares = Shares::new(&StrikeStores::sharing(&gauge), unbounded());
            let mut next = 0u64;
            for round in 0..20u64 {
                let now = BASE_MS + round * 60_000;
                for n in 0..600u64 {
                    let lives = if n % 2 == 0 { 1_000 } else { 86_400_000 };
                    let who = if n % 2 == 0 || round == 0 {
                        next += 1;
                        feeder(next)
                    } else {
                        continue;
                    };
                    assert!(shares.take(who, now + lives));
                    assert_eq!(
                        shares.charged(),
                        shares.counted(),
                        "round {round}, place {n}"
                    );
                }
                shares.expire(judged(now + 30_000));
                assert_eq!(shares.charged(), shares.counted());
            }
        }
    }

    /// A table left idle for longer than its ring of generations, or whose clock steps forward
    /// past it, forgets every entry the clock has passed, whatever slot it sits in: its
    /// fingerprints, its bytes and its deliverers' entries all given back, its floor raised to the
    /// newest it forgot, and every slot taken again for the seconds after without meeting a stale
    /// one. A swept table gives its entries back with no record judged (the relay's tick sweeps
    /// every table, `Hub::sweep_strikes`).
    #[test]
    fn an_idle_table_or_a_clock_stepped_forward_forgets_everything_it_has_passed() {
        let ring = (Usable::BATCHES.life_buckets() + 1) * 1_000;
        // Idle for longer than the ring, then a minute of steps; and a single step of days.
        for (gap, steps) in [(ring + 281_000, 60u64), (3 * 86_400_000, 1)] {
            let (mut table, gauge, shares) = table(usize::MAX, unbounded());
            for n in 0..100 {
                let at = BASE_MS + n * 1_000;
                // The relay's tick each second: every table swept, then the shares.
                table.swept(judged(at));
                assert_eq!(
                    table.take(&hash(n), at, Now::judging(at), peer(1)),
                    Verdict::New
                );
            }
            // Those of the last `R` (`FEEDER_BEHIND`, 91 s) are held still.
            assert_eq!(shares.held_by(peer(1)), 92);
            let later = BASE_MS + 99_000 + gap;
            table.swept(judged(later));
            assert_eq!(shares.held_by(peer(1)), 0);
            assert!(table.is_empty());
            assert_eq!(table.floor_ms(), Some(BASE_MS + 99_000));
            for step in 0..steps {
                let at = later + step * 1_000;
                assert_eq!(
                    table.take(&hash(1_000 + step), at, Now::judging(at), peer(2)),
                    Verdict::New
                );
            }
            for n in 0..100 {
                let at = BASE_MS + n * 1_000;
                assert!(!table.contains(&hash(n), at), "{n} outlived its window");
            }
            assert_eq!(table.len(), steps as usize);
            assert_eq!(shares.held_by(peer(2)), steps as usize);
            assert_eq!(table.charged(), table.bytes());
            assert_eq!(gauge.held(), table.bytes());
            // What was taken after is held to its own window still.
            let last = later + (steps - 1) * 1_000;
            assert_eq!(
                table.judge(
                    &hash(1_000 + steps - 1),
                    last,
                    Now::judging(
                        last + Window::PEER
                            .behind_span()
                            .span::<tally_wire::clocks::Judged>()
                            .ms()
                    ),
                    peer(3)
                ),
                Verdict::Duplicate
            );
        }
    }

    /// A clock that sweeps far ahead (a glitch forward, while the table was idle) and then comes
    /// back lets go of what it takes after, as it passes it: its fingerprints, their bytes and
    /// their deliverers' entries. Before, a table and its shares let go only past the furthest
    /// clock they had seen, so everything taken after the glitch was held, and counted against its
    /// deliverer's share, until the clock passed where the glitch had been.
    #[test]
    fn what_is_taken_after_a_clock_came_back_is_let_go_as_it_passes() {
        let (mut table, gauge, shares) = table(usize::MAX, unbounded());
        table.swept(judged(BASE_MS + 3_600_000));
        let signed = BASE_MS + 20_000;
        // The clock back: the relay's next tick sweeps by it.
        table.swept(judged(signed));
        assert_eq!(
            table.take(&hash(1), signed, Now::judging(signed), peer(1)),
            Verdict::New
        );
        assert_eq!(shares.held_by(peer(1)), 1);
        let passed = signed + Usable::BATCHES.retained_ms() + 2_000;
        table.swept(judged(passed));
        assert!(table.is_empty(), "held past its window");
        assert_eq!(shares.held_by(peer(1)), 0, "counted past its window");
        assert_eq!(table.floor_ms(), Some(signed));
        assert_eq!(gauge.held(), table.bytes());
    }

    /// A clock stepped back past a table's ring finds slots holding the records of buckets it
    /// has not reached: such a slot is never overwritten, and a record meeting one is late (held,
    /// never used, so its group does not ask for it again), its share given back, so what the
    /// slot holds is never new twice and the deliverer's count stays what the table holds. Before,
    /// the slot's generation was dropped to make room without giving back the counts it was
    /// charged, so a deliverer's share stayed spent for records no table held.
    #[test]
    fn a_slot_a_step_back_meets_is_never_overwritten_and_its_share_given_back() {
        let (mut table, _, shares) = table(usize::MAX, unbounded());
        let ring = Usable::BATCHES.life_buckets() + 1;
        let before = BASE_MS + 3_600_000;
        assert_eq!(
            table.take(&hash(1), before, Now::judging(before), peer(1)),
            Verdict::New
        );
        // Back by a whole number of rings: the same slot, another bucket.
        let back = before - 30 * ring * 1_000;
        assert_eq!(
            table.take(&hash(2), back, Now::judging(back), peer(1)),
            Verdict::Late
        );
        assert!(table.contains(&hash(1), before));
        assert_eq!(
            shares.held_by(peer(1)),
            1,
            "a share kept for a record not held"
        );
        // The first record again, at its own time: held still, a duplicate, never new twice.
        assert_eq!(
            table.take(&hash(1), before, Now::judging(before + 1_000), peer(2)),
            Verdict::Duplicate
        );
    }

    /// RFC 8446 §8.2: where a table starts. With no state it starts at `J + S + SKEW`; with a
    /// state directory at the lease it last held (the fallback floor when it never held one); a
    /// test's hub at no floor. A record used is covered by the lease, synced, before it is used,
    /// so a restart reading the lease starts above everything used. Each judges nothing until a
    /// synced clock begins it (RFC-0171 §3.6): the fallback floor is that clock's, never one read
    /// before it was synced.
    #[test]
    fn a_table_starts_above_everything_a_restart_could_have_used() -> Result<(), String> {
        let now = BASE_MS;
        let gauge = Gauge::unlimited(Store::PeerStrikes);
        let shares = Shares::new(&StrikeStores::sharing(&gauge), unbounded());
        assert!(matches!(Start::of(&Durable::Off, "batches"), Start::Empty));
        let fresh = Start::of(&Durable::Fresh, "batches");
        let mut table = Strikes::starting(
            Usable::BATCHES,
            &StrikeStores::sharing(&gauge),
            Arc::clone(&shares),
            &fresh,
        );
        assert_eq!(table.floor_ms(), None);
        assert_eq!(
            table.take(&hash(9), now, Now::judging(now), peer(1)),
            Verdict::Unjudged
        );
        // Synced only later: the floor is the synced clock's.
        let synced = now + 600_000;
        assert_eq!(table.begin(judged(synced)), Begun::Begun);
        assert_eq!(
            table.floor_ms(),
            Some(
                synced
                    + tally_wire::budget::FALLBACK_FLOOR
                        .span::<tally_wire::clocks::Judged>()
                        .ms()
            )
        );
        assert_eq!(table.begin(judged(synced + 1)), Begun::Already);
        let scratch = Scratch::new("strikes-start");
        let durable = Durable::Dir(scratch.dir()?);
        let start = Start::of(&durable, "batches");
        let mut table = Strikes::starting(
            Usable::BATCHES,
            &StrikeStores::sharing(&gauge),
            Arc::clone(&shares),
            &start,
        );
        assert_eq!(table.begin(judged(now)), Begun::Begun);
        assert_eq!(
            table.floor_ms(),
            Some(
                now + tally_wire::budget::FALLBACK_FLOOR
                    .span::<tally_wire::clocks::Judged>()
                    .ms()
            )
        );
        let used = now
            + tally_wire::budget::FALLBACK_FLOOR
                .span::<tally_wire::clocks::Judged>()
                .ms()
            + 5_000;
        assert_eq!(
            table.take(&hash(1), used, Now::judging(used), peer(1)),
            Verdict::New
        );
        drop(table);
        drop(start);
        let restarted = Start::of(&durable, "batches");
        let mut table = Strikes::starting(
            Usable::BATCHES,
            &StrikeStores::sharing(&gauge),
            shares,
            &restarted,
        );
        assert_eq!(table.begin(judged(used)), Begun::Begun);
        assert_eq!(
            table.floor_ms(),
            Some(tally_wire::budget::lease_bound(used))
        );
        assert_eq!(
            table.take(&hash(1), used, Now::judging(used + 1_000), peer(2)),
            Verdict::Late
        );
        Ok(())
    }

    /// A run whose clock ran ahead while it was unsynced leaves a lease far ahead of true time,
    /// and it may have used records up to it. A start with a synced clock keeps the bound as its
    /// floor all the same (safety first: no restart ever uses a record again), names it for the
    /// caller to say loudly, and uses nothing new until the clock passes it; the bound stays on
    /// disk, so a start before then meets it too. Before, the bound was refused and the fallback
    /// floor put in its place, and what that run used was new again.
    #[test]
    fn a_lease_ahead_of_a_synced_clock_stays_the_floor_until_the_clock_passes_it()
    -> Result<(), String> {
        let now = BASE_MS;
        let gauge = Gauge::unlimited(Store::PeerStrikes);
        let shares = Shares::new(&StrikeStores::sharing(&gauge), unbounded());
        let scratch = Scratch::new("strikes-ahead");
        let durable = Durable::Dir(scratch.dir()?);
        let start = Start::of(&durable, "batches");
        let mut table = Strikes::starting(
            Usable::BATCHES,
            &StrikeStores::sharing(&gauge),
            Arc::clone(&shares),
            &start,
        );
        // The unsynced run's clock an hour ahead: it began there and used a record there.
        let ahead = now + 3_600_000;
        assert_eq!(table.begin(judged(ahead)), Begun::Begun);
        let used = ahead
            + tally_wire::budget::FALLBACK_FLOOR
                .span::<tally_wire::clocks::Judged>()
                .ms()
            + 1_000;
        assert_eq!(
            table.take(&hash(1), used, Now::judging(used), peer(1)),
            Verdict::New
        );
        drop(table);
        drop(start);
        let held = tally_wire::budget::lease_bound(used);
        let restarted = Start::of(&durable, "batches");
        let mut table = Strikes::starting(
            Usable::BATCHES,
            &StrikeStores::sharing(&gauge),
            Arc::clone(&shares),
            &restarted,
        );
        assert_eq!(
            table.begin(judged(now)),
            Begun::LeaseAhead {
                held_ms: held,
                now_ms: now
            }
        );
        assert_eq!(table.floor_ms(), Some(held));
        // What the run ahead used is never used again, at any time.
        assert_eq!(
            table.take(&hash(1), used, Now::judging(used), peer(2)),
            Verdict::Late
        );
        // Nothing new is used before the clock passes the bound.
        let fresh = now
            + tally_wire::budget::FALLBACK_FLOOR
                .span::<tally_wire::clocks::Judged>()
                .ms()
            + 1_000;
        assert_eq!(
            table.take(&hash(2), fresh, Now::judging(fresh), peer(1)),
            Verdict::Late
        );
        drop(table);
        drop(restarted);
        // The bound stays: a start before the clock passes it meets it again.
        let again = Start::of(&durable, "batches");
        let mut table = Strikes::starting(
            Usable::BATCHES,
            &StrikeStores::sharing(&gauge),
            Arc::clone(&shares),
            &again,
        );
        assert!(matches!(
            table.begin(judged(now + 20_000)),
            Begun::LeaseAhead { held_ms, .. } if held_ms == held
        ));
        drop(table);
        drop(again);
        // Once the clock passes it, a record signed after it is new.
        let later = Start::of(&durable, "batches");
        let mut table = Strikes::starting(
            Usable::BATCHES,
            &StrikeStores::sharing(&gauge),
            shares,
            &later,
        );
        let past = held + 1_000;
        assert_eq!(table.begin(judged(past)), Begun::Begun);
        let after = past
            + tally_wire::budget::FALLBACK_FLOOR
                .span::<tally_wire::clocks::Judged>()
                .ms()
            + 1_000;
        assert_eq!(
            table.take(&hash(3), after, Now::judging(after), peer(1)),
            Verdict::New
        );
        Ok(())
    }

    /// A stop's dump read back into a table whose lease has not moved holds every fingerprint
    /// again, at the dump's own floor: a record used before the stop is a duplicate after it, and
    /// one never used is new, so a deploy is not deaf for a window. A dump that does not parse
    /// leaves the floor where the lease put it. A closed table takes nothing, so nothing is used
    /// after the dump is written.
    /// What a restart reads back is counted in the share of the class that took it, as one
    /// restored holder ([`Deliverer::Restored`]), so a class's store holds only what its share
    /// allows, with no exception: a dump of 50 peers' records, 30 feeders' and 10 of the relay's
    /// own is held again as three restored holders of those entries, and given back as they
    /// expire; read into shares too small for the peers' generation, that generation is dropped
    /// whole and the floor raised past it, so none of it is new again. Before, restored entries
    /// were charged to the store and to no share, and for an entry's life after a restart a store
    /// held them beside full shares.
    #[test]
    fn restored_fingerprints_are_counted_in_their_classs_share() -> Result<(), String> {
        let now = BASE_MS;
        let key = FingerprintKey::random();
        let stores = StrikeStores::unlimited();
        let shares = Shares::keyed(&stores, unbounded(), key);
        let mut table = Strikes::new(Usable::BATCHES, &stores, Arc::clone(&shares));
        let mut n = 0;
        for (who, count) in [(peer(1), 50), (feeder(1), 30), (Deliverer::Relay, 10)] {
            for _ in 0..count {
                assert_eq!(
                    table.take(&hash(n), now, Now::judging(now), who),
                    Verdict::New
                );
                n += 1;
            }
        }
        let mut dump = Vec::new();
        assert!(table.dump(&mut dump));
        // Read back into shares of no bound: every entry counted, as one restored holder a class.
        let restarted = Shares::keyed(&stores, unbounded(), key);
        let mut whole = Strikes::new(Usable::BATCHES, &stores, Arc::clone(&restarted));
        assert_eq!(whole.restore(&dump)?.1, Restored::Whole);
        for (class, count) in [(Class::Peers, 50), (Class::Feeders, 30), (Class::Own, 10)] {
            assert_eq!(restarted.held_by(Deliverer::Restored(class)), count);
            assert_eq!(restarted.held_of(class), (count, 1));
        }
        // Given back as they expire, every table swept and then the shares.
        let later = now + Usable::BATCHES.retained_ms() + 2_000;
        whole.swept(judged(later));
        for class in Class::ALL {
            assert_eq!(restarted.held_of(class), (0, 0));
        }
        // Read back into a peers' share too small for their generation: dropped whole, the floor
        // past it, and nothing of it new again; the other classes held as before.
        let small = Shares::keyed(
            &stores,
            Entries {
                peers: PEER_PLACE_ENTRIES + 20,
                ..unbounded()
            },
            key,
        );
        let mut partly = Strikes::new(Usable::BATCHES, &stores, Arc::clone(&small));
        assert_eq!(partly.restore(&dump)?.1, Restored::Partly);
        assert_eq!(small.held_of(Class::Peers), (0, 0));
        assert_eq!(small.held_of(Class::Feeders), (30, 1));
        assert_eq!(partly.floor_ms(), Some(now));
        for each in 0..50 {
            assert_eq!(
                partly.judge(&hash(each), now, Now::judging(now + 1_000), peer(2)),
                Verdict::Late
            );
        }
        Ok(())
    }

    #[test]
    fn a_stops_dump_is_read_back_so_a_deploy_is_not_deaf() -> Result<(), String> {
        let now = BASE_MS;
        let gauge = Gauge::unlimited(Store::PeerStrikes);
        let key = FingerprintKey::random();
        let shares = Shares::keyed(&StrikeStores::sharing(&gauge), unbounded(), key);
        let mut table = Strikes::new(
            Usable::BATCHES,
            &StrikeStores::sharing(&gauge),
            Arc::clone(&shares),
        );
        assert_eq!(
            table.take(&hash(1), now, Now::judging(now), peer(1)),
            Verdict::New
        );
        shares.close();
        assert_eq!(
            table.take(&hash(2), now, Now::judging(now), peer(1)),
            Verdict::Full
        );
        let mut dump = Vec::new();
        table.dump(&mut dump);
        // The restart's tables, under the state directory's key, at the lease's floor.
        let restarted = Shares::keyed(&StrikeStores::sharing(&gauge), unbounded(), key);
        let lease_floor = Start::At(now + 2_000);
        let mut resumed = Strikes::starting(
            Usable::BATCHES,
            &StrikeStores::sharing(&gauge),
            Arc::clone(&restarted),
            &lease_floor,
        );
        let (read, whole) = resumed.resume(&dump, None)?;
        assert_eq!((read, whole), (dump.len(), Restored::Whole));
        assert_eq!(resumed.floor_ms(), None);
        assert_eq!(
            resumed.take(&hash(1), now, Now::judging(now + 1_000), peer(2)),
            Verdict::Duplicate
        );
        assert_eq!(
            resumed.take(&hash(2), now, Now::judging(now + 1_000), peer(2)),
            Verdict::New
        );
        let mut broken = Strikes::starting(
            Usable::BATCHES,
            &StrikeStores::sharing(&gauge),
            Arc::clone(&restarted),
            &lease_floor,
        );
        assert!(broken.resume(&dump[..dump.len() - 3], None).is_err());
        assert_eq!(broken.floor_ms(), Some(now + 2_000));
        Ok(())
    }

    /// A run whose clock never synced has no floor of its own (its tables never began), so it
    /// writes no dump: a dump of its pending tables would read back as no floor at all beside the
    /// lease an earlier run proved, and what that run used would be new again. Before, it wrote
    /// one, and a record used before a crash was taken again two starts later (sweep 8, B1).
    #[test]
    fn a_run_that_never_synced_dumps_nothing_and_lowers_no_floor() -> Result<(), String> {
        let now = BASE_MS;
        let gauge = Gauge::unlimited(Store::PeerStrikes);
        let scratch = Scratch::new("strikes-unsynced-dump");
        let dir = scratch.dir()?;
        let durable = Durable::Dir(Arc::clone(&dir));
        let shares = Shares::keyed(&StrikeStores::sharing(&gauge), unbounded(), dir.key());
        // The first run syncs, uses a record, and crashes.
        let first = Start::of(&durable, "batches");
        let mut table = Strikes::starting(
            Usable::BATCHES,
            &StrikeStores::sharing(&gauge),
            Arc::clone(&shares),
            &first,
        );
        assert_eq!(table.begin(judged(now)), Begun::Begun);
        let used = now
            + tally_wire::budget::FALLBACK_FLOOR
                .span::<tally_wire::clocks::Judged>()
                .ms()
            + 1_000;
        assert_eq!(
            table.take(&hash(1), used, Now::judging(used), peer(1)),
            Verdict::New
        );
        drop(table);
        drop(first);
        // The second never syncs and stops gracefully: nothing to dump.
        let second = Start::of(&durable, "batches");
        let pending = Strikes::starting(
            Usable::BATCHES,
            &StrikeStores::sharing(&gauge),
            Arc::clone(&shares),
            &second,
        );
        let mut dump = Vec::new();
        assert!(!pending.dump(&mut dump));
        assert!(dump.is_empty());
        drop(pending);
        drop(second);
        // The third has no dump to resume, and starts at the lease's floor.
        let third = Start::of(&durable, "batches");
        let mut table = Strikes::starting(
            Usable::BATCHES,
            &StrikeStores::sharing(&gauge),
            Arc::clone(&shares),
            &third,
        );
        assert!(table.resume(&dump, None).is_err());
        assert_eq!(table.begin(judged(used)), Begun::Begun);
        assert_eq!(
            table.take(&hash(1), used, Now::judging(used + 1_000), peer(2)),
            Verdict::Late,
            "floor {:?}",
            table.floor_ms()
        );
        Ok(())
    }

    /// A dump resumed beside a lease another run wrote never takes the table below that lease's
    /// bound, whatever floor the dump states: no file lowers a floor a lease proves.
    #[test]
    fn a_resumed_floor_is_never_below_what_its_lease_proves() -> Result<(), String> {
        let now = BASE_MS;
        let gauge = Gauge::unlimited(Store::PeerStrikes);
        let key = FingerprintKey::random();
        // A dump of a table with no floor at all.
        let table = Strikes::new(
            Usable::BATCHES,
            &StrikeStores::sharing(&gauge),
            Shares::keyed(&StrikeStores::sharing(&gauge), unbounded(), key),
        );
        let mut dump = Vec::new();
        assert!(table.dump(&mut dump));
        let proven = now + 2_000;
        let mut resumed = Strikes::starting(
            Usable::BATCHES,
            &StrikeStores::sharing(&gauge),
            Shares::keyed(&StrikeStores::sharing(&gauge), unbounded(), key),
            &Start::At(proven),
        );
        resumed.resume(&dump, Some(proven))?;
        assert_eq!(resumed.floor_ms(), Some(proven));
        assert_eq!(
            resumed.take(&hash(1), now, Now::judging(now + 1_000), peer(1)),
            Verdict::Late
        );
        Ok(())
    }

    /// A dump far larger than its store is read back within the store: each fingerprint is held,
    /// and charged, as it is read, so reading it never allocates more than the store allows.
    /// Before, every fingerprint was gathered first and charged after.
    #[test]
    fn a_dump_is_charged_as_it_is_read() -> Result<(), String> {
        use tally_counting::Counting;
        let now = BASE_MS;
        let key = FingerprintKey::random();
        let unlimited = Gauge::unlimited(Store::PeerStrikes);
        let mut big = Strikes::new(
            Usable::BATCHES,
            &StrikeStores::sharing(&unlimited),
            Shares::keyed(&StrikeStores::sharing(&unlimited), unbounded(), key),
        );
        for n in 0..200_000u64 {
            assert_eq!(
                big.take(&hash(n), now, Now::judging(now), peer(1)),
                Verdict::New
            );
        }
        let mut dump = Vec::new();
        assert!(big.dump(&mut dump));
        drop(big);
        let limit = 64 * 1024;
        let gauge = Gauge::new(Store::PeerStrikes, limit);
        let mut small = Strikes::new(
            Usable::BATCHES,
            &StrikeStores::sharing(&gauge),
            Shares::keyed(&StrikeStores::sharing(&unlimited), unbounded(), key),
        );
        let base = Counting::peak_base();
        let (read, whole) = small.restore(&dump)?;
        let peak = Counting::peak_since(base);
        assert_eq!((read, whole), (dump.len(), Restored::Partly));
        assert!(
            peak <= limit as isize,
            "reading a dump of {} bytes held {peak} bytes at once on a store of {limit}",
            dump.len()
        );
        Ok(())
    }

    /// A table of few records that keeps its fingerprints themselves (feeder figures, fault
    /// proofs) logs each before it is used, and a restart reads them back: what was used is a
    /// duplicate after it, and a record signed long before is still new. Its log is folded into
    /// a checkpoint once it outgrows the table, so a take costs one append, not a rewrite.
    #[test]
    fn a_persisted_table_remembers_its_records_across_a_restart() -> Result<(), String> {
        let scratch = Scratch::new("strikes-persisted");
        let dir = scratch.dir()?;
        let key = dir.key();
        let gauge = Gauge::unlimited(Store::PeerStrikes);
        let usable = Usable::figures(crate::strikes::relay_signed(Deadlines::RELAY));
        let now = BASE_MS;
        // Its first start has no file: the fallback floor, as any table with no state.
        let signed = now
            + tally_wire::budget::FALLBACK_FLOOR
                .span::<tally_wire::clocks::Judged>()
                .ms()
            + 1_000;
        let mut table = Strikes::persisted(
            usable,
            &StrikeStores::sharing(&gauge),
            Shares::keyed(&StrikeStores::sharing(&gauge), unbounded(), key),
            &dir,
            "figures",
        );
        assert_eq!(table.begin(judged(now)), Begun::Begun);
        let checkpoint = dir.path().join("figures.strikes");
        let begun = std::fs::read(&checkpoint).map_err(|e| e.to_string())?;
        // Each take one record appended to the log, the checkpoint never rewritten for it.
        let many = 40;
        for n in 1..=many {
            assert_eq!(
                table.take(
                    &hash(n),
                    signed + n,
                    Now::judging(signed + n),
                    Deliverer::Relay
                ),
                Verdict::New
            );
        }
        assert_eq!(table.logged_records(), many);
        assert_eq!(
            std::fs::read(&checkpoint).map_err(|e| e.to_string())?,
            begun
        );
        drop(table);
        let mut again = Strikes::persisted(
            usable,
            &StrikeStores::sharing(&gauge),
            Shares::keyed(&StrikeStores::sharing(&gauge), unbounded(), key),
            &dir,
            "figures",
        );
        // Restarted ten minutes on: no floor of signed time beside the one it kept, so a record
        // signed long before is still new, and every one used a duplicate.
        let later = signed + 600_000;
        assert_eq!(again.begin(judged(later)), Begun::Begun);
        assert_eq!(
            again.floor_ms(),
            Some(
                now + tally_wire::budget::FALLBACK_FLOOR
                    .span::<tally_wire::clocks::Judged>()
                    .ms()
            )
        );
        for n in 1..=many {
            assert_eq!(
                again.take(&hash(n), signed + n, Now::judging(later), peer(1)),
                Verdict::Duplicate,
                "record {n}"
            );
        }
        assert_eq!(
            again.take(&hash(0), signed, Now::judging(later), peer(1)),
            Verdict::New
        );
        Ok(())
    }

    /// A table of few records whose own file is missing or not trusted (deleted, torn, another
    /// key's) starts at the fallback floor once the clock is synced, as any table with no state
    /// does: never at no floor, which would take again everything it used before. Before, a
    /// missing file meant a table with no floor at all. So does one whose checkpoint is good and
    /// whose log is gone (it held every record used since the checkpoint: before, they were
    /// dropped and taken again), and one whose checkpoint was written for other windows (its
    /// retention, bucket or ring: before, it was read into a table that keeps it otherwise).
    #[test]
    fn a_persisted_table_with_no_file_it_trusts_starts_at_the_fallback_floor() -> Result<(), String>
    {
        let now = BASE_MS;
        let gauge = Gauge::unlimited(Store::PeerStrikes);
        let usable = Usable::proofs(Deadlines::RELAY);
        let mut other = usable;
        other.bucket_ms *= 2;
        for case in ["missing", "torn", "flipped", "log missing", "windows"] {
            let scratch = Scratch::new("strikes-nofile");
            let dir = scratch.dir()?;
            let shares = || Shares::keyed(&StrikeStores::sharing(&gauge), unbounded(), dir.key());
            let mut table = Strikes::persisted(
                usable,
                &StrikeStores::sharing(&gauge),
                shares(),
                &dir,
                "fault_proofs",
            );
            assert_eq!(table.begin(judged(now)), Begun::Begun);
            let signed = now
                + tally_wire::budget::FALLBACK_FLOOR
                    .span::<tally_wire::clocks::Judged>()
                    .ms()
                + 1_000;
            assert_eq!(
                table.take(&hash(1), signed, Now::judging(signed), peer(1)),
                Verdict::New
            );
            drop(table);
            let checkpoint = dir.path().join("fault_proofs.strikes");
            let reopened = if case == "windows" { other } else { usable };
            match case {
                "missing" => std::fs::remove_file(&checkpoint).map_err(|e| e.to_string())?,
                "log missing" => std::fs::remove_file(dir.path().join("fault_proofs.log"))
                    .map_err(|e| e.to_string())?,
                "windows" => {}
                "torn" => {
                    let bytes = std::fs::read(&checkpoint).map_err(|e| e.to_string())?;
                    std::fs::write(&checkpoint, &bytes[..bytes.len() - 1])
                        .map_err(|e| e.to_string())?;
                }
                _ => {
                    let mut bytes = std::fs::read(&checkpoint).map_err(|e| e.to_string())?;
                    let at = bytes.len() / 2;
                    bytes[at] ^= 1;
                    std::fs::write(&checkpoint, &bytes).map_err(|e| e.to_string())?;
                }
            }
            let mut again = Strikes::persisted(
                reopened,
                &StrikeStores::sharing(&gauge),
                shares(),
                &dir,
                "fault_proofs",
            );
            let later = signed + 500;
            assert_eq!(
                again.take(&hash(1), signed, Now::judging(later), peer(2)),
                Verdict::Unjudged
            );
            assert_eq!(again.begin(judged(later)), Begun::Begun);
            assert_eq!(
                again.floor_ms(),
                Some(
                    later
                        + tally_wire::budget::FALLBACK_FLOOR
                            .span::<tally_wire::clocks::Judged>()
                            .ms()
                ),
                "{case}"
            );
            assert_eq!(
                again.take(&hash(1), signed, Now::judging(later), peer(2)),
                Verdict::Late,
                "{case}"
            );
        }
        Ok(())
    }

    /// A generation finds every fingerprint it holds as it grows, and nothing it does not, and
    /// keeps the newest signed time it was given.
    #[test]
    fn a_generation_holds_exactly_what_was_put_in() {
        let key = FingerprintKey::random();
        let mut generation = Generation::default();
        for n in 0..5_000u64 {
            let wanted = generation.slots_for(generation.len + 1);
            generation.insert(fingerprint(&key, &hash(n)), BASE_MS + n % 7);
            assert_eq!(generation.slots.len(), wanted);
            assert!(generation.len * 4 <= generation.slots.len() * 3);
        }
        assert_eq!(generation.len, 5_000);
        assert_eq!(generation.newest_ms, BASE_MS + 6);
        for n in 0..10_000u64 {
            assert_eq!(
                generation.contains(fingerprint(&key, &hash(n))),
                n < 5_000,
                "{n}"
            );
        }
        // At least 3/8 full, so a fingerprint costs at most what it is planned at.
        assert!(generation.bytes() <= generation.len * PLANNED_ENTRY_BYTES);
    }
}
