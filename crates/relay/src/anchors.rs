//! A feeder's batch is used at a hop only by the freshness anchors in its signed bytes (RFC-0171
//! §3.6): each a relay's signed reading of its judging clock (`tally_wire::Anchor`), which the
//! feeder had from a relay it holds a session with before it signed the batch. So a batch proves
//! it was made after that relay's clock read `j_ms`, and every hop bounds its age by its oldest
//! anchor, judged by the hop's own clock, never by the time the feeder signed: the pattern of TLS
//! 1.3's 0-RTT tickets (RFC 8446 §8.3, a ticket's age bounded by the server's own issue time) and
//! of Roughtime's nonces. A relay can say nothing of when a batch was made from its own evidence
//! (a hop whose first copy arrives at the batch's signed time has none), so the proof travels in
//! the batch.
//!
//! **The threat it answers.** Anchors protect an honest feeder's data from relays that would
//! make it look fresher than it is (a member that holds a reception and releases it later as
//! live). A malicious feeder is out of their scope: it can fabricate receptions at real time
//! anyway, so a far-ahead release of its own adds it nothing; that is the untrusted-feeder
//! problem, which MLAT and consensus answer.
//!
//! **The rule** ([`judge`]). Only the anchors a hop can check count: each of a relay this hop
//! knows (its own key, or one whose live offer it holds or its operator accepted:
//! `Hub::relay_trust`) whose signature verifies. With none, the batch is unanchored and never
//! usable here. Otherwise the **oldest** of them, `A`, must be within
//! [`crate::strikes::Window::ANCHOR`] of the hop's clock `J`: `J - A.j_ms <= W_a` and
//! `A.j_ms - J <= 32 s`. The oldest, so a known relay's lie can only make a batch less usable: an
//! anchor in the future is outweighed by an honest one, and one in the past only ages it; an
//! unknown or forged one is not evidence and changes nothing. This is besides the batch's own
//! signed time's window (`strikes`), never instead of it. Stale and ahead by anchor are counted
//! against nobody: a lying relay's anchor must never blame an honest feeder. Blame is the
//! origin's alone, by its own anchor, whose truth it knows (`Hub::admit`,
//! `strikes::blame`).
//!
//! **What it guarantees.** For an honest feeder, as long as one honest anchor it carries is known
//! at the hop, every batch used at an honest hop was made no earlier than
//! `J - W_a` by that hop's clock. The residual depends on what its feeder trusts
//! (`tally_feed`'s `RelayClocks::anchors`): with a trusted reference (its configured relays'
//! selection, or its host synced), it is those configured sources lying, the operator's trust;
//! with none, it is every relay it anchors to lying. Without a trusted reference one lying relay
//! can make that feeder's batches unusable (blamed on nobody); it makes a stale one usable only
//! at a hop that knows no honest anchor the batch carries, since while one honest known anchor
//! is there the oldest decides.
//!
//! **What it keeps.** Nothing correctness depends on: a cache of anchors verified here
//! ([`Anchors`]), fixed in size and allocated once (`Store::Anchors`, [`PLANNED_BYTES`]), so a
//! hop verifies a relay's anchor once and not for every batch that carries it. A miss costs one
//! signature check. The relay's own anchor, signed at most once a period (`Anchors::issue`).

use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use tally_wire::anchor::{ANCHOR_LEN, Anchor};
use tally_wire::clocks::{Judged, Raw};
use tally_wire::{FingerprintKey, PublicKey};

use crate::budget::{Charge, Gauge};
use crate::strikes::Window;

/// What a hop makes of a feeder's batch's anchors ([`judge`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Anchoring {
    /// Its oldest known anchor is within the window: usable, if its signed time and its table say
    /// so.
    Fresh,
    /// No anchor this hop can check: none at all (a format without them, an older feeder's; or a
    /// feeder that had none yet), or none of a relay this hop knows whose signature verifies.
    /// Never usable here, counted apart (`unanchored_records`), blamed on nobody.
    Unanchored,
    /// Its oldest known anchor is older than `W_a`: made too long ago to be used here, as far as
    /// the relays that signed it say. Blamed on nobody.
    Stale,
    /// Its oldest anchor is more than `tally_wire::budget::ANCHOR_AHEAD` ahead of this hop's clock: no honest
    /// relay's clock is, so not usable here, and blamed on nobody (this hop's own clock may be
    /// the one behind).
    Ahead,
}

/// What a batch carrying `anchors` is at a hop whose judging clock reads `now`: `known` says
/// whether a relay's key is one the hop knows, and `verified` whether an anchor's signature
/// verifies (a cache's answer, or the check itself). Only the anchors of known relays that verify
/// are judged; the oldest of them decides. Pure: the same anchors at the same reading are judged
/// the same at every hop that knows the same relays.
pub fn judge(
    anchors: &[Anchor],
    now: Judged,
    known: impl Fn(&PublicKey) -> bool,
    mut verified: impl FnMut(&Anchor) -> bool,
) -> Anchoring {
    let Some(oldest) = anchors
        .iter()
        .filter(|anchor| known(&anchor.relay) && verified(anchor))
        .map(|anchor| anchor.j_ms)
        .min()
    else {
        return Anchoring::Unanchored;
    };
    let window = Window::ANCHOR;
    if window.ahead(oldest, now) {
        Anchoring::Ahead
    } else if window.stale(oldest, now) {
        Anchoring::Stale
    } else {
        Anchoring::Fresh
    }
}

/// The slots of the cache of verified anchors: some ten thousand anchors are live at once on a
/// network of a hundred relays (each signs one a second, each lives `W_a`), and a miss costs one
/// signature check, so a quarter of that holds every relay's newest several seconds.
pub const SLOTS: usize = 4096;

/// The stripes the cache is locked in, so the ingest workers seldom meet on a lock.
const STRIPES: usize = 16;

/// One slot: an anchor's bytes as they verified, or none.
type Slot = Option<[u8; ANCHOR_LEN]>;

/// This relay's own anchors it remembers issuing, each with its raw monotonic clock then: one a
/// period at most, over [`tally_wire::budget::OWN_ANCHOR_OLDEST`], and one to spare.
pub const OWN_ISSUES: usize = (tally_wire::budget::OWN_ANCHOR_OLDEST
    .span::<tally_wire::clocks::Judged>()
    .ms()
    / tally_wire::budget::ANCHOR_PERIOD
        .span::<tally_wire::clocks::Judged>()
        .ms()) as usize
    + 2;

/// One of this relay's own anchors it issued: its reading `j_ms`, and its raw monotonic clock
/// when it signed it.
type Issued = (u64, Raw);

/// What the cache allocates, whatever it holds: its slots, allocated once (`Store::Anchors`,
/// planned before any feeder, as a fixed store is), and the ring of its own issues.
pub const PLANNED_BYTES: usize = SLOTS * std::mem::size_of::<Slot>()
    + STRIPES * std::mem::size_of::<Mutex<Box<[Slot]>>>()
    + OWN_ISSUES * std::mem::size_of::<Issued>();

/// A relay's anchors: the cache of anchors it verified, and the one it last issued.
pub struct Anchors {
    stripes: Box<[Mutex<Box<[Slot]>>]>,
    key: FingerprintKey,
    /// The anchor it last issued, and its raw monotonic clock then.
    issued: Mutex<Option<(Anchor, Raw)>>,
    /// Its own anchors' readings and their raw monotonic clocks at issue, oldest first, at most
    /// [`OWN_ISSUES`] and none older than `OWN_ANCHOR_OLDEST`: what blame measures an honest
    /// batch's age by, from the anchor its origin signed (`issued_by`).
    own: Mutex<std::collections::VecDeque<Issued>>,
    /// The raw monotonic clock at the newest issue the ring let go: an own anchor it no longer
    /// remembers was issued no later than this, so a batch its relay held back after it arrived
    /// (paced, queued) is aged from at most this and never more than its anchor's own age
    /// ([`Anchors::issued_by`]).
    forgotten: Mutex<Option<Raw>>,
    /// The raw monotonic clock at its first issue since it started: an own anchor of the relay's
    /// earlier run, whose issue nothing here remembers, was issued before it, so a batch carrying
    /// one is aged from at most this ([`Anchors::issued_by`]), and within `OWN_ANCHOR_OLDEST` of a
    /// restart no age can blame anyone.
    first: Mutex<Option<Raw>>,
    charge: Mutex<Charge>,
}

impl Default for Anchors {
    fn default() -> Self {
        Self::new()
    }
}

impl Anchors {
    pub fn new() -> Self {
        Self {
            stripes: (0..STRIPES)
                .map(|_| Mutex::new(vec![None; SLOTS / STRIPES].into_boxed_slice()))
                .collect(),
            key: FingerprintKey::random(),
            issued: Mutex::new(None),
            own: Mutex::new(std::collections::VecDeque::with_capacity(OWN_ISSUES)),
            first: Mutex::new(None),
            forgotten: Mutex::new(None),
            charge: Mutex::new(Charge::none()),
        }
    }

    /// Its slots charged to `gauge` (`Store::Anchors`), as allocated: what it was charged before
    /// given back first, so a budget charged again (resized) holds them once. A store whose limit
    /// is below them is charged nothing (an empty store takes any first charge, so its limit is
    /// asked), and a start refuses it (`charged_in_full`).
    pub fn charge_to(&self, gauge: &Arc<Gauge>) {
        let mut held = lock(&self.charge);
        *held = Charge::none();
        let mut charge = gauge.empty();
        if gauge.limit() >= PLANNED_BYTES {
            let _ = charge.try_grow(PLANNED_BYTES);
        }
        *held = charge;
    }

    /// What it is charged now.
    pub fn charged(&self) -> usize {
        lock(&self.charge).bytes()
    }

    /// Whether its planned bytes are charged in full: a relay whose anchor cache its store cannot
    /// hold refuses to start (`Network::fixed_charged`), since every slot is allocated at once.
    pub fn charged_in_full(&self) -> Result<(), String> {
        let charged = self.charged();
        if charged == PLANNED_BYTES {
            Ok(())
        } else {
            Err(format!(
                "the anchor cache needs {PLANNED_BYTES} bytes and its store gave it {charged}: \
                 give the relay more memory"
            ))
        }
    }

    /// Whether `anchor` verifies: from the cache when it verified here before, else checked and
    /// cached. The cache only saves the check; its answer is the check's.
    pub fn verified(&self, anchor: &Anchor) -> bool {
        let mut bytes = [0; ANCHOR_LEN];
        let mut written = Vec::with_capacity(ANCHOR_LEN);
        anchor.write(&mut written);
        bytes.copy_from_slice(&written);
        let slot =
            self.key
                .fingerprint(tally_wire::decoded::keyed::ANCHOR_SLOT, &bytes) as usize;
        let stripe = &self.stripes[slot % STRIPES];
        let at = (slot / STRIPES) % (SLOTS / STRIPES);
        if lock(stripe)[at] == Some(bytes) {
            return true;
        }
        if anchor.verify().is_err() {
            return false;
        }
        lock(stripe)[at] = Some(bytes);
        true
    }

    /// The anchor this relay states now, its judging clock reading `now` and its raw monotonic
    /// clock `raw` (`clock::RelayClock::raw`): the one it last signed while that is under a period
    /// old by the raw clock, else one `sign` makes now reading `now` (none while the relay signs
    /// nothing: its clock not judging, `signer::Signer`), remembered with `raw`
    /// ([`Anchors::issued_by`]). Paced by the raw clock, as the ring of its issues is
    /// sized ([`OWN_ISSUES`]): at most one a period of it, however fast a daemon slews the judging
    /// clock (chrony's fastest, 83,333 ppm, would issue one more every twelve seconds by it, and
    /// the ring would forget an honest batch's anchor early), and a step of the judging clock
    /// issues no extra one.
    pub fn issue(
        &self,
        now: Judged,
        raw: Raw,
        sign: impl FnOnce(Judged) -> Option<Anchor>,
    ) -> Option<Anchor> {
        let mut issued = lock(&self.issued);
        if let Some((anchor, at)) = *issued
            && !tally_wire::budget::ANCHOR_PERIOD
                .past(at, raw.later(tally_wire::budget::policy::<_, 1>()))
        {
            return Some(anchor);
        }
        let anchor = sign(now)?;
        *issued = Some((anchor, raw));
        lock(&self.first).get_or_insert(raw);
        let mut own = lock(&self.own);
        while own.front().is_some_and(|(_, at)| {
            own.len() >= OWN_ISSUES || tally_wire::budget::OWN_ANCHOR_OLDEST.past(*at, raw)
        }) {
            if let Some((_, at)) = own.pop_front() {
                let mut forgotten = lock(&self.forgotten);
                *forgotten = Some(forgotten.map_or(at, |was| was.latest(at)));
            }
        }
        own.push_back((anchor.j_ms, raw));
        Some(anchor)
    }

    /// The latest raw monotonic clock at which this relay issued its own anchor reading `j_ms`,
    /// so an age measured from it is never overstated: exactly while the ring remembers it
    /// ([`OWN_ISSUES`], none older than `OWN_ANCHOR_OLDEST`), the latest should a step back of its
    /// judging clock have made two alike; once the ring let it go, the newest issue it let go,
    /// which it was issued no later than; and one this run never issued (its key's in an earlier
    /// run), this run's first issue, before which it was issued. `None` before this run issued
    /// any. So a batch that arrived carrying a fresh anchor and was held back here past the
    /// ring's span (its link's pacing, a queue) is aged as it arrived, from at most its anchor's
    /// issue, and never blamed for the relay's own wait.
    pub fn issued_by(&self, j_ms: u64) -> Option<Raw> {
        let remembered = lock(&self.own)
            .iter()
            .rev()
            .find(|(issued, _)| *issued == j_ms)
            .map(|(_, at)| *at);
        remembered
            .or_else(|| *lock(&self.forgotten))
            .or_else(|| *lock(&self.first))
    }
}

/// The relay whose anchors the unit tests sign their feeders' batches with, the simulation's
/// (`tally_mlat_solver::sim::anchoring_relay`): every hub a unit test makes accepts it
/// (`Hub::new`), as an operator's `--accept-relay` would, so a test's batch is judged by the same
/// rule as a feeder's.
#[cfg(test)]
pub(crate) fn test_relay() -> tally_wire::Identity {
    tally_mlat_solver::sim::anchoring_relay()
}

/// A unit test's feeder's batch of `content`, anchored by [`test_relay`] at its signed time, so
/// fresh while that time is usable.
#[cfg(test)]
pub(crate) fn anchored(
    feeder: &impl tally_wire::Signs,
    content: &tally_wire::BatchContent,
) -> Result<tally_wire::Batch, tally_wire::WireError> {
    anchored_with(feeder, content, tally_wire::batch::Codec::Plain)
}

/// As [`anchored`], its receptions written by `codec`.
#[cfg(test)]
pub(crate) fn anchored_with(
    feeder: &impl tally_wire::Signs,
    content: &tally_wire::BatchContent,
    codec: tally_wire::batch::Codec,
) -> Result<tally_wire::Batch, tally_wire::WireError> {
    anchored_at(feeder, content, codec, content.wall_ms)
}

/// As [`anchored_with`], anchored by [`test_relay`]'s clock reading `anchor_ms`.
#[cfg(test)]
pub(crate) fn anchored_at(
    feeder: &impl tally_wire::Signs,
    content: &tally_wire::BatchContent,
    codec: tally_wire::batch::Codec,
    anchor_ms: u64,
) -> Result<tally_wire::Batch, tally_wire::WireError> {
    let anchor = Anchor::sign(&test_relay(), anchor_ms);
    tally_wire::Batch::sign_anchored(feeder, content, codec, &[anchor])
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::disallowed_methods, reason = "a test's scripted readings")]
    use super::*;
    use tally_wire::Identity;
    use tally_wire::clocks::recorded::{judged, raw};

    const NOW: u64 = 1_800_000_000_000;

    fn anchor(seed: u8, j_ms: u64) -> Anchor {
        Anchor::sign(&Identity::from_seed([seed; 32]), j_ms)
    }

    fn judged_at(anchors: &[Anchor], now_ms: u64) -> Anchoring {
        judge(
            anchors,
            judged(now_ms),
            |_| true,
            |anchor| anchor.verify().is_ok(),
        )
    }

    /// The window's edges, exactly: `W_a` behind and 32 s ahead are fresh, a millisecond past
    /// either is not; the oldest anchor decides, so a future anchor beside an old one leaves the
    /// batch stale and an old one beside a fresh one makes it stale sooner.
    #[test]
    fn the_oldest_anchor_decides_at_the_windows_edges() {
        let window = Window::ANCHOR;
        let behind = NOW
            - window
                .behind_span()
                .span::<tally_wire::clocks::Judged>()
                .ms();
        let ahead = NOW
            + window
                .ahead_span()
                .span::<tally_wire::clocks::Judged>()
                .ms();
        assert_eq!(judged_at(&[anchor(1, behind)], NOW), Anchoring::Fresh);
        assert_eq!(judged_at(&[anchor(1, behind - 1)], NOW), Anchoring::Stale);
        assert_eq!(judged_at(&[anchor(1, ahead)], NOW), Anchoring::Fresh);
        assert_eq!(judged_at(&[anchor(1, ahead + 1)], NOW), Anchoring::Ahead);
        // A lying relay's future anchor beside an honest old one: the old one decides.
        let hour = 3_600_000;
        assert_eq!(
            judged_at(&[anchor(1, NOW - hour), anchor(2, NOW + hour)], NOW),
            Anchoring::Stale
        );
        // An old anchor beside a fresh one only ages the batch.
        assert_eq!(
            judged_at(&[anchor(1, NOW), anchor(2, behind - 1)], NOW),
            Anchoring::Stale
        );
        assert_eq!(judged_at(&[], NOW), Anchoring::Unanchored);
    }

    /// Only anchors this hop can check count: one whose signature does not verify, or whose
    /// relay this hop does not know, is no evidence and changes nothing, so an honest known
    /// anchor beside it decides; a batch with none it can check is unanchored.
    #[test]
    fn only_known_verified_anchors_are_judged() {
        let good = anchor(1, NOW);
        let mut bad = anchor(2, NOW - 3_600_000);
        bad.signature[0] ^= 1;
        let only = good.relay;
        let known = |key: &PublicKey| *key == only;
        let check = |anchor: &Anchor| anchor.verify().is_ok();
        assert_eq!(
            judge(&[good, bad], judged(NOW), |_| true, check),
            Anchoring::Fresh
        );
        assert_eq!(judge(&[good], judged(NOW), known, check), Anchoring::Fresh);
        // An unknown relay's anchor an hour old beside the known one: still fresh.
        let stranger = anchor(3, NOW - 3_600_000);
        assert_eq!(
            judge(&[stranger, good], judged(NOW), known, check),
            Anchoring::Fresh
        );
        assert_eq!(
            judge(&[stranger], judged(NOW), known, check),
            Anchoring::Unanchored
        );
        assert_eq!(
            judge(&[bad], judged(NOW), |_| true, check),
            Anchoring::Unanchored
        );
    }

    /// The cache answers as the check does: a verified anchor is found again, a forged one (the
    /// same bytes but its reading) never cached and never verified; its charge is its planned
    /// bytes, whatever it holds.
    #[test]
    fn the_cache_answers_as_the_check_does() {
        let anchors = Anchors::new();
        let good = anchor(1, NOW);
        assert!(anchors.verified(&good));
        assert!(anchors.verified(&good));
        let forged = Anchor {
            j_ms: NOW + 3_600_000,
            ..good
        };
        assert!(!anchors.verified(&forged));
        assert!(!anchors.verified(&forged));
        let gauge = Gauge::unlimited(crate::budget::Store::Anchors);
        anchors.charge_to(&gauge);
        assert_eq!(anchors.charged(), PLANNED_BYTES);
    }

    /// Charged again to a store planned for exactly it (a hub's budget handed on), the cache gives
    /// its old charge back before it takes the new one, so it still holds its planned bytes.
    #[test]
    fn a_cache_charged_again_to_its_planned_store_holds_its_bytes() {
        let anchors = Anchors::new();
        let gauge = Gauge::new(crate::budget::Store::Anchors, PLANNED_BYTES);
        anchors.charge_to(&gauge);
        assert_eq!(anchors.charged(), PLANNED_BYTES);
        anchors.charge_to(&gauge);
        assert_eq!(anchors.charged(), PLANNED_BYTES);
        assert!(anchors.charged_in_full().is_ok());
        // A store a byte short: not charged in full, which refuses a start.
        anchors.charge_to(&Gauge::new(
            crate::budget::Store::Anchors,
            PLANNED_BYTES - 1,
        ));
        assert!(anchors.charged_in_full().is_err());
    }

    /// A relay issues one anchor a period and signs none while it cannot sign.
    #[test]
    fn a_relay_issues_one_anchor_a_period() {
        let anchors = Anchors::new();
        let relay = Identity::from_seed([1; 32]);
        let mut signed = 0;
        let mut sign = |j: tally_wire::clocks::Judged| {
            signed += 1;
            Some(Anchor::sign(&relay, j.ms()))
        };
        let first = anchors.issue(judged(NOW), raw(10), &mut sign);
        assert_eq!(
            anchors.issue(judged(NOW + 999), raw(1_009), &mut sign),
            first
        );
        let next = anchors.issue(judged(NOW + 1_000), raw(1_010), &mut sign);
        assert_eq!(next.map(|anchor| anchor.j_ms), Some(NOW + 1_000));
        assert_eq!(signed, 2);
        assert_eq!(
            anchors.issue(judged(NOW + 5_000), raw(5_010), |_| None),
            None
        );
        assert_eq!(anchors.issued_by(NOW), Some(raw(10)));
        assert_eq!(anchors.issued_by(NOW + 1_000), Some(raw(1_010)));
        // Never issued this run (its key's in an earlier one): issued before this run's first.
        assert_eq!(anchors.issued_by(NOW + 999), Some(raw(10)));
        assert_eq!(Anchors::new().issued_by(NOW), None);
    }

    /// A relay remembers its own anchors' issue on its raw clock for as long as an honest batch
    /// can carry one (`OWN_ANCHOR_OLDEST`) and no longer, in a ring of fixed size however often it
    /// issues; a step back of its judging clock that issues a reading twice answers the latest
    /// issue, so an age measured from it is never overstated.
    #[test]
    fn a_relay_remembers_its_own_anchors_issue_while_a_batch_may_carry_them() {
        let anchors = Anchors::new();
        let relay = Identity::from_seed([1; 32]);
        let sign = |j: tally_wire::clocks::Judged| Some(Anchor::sign(&relay, j.ms()));
        let oldest = tally_wire::budget::OWN_ANCHOR_OLDEST
            .span::<tally_wire::clocks::Judged>()
            .ms();
        for second in 0..200_u64 {
            anchors.issue(judged(NOW + second * 1_000), raw(second * 1_000), sign);
            assert!(lock(&anchors.own).len() <= OWN_ISSUES);
        }
        let last = 199_000;
        assert_eq!(anchors.issued_by(NOW + last), Some(raw(last)));
        let kept = NOW + (last - oldest).div_ceil(1_000) * 1_000;
        assert_eq!(anchors.issued_by(kept), Some(raw(kept - NOW)));
        // Let go: issued no later than the newest issue let go, the one before the oldest kept.
        assert_eq!(
            anchors.issued_by(kept - 1_000),
            Some(raw(kept - NOW - 1_000))
        );
        assert_eq!(anchors.issued_by(NOW), Some(raw(kept - NOW - 1_000)));
        // The judging clock stepped back a minute: the reading issued again is the newer issue.
        let again = NOW + last - 60_000;
        anchors.issue(judged(again), raw(last + 1_000), sign);
        assert_eq!(anchors.issued_by(again), Some(raw(last + 1_000)));
    }

    /// The ring holds every own anchor an honest batch may carry while the judging clock is
    /// slewed at chrony's fastest rate (`maxslewrate` 83,333 ppm), either way: issues are paced by
    /// the raw clock the ring is sized by, so one issued `OWN_ANCHOR_OLDEST` less a period ago by
    /// it is still remembered, asked for every 100 ms. Before, an anchor was issued each period of
    /// the judging clock, one more every twelve seconds at that slew, and the ring forgot the
    /// oldest some four seconds early.
    #[test]
    fn a_slewed_judging_clock_forgets_no_own_anchor_early() {
        let relay = Identity::from_seed([1; 32]);
        let sign = |j: tally_wire::clocks::Judged| Some(Anchor::sign(&relay, j.ms()));
        let oldest = tally_wire::budget::OWN_ANCHOR_OLDEST
            .span::<tally_wire::clocks::Judged>()
            .ms();
        for ppm in [83_333_i64, -83_333] {
            let anchors = Anchors::new();
            let judging =
                |at: u64| NOW.saturating_add_signed(at as i64 + at as i64 * ppm / 1_000_000);
            let mut issued = Vec::new();
            let mut at = 0;
            while at <= oldest + 20_000 {
                if let Some(anchor) = anchors.issue(judged(judging(at)), raw(at), sign) {
                    issued.push((anchor.j_ms, at));
                }
                at += 100;
            }
            let now = at - 100;
            let (j_ms, at) = issued
                .iter()
                .copied()
                .filter(|(_, at)| now - at <= oldest - 1_000)
                .min_by_key(|(_, at)| *at)
                .unwrap_or_default();
            assert_eq!(
                anchors.issued_by(j_ms),
                Some(raw(at)),
                "forgotten at {ppm} ppm"
            );
        }
    }
}
