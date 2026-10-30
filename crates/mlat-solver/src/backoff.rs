//! Which transmissions are solved (crate docs, § Solving, how many): one an aircraft a slot of
//! its transmit timeline, mlat-server's resolve backoff made a rule of the transmissions alone
//! (adsb.lol's `RESOLVE_BACKOFF`, 0.7 s, after which mlat-server solves an aircraft again).
//!
//! - **The slot** of a transmission is its aircraft's address and its heard time
//!   (`pair::Models::heard_unix_ns`, Unix nanoseconds by its reference clock) in whole
//!   [`SLOT_MS`] since the Unix epoch: aligned on the timeline, never on when a holder saw it.
//! - **The choice** of a slot is the transmission of most distinct receivers the models locate
//!   ([`Rank`]), ties to the lower message hash, then the lower lowest reception: a total order,
//!   so the same transmission whatever order the candidates came in.
//! - **When**: a slot is decided at the first step at least [`SLOT_MS`] after its earliest
//!   candidate fell due ([`Slots::decide`]): a transmission of the slot was sent at most a slot
//!   after that one, and its receptions reach the holder over the same spread of sealing phases,
//!   so it falls due within the slot's length of the first. A candidate of a slot already decided
//!   is never solved.
//! - **Never solved, counted**: every candidate not chosen, which [`Slots::offer`] hands back.
//!   Its receptions are the raw like any other, and nothing published cites them.
//! - mlat-server also solves an aircraft early when the new group has more degrees of freedom
//!   than its last result less the time since (`mlattrack.py`). That needs the order results were
//!   reached in, so it is not a rule of the transmissions: it is left out. A chosen transmission's
//!   complete fix (bigger, once its raw has come, `tally_mlat`'s engine) is what more receivers
//!   buy.
//!
//! The choice is the engine's division of work, as ownership is: a fix is judged by the models it
//! cites and its own receptions (§ Verifying a fix), never by which transmission of its slot it
//! was. The choice is a function of the due sets and the steps they fell due at, never of the
//! order they were handed over in or of another holder's fixes: two holders handed the same due
//! sets at the same steps choose the same transmissions, and a holder replaying the same arrivals
//! replays the choice. A fix's verifier holds only the fix's own receptions, so it cannot, and
//! need not.

use std::cmp::Reverse;
use std::collections::BTreeMap;

use crate::obs::ObservationId;

/// The length of a slot: mlat-server's `RESOLVE_BACKOFF`.
pub const SLOT_MS: u64 = 700;
const SLOT_NS: u64 = SLOT_MS * 1_000_000;

/// What a holder solves and publishes for each receiver it seats, a thousand seconds of the
/// receiver's at a time, at most: what the relay's tables sized by the fixes are planned at (its
/// book, what its engine remembers it solved, and its positions; `tally_relay::standing`). One
/// transmission an aircraft a slot is solved, not every transmission heard, so these follow the
/// slots and not the receptions kept.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Published {
    /// Sets of receptions due, each again as it grows: what a holder remembers it took up
    /// (`tally_mlat::fix::Solved`), at most.
    pub due_per_ks: usize,
    /// Transmissions solved, published or not.
    pub solved_per_ks: usize,
    /// Of them, fixes published (one a transmission; its complete fix once its raw has come is
    /// the relay's to plan, `tally_mlat::fix`).
    pub published_per_ks: usize,
    /// The receptions the fixes published considered.
    pub considered_per_ks: usize,
}

impl Published {
    /// Measured over the pairwise path at world density (`pair_tests::pairwise_path_sweep`, one
    /// seed for 60 s, 120 receivers in twelve areas, the densest scene and so the dearest a seat;
    /// 2026-10-26), from the first fix published on, each rounded up: the sweep fails a run past
    /// them. The receivers kept 155 receptions a second there, the rate the arrived pool is
    /// planned at (`arrived::Rates::MEASURED`). Before, every kept reception was planned in a
    /// transmission solved of the fewest receivers a fix cites, 50 a receiver a second.
    pub const MEASURED: Self = Self {
        due_per_ks: 9_000,
        solved_per_ks: 3_300,
        published_per_ks: 2_700,
        considered_per_ks: 79_000,
    };
}

/// A slot: an aircraft's address and the whole [`SLOT_MS`] since the Unix epoch its transmission
/// was heard in.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Slot {
    pub address: u32,
    pub index: u64,
}

impl Slot {
    /// The slot of a transmission of `address` heard at `heard_unix_ns`.
    pub fn of(address: u32, heard_unix_ns: u64) -> Self {
        Self {
            address,
            index: heard_unix_ns / SLOT_NS,
        }
    }
}

/// How a slot's candidates are ranked, the least the best: most distinct receivers located, then
/// the lower message hash, then the lower lowest reception.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Rank {
    receivers: Reverse<usize>,
    message: [u8; 32],
    first: ObservationId,
}

impl Rank {
    pub fn new(receivers: usize, first: ObservationId) -> Self {
        Self {
            receivers: Reverse(receivers),
            message: first.message,
            first,
        }
    }
}

/// A slot being decided: when, and its best candidate so far.
struct Open<T> {
    decide_ms: u64,
    rank: Rank,
    best: T,
}

/// The slots of one holder (module docs): those being decided, each with its best candidate (an
/// item `T` of the holder's), and those decided, remembered while a candidate of theirs may still
/// fall due.
pub struct Slots<T> {
    open: BTreeMap<Slot, Open<T>>,
    decided: BTreeMap<Slot, u64>,
}

impl<T> Default for Slots<T> {
    fn default() -> Self {
        Self {
            open: BTreeMap::new(),
            decided: BTreeMap::new(),
        }
    }
}

impl<T> Slots<T> {
    /// Offers a candidate of `slot`, ranked `rank`, that fell due at `due_ms` (its set's first
    /// arrival and the settle, the holder's arrival clock). The slot keeps the better of it and
    /// its best so far, and the other is backed off, never solved: returned, as is the candidate
    /// of a slot already decided. `None` when it is the slot's first.
    pub fn offer(&mut self, slot: Slot, rank: Rank, due_ms: u64, item: T) -> Option<T> {
        if self.decided.contains_key(&slot) {
            return Some(item);
        }
        let decide_ms = due_ms.saturating_add(SLOT_MS);
        match self.open.get_mut(&slot) {
            None => {
                self.open.insert(
                    slot,
                    Open {
                        decide_ms,
                        rank,
                        best: item,
                    },
                );
                None
            }
            Some(open) => {
                open.decide_ms = open.decide_ms.min(decide_ms);
                if rank < open.rank {
                    open.rank = rank;
                    Some(std::mem::replace(&mut open.best, item))
                } else {
                    Some(item)
                }
            }
        }
    }

    /// Decides every slot whose earliest candidate fell due `SLOT_MS` or more before `now_ms`:
    /// their best candidates, in the slots' order.
    pub fn decide(&mut self, now_ms: u64) -> Vec<T> {
        let ready: Vec<Slot> = self
            .open
            .iter()
            .filter(|(_, open)| open.decide_ms <= now_ms)
            .map(|(slot, _)| *slot)
            .collect();
        ready
            .into_iter()
            .filter_map(|slot| {
                let open = self.open.remove(&slot)?;
                self.decided.insert(slot, now_ms);
                Some(open.best)
            })
            .collect()
    }

    /// Forgets the slots decided more than `held_ms` before `now_ms`: no candidate of theirs falls
    /// due any more.
    pub fn forget(&mut self, now_ms: u64, held_ms: u64) {
        self.decided
            .retain(|_, decided_ms| decided_ms.saturating_add(held_ms) >= now_ms);
    }

    /// Whether `slot` is decided: every candidate offered to it now is backed off.
    pub fn is_decided(&self, slot: Slot) -> bool {
        self.decided.contains_key(&slot)
    }

    /// Slots being decided.
    pub fn open(&self) -> usize {
        self.open.len()
    }

    /// What it allocates: its trees' entries, and each held candidate's own allocation by
    /// `item_bytes`.
    pub fn bytes(&self, item_bytes: impl Fn(&T) -> usize) -> usize {
        let open = size_of::<(Slot, Open<T>)>() + 2 * size_of::<usize>();
        let decided = size_of::<(Slot, u64)>() + 2 * size_of::<usize>();
        self.open.len() * open
            + self.decided.len() * decided
            + self
                .open
                .values()
                .map(|open| item_bytes(&open.best))
                .sum::<usize>()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(byte: u8, message: u8) -> ObservationId {
        ObservationId {
            receiver: tally_wire::Identity::from_seed([byte; 32]).public(),
            epoch: 0,
            timestamp: u64::from(byte),
            message: [message; 32],
        }
    }

    /// A slot keeps the candidate of most receivers whatever order they are offered in, backs the
    /// others off, is decided a slot after its earliest candidate fell due, and backs off what
    /// comes after.
    #[test]
    fn a_slot_chooses_one_transmission_in_any_order() {
        let slot = Slot::of(7, 3 * SLOT_NS + 5);
        assert_eq!(slot, Slot::of(7, 4 * SLOT_NS - 1));
        assert_ne!(slot, Slot::of(7, 4 * SLOT_NS));
        let candidates = [
            (5, id(1, 9), 1_000),
            (8, id(2, 9), 1_400),
            (8, id(3, 4), 1_200),
        ];
        for order in [[0, 1, 2], [2, 1, 0], [1, 0, 2]] {
            let mut slots = Slots::default();
            let mut backed = 0;
            for at in order {
                let (receivers, first, due) = candidates[at];
                backed += usize::from(
                    slots
                        .offer(slot, Rank::new(receivers, first), due, at)
                        .is_some(),
                );
            }
            assert_eq!(backed, 2);
            assert!(slots.decide(1_000 + SLOT_MS - 1).is_empty());
            // Eight receivers each: the lower message hash.
            assert_eq!(slots.decide(1_000 + SLOT_MS), vec![2]);
            assert_eq!(
                slots.offer(slot, Rank::new(20, id(4, 0)), 1_800, 3),
                Some(3)
            );
            slots.forget(1_700 + 10_000, 10_000);
            assert_eq!(slots.decided.len(), 1);
            slots.forget(1_701 + 10_000, 10_000);
            assert_eq!(slots.decided.len(), 0);
        }
    }
}
