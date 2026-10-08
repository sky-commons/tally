//! Withdrawing from stripes when the upload cap is full (RFC-0174 §2.5, "The cap stays the
//! ceiling"). The egress serves its classes in order and, past what the cap carries, sheds peers
//! (`egress`); a peer that forwards shed is the sign that this relay cannot carry its slice. Then
//! it withdraws: one region it takes at a time, it forwards nothing there (a leaf in every tree of
//! every group under it) and its offers for the region say so (`stripes` 0), so every member lays
//! the trees out without it and the ordering's next member takes its place.
//!
//! - **Deterministic order.** Regions are withdrawn in the order of a rendezvous score over (region,
//!   this relay's key), highest first, and taken back last first: the same relay under the same
//!   pressure always gives up the same regions, and the relays of one area do not all give up the
//!   same one.
//! - **One step at a time.** At most one region every [`WITHDRAW_EVERY_MS`], so a withdrawal is
//!   re-signed, gossiped and laid out (and its load gone from the cap) before the next is judged.
//! - **Back when quiet.** Once no forwarding peer has been shed for [`RESTORE_AFTER_MS`], one region
//!   is taken back, then another after as long again.

use tally_wire::{PublicKey, Region, Streams};

use super::stripes::score;

/// The least time between two regions withdrawn.
pub const WITHDRAW_EVERY_MS: u64 = 30 * 1000;
/// How long with no forwarding peer shed before one withdrawn region is taken back.
pub const RESTORE_AFTER_MS: u64 = 10 * 60 * 1000;

const WITHDRAW: &[u8] = b"tally sharing withdraw";

#[derive(Clone, Debug, Default)]
pub struct Withdrawal {
    /// The egress's count of forwarding peers shed, as last seen.
    shed: Option<u64>,
    /// The regions withdrawn, in the order they were.
    withdrawn: Vec<Region>,
    /// When a region was last withdrawn or taken back, and when a forwarder was last shed.
    changed_ms: u64,
    pressed_ms: u64,
}

impl Withdrawal {
    /// One look: `shed` is the egress's running count of forwarding peers shed, `regions` the
    /// regions this relay takes now. Withdraws or takes back at most one region.
    pub fn observe(&mut self, shed: u64, regions: &[Region], me: &PublicKey, now_ms: u64) {
        self.withdrawn.retain(|region| regions.contains(region));
        let pressed = self.shed.is_some_and(|seen| shed > seen);
        self.shed = Some(shed);
        if pressed {
            self.pressed_ms = now_ms;
            if now_ms.saturating_sub(self.changed_ms) >= WITHDRAW_EVERY_MS
                && let Some(next) = order(regions, me)
                    .into_iter()
                    .find(|region| !self.withdrawn.contains(region))
            {
                self.withdrawn.push(next);
                self.changed_ms = now_ms;
            }
            return;
        }
        if !self.withdrawn.is_empty()
            && now_ms.saturating_sub(self.pressed_ms) >= RESTORE_AFTER_MS
            && now_ms.saturating_sub(self.changed_ms) >= RESTORE_AFTER_MS
        {
            self.withdrawn.pop();
            self.changed_ms = now_ms;
        }
    }

    /// The regions withdrawn, in the order they were.
    pub fn withdrawn(&self) -> &[Region] {
        &self.withdrawn
    }

    /// Whether `cell` overlaps a withdrawn region (lies in one, or holds one): an offer for it
    /// says this relay forwards nothing there.
    pub fn covers(&self, cell: Region) -> bool {
        self.withdrawn
            .iter()
            .any(|region| region.contains(cell) || cell.contains(*region))
    }
}

/// The order regions are withdrawn in: by the rendezvous score over (region, key), highest first.
pub fn order(regions: &[Region], me: &PublicKey) -> Vec<Region> {
    let mut ordered = regions.to_vec();
    ordered.sort_by_key(|region| {
        std::cmp::Reverse((
            score(WITHDRAW, *region, Streams(0), 0, 0, &[me]),
            region.as_u64(),
        ))
    });
    ordered.dedup();
    ordered
}
