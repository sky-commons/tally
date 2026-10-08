//! Capacity is admission, never a silent drop inside a store (RFC-0177 §9). Each store that holds
//! something per feeder ([`Store`]) states what one feeder costs it; a feeder's bytes in every
//! store are reserved together when it is admitted ([`Budget::reserve`]), in the same headroom
//! check RFC-0171 uses for egress, and released when it leaves ([`Reservation`] dropped). The
//! feeder ceiling is what the relay's memory holds of that sum; a Hello beyond it is refused ("no
//! spare slot"). The MLAT engine's receiver limit comes from the same ceiling. Whatever still
//! overflows is refused whole (a whole receiver, bin, area or second), counted and published.
//!
//! Step 1 of the RFC: the budget and its arithmetic are defined; admission does not consult it yet,
//! and each store still bounds itself as before.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

/// The stores that hold bytes per feeder.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Store {
    /// The one batch byte store, over the sharing repair horizon.
    Batches,
    /// MLAT's raw (`Held`), shared by the engine and standing.
    Held,
    /// The message exchange's two generations of fingerprints.
    Dedup,
    /// Subscriber queues' share of one feeder's inbound.
    Fanout,
    /// Delivery tags over the audit window.
    Delivery,
    /// Connection buffers.
    Buffers,
}

/// What one feeder costs each store, in bytes.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PerFeeder {
    pub batches: usize,
    pub held: usize,
    pub dedup: usize,
    pub fanout: usize,
    pub delivery: usize,
    pub buffers: usize,
}

impl PerFeeder {
    pub fn of(&self, store: Store) -> usize {
        match store {
            Store::Batches => self.batches,
            Store::Held => self.held,
            Store::Dedup => self.dedup,
            Store::Fanout => self.fanout,
            Store::Delivery => self.delivery,
            Store::Buffers => self.buffers,
        }
    }

    /// Every store's cost together: what admitting one feeder reserves.
    pub fn total(&self) -> usize {
        self.batches
            .saturating_add(self.held)
            .saturating_add(self.dedup)
            .saturating_add(self.fanout)
            .saturating_add(self.delivery)
            .saturating_add(self.buffers)
    }
}

/// The relay's memory for feeders, and how much of it admitted feeders hold.
#[derive(Debug)]
pub struct Budget {
    total: usize,
    per_feeder: PerFeeder,
    reserved: Arc<AtomicUsize>,
}

impl Budget {
    pub fn new(total: usize, per_feeder: PerFeeder) -> Self {
        Self {
            total,
            per_feeder,
            reserved: Arc::new(AtomicUsize::new(0)),
        }
    }

    /// The most feeders the budget admits: the feeder ceiling.
    pub fn ceiling(&self) -> usize {
        self.total
            .checked_div(self.per_feeder.total())
            .unwrap_or(usize::MAX)
    }

    /// Reserves one feeder's bytes in every store, or `None` when they do not fit (the Hello is
    /// refused).
    pub fn reserve(&self) -> Option<Reservation> {
        let needed = self.per_feeder.total();
        self.reserved
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |reserved| {
                reserved
                    .checked_add(needed)
                    .filter(|after| *after <= self.total)
            })
            .ok()?;
        Some(Reservation {
            bytes: needed,
            reserved: Arc::clone(&self.reserved),
        })
    }

    pub fn reserved(&self) -> usize {
        self.reserved.load(Ordering::Acquire)
    }
}

/// One admitted feeder's bytes, released when it is dropped.
#[derive(Debug)]
pub struct Reservation {
    bytes: usize,
    reserved: Arc<AtomicUsize>,
}

impl Drop for Reservation {
    fn drop(&mut self) {
        self.reserved.fetch_sub(self.bytes, Ordering::AcqRel);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_feeder_is_admitted_only_with_room_in_every_store_and_leaving_frees_it() {
        let per_feeder = PerFeeder {
            batches: 10,
            held: 20,
            ..PerFeeder::default()
        };
        let budget = Budget::new(65, per_feeder);
        assert_eq!(budget.ceiling(), 2);
        let first = budget.reserve();
        let second = budget.reserve();
        assert!(first.is_some() && second.is_some());
        assert!(budget.reserve().is_none());
        drop(first);
        assert_eq!(budget.reserved(), 30);
        assert!(budget.reserve().is_some());
    }
}
