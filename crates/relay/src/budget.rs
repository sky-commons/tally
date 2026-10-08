//! Capacity is admission, never a silent drop inside a store (RFC-0177 §9). Each store that holds
//! something per feeder ([`Store`]) states what one feeder costs it ([`PerFeeder::planned`]); a
//! feeder's bytes in every store are reserved together when it is admitted ([`Budget::reserve`]),
//! beside the upload cap's headroom check (RFC-0171, `admission`), and released when it leaves
//! ([`Reservation`] dropped). The feeder ceiling is what the relay's memory (`--memory`, by default
//! what the relay's cgroup or the host allows, [`memory_available`]) holds of that sum; a Hello
//! beyond it is refused ("no spare slot"). The MLAT engine's receiver limit comes from the same
//! ceiling. Whatever still overflows is refused whole (a whole receiver, bin, area or second),
//! counted and published.
//!
//! The per-feeder costs are planning figures at the rate the RFC sizes a feeder to
//! ([`PLANNED_RECEPTIONS_PER_SEC`], [`PLANNED_BYTES_PER_SEC`]) times each store's own window,
//! named where the store defines it, so a store that changes its window changes its reservation.

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

    /// What one feeder at the planned rate costs each store over that store's window. `holds_raw`:
    /// whether this relay holds MLAT raw (`Held`) at all, which it does only when it hosts MLAT.
    pub fn planned(holds_raw: bool) -> Self {
        let receptions = PLANNED_RECEPTIONS_PER_SEC;
        let bytes = PLANNED_BYTES_PER_SEC;
        Self {
            // The one batch byte store, over the sharing repair horizon.
            batches: bytes * crate::sharing::member::HORIZON_SECONDS as usize,
            // MLAT's raw (`Held`): its open bins over a bin and the engine's settling, and the
            // sealed bins a holder keeps, at the rates measured (`held::Rates::MEASURED`).
            held: if holds_raw {
                tally_mlat_solver::held::Rates::MEASURED
                    .cost(crate::mlat_host::SETTLE_MS)
                    .total()
            } else {
                0
            },
            // Two generations of fingerprints, one epoch each (`exchange`).
            dedup: receptions * 2 * DEDUP_ENTRY_BYTES,
            // A subscriber's queue holds `BEHIND_MS` of inbound: the batches, and while they wait
            // their one decode (a reception's reference and its inflated bytes).
            fanout: (bytes + receptions * (DECODED_BYTES_PER_RECEPTION))
                * crate::fanout::BEHIND_MS as usize
                / 1_000,
            // A delivery tag per batch over the audit window (`delivery`).
            delivery: crate::delivery::PER_FEEDER_BYTES,
            // A connection's Noise buffers come from one pool and an idle connection holds none
            // (`noise`): what the pool keeps idle is the process's (`BASE_BYTES`), not a feeder's.
            buffers: 0,
        }
    }
}

/// The rate the RFC sizes one feeder to: about 600 receptions and 8 KB of signed batches a second
/// (RFC-0177, "Requirement").
pub const PLANNED_RECEPTIONS_PER_SEC: usize = 600;
pub const PLANNED_BYTES_PER_SEC: usize = 8 * 1024;
/// One fingerprint remembered: 128 bits, the areas heard, and the table's slack.
const DEDUP_ENTRY_BYTES: usize = 64;
/// One reception's reference in a decoded batch, and its message inflated.
const DECODED_BYTES_PER_RECEPTION: usize = 24 + 14;
/// What the relay holds whatever its feeders: descriptions, stream tables, the runtime, and the
/// connection buffers the Noise pool keeps idle (`noise::POOL_IDLE` messages).
pub const BASE_BYTES: usize =
    (1 << 30) + tally_wire::noise::POOL_IDLE * tally_wire::noise::MAX_MESSAGE;

/// The bytes this relay may use, unless told (`--memory`): its cgroup's limit when it has one,
/// else the host's memory.
pub fn memory_available() -> usize {
    cgroup_limit()
        .or_else(host_memory)
        .unwrap_or(BASE_BYTES * 4)
}

/// cgroup v2's `memory.max` for this process, when it is a number.
fn cgroup_limit() -> Option<usize> {
    let membership = std::fs::read_to_string("/proc/self/cgroup").ok()?;
    let path = membership
        .lines()
        .find_map(|line| line.strip_prefix("0::"))?
        .trim();
    let max = std::fs::read_to_string(format!("/sys/fs/cgroup{path}/memory.max")).ok()?;
    max.trim().parse().ok()
}

/// `MemTotal` of `/proc/meminfo`.
fn host_memory() -> Option<usize> {
    let meminfo = std::fs::read_to_string("/proc/meminfo").ok()?;
    let kib: usize = meminfo
        .lines()
        .find_map(|line| line.strip_prefix("MemTotal:"))?
        .trim()
        .trim_end_matches("kB")
        .trim()
        .parse()
        .ok()?;
    kib.checked_mul(1024)
}

/// The relay's memory for feeders, and how much of it admitted feeders hold.
#[derive(Debug)]
pub struct Budget {
    total: usize,
    per_feeder: PerFeeder,
    reserved: Arc<AtomicUsize>,
}

impl Budget {
    /// The budget of a relay that may use `memory` bytes: what is left after `BASE_BYTES`.
    pub fn of_memory(memory: usize, per_feeder: PerFeeder) -> Self {
        Self::new(memory.saturating_sub(BASE_BYTES), per_feeder)
    }

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

    pub fn per_feeder(&self) -> PerFeeder {
        self.per_feeder
    }

    /// What every admitted feeder together may hold in `store`, at the ceiling.
    pub fn store_bytes(&self, store: Store) -> usize {
        self.per_feeder.of(store).saturating_mul(self.ceiling())
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

    #[test]
    fn the_planned_feeder_reserves_every_store_and_raw_only_where_held() {
        let without = PerFeeder::planned(false);
        let with = PerFeeder::planned(true);
        assert_eq!(without.held, 0);
        assert!(with.held > 0);
        for store in [Store::Batches, Store::Dedup, Store::Fanout, Store::Delivery] {
            assert!(without.of(store) > 0, "{store:?}");
        }
        // A relay of 64 GiB holds thousands of planned feeders, never none.
        let budget = Budget::of_memory(64 << 30, with);
        assert!(budget.ceiling() > 1_000);
        assert!(memory_available() > 0);
    }
}
