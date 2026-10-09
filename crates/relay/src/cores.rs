//! What the relay's cores carry (RFC-0181 §10, "Sizing"): the CPU half of admission, beside the
//! memory half (`budget`). Each stage's threads follow the load the relay is planned to admit,
//! never a fixed share of the host: the feeders its budget admits and the feeders its members'
//! shared rate is worth (`Budget::load`), each at the planned rate (one batch a second of
//! `PLANNED_RECEPTIONS_PER_SEC` receptions), over what one thread of that stage was measured to
//! sustain, with [`BUSY_PERCENT`] of headroom ([`threads_for`]). And the feeders a relay admits
//! are no more than its cores carry ([`feeders_carried`]): a feeder past them is turned away at
//! its Hello as a feeder past the memory is, and a relay whose cores cannot carry its members'
//! rate and one feeder beside it refuses to start (`Budget::check`).
//!
//! Before, the stages took a quarter of the cores for ingest and an eighth for the message
//! exchange whatever the load: a 10-core relay admitting 5,000 feeders (about 3 M receptions a
//! second) ran one message thread, 66% busy on average and saturated at each epoch's close, so its
//! queue filled, the ingest workers waited on it (raw's back-pressure, §10), and raw's p99 was
//! 0.6 to 1.2 s run to run; at the 20,000 feeders the RFC plans for, one thread could not keep up
//! at all, and the budget admitted them anyway.
//!
//! The capacities are measured (2026-10-09, `tally-load` built `-c opt`, the relay alone on cores
//! 0-9 of a 32-core host and the harness on 10-31, two areas, 60 s measured after a 60 s ramp and
//! 30 s warm-up): each stage's threads' CPU time over the measured minute, read from
//! `/proc/<pid>/task/*/stat`, beside the receptions and batches the subscriber read. Each figure is
//! the least a thread sustained over the thread counts and loads tried, so a stage is never sized
//! on its best case. A relay that holds MLAT raw (it hosts MLAT) does more in its ingest workers
//! (each batch's raw into its receivers' open bins), its sealer (the bins sealed) and its runtime
//! (the raw links), measured apart (2,000 feeders, two MLAT threads), and plans by those.
//!
//! The hosted MLAT engine's own threads (`--mlat-threads`) are not planned here: the engine sheds
//! whole steps it falls behind on, counted, and never pushes back on ingest (§10).

use crate::budget::PLANNED_RECEPTIONS_PER_SEC;
use crate::ingest::Threads;

/// Receptions a second one ingest worker sustains, each batch verified, hashed, admitted,
/// inflated, decoded and routed. Measured: 3.05 M receptions a second (5,040 batches) cost two
/// workers 0.594 of a core together (195 ns a reception), 3.02 M (5,000 batches) cost four 0.636
/// (211 ns), and 4.61 M (6,742 batches of 683 receptions) cost four 1.018 (221 ns, 151 us a batch).
/// 221 ns is 4.5 M receptions a second, 7,500 planned batches.
pub const INGEST_RECEPTIONS_PER_THREAD: usize = 4_500_000;
/// The same where MLAT raw is held. Measured: 1.21 M receptions a second (2,000 batches) cost two
/// workers 0.352 of a core (290 ns): 3.4 M receptions a second, 5,700 planned batches.
pub const INGEST_RECEPTIONS_PER_THREAD_HOLDING_RAW: usize = 3_400_000;

/// Receptions a second one message thread sustains, deduplicating its shards. Measured: 3.05 M
/// receptions a second cost one thread 0.660 of a core (216 ns a reception), 3.02 M cost two
/// threads 0.557 together and four 0.468, and 4.61 M cost four 0.620 (134 ns): a thread's shards
/// fit its caches better the fewer they are, and the slice each batch sends each thread costs
/// nothing measurable beside its receptions. Holding MLAT raw changes nothing here (1.21 M cost two
/// threads 0.159, 131 ns). 216 ns is 4.6 M receptions a second, 7,600 planned batches.
pub const MESSAGE_RECEPTIONS_PER_THREAD: usize = 4_600_000;

/// Receptions a second one sealer thread sustains, the sealer and its pool together (cutting,
/// signing and deriving each epoch's records). Measured: 3.02 M to 3.05 M receptions a second
/// cost the sealer alone 0.517 of a core, the sealer and one helper 0.506 together and the
/// sealer and three helpers 0.538 (178 ns a reception); 4.61 M cost the sealer and three helpers
/// 0.492 (107 ns). 178 ns is 5.6 M receptions a second, 9,300 planned batches. The part of it no
/// helper takes (gathering each epoch from every message thread, numbering its records in cell
/// order, applying them) was 0.144 to 0.164 of a core at 3.02 M and 0.144 at 4.61 M: it follows
/// the epochs and the areas, not the receptions, so it bounds no feeder count.
pub const SEAL_RECEPTIONS_PER_THREAD: usize = 5_600_000;
/// The same where MLAT raw is held (its bins sealed too). Measured: 1.21 M receptions a second
/// cost the sealer and one helper 0.370 of a core (305 ns): 3.2 M receptions a second.
pub const SEAL_RECEPTIONS_PER_THREAD_HOLDING_RAW: usize = 3_200_000;

/// Planned feeders one core of the async runtime carries: each one's Noise session and its
/// batches' framing, the fan-out's writes to subscribers, the links and the stats. Measured: ten
/// runtime workers took 0.404 to 0.412 of a core together at 5,000 feeders (82 us a feeder a
/// second), and 0.516 at 6,742 (77 us): 12,100 feeders a core.
pub const RUNTIME_FEEDERS_PER_CORE: usize = 12_000;
/// The same where MLAT raw is held. Measured: 0.243 of a core at 2,000 feeders (121 us a feeder a
/// second): 8,200 feeders a core.
pub const RUNTIME_FEEDERS_PER_CORE_HOLDING_RAW: usize = 8_000;

/// The most of each thread's time the plan fills at the planned rate: the rest is the headroom
/// for each epoch's close (every message thread freezes its shards and the sealer gathers them at
/// once, so a stage's load is bursty within the second) and for feeders above their planned rate.
/// Measured: one message thread 66% busy on average was saturated at each close, raw's p99 587 ms;
/// two at 28% each, 41 ms.
pub const BUSY_PERCENT: usize = 50;

/// A nanosecond of one core, a second.
const NANOS: usize = 1_000_000_000;

/// Nanoseconds of one core a second one thread is planned to spend ([`BUSY_PERCENT`] of it).
const PLANNED_PER_THREAD: usize = NANOS / 100 * BUSY_PERCENT;

/// The work of one stage of the relay.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Work {
    Ingest,
    Message,
    Seal,
    /// The async runtime's workers: not threads the plan sizes (the runtime starts one a core),
    /// but cores the plan spends.
    Runtime,
}

impl Work {
    pub const ALL: [Self; 4] = [Self::Ingest, Self::Message, Self::Seal, Self::Runtime];

    /// Nanoseconds of one core a second one planned feeder costs this work, in a relay that holds
    /// MLAT raw (`holds_raw`) or not.
    pub const fn per_feeder(self, holds_raw: bool) -> usize {
        let receptions = PLANNED_RECEPTIONS_PER_SEC;
        let per_thread = match (self, holds_raw) {
            (Self::Ingest, false) => INGEST_RECEPTIONS_PER_THREAD,
            (Self::Ingest, true) => INGEST_RECEPTIONS_PER_THREAD_HOLDING_RAW,
            (Self::Message, _) => MESSAGE_RECEPTIONS_PER_THREAD,
            (Self::Seal, false) => SEAL_RECEPTIONS_PER_THREAD,
            (Self::Seal, true) => SEAL_RECEPTIONS_PER_THREAD_HOLDING_RAW,
            (Self::Runtime, false) => return NANOS.div_ceil(RUNTIME_FEEDERS_PER_CORE),
            (Self::Runtime, true) => return NANOS.div_ceil(RUNTIME_FEEDERS_PER_CORE_HOLDING_RAW),
        };
        (NANOS * receptions).div_ceil(per_thread)
    }

    /// The threads this work needs for `load` planned feeders' worth, at least one, at most
    /// `cores` when they are known.
    pub fn threads_for(self, load: usize, holds_raw: bool, cores: Option<usize>) -> usize {
        let threads = load
            .saturating_mul(self.per_feeder(holds_raw))
            .div_ceil(PLANNED_PER_THREAD)
            .max(1);
        cores.map_or(threads, |cores| threads.min(cores.max(1)))
    }
}

/// Every stage's threads for `load` planned feeders' worth (the feeders admitted and those the
/// members' rate is worth), holding MLAT raw or not, on `cores` cores when they are known: what a
/// relay runs.
pub fn threads_for(load: usize, holds_raw: bool, cores: Option<usize>) -> Threads {
    Threads {
        ingest: Work::Ingest.threads_for(load, holds_raw, cores),
        message: Work::Message.threads_for(load, holds_raw, cores),
        seal: Work::Seal.threads_for(load, holds_raw, cores),
    }
}

/// The planned feeders' worth of load `cores` cores carry, holding MLAT raw or not: every
/// stage's work at the planned rate, the runtime's with it, in [`BUSY_PERCENT`] of them.
pub fn load_carried(cores: usize, holds_raw: bool) -> usize {
    let per_feeder: usize = Work::ALL
        .iter()
        .map(|work| work.per_feeder(holds_raw))
        .sum();
    cores
        .saturating_mul(PLANNED_PER_THREAD)
        .checked_div(per_feeder)
        .unwrap_or(usize::MAX)
}

/// The feeders `cores` cores carry beside `member_feeders`, the feeders the members' shared rate
/// is worth (which the plan holds first, as the memory's members' pool is): none when they carry
/// no more than the members.
pub fn feeders_carried(cores: usize, holds_raw: bool, member_feeders: usize) -> usize {
    load_carried(cores, holds_raw).saturating_sub(member_feeders)
}

/// The cores this process may run on: its affinity and its cgroup's CPU quota
/// (`std::thread::available_parallelism`), one when it cannot be read.
pub fn cores_available() -> usize {
    std::thread::available_parallelism().map_or(1, std::num::NonZero::get)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_stage_follows_the_load_and_never_runs_on_no_thread() {
        for holds_raw in [false, true] {
            // No load: one thread a stage, as a relay at rest needs.
            assert_eq!(
                threads_for(0, holds_raw, Some(16)),
                Threads {
                    ingest: 1,
                    message: 1,
                    seal: 1
                }
            );
            // The load the 2026-10-09 measurement ran: 5,000 feeders, about 3 M receptions a
            // second, which one message thread could not carry.
            let five = threads_for(5_000, holds_raw, Some(10));
            assert!(
                five.message >= 2 && five.ingest >= 2 && five.seal >= 2,
                "{five:?}"
            );
            // Four times the load, about four times the threads.
            let twenty = threads_for(20_000, holds_raw, None);
            assert!(
                twenty.message >= 4 * five.message - 3,
                "{twenty:?} {five:?}"
            );
            // Each thread planned at most BUSY_PERCENT of its time, and more than the threads
            // but one would be (no stage takes a thread it will not use).
            for (work, threads) in [
                (Work::Ingest, twenty.ingest),
                (Work::Message, twenty.message),
                (Work::Seal, twenty.seal),
            ] {
                let spent = 20_000 * work.per_feeder(holds_raw);
                assert!(
                    spent <= threads * PLANNED_PER_THREAD,
                    "{work:?} on {threads}"
                );
                assert!(
                    spent > (threads - 1) * PLANNED_PER_THREAD,
                    "{work:?} on {threads}"
                );
            }
            // Never more threads than cores.
            assert_eq!(threads_for(1_000_000, holds_raw, Some(3)).message, 3);
        }
        // Holding MLAT raw costs the ingest workers and the sealer more.
        assert!(threads_for(20_000, true, None).ingest > threads_for(20_000, false, None).ingest);
    }

    #[test]
    fn the_cores_carry_what_their_headroom_holds() {
        for holds_raw in [false, true] {
            // One core carries a relay's worth of feeders at the public relay's scale.
            assert!(feeders_carried(1, holds_raw, 0) > 100);
            // The load carried grows with the cores.
            assert_eq!(load_carried(10, holds_raw) / 10, load_carried(1, holds_raw));
            // At the load carried, the cores' planned share holds every stage's work.
            for cores in [1, 4, 10, 32] {
                let load = load_carried(cores, holds_raw);
                let spent: usize = Work::ALL
                    .iter()
                    .map(|work| load * work.per_feeder(holds_raw))
                    .sum();
                assert!(spent <= cores * PLANNED_PER_THREAD, "{cores}");
            }
            // The members' rate is carried first.
            let four = load_carried(4, holds_raw);
            assert_eq!(feeders_carried(4, holds_raw, four), 0);
            assert_eq!(feeders_carried(4, holds_raw, 10), four - 10);
        }
        // Holding raw, a core carries fewer.
        assert!(load_carried(10, true) < load_carried(10, false));
        // 5,000 feeders without MLAT fit the 10 cores they were measured on.
        assert!(load_carried(10, false) >= 5_000);
        assert!(cores_available() >= 1);
    }
}
