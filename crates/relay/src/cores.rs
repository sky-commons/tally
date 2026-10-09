//! What the relay's cores carry (RFC-0181 §10, "Sizing"): the CPU half of admission, beside the
//! memory half (`budget`). Each stage's threads follow the load the relay is planned to admit,
//! never a fixed share of the host: the feeders its budget admits and the feeders its members'
//! shared rate is worth (`Budget::load`), each at the planned rate (one batch a second of
//! `PLANNED_RECEPTIONS_PER_SEC` receptions, the measured mean: the reception pace bounds abuse, it
//! is not what the cores are planned for), over what one thread of that stage was measured to
//! sustain, with [`BUSY_PERCENT`] of headroom ([`threads_for`]). The ingest workers' share is the
//! more of those receptions and the records a second the source may send, each a signature
//! verified whatever its size ([`Source`], `ingest::INGEST_NANOS_PER_RECORD`); the runtime's is each
//! feeder's session and every record answered there ([`RUNTIME_NANOS_PER_RECORD`]), and the cores
//! hold each source's records once, at the dearer of the two ([`spent_per_feeder`]). A relay that
//! hosts MLAT plans its engine in the same cores: the stages keep their half-busy share for raw, and MLAT's steps take
//! what is left ([`mlat_threads_for`]), below the stages' priority (`mlat_host`, `Urgency`). And the feeders a relay admits are no more than
//! its cores carry, the stages' share and MLAT's together ([`feeders_carried`]): a feeder past them
//! is turned away at its Hello as a feeder past the memory is, and a relay whose cores cannot carry
//! its members' rate and one feeder beside it refuses to start (`Budget::check`).
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
//! Before, the hosted MLAT engine's threads were not planned (`--mlat-threads`, every core the
//! relay saw by default): its window steps spread over every core beside the stages, at the
//! stages' priority in its provisional steps, so on a relay hosting MLAT under load nothing kept a
//! core for raw.

use crate::budget::PLANNED_RECEPTIONS_PER_SEC;
use crate::ingest::{INGEST_NANOS_PER_RECORD, MEMBER_RECORDS_PER_FEEDER, Threads};

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

/// Nanoseconds of the async runtime one record answered there costs at most, whatever its size
/// (R4 of sweep 5): the records no ingest worker takes (an echo's reply signed, a delivery query's
/// answer signed, a clock model, positions or a description verified, a fault proof's two records
/// verified). The costliest is two signatures verified and the record parsed. Measured
/// (2026-10-09, release build, one core of the 32-core build host, `ed25519-dalek` as the relay
/// links it): a strict verification of a 64-byte message 26.8 us and of a 1 KiB one 28.1 us, a
/// signature made 10.5 us; two verifications of a kilobyte, 56 us, planned as 60. A source's
/// records are paced together (`ingest::RecordPace`), whichever of the two takes them, so each is
/// planned at the dearer of this and [`INGEST_NANOS_PER_RECORD`] ([`Source::records_nanos`]).
///
/// Before, only the ingest workers' share of a record was planned: a feeder's eight records a second
/// sent as echoes or fault proofs, each answered on the runtime, cost some 480 us of a core a
/// second the plan never held, beside the 83 us its session was planned.
pub const RUNTIME_NANOS_PER_RECORD: usize = 60_000;

/// The most of each thread's time the plan fills at the planned rate: the rest is the headroom
/// for each epoch's close (every message thread freezes its shards and the sealer gathers them at
/// once, so a stage's load is bursty within the second) and for feeders above their planned rate.
/// Measured: one message thread 66% busy on average was saturated at each close, raw's p99 587 ms;
/// two at 28% each, 41 ms.
pub const BUSY_PERCENT: usize = 50;

/// Nanoseconds of one core a second hosted MLAT's window steps cost a hosted feeder: the seals of
/// its raw, each window step's fits and solutions (spread over the step's threads,
/// `window::parallel`), and the engine's own thread that steps them. Measured (2026-10-09, the
/// relay built `-c opt` with each MLAT thread adding its own run time (`/proc/thread-self/schedstat`)
/// to its kind's count as it ended, on cores 0-9 of a 32-core host with the harness on 10-31, two
/// areas, eight MLAT threads; a window step came about every 40 s, so each is taken whole, after
/// the ramp): at 500 feeders a window step cost 10.0 and 11.0 cores-seconds (0.27 of a core), the
/// seals 0.058 of a core and the engine's thread 0.008, 0.68 ms a feeder a second; at 2,000 a
/// window step cost 39.4 cores-seconds every 41 s (0.96 of a core), the seals 0.21 and the engine's
/// thread 0.085, 0.63 ms. 0.68 ms is planned as 0.70.
pub const MLAT_WINDOW_NANOS_PER_FEEDER: usize = 700_000;
/// The same of its provisional steps: weighing what each batch told its address shards and solving
/// what is due, every second. Measured in the same runs, over each 10 s once the feeders were all
/// up: 0.14 to 0.20 of a core at 500 feeders (0.41 ms a feeder a second at its most), and 0.72 to
/// 0.80 at 2,000 (0.40 ms at its most). 0.41 ms.
pub const MLAT_PROVISIONAL_NANOS_PER_FEEDER: usize = 410_000;

/// The most of MLAT's share of the cores the plan fills with its measured cost. MLAT plans no
/// headroom of its own, unlike a stage ([`BUSY_PERCENT`]): it runs below the stages' priority, so
/// the half of the stages' share they leave idle on average is MLAT's too whenever they do not
/// need it, and what it cannot do in time it sheds, counted (`mlat_host`, Behind), never pushing
/// back on raw. Its window steps are bursty (a step every 40 s or so, each seconds of every thread
/// it has), which a window step past the steps MLAT may be behind absorbs by shedding the empty
/// steps queued behind it into the next (no window is lost); its provisional steps, every second,
/// run above the window steps.
pub const MLAT_BUSY_PERCENT: usize = 100;

/// A nanosecond of one core, a second.
const NANOS: usize = 1_000_000_000;

/// Nanoseconds of one core a second one thread is planned to spend ([`BUSY_PERCENT`] of it).
const PLANNED_PER_THREAD: usize = NANOS / 100 * BUSY_PERCENT;

/// Where one planned feeder's worth of load comes from, which decides what it costs the ingest
/// workers: a record costs them [`INGEST_NANOS_PER_RECORD`] whatever its receptions, so a source
/// costs the more of its planned receptions and the records a second it may send.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Source {
    /// A feeder, sending at most this many records a second (`ingest::records_per_sec` of its
    /// byte ceiling, `--max-feeder-bytes-per-sec`): eight at the default 256 KiB/s, so one sending
    /// tiny batches up to its pace costs the workers more than a planned feeder's receptions do.
    Feeder { records_per_sec: u64 },
    /// One planned feeder's worth of the members' shared rate, its records at
    /// `ingest::MEMBER_RECORDS_PER_FEEDER` a second.
    Member,
}

impl Source {
    /// The records a second it may send.
    pub const fn records_per_sec(self) -> u64 {
        match self {
            Self::Feeder { records_per_sec } => records_per_sec,
            Self::Member => MEMBER_RECORDS_PER_FEEDER,
        }
    }

    /// Nanoseconds of one core a second its records cost at most, wherever they are taken: each at
    /// the dearer of an ingest worker's ([`INGEST_NANOS_PER_RECORD`]) and the runtime's
    /// ([`RUNTIME_NANOS_PER_RECORD`]), since one pace holds them all and any may be either.
    pub const fn records_nanos(self) -> usize {
        let each = if RUNTIME_NANOS_PER_RECORD > INGEST_NANOS_PER_RECORD {
            RUNTIME_NANOS_PER_RECORD
        } else {
            INGEST_NANOS_PER_RECORD
        };
        (self.records_per_sec() as usize).saturating_mul(each)
    }
}

/// The sessions a relay holds beside its feeders and its members' rate, whose records the cores
/// carry on the async runtime (R4 of sweep 5), each paced at what its role legitimately sends
/// (`ingest`'s `RolePace`s, `link::Paces`): every session under the connection cap (not yet
/// identified, probes, engines; `--max-connections`) at the dearest of their paces
/// (`ingest::GENERAL_RECORDS_PER_MINUTE`), every subscriber (`--max-subscribers`) at its own
/// (`ingest::SUBSCRIBER_RECORDS`), and every directory link at the one pace they share
/// (`ingest::DIRECTORY_RECORDS`), planned once whatever the links (a directory link holds a place
/// under the cap, so a relay with none holds no directory link). Each record at
/// [`RUNTIME_NANOS_PER_RECORD`], at [`BUSY_PERCENT`]: a fixed share of the cores, taken before any
/// feeder's (`feeders_carried`). Before, only a feeder's and the members' records were planned,
/// while the 2,048 connections the cap allows by default could each send eight a second, some
/// 0.98 of a core the plan never held; now each is held to six a minute.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Sessions {
    /// The sessions under the connection cap (`--max-connections`).
    pub general: usize,
    /// The subscribers (`--max-subscribers`).
    pub subscribers: usize,
}

impl Sessions {
    /// The records a minute they may send together, at most.
    pub const fn records_per_minute(self) -> u64 {
        let general =
            (self.general as u64).saturating_mul(crate::ingest::GENERAL_RECORDS_PER_MINUTE);
        let subscribers =
            (self.subscribers as u64).saturating_mul(crate::ingest::SUBSCRIBER_RECORDS.per_minute);
        let directory = if self.general > 0 {
            crate::ingest::DIRECTORY_RECORDS.per_minute
        } else {
            0
        };
        // The bursts new sessions are granted, from one shared pace whatever reconnects
        // (`ingest::BURST_GRANTS`): planned once, as the directory's pace is.
        let bursts = if self.general > 0 || self.subscribers > 0 {
            crate::ingest::BURST_GRANTS.per_minute
        } else {
            0
        };
        general
            .saturating_add(subscribers)
            .saturating_add(directory)
            .saturating_add(bursts)
    }

    /// Nanoseconds of one core a second the plan sets aside for their records.
    pub const fn planned(self) -> usize {
        (self.records_per_minute() as usize)
            .saturating_mul(RUNTIME_NANOS_PER_RECORD)
            .div_ceil(60)
            .saturating_mul(100)
            .div_ceil(BUSY_PERCENT)
    }
}

/// The load a relay is planned to admit: its feeders, each sending at most `feeder_records_per_sec`
/// records a second, the feeders its members' shared rate is worth (`Budget::load`), and its other
/// sessions ([`Sessions`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Load {
    pub feeders: usize,
    pub member_feeders: usize,
    pub feeder_records_per_sec: u64,
    pub sessions: Sessions,
}

impl Load {
    /// The feeder's source of this load.
    pub const fn feeder(&self) -> Source {
        Source::Feeder {
            records_per_sec: self.feeder_records_per_sec,
        }
    }

    /// Nanoseconds of one core a second `cost` adds over this load: its feeders' and its members'.
    fn spent(&self, cost: impl Fn(Source) -> usize) -> usize {
        self.feeders
            .saturating_mul(cost(self.feeder()))
            .saturating_add(self.member_feeders.saturating_mul(cost(Source::Member)))
    }

    /// The planned feeders' worth it is: its feeders and the members' rate's.
    pub const fn planned_feeders(&self) -> usize {
        self.feeders.saturating_add(self.member_feeders)
    }
}

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

    /// Nanoseconds of one core a second one planned feeder's worth from `source` costs this work,
    /// in a relay that holds MLAT raw (`holds_raw`) or not, at its busiest: what its threads are
    /// sized by. The ingest workers' is the more of its planned receptions and its records a second
    /// at [`INGEST_NANOS_PER_RECORD`] each (R-N12): before, only the receptions were planned, while
    /// a feeder sending tiny batches up to its records' pace cost the workers 1.8 times a planned
    /// one. The runtime's is its session's and every record answered there
    /// ([`RUNTIME_NANOS_PER_RECORD`], R4 of sweep 5). The two count the same records, each the
    /// one stage's whole pace: what the cores spend on a source together is
    /// [`Work::receptions_part`] of each and its records once ([`Source::records_nanos`]).
    pub const fn per_feeder(self, holds_raw: bool, source: Source) -> usize {
        let part = self.receptions_part(holds_raw);
        let records = source.records_per_sec() as usize;
        match self {
            Self::Ingest => {
                let records = records.saturating_mul(INGEST_NANOS_PER_RECORD);
                if records > part { records } else { part }
            }
            Self::Runtime => part.saturating_add(records.saturating_mul(RUNTIME_NANOS_PER_RECORD)),
            Self::Message | Self::Seal => part,
        }
    }

    /// Nanoseconds of one core a second one planned feeder's worth costs this work apart from its
    /// records: its planned receptions, or for the runtime its session.
    pub const fn receptions_part(self, holds_raw: bool) -> usize {
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

    /// The threads this work needs for `load`, at least one, at most `cores` when they are known.
    pub fn threads_for(self, load: Load, holds_raw: bool, cores: Option<usize>) -> usize {
        let threads = load
            .spent(|source| self.per_feeder(holds_raw, source))
            .div_ceil(PLANNED_PER_THREAD)
            .max(1);
        cores.map_or(threads, |cores| threads.min(cores.max(1)))
    }
}

/// Every stage's threads for `load` (the feeders admitted and those the members' rate is worth),
/// holding MLAT raw or not, on `cores` cores when they are known: what a relay runs.
pub fn threads_for(load: Load, holds_raw: bool, cores: Option<usize>) -> Threads {
    Threads {
        ingest: Work::Ingest.threads_for(load, holds_raw, cores),
        message: Work::Message.threads_for(load, holds_raw, cores),
        seal: Work::Seal.threads_for(load, holds_raw, cores),
    }
}

/// Nanoseconds of one core a second hosted MLAT costs one planned feeder: its window steps and its
/// provisional steps, in a relay that hosts MLAT (`hosts_mlat`, the relay that holds MLAT raw), and
/// nothing in one that does not.
pub const fn mlat_per_feeder(hosts_mlat: bool) -> usize {
    if hosts_mlat {
        MLAT_WINDOW_NANOS_PER_FEEDER + MLAT_PROVISIONAL_NANOS_PER_FEEDER
    } else {
        0
    }
}

/// Nanoseconds of one core a second the stages and the runtime spend on one planned feeder's
/// worth from `source` at most, together: every work's receptions part (the runtime's session) and
/// its records once, each at the dearer of where it may be taken. A record goes to the ingest
/// workers or to the runtime, never both, so of `r` records `k` taken as batches cost no more than
/// the receptions planned and `k` ingest records, and the rest the runtime's: at most the
/// receptions and `r` at the dearer, whatever `k`.
pub const fn spent_per_feeder(source: Source, holds_raw: bool) -> usize {
    let mut spent = source.records_nanos();
    let mut at = 0;
    while at < Work::ALL.len() {
        spent = spent.saturating_add(Work::ALL[at].receptions_part(holds_raw));
        at += 1;
    }
    spent
}

/// Nanoseconds of one core a second the plan sets aside for one planned feeder's worth from
/// `source` in the stages ([`spent_per_feeder`] at [`BUSY_PERCENT`]), holding MLAT raw or not.
fn stage_planned(source: Source, holds_raw: bool) -> usize {
    spent_per_feeder(source, holds_raw)
        .saturating_mul(100)
        .div_ceil(BUSY_PERCENT)
}

/// The same over `load`.
fn stages_planned(load: Load, holds_raw: bool) -> usize {
    load.spent(|source| stage_planned(source, holds_raw))
}

/// The same for hosted MLAT's steps over `load` (at [`MLAT_BUSY_PERCENT`]): none where it is not
/// hosted. MLAT's work follows the receptions, whatever the records carry them.
fn mlat_planned(load: Load, hosts_mlat: bool) -> usize {
    load.planned_feeders()
        .saturating_mul(mlat_per_feeder(hosts_mlat))
        .saturating_mul(100)
        .div_ceil(MLAT_BUSY_PERCENT)
}

/// Nanoseconds of one core a second the plan sets aside for one planned feeder's worth from
/// `source`: the stages' share and, hosting MLAT, its steps'.
pub fn planned_per_feeder(source: Source, holds_raw: bool) -> usize {
    let one = Load {
        feeders: 0,
        member_feeders: 0,
        feeder_records_per_sec: source.records_per_sec(),
        sessions: Sessions::default(),
    };
    let one = match source {
        Source::Feeder { .. } => Load { feeders: 1, ..one },
        Source::Member => Load {
            member_feeders: 1,
            ..one
        },
    };
    stages_planned(one, holds_raw).saturating_add(mlat_planned(one, holds_raw))
}

/// The feeders sending at most `records_per_sec` records a second that `cores` cores carry,
/// holding MLAT raw (hosting MLAT) or not: every stage's work at the planned rate, the runtime's
/// with it, in [`BUSY_PERCENT`] of their share, and beside them hosted MLAT's steps in
/// [`MLAT_BUSY_PERCENT`] of what is left.
pub fn load_carried(cores: usize, holds_raw: bool, records_per_sec: u64) -> usize {
    cores
        .saturating_mul(NANOS)
        .checked_div(planned_per_feeder(
            Source::Feeder { records_per_sec },
            holds_raw,
        ))
        .unwrap_or(usize::MAX)
}

/// The threads hosted MLAT's steps are spread over for `load`, on `cores` cores when they are
/// known: none where it is not hosted; else the cores the stages' share leaves, rounded up, at
/// least one, or where the cores are not known as many as its measured cost at
/// [`MLAT_BUSY_PERCENT`] needs, at least one. The load a relay admits is no more than its cores
/// carry with MLAT's share beside the stages' ([`feeders_carried`]), so at its ceiling the cores
/// left hold what MLAT needs on average. MLAT is given all of them, not only that, because its
/// work is not even: a window step's comes at once every 40 s or so, and a provisional step carries
/// exactly the models of the window steps `tally_mlat::engine::MODELS_RIPEN_MS` (15 s) before it,
/// by their stamp, and is shed, counted (`provisional_models_late`), when one of them has not
/// reported by its turn: the sooner a window step reports, the fewer provisional steps are shed.
/// Measured (2026-10-09, 2,000 feeders on 10 cores): on the three threads its average cost needs, a
/// window step took 19 and 24 s, past the ripening; on eight, about 10 s, within it. Its threads
/// run below the stages' priority, so the cores they share with the stages cost the stages
/// nothing, and the relay's resident memory was the same on either (4.4 to 4.7 GB at its peak on
/// three, 4.3 on eight).
pub fn mlat_threads_for(load: Load, hosts_mlat: bool, cores: Option<usize>) -> usize {
    if !hosts_mlat {
        return 0;
    }
    match cores {
        Some(cores) => cores
            .saturating_mul(NANOS)
            .saturating_sub(stages_planned(load, true))
            .saturating_sub(load.sessions.planned())
            .div_ceil(NANOS)
            .max(1),
        None => mlat_planned(load, true).div_ceil(NANOS).max(1),
    }
}

/// The feeders (sending at most `load.feeder_records_per_sec` records a second each) `cores`
/// cores carry beside `load.member_feeders`, the feeders the members' shared rate is worth, and
/// `load.sessions` (which the plan holds first, as the memory's members' pool and connection
/// buffers are): none when they carry no more than those. `load.feeders` is not read.
pub fn feeders_carried(cores: usize, holds_raw: bool, load: Load) -> usize {
    let members = load
        .member_feeders
        .saturating_mul(planned_per_feeder(Source::Member, holds_raw));
    cores
        .saturating_mul(NANOS)
        .saturating_sub(members)
        .saturating_sub(load.sessions.planned())
        .checked_div(planned_per_feeder(load.feeder(), holds_raw))
        .unwrap_or(usize::MAX)
}

/// The cores this process may run on: its affinity and its cgroup's CPU quota
/// (`std::thread::available_parallelism`), one when it cannot be read.
pub fn cores_available() -> usize {
    std::thread::available_parallelism().map_or(1, std::num::NonZero::get)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The default feeder's records a second: its 256 KiB/s ceiling's.
    const RECORDS: u64 =
        crate::ingest::records_per_sec(crate::hub::DEFAULT_MAX_FEEDER_BYTES_PER_SEC);

    fn feeders(feeders: usize) -> Load {
        Load {
            feeders,
            member_feeders: 0,
            feeder_records_per_sec: RECORDS,
            sessions: Sessions::default(),
        }
    }

    const FEEDER: Source = Source::Feeder {
        records_per_sec: RECORDS,
    };

    #[test]
    fn each_stage_follows_the_load_and_never_runs_on_no_thread() {
        for holds_raw in [false, true] {
            // No load: one thread a stage, as a relay at rest needs.
            assert_eq!(
                threads_for(feeders(0), holds_raw, Some(16)),
                Threads {
                    ingest: 1,
                    message: 1,
                    seal: 1
                }
            );
            // The load the 2026-10-09 measurement ran: 5,000 feeders, about 3 M receptions a
            // second, which one message thread could not carry.
            let five = threads_for(feeders(5_000), holds_raw, Some(10));
            assert!(
                five.message >= 2 && five.ingest >= 2 && five.seal >= 2,
                "{five:?}"
            );
            // Four times the load, about four times the threads.
            let twenty = threads_for(feeders(20_000), holds_raw, None);
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
                let spent = 20_000 * work.per_feeder(holds_raw, FEEDER);
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
            assert_eq!(
                threads_for(feeders(1_000_000), holds_raw, Some(3)).message,
                3
            );
        }
        // Holding MLAT raw costs the sealer more, and the ingest workers' receptions more.
        assert!(
            threads_for(feeders(20_000), true, None).seal
                > threads_for(feeders(20_000), false, None).seal
        );
        assert!(
            Work::Ingest.per_feeder(true, Source::Member)
                > Work::Ingest.per_feeder(false, Source::Member)
        );
    }

    /// R-N12: a record costs the ingest workers `INGEST_NANOS_PER_RECORD` whatever its receptions,
    /// so a feeder is planned at the more of its receptions and the records its ceiling lets it
    /// send, and a members' feeder's worth at its own records; the faster the feeders' ceiling, the
    /// more ingest threads and the fewer feeders the cores carry.
    #[test]
    fn the_ingest_workers_are_planned_for_the_records_a_feeder_may_send() {
        for holds_raw in [false, true] {
            let receptions =
                Work::Ingest.per_feeder(holds_raw, Source::Feeder { records_per_sec: 1 });
            // One record a second costs less than a planned batch's receptions.
            assert!(receptions > INGEST_NANOS_PER_RECORD);
            // The default ceiling's eight tiny records cost more than a planned batch.
            assert_eq!(
                Work::Ingest.per_feeder(holds_raw, FEEDER),
                RECORDS as usize * INGEST_NANOS_PER_RECORD
            );
            assert!(RECORDS as usize * INGEST_NANOS_PER_RECORD > receptions);
            // A member's feeder's worth at its own records.
            assert_eq!(
                Work::Ingest.per_feeder(holds_raw, Source::Member),
                receptions.max(MEMBER_RECORDS_PER_FEEDER as usize * INGEST_NANOS_PER_RECORD)
            );
            // Twice the ceiling, twice the records: more threads, fewer feeders carried.
            let fast = Load {
                feeder_records_per_sec: 2 * RECORDS,
                ..feeders(5_000)
            };
            assert!(
                threads_for(fast, holds_raw, None).ingest
                    > threads_for(feeders(5_000), holds_raw, None).ingest
            );
            assert!(
                load_carried(10, holds_raw, 2 * RECORDS) < load_carried(10, holds_raw, RECORDS)
            );
            // The other stages follow the receptions, whatever the records.
            assert_eq!(
                threads_for(fast, holds_raw, None).message,
                threads_for(feeders(5_000), holds_raw, None).message
            );
        }
    }

    #[test]
    fn the_cores_carry_what_their_headroom_holds() {
        for holds_raw in [false, true] {
            // One core carries a relay's worth of feeders at the public relay's scale.
            assert!(feeders_carried(1, holds_raw, feeders(0)) > 100);
            // The load carried grows with the cores.
            assert_eq!(
                load_carried(10, holds_raw, RECORDS) / 10,
                load_carried(1, holds_raw, RECORDS)
            );
            // At the load carried, the cores hold every stage's work at BUSY_PERCENT and hosted
            // MLAT's at MLAT_BUSY_PERCENT beside it.
            for cores in [1, 4, 10, 32] {
                let load = load_carried(cores, holds_raw, RECORDS);
                let stages = load * spent_per_feeder(FEEDER, holds_raw);
                let mlat = load * mlat_per_feeder(holds_raw);
                assert!(
                    stages * 100 / BUSY_PERCENT + mlat * 100 / MLAT_BUSY_PERCENT <= cores * NANOS,
                    "{cores}"
                );
            }
            // The members' rate is carried first, at its own cost.
            let members = |member_feeders| Load {
                member_feeders,
                ..feeders(0)
            };
            let all = 4 * NANOS / planned_per_feeder(Source::Member, holds_raw);
            assert_eq!(feeders_carried(4, holds_raw, members(all + 1)), 0);
            assert_eq!(
                feeders_carried(4, holds_raw, members(10)),
                (4 * NANOS - 10 * planned_per_feeder(Source::Member, holds_raw))
                    / planned_per_feeder(FEEDER, holds_raw)
            );
        }
        // Hosting MLAT, a core carries fewer: its raw costs the stages more, and its steps are
        // planned beside them.
        assert!(load_carried(10, true, RECORDS) < load_carried(10, false, RECORDS));
        // 5,000 feeders without MLAT fit the 10 cores they were measured on, and the 2,000 the
        // MLAT runs measured fit them hosting it.
        assert!(load_carried(10, false, RECORDS) >= 5_000);
        assert!(load_carried(10, true, RECORDS) >= 2_000);
        assert!(cores_available() >= 1);
    }

    /// R4 of sweep 5: a source's records are paced together and any may be answered on the
    /// runtime (an echo's reply signed, a fault proof's two records verified) instead of taken by
    /// an ingest worker, so the runtime is planned for every one of them beside its session, and
    /// the cores hold every split of them between the two. Before, the runtime was planned for a
    /// feeder's session alone (83 us of a core a second) while its eight records a second
    /// answered there cost some 480 us.
    #[test]
    fn every_record_a_source_may_send_is_planned_wherever_it_is_answered() {
        for holds_raw in [false, true] {
            for source in [FEEDER, Source::Member] {
                let records = source.records_per_sec() as usize;
                let session = Work::Runtime.receptions_part(holds_raw);
                assert_eq!(
                    Work::Runtime.per_feeder(holds_raw, source),
                    session + records * RUNTIME_NANOS_PER_RECORD
                );
                // Every split of its records between the ingest workers (k, each with a planned
                // batch's receptions at most) and the runtime (the rest) is within what the cores
                // hold for it.
                let others: usize = [Work::Message, Work::Seal]
                    .iter()
                    .map(|work| work.per_feeder(holds_raw, source))
                    .sum();
                let receptions = Work::Ingest.receptions_part(holds_raw);
                for k in 0..=records {
                    let ingest = receptions.max(k * INGEST_NANOS_PER_RECORD);
                    let runtime = session + (records - k) * RUNTIME_NANOS_PER_RECORD;
                    assert!(
                        ingest + runtime + others <= spent_per_feeder(source, holds_raw),
                        "{source:?} {k}"
                    );
                }
            }
        }
        // The default feeder's eight records answered on the runtime cost more than its session.
        assert!(RECORDS as usize * RUNTIME_NANOS_PER_RECORD > 4 * NANOS / RUNTIME_FEEDERS_PER_CORE);
    }

    /// RFC-0181 §10, "The cores": MLAT's steps are planned in the same cores as the stages. The
    /// stages keep their half-busy share for raw; MLAT is given what is left, which at the load
    /// the cores carry holds its measured cost; and a relay that does not host MLAT runs none.
    #[test]
    fn mlat_takes_the_cores_the_stages_leave_and_admission_keeps_them_enough() {
        assert_eq!(mlat_threads_for(feeders(1_000), false, Some(10)), 0);
        assert_eq!(mlat_threads_for(feeders(1_000), false, None), 0);
        for cores in [1, 2, 4, 10, 32] {
            let carried = load_carried(cores, true, RECORDS);
            for load in [0, 1, carried / 2, carried] {
                let load = feeders(load);
                let threads = mlat_threads_for(load, true, Some(cores));
                assert!(
                    threads >= 1 && threads <= cores,
                    "{cores} {load:?} {threads}"
                );
                // MLAT's threads are what is left beside the stages' share, and at the load
                // carried what is left holds its planned cost.
                let left = (cores * NANOS).saturating_sub(stages_planned(load, true));
                assert_eq!(threads, left.div_ceil(NANOS).max(1), "{cores} {load:?}");
                assert!(mlat_planned(load, true) <= left, "{cores} {load:?}");
                assert!(
                    threads * NANOS >= mlat_planned(load, true),
                    "{cores} {load:?}"
                );
            }
            // Past the load carried, what is left no longer holds it: admission stops there.
            let past = feeders(carried + 1);
            assert!(
                mlat_planned(past, true)
                    > (cores * NANOS).saturating_sub(stages_planned(past, true)),
                "{cores}"
            );
        }
        // Where the cores are not known, MLAT is given what its cost needs.
        assert_eq!(mlat_threads_for(feeders(0), true, None), 1);
        assert_eq!(
            mlat_threads_for(feeders(10_000), true, None),
            (10_000 * mlat_per_feeder(true)).div_ceil(NANOS)
        );
        // The measured 2,000 feeders on ten cores: MLAT keeps more than its cost.
        let threads = mlat_threads_for(feeders(2_000), true, Some(10));
        assert!(
            threads * NANOS >= 2_000 * mlat_per_feeder(true),
            "{threads}"
        );
    }

    /// R4 of sweep 5: every session beside the feeders and the members is planned at its role's
    /// pace, before any feeder, so the more sessions a relay may hold the fewer feeders its cores
    /// carry, and its MLAT is left what both leave. The packaged unit's (one core, the default
    /// caps) still carries feeders.
    #[test]
    fn every_session_is_planned_at_its_roles_pace() {
        let none = Sessions::default();
        assert_eq!(none.planned(), 0);
        let some = Sessions {
            general: 2_048,
            subscribers: 64,
        };
        assert_eq!(
            some.records_per_minute(),
            2_048 * crate::ingest::GENERAL_RECORDS_PER_MINUTE
                + 64 * crate::ingest::SUBSCRIBER_RECORDS.per_minute
                + crate::ingest::DIRECTORY_RECORDS.per_minute
                + crate::ingest::BURST_GRANTS.per_minute
        );
        assert_eq!(
            some.planned(),
            (some.records_per_minute() as usize * RUNTIME_NANOS_PER_RECORD).div_ceil(60) * 100
                / BUSY_PERCENT
        );
        for holds_raw in [false, true] {
            let with = Load {
                sessions: some,
                ..feeders(0)
            };
            assert_eq!(
                feeders_carried(4, holds_raw, with),
                (4 * NANOS - some.planned()) / planned_per_feeder(FEEDER, holds_raw)
            );
            assert!(
                feeders_carried(4, holds_raw, with) < feeders_carried(4, holds_raw, feeders(0))
            );
            assert!(
                feeders_carried(1, holds_raw, with) > 0,
                "one core, the default caps"
            );
        }
        let load = Load {
            sessions: some,
            ..feeders(100)
        };
        assert_eq!(
            mlat_threads_for(load, true, Some(10)),
            (10 * NANOS - stages_planned(load, true) - some.planned())
                .div_ceil(NANOS)
                .max(1)
        );
    }
}
