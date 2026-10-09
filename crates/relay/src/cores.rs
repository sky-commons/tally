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

/// Nanoseconds of one core a Noise XX handshake and the Hello's verification cost the responder.
/// Measured (2026-10-09, release build, one core of the 32-core build host): 160 to 200 us the
/// responder's side, 5,000 to 6,000 a second a core; planned at the dearer, 200 us.
pub const HANDSHAKE_NANOS: usize = 200_000;
/// How long a planned handshake waits on its peer from its first byte to its last (a round trip
/// and a half of a peer within some 50 ms), which holds its permit without costing a core.
pub const HANDSHAKE_WAIT_MS: usize = 100;

/// The handshakes a second the runtime's `cores` pass, planned: [`BUSY_PERCENT`] of each core at
/// [`HANDSHAKE_NANOS`] a handshake. A reconnect storm is admitted at this pace, so it never takes
/// the sessions already served with it, and 20,000 feeders reconnecting at once are all admitted in
/// a few seconds on a few cores.
pub const fn handshake_pace_per_sec(cores: usize) -> u64 {
    (cores.saturating_mul(PLANNED_PER_THREAD) / HANDSHAKE_NANOS) as u64
}

/// The handshakes a second `permits` at once pass when each holds its permit [`HANDSHAKE_WAIT_MS`].
pub const fn handshake_pace_of(permits: usize) -> u64 {
    (permits as u64).saturating_mul(1_000) / HANDSHAKE_WAIT_MS as u64
}

/// The handshakes allowed at once on `cores` cores: the pace over the time each holds its permit
/// waiting on its peer ([`HANDSHAKE_WAIT_MS`], Little's law), so the cap passes the pace and
/// admits no more than it. At least one.
pub const fn handshakes_in_flight(cores: usize) -> usize {
    let permits =
        (handshake_pace_per_sec(cores) as usize).saturating_mul(HANDSHAKE_WAIT_MS) / 1_000;
    if permits == 0 { 1 } else { permits }
}

/// Where a planned feeder's worth of load comes from, which decides what it costs the ingest
/// workers. The feeders' own records are not planned per feeder (a planned feeder's one batch a
/// second is inside the reception costs measured over whole batches, and the records beyond them
/// are metered at ingest against one relay-wide figure, [`RECORDS_PER_PLANNED_FEEDER`] of the
/// rate admitted); only the members' rate is planned by its records, which come over links the
/// relay does not meter per source.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Source {
    /// One planned feeder's worth of the members' shared rate, its records at
    /// `ingest::MEMBER_RECORDS_PER_FEEDER` a second.
    Member,
}

/// The records a second the relay-wide rate admits for each planned feeder's worth of it
/// (`Budget::max_records_per_sec`): the batch a second a planned feeder sends and as many again
/// (small batches, echoes, queries). The stages' headroom ([`BUSY_PERCENT`]) holds the ingest
/// workers' verification of them, a record costing [`INGEST_NANOS_PER_RECORD`] against the 133 us a
/// planned feeder's receptions cost the workers; past it ingest sheds.
pub const RECORDS_PER_PLANNED_FEEDER: u64 = 2;

impl Source {
    /// The records a second it may send.
    pub const fn records_per_sec(self) -> u64 {
        MEMBER_RECORDS_PER_FEEDER
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

/// The load a relay is planned to carry (`Budget::load`): the receptions a second its stages carry
/// (the relay-wide rate `R_max`, `Budget::max_receptions_per_sec`), the feeder connections its
/// runtime serves, the MLAT seats it hosts, the feeders its members' shared rate is worth and its
/// other sessions ([`Sessions`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Load {
    /// Receptions a second the stages carry for feeders (not the members').
    pub receptions_per_sec: u64,
    /// The feeder connections: each a Noise session on the runtime.
    pub connections: usize,
    /// The MLAT seats hosted (each a feeder's worth of MLAT's steps).
    pub seats: usize,
    pub member_feeders: usize,
    pub sessions: Sessions,
}

impl Load {
    /// Nanoseconds of one core a second `work` spends on this load at its average: the stages by
    /// their receptions (a planned feeder's 600 cost [`Work::receptions_part`]), the runtime by
    /// its connections' sessions, and the members' feeders' worth apiece.
    fn average_nanos(&self, work: Work, holds_raw: bool) -> usize {
        let part = work.receptions_part(holds_raw) as u128;
        let own = match work {
            Work::Runtime => part * self.connections as u128,
            _ => part * u128::from(self.receptions_per_sec) / PLANNED_RECEPTIONS_PER_SEC as u128,
        };
        usize::try_from(own).unwrap_or(usize::MAX).saturating_add(
            self.member_feeders
                .saturating_mul(work.per_feeder(holds_raw, Source::Member)),
        )
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
    /// in a relay that holds MLAT raw (`holds_raw`) or not, at its busiest. The ingest workers' is
    /// the more of its planned receptions and its records a second at [`INGEST_NANOS_PER_RECORD`]
    /// each (R-N12); the runtime's is its session's and every record answered there
    /// ([`RUNTIME_NANOS_PER_RECORD`], R4 of sweep 5).
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
            .average_nanos(self, holds_raw)
            .div_ceil(PLANNED_PER_THREAD)
            .max(1);
        cores.map_or(threads, |cores| threads.min(cores.max(1)))
    }
}

/// Every stage's threads for `load`, holding MLAT raw or not, on `cores` cores when they are
/// known: what a relay runs.
pub fn threads_for(load: Load, holds_raw: bool, cores: Option<usize>) -> Threads {
    Threads {
        ingest: Work::Ingest.threads_for(load, holds_raw, cores),
        message: Work::Message.threads_for(load, holds_raw, cores),
        seal: Work::Seal.threads_for(load, holds_raw, cores),
    }
}

/// Nanoseconds of one core a second hosted MLAT costs one seat (a planned feeder's worth): its
/// window steps and its provisional steps, in a relay that hosts MLAT (`hosts_mlat`), and nothing
/// in one that does not.
pub const fn mlat_per_feeder(hosts_mlat: bool) -> usize {
    if hosts_mlat {
        MLAT_WINDOW_NANOS_PER_FEEDER + MLAT_PROVISIONAL_NANOS_PER_FEEDER
    } else {
        0
    }
}

/// Nanoseconds of one core a second the stages and the runtime spend on one planned feeder's
/// worth from `source` at most, together: every work's receptions part (the runtime's session)
/// and its records once, each at the dearer of where it may be taken.
pub const fn spent_per_feeder(source: Source, holds_raw: bool) -> usize {
    let mut spent = source.records_nanos();
    let mut at = 0;
    while at < Work::ALL.len() {
        spent = spent.saturating_add(Work::ALL[at].receptions_part(holds_raw));
        at += 1;
    }
    spent
}

/// The same over `load`, every work at [`BUSY_PERCENT`] of its threads.
fn stages_planned(load: Load, holds_raw: bool) -> usize {
    Work::ALL
        .iter()
        .map(|work| load.average_nanos(*work, holds_raw))
        .fold(0usize, usize::saturating_add)
        .saturating_mul(100)
        .div_ceil(BUSY_PERCENT)
}

/// The same for hosted MLAT's steps over `load` (at [`MLAT_BUSY_PERCENT`]): none where it is not
/// hosted. MLAT's work follows the seats and the members' raw.
fn mlat_planned(load: Load, hosts_mlat: bool) -> usize {
    load.seats
        .saturating_add(load.member_feeders)
        .saturating_mul(mlat_per_feeder(hosts_mlat))
        .saturating_mul(100)
        .div_ceil(MLAT_BUSY_PERCENT)
}

/// Nanoseconds of one core a second the plan sets aside for one planned feeder's worth of the
/// members' rate: the stages' share at [`BUSY_PERCENT`] and, hosting MLAT, its steps'.
pub fn planned_per_feeder(source: Source, holds_raw: bool) -> usize {
    let stages = spent_per_feeder(source, holds_raw)
        .saturating_mul(100)
        .div_ceil(BUSY_PERCENT);
    stages.saturating_add(
        mlat_per_feeder(holds_raw)
            .saturating_mul(100)
            .div_ceil(MLAT_BUSY_PERCENT),
    )
}

/// Nanoseconds of one core a second the cores leave the feeders' connections and the MLAT seats:
/// all of `cores` less the members' rate's worth (stages and raw) and the other sessions' records,
/// which the plan holds first, as the memory's members' pool and connection buffers are.
pub fn available_nanos(
    cores: usize,
    holds_raw: bool,
    member_feeders: usize,
    sessions: Sessions,
) -> usize {
    cores
        .saturating_mul(NANOS)
        .saturating_sub(
            member_feeders.saturating_mul(planned_per_feeder(Source::Member, holds_raw)),
        )
        .saturating_sub(sessions.planned())
}

/// Nanoseconds a feeder connection's session costs the runtime, at [`BUSY_PERCENT`].
pub fn connection_nanos(holds_raw: bool) -> usize {
    Work::Runtime
        .receptions_part(holds_raw)
        .saturating_mul(100)
        .div_ceil(BUSY_PERCENT)
}

/// Nanoseconds the stages spend on a planned feeder's 600 receptions a second, at
/// [`BUSY_PERCENT`]: ingest, message exchange and sealer together. The cost of a reception is this
/// over 600.
pub fn stage_nanos(holds_raw: bool) -> usize {
    [Work::Ingest, Work::Message, Work::Seal]
        .iter()
        .map(|work| work.receptions_part(holds_raw))
        .fold(0usize, usize::saturating_add)
        .saturating_mul(100)
        .div_ceil(BUSY_PERCENT)
}

/// The feeder connections `available` nanoseconds carry at the planned mean (their sessions and
/// their receptions through the stages, at [`BUSY_PERCENT`]) beside `seats` MLAT seats.
pub fn connections_carried(available: usize, holds_raw: bool, seats: usize) -> usize {
    available
        .saturating_sub(seats.saturating_mul(mlat_per_feeder(holds_raw)))
        .checked_div(connection_nanos(holds_raw).saturating_add(stage_nanos(holds_raw)))
        .unwrap_or(usize::MAX)
}

/// The receptions a second the stages carry in what `available` nanoseconds leave after
/// `connections` sessions and `seats` MLAT seats: the cores' bound on `R_max`.
pub fn rate_carried(available: usize, holds_raw: bool, connections: usize, seats: usize) -> u64 {
    let left = available
        .saturating_sub(seats.saturating_mul(mlat_per_feeder(holds_raw)))
        .saturating_sub(connections.saturating_mul(connection_nanos(holds_raw)));
    (left as u128 * PLANNED_RECEPTIONS_PER_SEC as u128)
        .checked_div(stage_nanos(holds_raw) as u128)
        .map_or(u64::MAX, |rate| u64::try_from(rate).unwrap_or(u64::MAX))
}

/// The seats the cores carry once `connections` are planned at the mean: what `available`
/// nanoseconds leave after their sessions and receptions through the stages, over a seat's steps.
/// MLAT's seats are planned from what the connections leave, never the reverse.
pub fn seats_carried(available: usize, holds_raw: bool, connections: usize) -> usize {
    available
        .saturating_sub(
            connections
                .saturating_mul(connection_nanos(holds_raw).saturating_add(stage_nanos(holds_raw))),
        )
        .checked_div(mlat_per_feeder(holds_raw))
        .unwrap_or(usize::MAX)
}

/// The part of the memory and of the cores a relay hosting MLAT keeps for its seats when it plans
/// its connections (`budget::Plan::admit`): the connections are planned from the rest, at their
/// floor and the windows of their mean rate, and the seats from the share and whatever the
/// connections leave unused (a relay whose cores bind its connections leaves memory), never more
/// than the connections. Without it a relay bound by memory would plan every byte to connections
/// and have none for a seat, and with a seat for each connection (before) it admitted about
/// fifteen on the public pod.
pub const MLAT_SHARE_PERCENT: usize = 25;

/// `total` less the share a relay hosting MLAT keeps for its seats ([`MLAT_SHARE_PERCENT`]).
pub const fn after_mlat_share(total: usize, holds_raw: bool) -> usize {
    if holds_raw {
        total - total / 100 * MLAT_SHARE_PERCENT
    } else {
        total
    }
}

/// The threads hosted MLAT's steps are spread over for `load`, on `cores` cores when they are
/// known: none where it is not hosted; else the cores the stages' share leaves, rounded up, at
/// least one, or where the cores are not known as many as its measured cost at
/// [`MLAT_BUSY_PERCENT`] needs, at least one. MLAT is given all of what is left, not only its
/// average, because its work is not even: a window step's comes at once every 40 s or so, and a
/// provisional step carries exactly the models of the window steps `tally_mlat::engine::MODELS_RIPEN_MS`
/// (15 s) before it, by their stamp, and is shed, counted (`provisional_models_late`), when one of
/// them has not reported by its turn: the sooner a window step reports, the fewer provisional steps
/// are shed. Measured (2026-10-09, 2,000 feeders on 10 cores): on the three threads its average
/// cost needs, a window step took 19 and 24 s, past the ripening; on eight, about 10 s, within
/// it. Its threads run below the stages' priority, so the cores they share with the stages cost
/// the stages nothing.
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

/// The cores this process may run on: its affinity and its cgroup's CPU quota
/// (`std::thread::available_parallelism`), one when it cannot be read.
pub fn cores_available() -> usize {
    std::thread::available_parallelism().map_or(1, std::num::NonZero::get)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn load(receptions_per_sec: u64) -> Load {
        Load {
            receptions_per_sec,
            connections: (receptions_per_sec / PLANNED_RECEPTIONS_PER_SEC as u64) as usize,
            seats: 0,
            member_feeders: 0,
            sessions: Sessions::default(),
        }
    }

    /// The receptions a second of `feeders` planned feeders.
    fn planned(feeders: u64) -> u64 {
        feeders * PLANNED_RECEPTIONS_PER_SEC as u64
    }

    #[test]
    fn each_stage_follows_the_rate_and_never_runs_on_no_thread() {
        for holds_raw in [false, true] {
            // No load: one thread a stage, as a relay at rest needs.
            assert_eq!(
                threads_for(load(0), holds_raw, Some(16)),
                Threads {
                    ingest: 1,
                    message: 1,
                    seal: 1
                }
            );
            // 5,000 planned feeders, about 3 M receptions a second, which one message thread
            // could not carry.
            let five = threads_for(load(planned(5_000)), holds_raw, Some(10));
            assert!(
                five.message >= 2 && five.ingest >= 2 && five.seal >= 2,
                "{five:?}"
            );
            // Four times the rate, about four times the threads.
            let twenty = threads_for(load(planned(20_000)), holds_raw, None);
            assert!(
                twenty.message >= 4 * five.message - 3,
                "{twenty:?} {five:?}"
            );
            // Each thread planned at most BUSY_PERCENT of its time, and more than the threads but
            // one would be (no stage takes a thread it will not use).
            for (work, threads) in [
                (Work::Ingest, twenty.ingest),
                (Work::Message, twenty.message),
                (Work::Seal, twenty.seal),
            ] {
                let spent = load(planned(20_000)).average_nanos(work, holds_raw);
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
                threads_for(load(planned(1_000_000)), holds_raw, Some(3)).message,
                3
            );
        }
        // Holding MLAT raw costs the sealer more, and the ingest workers' receptions more.
        assert!(
            threads_for(load(planned(20_000)), true, None).seal
                > threads_for(load(planned(20_000)), false, None).seal
        );
        assert!(
            Work::Ingest.per_feeder(true, Source::Member)
                > Work::Ingest.per_feeder(false, Source::Member)
        );
    }

    /// R-N12: a record costs the ingest workers `INGEST_NANOS_PER_RECORD` whatever its receptions,
    /// so the members' feeder's worth (whose records come over links the relay does not meter per
    /// source) is planned at the more of its receptions and its records.
    #[test]
    fn the_members_are_planned_for_their_records() {
        for holds_raw in [false, true] {
            let receptions = Work::Ingest.receptions_part(holds_raw);
            assert_eq!(
                Work::Ingest.per_feeder(holds_raw, Source::Member),
                receptions.max(MEMBER_RECORDS_PER_FEEDER as usize * INGEST_NANOS_PER_RECORD)
            );
        }
    }

    /// The cores' bounds are the stages' and sessions' planned costs, and what they carry fits
    /// them: the connections carried at the mean (after MLAT's share when it is hosted), the seats
    /// from what they leave, the rate beside them.
    #[test]
    fn the_cores_carry_what_their_headroom_holds() {
        for holds_raw in [false, true] {
            for cores in [1usize, 4, 10, 16, 32] {
                let available = available_nanos(cores, holds_raw, 0, Sessions::default());
                assert_eq!(available, cores * NANOS);
                let connections =
                    connections_carried(after_mlat_share(available, holds_raw), holds_raw, 0);
                let seats = if holds_raw {
                    seats_carried(available, holds_raw, connections).min(connections)
                } else {
                    0
                };
                // Connections carried at the mean with their seats fit the cores.
                assert!(
                    connections * (connection_nanos(holds_raw) + stage_nanos(holds_raw))
                        + seats * mlat_per_feeder(holds_raw)
                        <= available,
                    "{cores} {holds_raw}"
                );
                if holds_raw {
                    // MLAT's share is kept for the seats, and connections went on beyond them.
                    assert!(seats > 0 && seats <= connections, "{cores} {seats}");
                    assert!(
                        (seats + 1) * mlat_per_feeder(true) >= available / 100 * MLAT_SHARE_PERCENT
                            || seats == connections,
                        "{cores} {seats} {connections}"
                    );
                } else {
                    assert_eq!(after_mlat_share(available, false), available);
                }
                // The rate left beside them is at least their mean.
                let rate = rate_carried(available, holds_raw, connections, seats);
                assert!(rate >= planned(connections as u64), "{cores} {holds_raw}");
            }
            // More cores, proportionally more.
            let one = connections_carried(NANOS, holds_raw, 0);
            let ten = connections_carried(10 * NANOS, holds_raw, 0);
            assert!(ten >= 10 * one && ten <= 10 * one + 10, "{one} {ten}");
        }
        // The seats are the cores' leftover over a seat's steps: none when the connections take
        // them all.
        let all = connections_carried(10 * NANOS, true, 0);
        assert_eq!(seats_carried(10 * NANOS, true, all + 1), 0);
        // The members' rate and the other sessions are held first.
        let sessions = Sessions {
            general: 2_048,
            subscribers: 64,
        };
        for holds_raw in [false, true] {
            assert_eq!(
                available_nanos(4, holds_raw, 10, sessions),
                4 * NANOS - 10 * planned_per_feeder(Source::Member, holds_raw) - sessions.planned()
            );
            let all = 4 * NANOS / planned_per_feeder(Source::Member, holds_raw);
            assert_eq!(
                connections_carried(
                    available_nanos(4, holds_raw, all + 1, Sessions::default()),
                    holds_raw,
                    0
                ),
                0
            );
        }
        // The packaged unit's one core, the default caps, still carries connections.
        assert!(
            connections_carried(available_nanos(1, true, 0, sessions), true, 0) > 100,
            "one core"
        );
        assert!(cores_available() >= 1);
    }

    /// The handshake cap is planned from the measured cost of one: the pace is the share of each
    /// core at that cost, the permits the pace over the time a handshake waits on its peer, and a
    /// reconnect storm of 20,000 feeders clears in seconds on the cores that carry them.
    #[test]
    fn the_handshake_cap_follows_the_measured_cost() {
        // 200 us each at half a core: 2,500 a second a core.
        assert_eq!(handshake_pace_per_sec(1), 2_500);
        assert_eq!(handshake_pace_per_sec(16), 40_000);
        // Little's law: 2,500 a second, each holding a permit 100 ms: 250 in flight a core.
        assert_eq!(handshakes_in_flight(1), 250);
        assert_eq!(handshakes_in_flight(16), 4_000);
        assert_eq!(
            handshake_pace_of(handshakes_in_flight(16)),
            handshake_pace_per_sec(16)
        );
        assert_eq!(handshakes_in_flight(0), 1);
        // 20,000 feeders reconnecting at once are admitted within a second on 16 cores.
        assert!(20_000 <= handshake_pace_per_sec(16));
    }

    /// The records the stages are planned to verify fit the ingest headroom: at
    /// `RECORDS_PER_PLANNED_FEEDER` a second for each planned feeder, a record's verification
    /// costs the ingest workers no more than the receptions they are planned for.
    #[test]
    fn the_records_admitted_fit_the_ingest_workers_planned_time() {
        for holds_raw in [false, true] {
            assert!(
                RECORDS_PER_PLANNED_FEEDER as usize * INGEST_NANOS_PER_RECORD
                    <= Work::Ingest.receptions_part(holds_raw),
                "{holds_raw}"
            );
        }
    }

    /// R4 of sweep 5: a source's records are paced together and any may be answered on the
    /// runtime instead of taken by an ingest worker, so the members' records are planned wherever
    /// they are answered, and the cores hold every split of them between the two.
    #[test]
    fn every_record_a_member_may_send_is_planned_wherever_it_is_answered() {
        for holds_raw in [false, true] {
            let source = Source::Member;
            let records = source.records_per_sec() as usize;
            let session = Work::Runtime.receptions_part(holds_raw);
            assert_eq!(
                Work::Runtime.per_feeder(holds_raw, source),
                session + records * RUNTIME_NANOS_PER_RECORD
            );
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

    /// RFC-0181 §10, "The cores": MLAT's steps are planned in the same cores as the stages. The
    /// stages keep their half-busy share for raw; MLAT is given what is left; a relay that does
    /// not host MLAT runs none.
    #[test]
    fn mlat_takes_the_cores_the_stages_leave() {
        assert_eq!(mlat_threads_for(load(planned(1_000)), false, Some(10)), 0);
        assert_eq!(mlat_threads_for(load(planned(1_000)), false, None), 0);
        for cores in [1usize, 2, 4, 10, 32] {
            let available = available_nanos(cores, true, 0, Sessions::default());
            let carried = connections_carried(after_mlat_share(available, true), true, 0);
            let seats = seats_carried(available, true, carried).min(carried);
            for fraction in [0, 1, 2] {
                let connections = carried * fraction / 2;
                let load = Load {
                    receptions_per_sec: planned(connections as u64),
                    connections,
                    seats,
                    member_feeders: 0,
                    sessions: Sessions::default(),
                };
                let threads = mlat_threads_for(load, true, Some(cores));
                assert!(
                    threads >= 1 && threads <= cores,
                    "{cores} {load:?} {threads}"
                );
                let left = (cores * NANOS).saturating_sub(stages_planned(load, true));
                assert_eq!(threads, left.div_ceil(NANOS).max(1), "{cores} {load:?}");
                // At the pairs the cores carry, what the stages leave holds MLAT's planned cost.
                assert!(mlat_planned(load, true) <= left, "{cores} {load:?}");
            }
        }
        // Where the cores are not known, MLAT is given what its cost needs.
        assert_eq!(mlat_threads_for(load(0), true, None), 1);
        let load = Load {
            seats: 10_000,
            ..load(0)
        };
        assert_eq!(
            mlat_threads_for(load, true, None),
            (10_000 * mlat_per_feeder(true)).div_ceil(NANOS)
        );
    }

    /// R4 of sweep 5: every session beside the feeders and the members is planned at its role's
    /// pace, before any feeder, so the more sessions a relay may hold the fewer connections its
    /// cores carry.
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
            let with = connections_carried(available_nanos(4, holds_raw, 0, some), holds_raw, 0);
            let without = connections_carried(available_nanos(4, holds_raw, 0, none), holds_raw, 0);
            assert!(with < without, "{holds_raw}");
        }
    }
}
