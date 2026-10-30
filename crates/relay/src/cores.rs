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
//! relay saw by default): its steps spread over every core beside the stages, at the stages'
//! priority, so on a relay hosting MLAT under load nothing kept a core for raw.

use crate::budget::PLANNED_RECEPTIONS_PER_SEC;
use crate::ingest::{INGEST_NANOS_PER_RECORD, MEMBER_RECORDS_PER_FEEDER, Threads};

/// Receptions a second one ingest worker sustains, each batch verified, hashed, admitted,
/// inflated, decoded, credited to its feeder's figures (each position's CPR decoded and its H3
/// cell found, `figures::Figures::batch`) and routed. Measured (2026-10-27, `tally-load` `-c opt`,
/// the relay on cores 0-15, its feeders sending the measured mix of `tally_load::traffic`, 60 s of
/// each ingest worker's CPU time from `/proc/<pid>/task/*/stat` after a 60 s ramp and a 110 s
/// warm-up, with `--no-mlat`): 1.23 M receptions a second (2,000 feeders) cost ten workers 0.589
/// of a core together (480 ns a reception), and 2.97 M (5,000 feeders, a 120 s ramp) seven 1.414
/// (476 ns): 2.0 M receptions a second, planned at 500 ns. A feeder's batch is inflated once, its
/// wanted receptions and its decode read from the same bytes (`tally_wire::Inflated`). Before, 1.15 M (865 ns,
/// 2026-10-26), when each feeder's figures found the CPR zone count of every position by `acos`
/// and the H3 cell of every placing, its receiver's public cell's centre again for every batch,
/// and every aircraft's last placing again for each feeder that heard it; and 4.5 M (221 ns) on
/// 2026-10-09, over traffic of no position to credit, before the figures decoded positions at all.
pub const INGEST_RECEPTIONS_PER_THREAD: usize = 2_000_000;
/// The same where MLAT raw is held (each batch's wanted receptions into its raw shard's inbox
/// besides, `mlat_host::MlatHost::offer_batch`). Measured the same way hosting MLAT: 1.22 M
/// receptions a second (2,000 feeders, 457 seats) cost eight workers 0.839 to 0.862 of a core (687
/// to 706 ns): at the dearer, 1.4 M receptions a second. Before, 0.9 M (1,105 ns, 2026-10-26), and
/// 3.4 M (290 ns) on 2026-10-09 as the line above.
pub const INGEST_RECEPTIONS_PER_THREAD_HOLDING_RAW: usize = 1_400_000;

/// Receptions a second one message thread sustains, deduplicating its shards: one table a
/// thread, each reception probing the one place its fingerprint and what it was kept for hash to,
/// prefetched ahead, and each epoch let go from the homes it listed (`exchange::Fingerprints`).
/// Measured (2026-10-27, as the ingest workers above, `--no-mlat`): 1.18 M receptions a second
/// (2,000 feeders) cost three threads 0.059 of a core together (50 ns a reception), and 2.91 M
/// (5,000 feeders) three 0.140 (48 ns): at the dearer, 20 M receptions a second. Before, 10 M
/// (98 ns) when each epoch listed its keys whole; 3.9 M (253 ns at 5,000 feeders) when each
/// reception probed every epoch's table (`DEDUP_EPOCHS`) and walked its fingerprint's list of the
/// areas it was kept for, and the more an epoch filled them the more of those probes missed the
/// caches; and 4.6 M (216 ns) on 2026-10-09.
pub const MESSAGE_RECEPTIONS_PER_THREAD: usize = 20_000_000;

/// Receptions a second one sealer thread sustains, the sealer and its pool together (cutting,
/// signing and deriving each epoch's records). Measured: 3.02 M to 3.05 M receptions a second
/// cost the sealer alone 0.517 of a core, the sealer and one helper 0.506 together and the
/// sealer and three helpers 0.538 (178 ns a reception); 4.61 M cost the sealer and three helpers
/// 0.492 (107 ns). 178 ns is 5.6 M receptions a second, 9,300 planned batches. The part of it no
/// helper takes (gathering each epoch from every message thread, numbering its records in cell
/// order, applying them) was 0.144 to 0.164 of a core at 3.02 M and 0.144 at 4.61 M: it follows
/// the epochs and the areas, not the receptions, so it bounds no feeder count. Measured again over
/// the measured mix (2026-10-27): 1.23 M receptions a second cost the sealer and two helpers
/// 0.068 to 0.080 of a core (55 to 65 ns), 2.97 M 0.194 (65 ns): 15 M receptions a second. Before,
/// 5.6 M (178 ns), measured on 2026-10-09 before the sealer's records were cut and signed in its
/// pool.
pub const SEAL_RECEPTIONS_PER_THREAD: usize = 15_000_000;
/// The same where MLAT raw is held (its bins sealed too). Measured (2026-10-27, 457 seats): 1.22 M
/// receptions a second cost the sealer and two helpers 0.076 of a core (62 ns), planned at the
/// dearer figure without raw: 15 M receptions a second. Before, 3.2 M (305 ns, 2026-10-09).
pub const SEAL_RECEPTIONS_PER_THREAD_HOLDING_RAW: usize = 15_000_000;

/// Planned feeders one core of the async runtime carries: each one's Noise session and its
/// batches' framing, the fan-out's writes to subscribers, the links and the stats. Measured: ten
/// runtime workers took 0.404 to 0.412 of a core together at 5,000 feeders (82 us a feeder a
/// second), and 0.516 at 6,742 (77 us): 12,100 feeders a core. Measured again over the measured mix
/// (2026-10-27): sixteen workers took 0.119 to 0.128 of a core at 2,000 feeders (64 us) and 0.303
/// at 5,000 (61 us): 15,600 feeders a core, planned at 15,000.
pub const RUNTIME_FEEDERS_PER_CORE: usize = 15_000;
/// The same where MLAT raw is held. Measured: 0.243 of a core at 2,000 feeders (121 us a feeder a
/// second), 8,200 feeders a core (2026-10-09); again (2026-10-27, 457 seats) 0.142 to 0.161 (81
/// us): 12,400 a core, planned at 12,000.
pub const RUNTIME_FEEDERS_PER_CORE_HOLDING_RAW: usize = 12_000;

/// Nanoseconds of the async runtime one record answered there costs at most, whatever its size
///: the records no ingest worker takes (an echo's reply signed, a delivery query's
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

// Hosted MLAT's cost a seat (RFC-0171 §3.8.1 as amended 2026-10-24; RFC-0181 §10, "MLAT in the
// cores"), measured where the host pays it: `tally-load` (`-c opt`) against the world relay's plan
// (`crates/relay/tests/world-relay.txt`: 16 cores, its memory, so 4 MLAT threads), the relay on
// cores 0-15 of the 32-core build host and the harness on 16-31 (`--relay-cores 16`), 2,000
// feeders sending the measured mix (`tally_load::traffic`, about 600 receptions a second a
// receiver, 60% of them messages MLAT wants), 60 s measured after a 60 s ramp and a 110 s warm-up,
// 2026-10-27, its seats at the 546 its plan printed: each thread's CPU time from
// `/proc/<pid>/task/*/stat` (the step's own threads come and go, so theirs is the process's less
// every named thread's), the steps' fit and solve times from `GET /mlat` (`steps_total`, read at
// both ends of the window). Before (2026-10-27, 457 seats), 5.37 ms a seat: refits 1.72, solving
// 1.02, the host 0.27, the rest 1.57, publishing 0.41; the refit since gathers its area's
// receptions into compact items sorted once and reads its sync points through integer ranks and
// one list of hearers, and the step's intake sorts light tuples and builds a reception only for
// those it keeps (`tally_mlat_solver`). Before that (2026-10-26, 522 seats), 5.97 ms: refits
// 1.87, solving 0.86, the host 0.32, the rest 1.89, publishing 0.64. A relay
// alone verifies no neighbour's model, so that one part is the pairwise path sweep's
// (`tally-mlat-solver`'s `pairwise_path_sweep`, world density, seed 9000). Every figure is
// milliseconds of one core a seat-second. `//crates/load:plan_seats` runs the same load and holds
// the seats it settles at within 15% of the seats the plan prints. Before, every part was the
// sweep's alone (refits 0.872, verifying 0.387, solving 0.682: 1.94 ms a seat, filled to the whole
// of MLAT's threads), which leaves out the host's own work around the solver and runs one thread
// over an even scene: the plan printed 2,022 seats on the world relay, and its load settled at
// about 500.

/// Nanoseconds of one core a second an area's refits cost for each of its receivers: the pair
/// fits of its model every `tally_wire::budget::REFIT_EVERY_MS`, each pair sought from its knots in
/// the area's previous model, over the trailing window, as the host runs them on MLAT's threads
/// (the steps' `fit_ms`, 803 ms a second over 546 seats, 72.5 refits a second at 11.1 ms; the
/// sweep's "sync" was 0.872, one thread over an even scene). Dearer than the sweep for its refits,
/// not their cost: each area refit cost what the sweep's did (11.1 ms against 15.6), but the load's
/// seats lie over more areas each, 0.133 refits a seat-second against the sweep's 0.056. A refit
/// has no fixed part: over the world's areas its cost follows its points, about 640 ns a point and
/// rising with them, the pair fits most of it (`pair_tests`, `a_refits_cost_follows_its_points`).
pub const MLAT_REFIT_NANOS_PER_FEEDER: usize = 1_470_000;
/// Nanoseconds of one core a second verifying the neighbouring areas' models costs a seat: each
/// such model checked once over the raw the engine holds (`Engine::verify_model`, `mlat_host`),
/// and only when a fix the engine publishes or judges cites it (`mlat_host`, unneeded): the
/// sweep's "a holder of the window verifying each model", 0.602 ms a feeder-second, times the
/// share of its band's models an area's relay's fixes cite, 2.693 of 4.185 ms (1,433 of 2,259
/// models), so 0.387. The one part the load test cannot measure: a relay alone has no neighbour
/// (`models_verified` 0 there).
pub const MLAT_VERIFY_NANOS_PER_FEEDER: usize = 387_000;
/// Nanoseconds of one core a second hosted MLAT's solving costs a seat: every due set its areas'
/// relays take up grouped into its transmissions, and of them one an aircraft a slot of 0.7 s
/// solved (`tally_mlat_solver::backoff`, mlat-server's `RESOLVE_BACKOFF`), and again as its set
/// closes bigger, from at most `pair::HEARERS_MOST` (32) receivers, with its verification and
/// signing (the steps' `solve_ms`, 548 ms a second over 546 seats; the sweep's "fixes" was 0.682).
pub const MLAT_SOLVE_NANOS_PER_FEEDER: usize = 1_000_000;
/// Nanoseconds of one core a second the host's own thread spends a seat: taking each step's due
/// batches from the inboxes, admitting them into the pool in order once MLAT's threads have
/// classified them (`mlat_host`, take), settling the pool's charge, applying the cuts and judging
/// the step (the governor), and the serial parts of the step it starts: the `tally-mlat` thread,
/// 0.153 of a core over 546 seats.
pub const MLAT_HOST_NANOS_PER_FEEDER: usize = 280_000;
/// Nanoseconds of one core a second MLAT's threads spend a seat beyond its refits and its solving:
/// classifying its batches (hashing each message, finding its positions,
/// `tally_mlat::engine::classify`), building and judging the due sets taken up (`fix::choose`),
/// weighing them, building their records, letting go of what the step took, and the background
/// work beside the steps (standing's checks, forgetting receivers): the step threads' CPU, 2.029
/// of a core, less `fit_ms` and `solve_ms`, 0.678 over 546 seats.
pub const MLAT_STEP_REST_NANOS_PER_FEEDER: usize = 1_240_000;
/// Nanoseconds of one core a second publishing a seat's share of MLAT's output costs the relay's
/// duties thread: each step's positions, tagged positions and the clock models they cite signed
/// into the hub, forwarded and released (`Hub::publish_from`, `publish_positions`,
/// `publish_clock_model`), and the consistency checks of what it published: the duties thread's
/// CPU hosting MLAT, 0.259 of a core, less what it spends not hosting it at the same feeders
/// (0.028, `--no-mlat`), 0.231 over 546 seats (0.335 over 522 before each positions record's keys
/// were checked once for its five readers, `tally_wire::Positions::fixes`).
pub const MLAT_PUBLISH_NANOS_PER_FEEDER: usize = 420_000;

/// The most of MLAT's threads the plan fills with its measured cost: the governor's target
/// (`mlat_host::STEP_TARGET_MS` of `STEP_BUDGET_MS`), where a cut aims a step, so seats planned at
/// it run their steps where the governor holds them and are never cut for their cost alone
/// (`mlat_host`, Overload), and a cut on one dear step is lifted back to within an eighth of it.
/// Its work is even: one step a second, each a second's solves and half
/// the areas' refits (`tally_mlat::area::refit_turn`), so no step carries every area's refit at
/// once. Before, 100: the plan filled MLAT's threads whole, so its seats ran their steps past the
/// target and the governor cut them on the first dear step to the target's worth, a quarter below
/// the plan (662 planned, 522 settled, 2026-10-26).
pub const MLAT_BUSY_PERCENT: usize =
    (crate::mlat_host::STEP_TARGET_MS * 100 / crate::mlat_host::STEP_BUDGET_MS) as usize;

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
/// carry on the async runtime, each paced at what its role legitimately sends
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
    /// each; the runtime's is its session's and every record answered there
    /// ([`RUNTIME_NANOS_PER_RECORD`]).
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

/// Nanoseconds of one core a second hosted MLAT costs one seat (a planned feeder's worth): every
/// cost the host pays for it, as the load test measured them (above): its share of its area's
/// refits, of verifying its neighbours' models and its solving, the host thread's taking and
/// judging, the rest of MLAT's threads' work around the solver, and publishing what it solved, in
/// a relay that hosts MLAT (`hosts_mlat`), and nothing in one that does not: 5.37 ms (5.97 on
/// 2026-10-26, before the profile's cuts of 2026-10-27). Before, the
/// sweep's solver work alone, 1.94 ms (0.87 refitting, 0.39 verifying, 0.68 solving), which the
/// load test showed a quarter of what a seat costs the host; and before that the tiles' joint
/// fits at the steps' cap of refits and their solving, 43.5 ms planned.
pub const fn mlat_per_feeder(hosts_mlat: bool) -> usize {
    if hosts_mlat {
        MLAT_REFIT_NANOS_PER_FEEDER
            + MLAT_VERIFY_NANOS_PER_FEEDER
            + MLAT_SOLVE_NANOS_PER_FEEDER
            + MLAT_HOST_NANOS_PER_FEEDER
            + MLAT_STEP_REST_NANOS_PER_FEEDER
            + MLAT_PUBLISH_NANOS_PER_FEEDER
    } else {
        0
    }
}

/// The part of [`mlat_per_feeder`] a step of a relay alone runs (its refits, its solving, the
/// host's taking and judging, the rest around the solver): not verifying neighbours' models, of
/// which it has none, nor publishing, on the duties thread. What a load test of one relay holds
/// its steps' time to, as a share of the target (`//crates/load:plan_seats`).
pub const fn mlat_step_per_feeder() -> usize {
    MLAT_REFIT_NANOS_PER_FEEDER
        + MLAT_SOLVE_NANOS_PER_FEEDER
        + MLAT_HOST_NANOS_PER_FEEDER
        + MLAT_STEP_REST_NANOS_PER_FEEDER
}

/// Nanoseconds of one core a second the plan sets aside for one seat: its cost
/// ([`mlat_per_feeder`]) at [`MLAT_BUSY_PERCENT`] of MLAT's threads, so the seats the cores carry
/// run their steps at the governor's target.
pub const fn mlat_planned_per_feeder(hosts_mlat: bool) -> usize {
    (mlat_per_feeder(hosts_mlat) * 100).div_ceil(MLAT_BUSY_PERCENT)
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
/// hosted. MLAT's work follows the seats, which hold the members' raw it takes part with too
/// ([`planned_per_feeder`]).
fn mlat_planned(load: Load, hosts_mlat: bool) -> usize {
    load.seats
        .saturating_mul(mlat_planned_per_feeder(hosts_mlat))
}

/// Nanoseconds of one core a second the plan sets aside for one planned feeder's worth of
/// `source`'s rate: the stages' share at [`BUSY_PERCENT`]. Its MLAT is a seat's
/// ([`mlat_per_feeder`]): the engine's seats are every receiver it holds, the members' border band
/// as much as the feeders (`tally_mlat::engine::Capacity::receivers`), so a member's raw takes part
/// only where it holds a seat, and is never planned a second time beside them. Before, each
/// feeder's worth of the members' rate was planned a seat's MLAT ahead of every feeder as well,
/// so a relay on one core with the members' rate it is packaged with carried no feeder at all.
pub fn planned_per_feeder(source: Source, holds_raw: bool) -> usize {
    spent_per_feeder(source, holds_raw)
        .saturating_mul(100)
        .div_ceil(BUSY_PERCENT)
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
        .saturating_sub(seats.saturating_mul(mlat_planned_per_feeder(holds_raw)))
        .checked_div(connection_nanos(holds_raw).saturating_add(stage_nanos(holds_raw)))
        .unwrap_or(usize::MAX)
}

/// The receptions a second the stages carry in what `available` nanoseconds leave after
/// `connections` sessions and `seats` MLAT seats: the cores' bound on `R_max`.
pub fn rate_carried(available: usize, holds_raw: bool, connections: usize, seats: usize) -> u64 {
    let left = available
        .saturating_sub(seats.saturating_mul(mlat_planned_per_feeder(holds_raw)))
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
        .checked_div(mlat_planned_per_feeder(holds_raw))
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
/// average: a step's refits and solves come together once a second, and a step that runs past
/// its second is overload (`mlat_host`, Overload), which cuts seats. Its threads run below the
/// stages' priority, so the cores they share with the stages cost the stages nothing.
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
            // 5,000 planned feeders, about 3 M receptions a second, which one ingest worker could
            // not carry (one message thread and the sealer's one thread carry them: 98 and 65 ns
            // a reception).
            let five = threads_for(load(planned(5_000)), holds_raw, Some(10));
            assert!(
                five.message >= 1 && five.ingest >= 2 && five.seal >= 1,
                "{five:?}"
            );
            // 20,000, about 12 M, which neither one message thread nor one sealer could.
            let twenty = threads_for(load(planned(20_000)), holds_raw, None);
            assert!(twenty.seal >= 2 && twenty.message >= 2, "{twenty:?}");
            // Four times the rate, about four times the threads.
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
        // Holding MLAT raw never costs the sealer less (measured no dearer since 2026-10-27), and
        // costs the ingest workers' receptions more.
        assert!(
            threads_for(load(planned(20_000)), true, None).seal
                >= threads_for(load(planned(20_000)), false, None).seal
        );
        assert!(
            Work::Ingest.per_feeder(true, Source::Member)
                > Work::Ingest.per_feeder(false, Source::Member)
        );
    }

    /// A record costs the ingest workers `INGEST_NANOS_PER_RECORD` whatever its receptions,
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
                        + seats * mlat_planned_per_feeder(holds_raw)
                        <= available,
                    "{cores} {holds_raw}"
                );
                if holds_raw {
                    // MLAT's share is kept for the seats, and connections went on beyond them.
                    assert!(seats > 0 && seats <= connections, "{cores} {seats}");
                    assert!(
                        (seats + 1) * mlat_planned_per_feeder(true)
                            >= available / 100 * MLAT_SHARE_PERCENT
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

    /// A source's records are paced together and any may be answered on the
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
            (10_000 * mlat_planned_per_feeder(true)).div_ceil(NANOS)
        );
    }

    /// Every session beside the feeders and the members is planned at its role's
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

    /// A seat costs every part the host pays for it, each as measured, and is planned at the
    /// governor's target of MLAT's threads; nothing where MLAT is not hosted.
    #[test]
    fn a_seat_costs_its_share_of_its_areas_refits_and_its_solving() {
        assert_eq!(mlat_per_feeder(false), 0);
        assert_eq!(mlat_planned_per_feeder(false), 0);
        assert_eq!(MLAT_BUSY_PERCENT, 75);
        assert!(mlat_planned_per_feeder(true) * MLAT_BUSY_PERCENT >= mlat_per_feeder(true) * 100);
        assert_eq!(
            mlat_per_feeder(true),
            MLAT_REFIT_NANOS_PER_FEEDER
                + MLAT_VERIFY_NANOS_PER_FEEDER
                + MLAT_SOLVE_NANOS_PER_FEEDER
                + MLAT_HOST_NANOS_PER_FEEDER
                + MLAT_STEP_REST_NANOS_PER_FEEDER
                + MLAT_PUBLISH_NANOS_PER_FEEDER
        );
    }
}
