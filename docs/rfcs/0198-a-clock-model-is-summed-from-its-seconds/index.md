# RFC-0198: A clock model is summed from its seconds

- Status: proposed, for this review (2026-11-01)
- Builds on: RFC-0171 §3.8.1 (as amended 2026-10-24), RFC-0181 §10 ("MLAT in the cores")
- Measured on: `742ac7b` (main after #38) and wiedehopf/mlat-server `c2d35b7`, on anvil (Ryzen 9
  9950X, 16 cores, 32 threads), release builds

## §0 The answer, in short

A hosted MLAT seat costs 8.10 ms of one core a seat-second, all stages (`cores::mlat_per_feeder`,
Tally #38), so the world relay (`tests/world-relay.txt`, 16 cores, 4 MLAT threads) plans 363 seats.
The goal is at most 1 ms a seat-second, all stages.

**First, mlat-server was measured on the same sky (§2).** wiedehopf's mlat-server ran on one
core. A load generator emulated N mlat-clients from tally-load's own scene and spoke mlat-client's
wire protocol to it. Tally ran on the same scene at the same N. Measured:

- mlat-server costs 1.69 ms of one core a receiver-second at 250 receivers and 1.93 at 500. At
  500 it uses 0.96 of its core. At 1,000 it falls over: the core is full, its status loop runs
  minutes late, and it publishes no Mode S fix in the measured window.
- On the same scene, Tally's MLAT costs 5.40 ms a seat-second at 250 receivers and 4.74 at 500.
  This is the relay's CPU with MLAT on less with it off, over the seats held, with no neighbour
  to verify. The plan's 8.10 also counts verification and the 2,000-feeder load's geography.
- **Per receiver, Tally is 2.5 to 3.2 times dearer than mlat-server on the same sky; against the
  plan's 8.10, 4.2 to 4.8 times.** Per core, mlat-server carries about 500 receivers before it
  falls over. Tally carries 211 seats on a fully busy core at 4.74 ms, or 123 at 8.10.
- Per fix, Tally is the cheaper of the two: 3.3 ms of core a Mode S fix, against 5.6 to 8.9.
  Tally published 4.6 to 4.8 times the Mode S fixes and solved 0.47 to 0.49 of the eligible
  (aircraft, 0.7 s) slots, against mlat-server's 0.15 to 0.16. Its median horizontal error was 29
  to 40 m against 61 to 73 m. Some of mlat-server's low yield may be this scene's doing (§2).
- The gap is one stage. mlat-server's clock synchronisation, all of `ClockTracker.receiver_sync`
  with its pair updates, costs 0.10 ms a receiver-second (its own profiler). Tally's refit costs
  5.04 ms a seat-second, about 50 times as much. On solving, Tally is already cheaper: 0.63
  against 0.83.

**The target.** The goal stays at most 1.0 ms a seat-second, all stages. Parity with mlat-server
is a looser number: 1.7 to 1.9 ms. Both are stated with the seats they plan (§4). At 1.0 ms the
world relay's cores carry 2,946 seats; at parity, 1,733. Either way its memory then binds at
1,334 seats, unless a seat's planned 6.55 MB falls too.

**The plan.** Every stage gets a share of the 1 ms and a costed way to reach it (§5). The
headline is the refit's change (§6): windowed fits from per-second sufficient statistics. Each
pair block is built from its own second's raw. Its sums are exact integers that move into any
window's frame exactly. A refit adds the new seconds and drops the expired one. So a raw point is
read from raw about twice in its life, not about fifteen times (a block's pooling merges runs
already sorted), and the model stays a deterministic function of the cited window's raw. The other option is now secondary: fewer reference events
(option B of the first revision).

**Estimated, not measured:**

| Plan | Refit (ms a seat-second) | Whole pipeline | World relay seats |
| --- | --- | --- | --- |
| The headline alone | 1.6 to 2.1 | | 580 to 651 |
| Headline and B | 1.0 to 1.3 | | 701 to 760 |
| Every stage's plan | | 1.6 to 2.95 | 998 to 1,334 (memory binds at the low end) |

So the costed plan reaches, at its best, about parity with mlat-server (1.6 against 1.69 to
1.93), not the 1 ms goal. §5 names the 0.6 to 1.95 ms it leaves and where it sits.

## §1 Why a window

**What the window serves.** RFC-0171 §3.8.1 makes the clock model shared evidence:

- *A model is a function of its cited inputs.* "Each fix ... is a deterministic function of its
  used set, its model and the version; the model is a deterministic function of its own input
  set." A model cites its area, its trailing window and its input set by hash, count and each
  member's frontier.
- *Any relay verifies it from raw it holds.* "Verifying a model is rebuilding its area's members
  and pairs from the site records and its inputs from the batches its frontiers cite, ... then
  checking each pair at its published knots." In code: `Engine::verify_model` (`tally_mlat`) calls
  `verify_pair_model_held`, which rebuilds the inputs with `Arrived::rebuild(model)` and checks the
  model with `pair::check_model`. A relay holds raw for `arrived::HELD_MS` (32.5 s), so a model
  must be a function of a bounded span of raw, or no relay could rebuild it.
- *A fault is provable.* "A fault is a signed model or fix that fails verification on its own
  cited raw: any relay holding that raw shows it."
- *Relays agree, so clients can merge.* Two relays holding the same batches fit the same inputs
  at the same edge (the 2026-10-24 amendment, held by
  `the_same_batches_in_any_order_and_copies_publish_the_same_models`), and "clients merge by the
  hash of a model's inputs, never its bytes".

**Why an incremental filter breaks it.** RFC-0171 §3.8.1 says "mlat-server's clock sync is
private and stateful, so its outputs could be neither deduplicated nor verified", and §7 kills
"Bridging to mlat-server" and "Adding MLAT summaries" for that reason. mlat-server's source shows
how deep the dependence runs (`mlat/clocktrack.pyx` at `c2d35b7`):

- `ClockPairing.update` judges each sync against its running prediction (`outlier_threshold`,
  1.5 µs).
- The drift is a proportional-integral loop (`_update_drift`, `KP` 0.06, `KI` 0.008).
- The offset is a weighted running average over a ring of 32 (`_update_offset`).
- Which pairs update depends on the order reports reach the server (`_add_to_existing_syncpoint`)
  and on its wall clock (`now - pairing.update_attempted < 0.2`, `now - self.updated < 35.0`).

Nothing a third party holds reproduces that state.

**What the window does not require.** The specification asks for a result, not a procedure: "Any
engine whose models pass is honest, whatever path it took to them: a warm start, another order of
passes, work reused from an earlier refit" (`tally_mlat_solver` crate docs, "Determinism"). The
refit's cost comes from the engine's choices and the specification's point density, not from the
window.

**The pair blocks were not specified, and this PR specifies them.** `blocks.rs`, `sync.rs` and
`pair.rs` cited "crate docs, § The pairwise path, blocks", but the crate docs had no such section.
They still described the Huber and cutoff passes the blocks replaced (`pair::HUBER_PASSES` and
`pair::CUTOFF_PASSES_MOST`, which are no longer in the code). They also said "the points are not
carried ... each refit forms them again".

This PR rewrites the crate docs (`tally/crates/mlat-solver/src/lib.rs`, the specification) to
state what the code does:

- the blocks: their events, their pooled robust line, their inliers, their sums by knot interval,
  their steps and their read span;
- the fit from the blocks' sums, with no robust pass at the pair;
- the anchors;
- the warm start, as noise and rates only;
- jumps, as the blocks' steps.

An independent verifier can now be written from them. No code changed, and clippy and rustfmt
pass.

## §2 The baseline: mlat-server on the same sky

**What ran.**

- *The server.* wiedehopf/mlat-server `c2d35b7` on Python 3.12.3, numpy 2.5.4, scipy 1.18.1 and
  Cython 3.3.0, with its extensions built in place. It ran on one CPU (`taskset -c 15`) with BLAS
  held to one thread. It listened on TCP. It wrote every result to its CSV.
- *Three changes to its checkout, none to its processing.* The CSV log rotates at 4 GB, not
  10 MB, and prints latitude and longitude to six decimals, not four, so no fix is lost or
  rounded to 11 m. `constants.Cair` is the vacuum speed of light, not c / 1.00032: the scene
  propagates at c (`tally_mlat_solver::geo::C`), and Tally's solver assumes the same. Left alone,
  it would charge mlat-server a range scale error of 3.2 parts in 10,000, about 0.1 to 0.3 µs
  between receivers 100 to 300 km apart, which a real sky does not impose relative to its own
  assumption.
- *The load generator* (`mlat-emu`, a local build in the Tally tree, not shipped). It rebuilds
  tally-load's scene exactly: the same scenarios, receivers, clocks and aircraft. Its reception
  probability is calibrated as `tally_load::traffic` does it: 0.5685 at 250 receivers, which
  tally-load printed as 0.569.
- *It plays the scene in real time.* For each receiver it runs mlat-client's coordinator logic
  (wiedehopf/mlat-client `28ae4f7`):
  - an aircraft is ten messages old before it is used;
  - a sync is sent for each new DF17 airborne position of a requested aircraft once an even and
    an odd are held within 5 s, with an altitude and NUCp of at least 6;
  - an mlat message is sent for each DF11 or DF4 of a requested aircraft with no recent position;
  - seen and lost reports and rate reports go out every fourth aircraft update (4.5 s and up to a
    second);
  - `start_sending` and `stop_sending` are honoured.
- *It speaks mlat-client's wire.* Version 3 handshake. zlib2 framing both ways: level 1,
  `Z_SYNC_FLUSH`, the tail stripped, a two-byte length. Lines flushed every 0.25 s as mlat-client's
  `server_send` does. A heartbeat every 30 s. Results returned in the ecef format.
- *Tally on the same scene.* tally-load ran at the same N with the world relay's arguments (16
  cores, its memory, 1,024 connections), once with MLAT and once without. Every fix the relay
  published was dumped through a local patch to `Hub::publish_positions`, not shipped. Both
  systems' fixes were scored by the same code against the scene's truth.

**Where the emulation is not faithful, and what that changes.**

1. *TCP only.* mlat-client sends syncs and mlat messages as packed binary over UDP when a server
   offers a UDP port. Whether adsb.lol does is not known. JSON over TCP costs the server more to
   parse, so this baseline may overstate mlat-server's cost by up to the unprofiled remainder
   below (about 10% of its CPU).
2. *Only the message kinds the client uses are fed to it:* DF17 airborne positions, DF11 and DF4.
   The scene's other DF17 kinds would only have counted toward an aircraft's first ten messages,
   so an aircraft starts being used a little later. The server sees the same traffic in the
   steady state.
3. *One receiver in fifty is GNSS-disciplined in the scene.* It is announced as `dump1090`, with
   its time of day turned into a 12 MHz count. mlat-server then models it with its looser clock
   class (100 ppm, 500 ns) rather than `radarcape_gps`.
4. *Counters are not wrapped at 48 bits.* The scene's start counts are below 2^41, so no client
   would have announced an epoch rollover in these runs.
5. *Sends are quantised.* They go out at 20 ms ticks and 0.25 s flushes. mlat-server stamps a
   result with the server-clock arrival of its first copy, so its error "at its stated time"
   includes up to a quarter second of client batching. "On its track" removes timing from both
   systems.

**The scene bears on mlat-server in three ways, which are not emulation faults.**

- A receiver keeps each message with probability 0.57, independently, which is how tally-load
  reaches 600 receptions a second with 9,000 aircraft a cluster. A sync point needs both
  receivers to hold the same even and the same odd message, so independent loss thins mlat-server's
  clock pairs more than Tally's events.
- A third of the aircraft are Mode S only, so there are many mlat messages: about 38 a
  receiver-second at 250 receivers, beside 8 syncs.
- Pressure altitude differs from height by 100 m (one standard deviation, `baro_offset_m`), and
  mlat-server uses the altitude as height.

In every run, half to two-thirds of the receivers sat in mlat-server's bad-sync timeout (its own
`bad_syncs`, from pair errors and jumps). Their mlat messages are then dropped. That is the main
reason for its low yield here. A run at p = 1 (4,900 aircraft a cluster) still had 135 of 250
receivers in timeout. Whether a real sky does this to mlat-server is not known from these runs,
so the yield and accuracy comparison is indicative. The CPU comparison is the robust one: the
p = 1 run cost 1.72 ms a receiver-second against 1.69.

**Measured** (anvil, 2026-11-01, 90 s warm-up then 120 s measured; "foreign" is other users'
CPU on the host during the window):

| N | mlat-server, cores | ms a receiver-second | Mode S fixes a second | Solved slots | Horizontal on track, p50 / p95 | At stated time, p50 | Bad-sync receivers | Foreign, cores |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 250 | 0.422 | 1.69 | 75.7 | 0.158 | 73 / 1,076 m | 118 m | 165 to 167 | 1.9 |
| 350 | 0.688 | 1.97 | 63.9 | 0.117 | 60 / 1,183 m | 101 m | 242 to 245 | 5.9 |
| 500 | 0.963 | 1.93 | 108.0 | 0.146 | 61 / 541 m | 130 m | 339 to 340 | 2.1 |
| 1,000 | 1.000 (full) | (over) | 0 (342 ADS-B) | 0 | | | 552 to 597 | 0.4 |
| 250, p = 1 | 0.430 | 1.72 | 57.6 | 0.198 | 59 / 724 m | 98 m | 135 | 8.2 |

| N | Tally seats held | MLAT cores (on less off) | ms a seat-second | Mode S fixes a second | Solved slots | On track, p50 / p95 | At stated time, p50 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 250 | 213 mean (157 to 250) | 1.340 - 0.188 = 1.152 | 5.40 | 345.7 | 0.467 | 40 / 817 m | 70 m |
| 500 | 363 (the plan's cap) | 1.959 - 0.238 = 1.721 | 4.74 | 518.6 | 0.487 | 29 / 690 m | 52 m |

Notes on the tables:

- "Solved slots" is the share of (aircraft, 0.7 s) slots of Mode S-only aircraft, with a
  transmission heard by four or more receivers in the scene, that have a fix.
- At 250 the Tally run shared the host with other users' work, and its governor cut the seats to
  157 for part of the window. The 500 runs were quiet.
- At 1,000, mlat-server's status lines, due every 15 s, came 1.5 to 5 minutes apart.
- A relay alone verifies no neighbour's models, so Tally's figures leave out the 0.39 ms the plan
  carries for that.

**Where mlat-server spends its core.** Its own profiler (`MLAT_CPU_PROFILE=1`, `mlat/profile.py`)
was run at 250 receivers over 240 s, warm-up included: 94.9 CPU-seconds, 1.58 ms a
receiver-second.

| mlat-server function | Share | ms a receiver-second | Tally's stage | Tally, ms a seat-second (plan) |
| --- | --- | --- | --- | --- |
| `ClockTracker.receiver_sync` (clock sync, with every pair update) | 6.2% | 0.10 | Refit | 5.04 |
| `MlatTracker._resolve` (grouping, `normalize2` 0.32, `solver.solve` 0.27, Kalman 0.15) | 52% | 0.83 | Solving | 0.63 |
| `receiver_rate_report` and `Tracker.update_interest` (which aircraft each receiver sends) | 28% | 0.44 | Host | 0.32 |
| `receiver_mlat` (taking mlat messages) | 1.9% | 0.03 | Step rest | 1.24 |
| `forward_results` | 0.9% | 0.01 | Publishing | 0.48 |
| Not wrapped (JSON parsing, zlib, the event loop) | about 10% | about 0.16 | (ingest, outside MLAT) | |
| No equivalent | | | Verifying | 0.39 |

These rows nest as mlat-server's profiler reports them: `_resolve` includes the solver and the
Kalman filter, and the rate reports include `update_interest`.

mlat-server's clients filter for it. Only syncs of the aircraft it asks for (at most 15 aircraft
and 12 messages a second a receiver, `MAX_SYNC_AC`, `MAX_SYNC_RATE`) and mlat messages for the
aircraft it wants cross the wire. In the measured window that was 0.9 kB a receiver-second.
Tally's engine classifies a seat's whole 600 receptions a second, because the relay holds all of
it.

## §3 What a seat costs Tally now, by stage

The plan (`cores.rs`, measured 2026-10-31 at 335 seats of 2,000 feeders): refit 5.04, step rest
1.24, solving 0.63, publishing 0.48, verifying 0.39 (the sweep's), host 0.32: 8.10 ms a
seat-second.

**The refit.** One refit was split into parts with timers added to `pair::fit` for the
measurement only, not committed. It ran `a_refits_cost_follows_its_points` (world density, seed
9000, 624 refits) and `pairwise_path_sweep` (world density, 60 s) on 2026-11-01, on a busy host,
so the absolute times are about twice a quiet run's. The shares are what is used:

| Part of one refit | ms (loaded host) | Share | Scales with |
| --- | --- | --- | --- |
| Gathering the window from `Arrived` (`area_inputs_over`) | 3.2 | 7% | the window's receptions, every refit |
| Reading it into events (`sync::Reader::new`) | 5.0 | 11% | the window's receptions, every refit |
| Digests, the window's clocks and pairs, gathering the blocks | 2.4 | 5% | the window's receptions, every refit |
| Building the blocks whose digest changed (`BlockCache::update`) | 24.6 | 53% | 6 seconds a refit, each pooling 5 seconds of every pair's points |
| Settling jumps and summing each pair's blocks (`settle`, `PairSums::of`) | 6.4 | 14% | pairs times blocks times knots and aircraft |
| The fixed point's passes and assembling the model | 5.2 | 11% | pairs times passes |
| A refit | 46.8 | | |

At world density, a refit's mean is:

- 58 clocks and 1,042 events;
- 337 valid pairs holding 64,511 points, which is 191 points a pair over the window, or 12.8 a
  pair-second;
- of the window's 15 seconds, 5.97 blocks built and 9.03 held from the last refit.

Each pair point is pooled in five blocks. Each block is built about three times in its life, so
each point is sorted and scored about fifteen times. Each reception is also gathered and read
once a refit for the 21 s from its read-back to leaving the window: about ten times, for every
area it is a member of. mlat-server's equivalent work touches each sync once.

## §4 The target

| Target | ms a seat-second | Seats a fully busy MLAT core | At the plan's 75% | World relay, by its cores | World relay, planned |
| --- | --- | --- | --- | --- | --- |
| Today's plan | 8.10 | 123 | 93 | 363 | 363 |
| Measured on the shared scene, 500 receivers | 4.74 | 211 | 158 | | |
| mlat-server, measured | 1.69 to 1.93 | about 500 before it falls over | | | |
| Parity | 1.7 | 588 | 441 | 1,733 | 1,334 (memory) |
| **Goal** | **1.0** | **1,000** | **750** | **2,946** | **1,334 (memory)** |

The world relay's figures come from `tally-relay check` with the world relay's arguments and the
target's stage budgets put into `cores.rs`, run on 2026-11-01. Below about 2.2 ms a seat-second
the relay's memory, not its cores, binds the seats: 6.55 MB a seat (`per-seat`), so 1,334 seats.
The goal's 2,946 needs a seat at about 2.97 MB. That is the subject of #37 (the arrived store
over its plan), and this RFC does not plan it. The headline holds each area's blocks for the
window, as `BlockCache` does today (208 KiB a receiver, `AREA_CACHE_BYTES_PER_RECEIVER`); its
per-second sorted point runs add to that by an amount slice 2 measures.

## §5 Every stage's share

| Stage | Today (plan) | mlat-server's equivalent, measured | Budget | Plan | Estimated landing |
| --- | --- | --- | --- | --- | --- |
| Refit | 5.04 | 0.10 | 0.30 | §6, then B, then one pass of the fixed point, then a 4 s refit | 0.5 to 1.2 |
| Step rest | 1.24 | 0.03 taking, 0.16 parsing | 0.20 | classify once at ingest | 0.3 to 0.5 |
| Solving | 0.63 | 0.83 | 0.20 | self-check reuses the solve | 0.4 to 0.5 |
| Publishing | 0.48 | 0.01 | 0.10 | a model only when it changed | 0.15 to 0.3 |
| Verifying | 0.39 (likely understated) | none | 0.10 | §6's blocks for neighbours' models | 0.1 to 0.2 |
| Host | 0.32 | 0.44 | 0.10 | per step, not per batch | 0.15 to 0.25 |
| **Whole** | **8.10** | **1.69 (1.58 profiled)** | **1.00** | | **1.6 to 2.95** |

Each estimate is from the measured shares and what the plan removes from them. None is measured.
The stages are planned as follows.

- **Refit, 5.04 to a budget of 0.30.** It goes down in four steps:
  - §6 takes it to 1.6 to 2.1.
  - B (§6, the secondary knob) cuts the reads and builds by about 0.375 at
    `REFERENCE_EVENTS_PER_BATCH` 12, which takes it to 1.0 to 1.3. What remains is then mostly the
    fixed point's passes (11% of a refit today, about 0.55 ms), which scale with pairs, not points.
  - One warm pass of the fixed point where the last model's noise and rates still hold takes it
    to 0.7 to 1.2.
  - Refitting every 4 s instead of 2 halves the per-refit parts but not the per-second ones, which
    takes it to 0.5 to 0.8. That needs a specification change (`REFIT_EVERY` is a grid every relay
    shares) and costs every fix a second more carry on average, which the pair sweep must measure.

  mlat-server spends 0.10 on the equivalent, because it updates a pair per sync it is sent and is
  sent few.
- **Step rest, 1.24 to 0.20.** This is classifying each batch (hashing each message, finding its
  positions), choosing and weighing due sets, building records and letting go. The relay already
  inflates and decodes every batch once for its own figures. Classifying for MLAT there, into the
  light tuples the engine takes, and applying the thresholds before a reception is built, removes
  the second pass. B also thins what is classified. Estimated 0.3 to 0.5. The 0.2 budget is what
  mlat-server pays to take and parse what its clients already filtered. Tally's feeders send
  everything, by RFC-0171 §3.1's unit, so the relay does the filtering.
- **Solving, 0.63 to 0.20.** This includes verifying each fix before it is published (20% of
  solving, RFC-0171 §3.8.1, about 0.1). Plans: verify from the solve's own factorisation instead of
  solving again; normalise once per transmission group. Estimated 0.4 to 0.5. mlat-server spends
  0.83 for a quarter of the fixes. Reaching 0.2 would mean solving fewer transmissions a seat
  (Tally solves 3.2 a seat-second and publishes 2.6), which costs latency or yield; slice 6 measures
  that before it is proposed.
- **Publishing, 0.48 to 0.10.** Clock models are about two thirds of what is published (1.25 of
  1.84 MB/s on 2026-10-31). Publishing a model only when its pairs moved beyond the verifier's
  tolerance since the last one, with unchanged parts not sent again, estimated 0.15 to 0.3.
  Signing is not the cost (about 0.26 signatures a seat-second).
- **Verifying, 0.39 to 0.10.** The figure predates the pair blocks. On 2026-11-01 the sweep put a
  model's verification at 0.94 of a refit's cost, where it was 0.69 when the constant was set, so
  a relay with neighbours likely pays more than 0.39. The headline makes a neighbour's model
  verifiable from the same held blocks (`Engine::verify_model` already uses the area's
  `PairCache`): the verifier sums cached blocks and checks the fixed point. Estimated 0.1 to 0.2.
  A two-relay load measures it (slice 5).
- **Host, 0.32 to 0.10.** This is taking batches into the pool, settling its charge, cuts and the
  governor. Taking a step's batches as one sorted run rather than one by one is estimated at 0.15
  to 0.25. mlat-server pays 0.44 here, for choosing what each receiver sends.

**What the costed plan leaves.** It lands at 1.6 to 2.95 ms: about parity with mlat-server at
its best, not 1 ms. The largest gaps to budget are the refit (0.2 to 0.9 over), solving (0.2 to
0.3 over) and step rest (0.1 to 0.3 over). Closing the rest would take decisions this RFC does not make:

- solving fewer transmissions;
- marking at ingest the receptions MLAT can use, so the engine never sees the rest;
- refitting less often.

Each is measured before it is proposed.

## §6 The headline: windowed fits from per-second sufficient statistics

**What is already there.** A pair block (`pair/blocks.rs`, now specified in the crate docs) holds,
for one pair and one second, its inliers' sums by knot interval and by aircraft. A refit sums a
pair's blocks (`PairSums::of`) and solves the knots in closed form, with no robust pass at the
pair. So the window's normal equations are already a sum of per-second summaries. Four things,
all measured in §3, keep a refit from simply adding the new seconds and dropping the expired one:

1. *A block is not final when it is first built.* It reads 2 s past its own second
   (`SPAN_AFTER_S`: one transmission's receptions are batched up to 2 s apart). Its digest covers
   every reception from 6 s before to 2 s after, across all pairs. So at each edge the newest four
   blocks change, and late batches change more: 5.97 of 15 are built each refit.
2. *A block pools its own and the four seconds before it* (`LINE_BLOCKS`) for its robust line. It
   re-reads and re-sorts them, so each point is pooled in five builds.
3. *Every refit gathers and reads the whole window:* 23% of a refit.
4. *A block's sums are taken about its own line, in floating point.* Moving them into a window's
   frame (`PairSums::of`'s centre and shift) transforms every block's units each refit, and a
   floating-point sum depends on its order, so the reference engine re-sums all fifteen.

**The change.**

- **Exact sums** (specification version 9). A block's inliers are summed in integers:
  - `x`, `y` and the ranges in signed picoseconds from the block's reference counts;
  - the weight `2 / h` in fixed point, at 2^-32;
  - the products in 128 bits, which are exact at these magnitudes.

  A block's sums move to any window's anchors exactly, as polynomial identities in the shift
  (`sum (y + d)^2 = sum y^2 + 2 d sum y + n d^2`). A window's sums are then the exact sum of its
  blocks' sums in any order. A refit adds the new seconds and subtracts the expired one, and gets
  what re-summing all fifteen would. The solve converts to floating point once a refit, per pair.
- **Each block built twice at most.** A block is built provisionally while its 2 s read-after is
  still arriving, and finally once it has passed (`FIT_LAG` after). Each refit then builds four
  seconds' blocks rather than about six. A late batch rebuilds only the blocks whose events it
  joined. A per-event digest replaces today's per-second digest over every reception, so one late
  receiver no longer rebuilds every pair of the second.
- **Pooling without re-reading.** Each pair keeps its own points of each second sorted by `x`,
  for the four blocks after it. A block's pooled list becomes a merge of five sorted runs, not a
  re-read and a sort. The same multiset in the same order gives the same medians to the bit, so
  this part is the reference engine's, not the specification's.
- **Reads per second.** The gathering and the reader's events are held per second, by the
  batches each second read. A refit reads only the seconds whose batches changed. Each batch's
  part digest is already computed once on arrival, as the specification says.
- **Jumps, the fixed point and inflation are unchanged in kind.** Steps are found per block as
  now. Attribution runs per refit over the pairs' steps. A kept-segment cut rebuilds only the
  blocks pooling points before it. The noise and rates are sought from the previous model's, over
  pairs. The between-aircraft inflation is per-aircraft sums, which add.

**Verifiability is unchanged.** A block is a function of the raw in its read span. A window's
sums are the exact sum of its blocks'. The fit is the closed-form optimum of those sums under the
published noise and rates. So the model remains a deterministic function of the cited window's
raw (RFC-0171 §3.8.1). A verifier recomputes the blocks from the cited raw by the same rule and
gets the same integers. It may keep a neighbour area's blocks between that neighbour's
successive models, as `Engine::verify_model` already does with the area's `PairCache`. Nothing
carried from one model to the next enters a model.

**What does not decompose.**

1. *The robust line and its inlier test.* They are median-based, so not additive. They are decided
   once per block, from its pooled raw, deterministically. With the merge, the line is today's to
   the bit, so there is no accuracy change.
2. *The newest two seconds* are not final until their read-after has passed. They are built twice:
   the cost above. The alternative is to end a model's sync two seconds before its edge, so every
   block is built once. That carries every fix two seconds further on its models (still within
   `MAX_CARRY`). Its accuracy cost is unmeasured and would come from the pair sweep; it is not
   proposed.
3. *Late batches and jump cuts* rebuild blocks from raw. The cost is bounded by the late raw and
   by the pairs of a clock with a newly attributed jump. How often either happens on real traffic
   is not measured.
4. *The fixed point and the noise estimate* are nonlinear in the sums, but over pairs and clocks,
   not points. They stay per refit: the 11% that bounds the refit once the rest is gone.
5. *Integer quantisation* (weights at 2^-32, ranges and times at 1 ps) changes a model's bytes
   from version 8's by far less than the verifier's tolerance, but it changes them. Hence a
   specification version: a verifier judges only its own version and counts another unjudged,
   never failed (`tally_mlat_solver::judges`).

**A further option that is not proposed.** Drawing a block's line through per-block summaries (the
medians of each pooled second's halves) instead of the pooled points would read each point once
in its block and never again. The inlier test would then be coarser: points near the cutoff
could be misjudged. Coverage would have to be measured over the pair sweep and LocaRDS before it
could be proposed.

**Estimated cost.**

| Part of a refit | Share today | After | Why |
| --- | --- | --- | --- |
| Reads (gather, reader, digests) | 23% | 0.15 of it | 2 to 4 changed seconds of 21 read |
| Block builds | 53% | 0.27 to 0.40 of it | 4 builds a refit instead of 6, and merging instead of re-reading and sorting (0.4 to 0.6) |
| Settling and summing | 14% | 0.2 to 0.4 of it | exact add and drop instead of re-summing fifteen |
| Passes | 11% | unchanged | |
| **A refit** | **100%** | **0.32 to 0.41** | |

So the refit falls from 5.04 to 1.6 to 2.1 ms a seat-second, and the world relay plans 580 to 651
seats, with verifying falling with it and the other stages as they are. With B at 12 it is 1.0 to
1.3 ms and 701 to 760 seats.

**Open risks.**

- *Memory*, which binds at the target: holding sorted per-second runs and per-event digests.
- *How often* real late batches and jumps force rebuilds.
- *The specification version's rollout:* relays upgrading together judge each other's models as
  unjudged, not failed.
- *The 11% the passes leave*, which no part of this change touches. Once the rest is gone the
  passes bound the refit.

**B, now the secondary knob.** B lowers `threshold::REFERENCE_EVENTS_PER_BATCH` from 32 to the
least value the pair sweep's calibration holds, expected near 12. A pair keeps an event both its
ends heard at the lower of their two rates. Where both caps bind, as at world density, a pair's
points fall in proportion: 12.8 a pair-second becomes about 4.8, near mlat-server's at most five
a pair-second (`pairing.n > 8 and now - pairing.update_attempted < 0.2`). It stays a hash
threshold, a function of one batch alone, so it keeps every property of §1. Alone it is
estimated at a refit of 2.3 to 2.8 ms (521 to 576 seats). It is taken only if the calibration
holds (slice 3).

## §7 Measurement plan and slices

Every slice is measured three ways:

- *The world relay's load.* `tally-load` with 2,000 feeders against the world relay's plan, its
  per-thread CPU and the steps' timers sampled over the window on a quiet anvil, as `cores.rs`
  describes. Then `//crates/load:plan_seats`.
- *The shared-scene comparison* of §2 at 250 and 500 receivers. Its harness is the
  baseline's: `mlat-emu`, `sweep.sh`, `sample_mlat.py`, `sample_tally.py` and `profile.sh`, kept
  with every run's raw data in `anvil:/data/johnny/tally-trees/mlat-baseline`.
- *The solver's own measures:* `a_refits_cost_follows_its_points` and `pairwise_path_sweep`.

The slices:

0. **The baseline and the specification (this PR).** mlat-server and Tally on one scene (§2), and
   the pair blocks written into the crate docs (§1). No byte published changes.
1. **The refit measured in parts.** Its parts (gather, read, blocks built and held, build,
   settle, passes) and its points, clocks and members go into `pair::Stats`, `/mlat`'s
   `steps_total` and `a_refits_cost_follows_its_points`, so every later slice is measured where it
   cuts. No byte changes.
2. **The headline, engine part.** Reads held per second, pooling by merge, per-event digests,
   blocks built at most twice. Bytes unchanged: `the_same_batches_in_any_order_and_copies_publish_the_same_models`
   and the pair-model golden must pass unchanged. Measured as above, with the memory the held runs
   cost.
3. **The headline, specification part (version 9).** Exact integer sums, and the refit as add and
   drop. The pair sweep's calibration must stay within 0.92 to 0.98 in every scene, with world
   density's median and 95th-percentile error within 2%, no false jump, and every model and
   sampled fix verified. Then B, measured as a knob at 32, 20, 16 and 12: take the least value at
   which every scene's coverage stays within 0.92 to 0.98, the medians move by no more than 10%,
   and LocaRDS coverage stays within 0.01 of version 8's 0.954.
4. **The fixed point.** One warm pass where the last model's noise and rates still hold, measured
   by passes a refit and calibration.
5. **Verifying, measured.** A load with two relays splitting the world relay's areas, so each
   verifies the models of the other's that its fixes cite. Then
   `MLAT_VERIFY_NANOS_PER_FEEDER` is set from it.
6. **The other stages.** Classifying at ingest (step rest); the self-check from the solve's
   factorisation (solving); a model only when changed (publishing); a step's batches as one run
   (host). Each is measured alone, then the `cores` constants, `world-relay.txt`, `cores-10.txt`
   and RFC-0181 §10 are updated and `plan_seats` passes. Whether to solve fewer transmissions
   is measured here before anything is proposed.

## §8 What is measured and what is estimated

Measured:

- **mlat-server on the shared scene:** its CPU per receiver-second at 250, 350, 500 and 1,000
  receivers, and at 250 with p = 1; its Mode S fixes, solved slots and horizontal errors against
  the scene's truth; its bad-sync receivers and clock pairs (`sync.json`); where it falls over
  (§2).
- **mlat-server's own CPU split** at 250 receivers (`MLAT_CPU_PROFILE=1`).
- **Tally on the same scene** at 250 and 500 receivers: the relay's CPU with MLAT and without, the
  seats held, its fixes, solved slots and errors.
- **The per-seat costs** (Tally #38, `cores.rs`, 2026-10-31).
- **A refit's split into parts** and its points, pairs and blocks (2026-11-01, on a busy host;
  shares used).
- **The verification-to-refit ratio** of 0.94 in the 2026-11-01 sweep, against 0.69 when the
  constant was set.
- **Every "World relay seats" figure:** `tally-relay check` with the world relay's arguments and
  the stated per-seat costs put into `cores.rs`.

Estimated:

- every option's and stage's landing (§5, §6), from the measured shares and what each plan
  removes;
- the memory the headline adds;
- how often late batches and jumps force rebuilds;
- B's and the headline's accuracy, which slice 3 measures before either is taken.

Not established:

- whether mlat-server's bad-sync rate here is the scene's doing or would happen on a real sky;
- how much UDP transport would save mlat-server.
