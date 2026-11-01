# RFC-0198: A clock model is summed from its seconds

- Status: proposed, for this review (2026-11-01, fourth revision)
- Builds on: RFC-0171 §3.8.1 (as amended 2026-10-24), RFC-0181 §10 ("MLAT in the cores")
- Prerequisite: #37 (a seat's memory measured and planned), for any slice that changes
  `cores.rs`, `tests/world-relay.txt` or `tests/cores-10.txt`
- Measured on: `742ac7b` (main after #38) and wiedehopf/mlat-server `c2d35b7`, on anvil (Ryzen 9
  9950X, 16 cores, 32 threads), release builds

## §0 The decision asked for

This RFC asks for one decision now: **run slice 1**, a measurement slice that changes no
specification and no production code. Its results decide whether slice 3 is built. Slice 3 is an
engine-only incremental refit that leaves published bytes unchanged and is checked, on a sample
of refits, against a full refit while it runs.

Anything that changes the specification is decided later, in its own slice, on the evidence the
earlier slices produce. That covers fewer reference events (slice 4) and exact integer sums
(slice 6, a later RFC if it is wanted at all).

**The scope is parity with mlat-server per receiver, but this RFC builds no path to it.**
Parity is about 1.8 ms a seat-second, the whole pipeline. Slice 3 changes only the refit, and
leaves the pipeline at about 5.3 to 6.4 ms a seat-second. The stages that would close the rest
(step rest, solving, publishing, verifying, host) are open questions (§8), as are the 1 ms goal
and the budgets below parity.

**Why.** A hosted MLAT seat costs 8.10 ms of one core a seat-second, all stages
(`cores::mlat_per_feeder`, Tally #38), so the world relay plans 363 seats.

- **mlat-server on the same simulated sky (§2).** As shipped, on one core, it costs 1.77 ms a
  receiver-second at 250 receivers (two quiet repeats). It carries about 500 receivers before its
  core is full, and falls over by 1,000.
- **The bad-sync bound.** Most of its emulated receivers sat in bad-sync timeout, which drops
  their mlat messages. With that drop patched out, it costs 2.28 ms at 250.
- **Tally on the same scene.** Its MLAT costs 4.74 ms a seat-second at 500 receivers, in a clean
  run.
- **The gap per receiver.** Against mlat-server as shipped, Tally is 2.68 times dearer (1.77 at
  250 against Tally's 4.74 at 500) or 2.59 times (mlat-server's 1.83 at 500). Against the
  2.28 ms sensitivity point it is 2.08 times. These are not bounds: a healthy sky with more
  solves could cost mlat-server more, and its figure includes parsing that Tally's excludes.
- **The refit is the gap.** On the shared scene it costs 2.98 ms a seat-second, against 0.10 for
  mlat-server's whole clock synchronisation: about 30 times, again an upper bound.

**What is estimated.** Slice 3 is estimated to take the refit from 5.04 ms to 2.25 to 3.31 ms
a seat-second, the sampled shadow check included. With verifying left at 0.39 ms, that plans 462
to 554 world-relay seats (`tally-relay check`). The range stands until slice 1 measures it.

**The go threshold.** Slice 1 measures slice 3's ceiling: an oracle with all of slice 3's
savings, plus the shadow check's cost, on the relay, on a quiet host. Slice 3 is built only if
that ceiling is at most 0.6 of the relay's measured refit. That is 3.0 ms on today's 5.04 ms plan
(486 seats, 34% more), or 1.79 ms on the shared scene's 2.98 ms.

**Memory binds before cores do.** At the measured footprint the world relay's memory carries
about 900 to 1,100 seats, not the planned 1,334.

## Glossary

- **Seat-second:** one hosted MLAT receiver (a seat) for one second. Costs are milliseconds of
  one core per seat-second.
- **On less off:** the relay's CPU with MLAT hosted less the same load without it. This is what
  MLAT costs the relay, apart from ingest it does anyway.
- **Step rest:** MLAT's step work beyond refits and solving: classifying batches, choosing and
  weighing due sets, building records, letting go (`MLAT_STEP_REST_NANOS_PER_FEEDER`).
- **Carry:** how far past its models' trailing edge a fix is solved.
- **Read-after:** the 2 s after a block's own second that its events gather receptions over
  (`sync::SPAN_AFTER_S`), because one transmission's receptions arrive in batches up to 2 s apart.
- **Fewer reference events:** lowering `threshold::REFERENCE_EVENTS_PER_BATCH`. The first
  revision called it option B.

## §1 Why a window

**What the window serves.** RFC-0171 §3.8.1 makes the clock model shared evidence:

- *A model is a function of its cited inputs.* A model cites its area, its trailing window and
  its input set by hash, count and each member's frontier.
- *Any relay verifies it from raw it holds.* `Engine::verify_model` calls
  `verify_pair_model_held`, which rebuilds the inputs with `Arrived::rebuild(model)` and checks
  them with `pair::check_model`. A relay holds raw for `arrived::HELD_MS` (32.5 s).
- *A fault is provable* on the model's own cited raw.
- *Relays holding the same batches fit the same inputs*, and clients match models by the hash of
  their inputs.

**Why an incremental filter breaks it.** RFC-0171 §3.8.1 says "mlat-server's clock sync is
private and stateful, so its outputs could be neither deduplicated nor verified". mlat-server's
`ClockPairing.update` (`mlat/clocktrack.pyx`) judges each sync against its running prediction.
Its drift is a proportional-integral loop and its offset a weighted running average. Which pairs
update depends on arrival order and on the server's wall clock. Nothing a third party holds
reproduces that state.

**What the window requires, stated exactly.** A published model passes verification against its
cited raw: each pair is an optimum within tolerance, and the noise and rates are at the fixed
point within the band. Its *bytes* may depend on history. The fixed point is sought from the
previous model's noise and rates, and a clock's noise is kept while within half the verifier's
band of its estimate (`NOISE_HOLD`), so a warm and a cold refit of the same inputs can publish
different bytes. The first and second revisions said that nothing carried enters a model; that
was false and is withdrawn.

`a_warm_refit_publishes_what_a_cold_refit_publishes` used to pass the previous model with its
pairs stripped, which `pair::fit` does not read, so it compared a warm refit with itself. It now
fits cold from nothing (`warm = None`). It asserts that both models pass their verifier, carry
the same clocks and pairs, and hold each clock's noise within `verify::NOISE_BAND` of the other.
With a truly cold start the bytes differ, as expected. The test passes.

**The specification is written down.** `blocks.rs`, `sync.rs` and `pair.rs` cited "crate docs, §
The pairwise path, blocks", but the crate docs had no such section, and they still described the
Huber and cutoff passes the blocks replaced. This PR writes the blocks into the crate docs
(`crates/mlat-solver/src/lib.rs`):

- their events and their pooled robust line;
- their inliers, their sums by knot interval and their steps;
- their read span, stated as the receptions *in the window's inputs*. The newest two seconds'
  blocks of one window differ from the same seconds in a later window, because a window's inputs
  end at its edge (`Trailing::reads`).

It also states the fit from the blocks' sums with no robust pass at the pair, the anchors, the
warm start as noise and rates only, and jumps as the blocks' steps.

## §2 The baseline: mlat-server on the same sky

The method, the emulation's fidelity and the scene's properties are in Appendix A. In short:

- wiedehopf's mlat-server ran on one CPU;
- `mlat-emu` emulated N mlat-clients from tally-load's own scene, speaking mlat-client's JSON and
  zlib2 protocol over TCP;
- Tally ran on the same scene at the same N, with MLAT on and off;
- both systems' fixes were scored against the scene's truth.

The harness is now in the repository (`tools/mlat-baseline`, Appendix A).

**First measurements** (2026-11-01, each run once, 90 s warm-up then 120 s measured; "foreign" is
other users' CPU on the host):

| N | mlat-server, cores | ms a receiver-second | Mode S fixes a second | Solved slots | On track, p50 / p95 | Receivers in bad-sync timeout | Foreign, cores |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 250 | 0.422 | 1.69 | 75.7 | 0.158 | 73 / 1,076 m | 170 of 250 | 1.9 |
| 350 | 0.688 | 1.97 | 63.9 | 0.117 | 60 / 1,183 m | 244 of 350 | 5.9 |
| 500 | 0.963 | 1.93 | 108.0 | 0.146 | 61 / 541 m | 340 of 500 | 2.1 |
| 1,000 | 1.000 (full) | (over) | 0 | 0 | | 552 of 1,000 | 0.4 |
| 250, p = 1 | 0.430 | 1.72 | 57.6 | 0.198 | 59 / 724 m | 132 of 250 | 8.2 |

| N | Tally seats | MLAT cores, on less off | ms a seat-second | Refit (steps' timers) | Mode S fixes a second | Solved slots | On track, p50 / p95 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 250 (contaminated, superseded) | 213 mean (157 to 250) | 1.152 | 5.40 | | 345.7 | 0.467 | 40 / 817 m |
| 500 | 363 of 500 | 1.721 | 4.74 | 26.5 refits a second at 40.8 ms: 2.98 ms a seat-second | 518.6 | 0.487 | 29 / 690 m |

**Quiet repeats and the bad-sync sensitivity point** (2026-11-01 evening, `repeats.sh`).
mlat-server ran as shipped and with `patches/mlat-server-bad-sync-kept.diff`. Two repeats of each
completed before other work returned to the host. The third repeat and the Tally 250 rerun are
part of slice 1.

| Configuration | Runs | mlat-server, cores | ms a receiver-second | Mode S fixes a second | Solved slots | On track, p50 | Foreign, cores |
| --- | --- | --- | --- | --- | --- | --- | --- |
| As shipped, 250 | 2 | 0.442 and 0.444 | 1.77 | 75.9 and 76.9 | 0.159 and 0.160 | 65 and 74 m | 0.06 and 0.08 |
| As shipped, 500 | 1 clean | 0.917 | 1.83 | 120.1 | 0.163 | 55 m | 0.0 |
| As shipped, 500 | 1 contaminated | 0.990 (core full) | | 27.1 | 0.037 | 80 m | 12.5 |
| Bad-sync kept, 250 | 2 | 0.570 and 0.570 | 2.28 | 84.4 and 84.7 | 0.176 | 323 and 345 m | 0.04 and 0.21 |
| Bad-sync kept, 500 | 2 | 1.000 (core full) | (over) | 104.4 and 16.0 | 0.14 and 0.02 | 396 and 1,007 m | 0.0 and 9.3 |

- **The cost moves.** Keeping the receivers in bad-sync timeout raises mlat-server's cost at 250
  by 29%, to 2.28 ms a receiver-second. Its accuracy collapses (a median of 323 to 345 m), because
  those receivers' clocks are poor.
- **Its core fills earlier.** As shipped it carries about 500 receivers on one core. With the
  drop removed, its core is full at 500.
- **The 2.28 ms run is a sensitivity point, not an upper bound.** A healthy sky, with every
  receiver in sync and more solves, could cost mlat-server more. Against Tally's 4.74 at 500 (the
  clean shared-scene run), the gap is:
  - 2.68 times against mlat-server at 250 as shipped;
  - 2.59 times against mlat-server at 500 as shipped;
  - 2.08 times against the sensitivity point.

  mlat-server's figure includes parsing that Tally's excludes.
- **The scene still sets the bad-sync rate:** 162 to 170 of 250 receivers in every run. Slice 1
  either changes the scene's sync to under 10% bad-sync, or reports both bounds as here.


**What these numbers can and cannot carry.**

- *mlat-server's cost is understated.* Half to two-thirds of its receivers sat in bad-sync
  timeout. For those receivers `jsonclient.py:593` returns before `receiver_mlat`, and
  `Receiver.update_interest_sets` asks them for no mlat traffic (`coordinator.py:105`), so mlat-server
  did less work than a healthy sky asks of it. The bad-sync counts above are corrected. The harness
  had read a key `clients.json` does not carry and reported 0; it now reads `bad_sync_timeout`.
- *The two figures measure different things.* mlat-server's includes about 10% of unprofiled
  parsing, zlib and event loop. Tally's on-less-off figure excludes the relay's ingest.
- *So the ratios are indicative.* From these single runs: 2.5 to 3.2 times per receiver (4.2 to
  4.8 against the plan's 8.10), and about 30 times on the refit. With the repeats below, as
  shipped: 2.68 times (mlat-server at 250 against Tally at 500) and 2.59 times (both at 500).
- *The yield and accuracy columns are unproven as a comparison.* At "500", Tally solved with 363
  seated receivers (137 refused by its plan's cap), mlat-server with 500.
- *The runs were not clean.* The Tally 250 run shared the host with other work and its governor
  cut seats, so it is superseded. A first mlat-server run at 500 was made during a burst of other
  work (14.6 foreign cores, 49.7 fixes a second). It was replaced by the run in the table and is
  disclosed here.
- *The scene propagates at c, and Tally's solver assumes c.* So the scene cannot show Tally's
  range-scale bias on a real sky, where signals travel at about c / 1.00032 (3.2e-4).
  mlat-server's constant was set to c to match the scene (Appendix A). Only real data
  (LocaRDS) shows that bias.

**Where mlat-server spends its core** (its own profiler, `MLAT_CPU_PROFILE=1`, 250 receivers,
240 s with warm-up included: 1.58 ms a receiver-second):

| Function | Share | ms a receiver-second | Tally's nearest stage, plan (shared scene) |
| --- | --- | --- | --- |
| `ClockTracker.receiver_sync` (clock sync with every pair update) | 6.2% | 0.10 | refit 5.04 (2.98) |
| `MlatTracker._resolve` (normalise 0.32, solve 0.27, Kalman 0.15) | 52% | 0.83 | solving 0.63 |
| rate reports and `Tracker.update_interest` | 28% | 0.44 | host 0.32 |
| `receiver_mlat` | 1.9% | 0.03 | step rest 1.24 |
| `forward_results` | 0.9% | 0.01 | publishing 0.48 |
| not wrapped (JSON, zlib, event loop) | about 10% | about 0.16 | (relay ingest, excluded from Tally's figure) |
| none | | | verifying 0.39 |

Rows nest as the profiler reports them.

## §3 What a refit costs now

The plan (`cores.rs`, 2026-10-31, 335 seats of 2,000 feeders):

| Stage | ms a seat-second |
| --- | --- |
| Refit | 5.04 |
| Step rest | 1.24 |
| Solving | 0.63 |
| Publishing | 0.48 |
| Verifying (the sweep's) | 0.39 |
| Host | 0.32 |
| **Total** | **8.10** |

On the shared scene at 500 receivers the refit measured 2.98 ms a seat-second, from the steps'
own timers. Which base the world relay's plan should carry is one of slice 1's relay-side
measurements.

**One refit, split** (timers added for the measurement only; `a_refits_cost_follows_its_points`,
world density, seed 9000):

| Part | Share | Scales with |
| --- | --- | --- |
| Gathering the window (`area_inputs_over`) | 7% | the window's receptions, every refit |
| Reading it into events (`sync::Reader::new`) | 11% | the window's receptions, every refit |
| Digests, the window's clocks and pairs, gathering blocks | 5% | the window's receptions, every refit |
| Building changed blocks (`BlockCache::update`) | 53% | about 6 seconds a refit, each pooling 5 seconds |
| Settling jumps and summing blocks (`settle`, `PairSums::of`) | 14% | pairs times blocks times knots and aircraft |
| Fixed-point passes and assembly | 11% | pairs times passes |

These shares are provisional:

- They come from an instrumented run on a busy host (46.8 ms a refit). The uninstrumented run on
  the same host read 36.8 ms (gather 2.65, read 24.5, fit 9.6).
- The phase timers counted every refit, warm-up included, in every phase. Only the gather, read
  and fit totals averaged the measured refits alone. The split's shares mix the two.
- They are the solver test's, not the relay's.

Slice 1 measures them again on a quiet host, warm-up excluded, on the relay too, and with the
build split into its parts. All three runs' printed output (`refit-instrumented-2026-11-01.txt`),
the uninstrumented log and the sweep log are archived in
`anvil:/data/johnny/tally-trees/refit-measure/archive`.

At world density a refit's mean is 337 valid pairs, 64,511 points (12.8 a pair-second), and 5.97
of 15 blocks built and 9.03 held.

## §4 Parity, and what it plans

| | ms a seat-second | Seats a fully busy MLAT core | World relay, by its cores | World relay, by measured memory |
| --- | --- | --- | --- | --- |
| Today's plan | 8.10 | 123 | 363 | |
| Shared scene, 500 receivers | 4.74 | 211 | | |
| mlat-server, measured: as shipped, and with bad-sync kept | 1.77 to 2.28 | about 500 as shipped, fewer with bad-sync kept | | |
| **Parity** | **1.8** | **556** | **1,637** | **about 900 to 1,100** |

**Memory binds first.** The plan carries 6.55 MB a seat (`per-seat`). Measured in the
2026-10-31 load (#37):

- a seat's `Arrived` store held 2.4 to 2.95 MB against 1.61 MB planned;
- its `Engine` held 1.04 MB against 0.59 MB;
- the solver test's area memos held 1,679,480 bytes a receiver against the 212,992 planned
  (`AREA_CACHE_BYTES_PER_RECEIVER`).

That puts a seat at about 8 to 9.5 MB, so the memory the world relay keeps for seats carries about
900 to 1,100 of them, below what its cores carry at parity. The memos may be counted twice in
that range: the solver test's per-receiver memo figure and the load's `Engine` figure may hold
the same bytes. #37's `Engine::bytes` breakdown settles it. #37 is therefore a prerequisite for
any slice that changes `cores.rs`, `tests/world-relay.txt` or `tests/cores-10.txt`.

## §5 The proposal: an incremental refit, engine only (slice 3)

**What is already there.** A pair block holds one second's inliers' sums for one pair. A refit
sums a pair's blocks (`PairSums::of`) and solves in closed form. What keeps a refit from touching
only new data:

1. *Builds.* About 6 of 15 blocks are built a refit. The newest four change at every edge because
   of the 2 s read-after, and late data changes more. The digest is conservative: one per second,
   over every reception of the 6 s before and 2 s after.
2. *Pooling.* A build pools the block's own second and the four before it, re-reading and
   re-sorting them, so each point is pooled in five builds.
3. *Reads.* Every refit gathers and reads the whole window.
4. *Sums.* Re-summing all fifteen blocks per pair, in floating point, about each block's own line.

**The change.** Bytes are unchanged and there is no specification change.

- **Reads held per second.** The gathered receptions and the reader's events are kept per second
  of the window's inputs. A second's events depend on batches across its read span, `[s - 2,
  s + 3)`: its look-back, CPR reference, NACp, heard-twice and `h`. So a second is read again
  whenever a batch in its read span changed, not only when its own second's batches did.
- **Pooling by merge, then version 8's order.** Each pair's points of a second are kept, with
  their raw counts and ranges, in runs sorted by an exact key (`a`'s count, then `b`'s, the
  address and the second). That is not version 8's order: version 8 sorts by the float `x = la ·
  ka - range_a`, and the range term reorders points.

  So a build merges the five runs by the exact key, recomputes `x` in the block's own frame, and
  runs an insertion pass with version 8's exact comparator (`x` by total order, then `a`'s count,
  `b`'s, the address and the second). The insertion pass is linear on nearly sorted input. The
  result is version 8's order by construction.

  This removes point formation and the pooled copy, and makes the sort nearly linear. It leaves
  the medians, the MAD, the residuals, `steps()` and the sums, which still touch every pooled
  point about ten times over its life.
- **Invalidation stays conservative.** The per-second digest is kept. Per-(address, second)
  invalidation is adopted only if slice 1's rebuild classification shows it is worth it, and then
  only by the full rule. Block `s` depends on:
  - its look-back `[s - 2, s)`;
  - the CPR references found over all of an address's position receptions in its read span;
  - NACp from status receptions;
  - "heard twice";
  - deduplication moving receptions between seconds;
  - each event's hearer count `h`, which sets `w0 = 2 / h` for every pair of the event;
  - through pooling, the next four blocks.

  So per-(address, second) invalidation means a digest over position and status receptions in
  `[s - 2, s + 3)` plus the look-back, rebuilding every pair of the old and new hearer sets and
  blocks `s` to `s + 4`. The second revision's "a late batch rebuilds only the blocks whose events
  it joined" was wrong and is withdrawn.
- **Cut blocks cached with their second.** After a jump, the blocks that pool points before a
  clock's kept start are rebuilt today at every refit, for about 8 refits. They are held inside
  that second's held state instead, keyed by (second, `from_a`, `from_b`), so they drop with the
  second whenever its read span's digest changes. A late batch therefore never reuses a stale cut
  block, and neither does a second jump on the other clock, which changes the key.
- **Site changes clear everything, as today.** Any scope change clears the whole `BlockCache`.
  The per-second digest does not hash a site's location or precision, and a site edit changes:
  - ranges;
  - which receivers are within `MAX_RANGE_M`, and with it `h` and `w0` for every pair of those
    events;
  - the nearest-40 network, adding and removing pairs.

  With two feeders the full clear costs nothing worth saving. A finer rule is future work. It
  would have to cover the edited receiver's pairs, every pair of the events it heard under the
  old and the new hearer sets, the pairs added or removed, and the four blocks after each.
- **Sums.** Re-summed in canonical order, as now. No running total is kept, so there is no state
  to drift. What is carried is the held reads, runs and blocks, and the shadow check below is
  what catches a bug in them.

**Why the insertion pass.** A merge by float `x` alone would not be "bit-identical": `x` is
computed in each block's own frame, so runs formed in another frame can order near-ties
differently. That could move a point across the `n / 2` split or change a step in `steps()`.
Recomputing `x` in the block's frame and ordering by version 8's comparator removes that, which
is why the gate below compares against today's build path rather than against itself.

**Safety.**

- *In production, a sampled shadow check.*
  - Every 64th refit of an area is also computed from scratch, with empty caches and nothing held
    but the same warm model. A model's bytes legitimately depend on the warm start through
    `NOISE_HOLD`, so a shadow from a cold start would alarm constantly.
  - The two are compared byte for byte, and mismatches are counted on `/mlat`. This is what
    catches a bug in carried state.
  - On a mismatch, the shadow's model is the one published for that refit, and that area's
    caches are cleared. That heals the area without a setting.
  - The cost is one full refit in 64: about 0.08 ms a seat-second at today's cost. It is
    counted in the estimate below and in the `cores` constants slice 3 sets. One in 16 would cost
    about 0.32 ms.
- *No setting and no automatic fallback.* The network is two relays of our own, so a bad build is
  rolled back by redeploying the previous release.
- *Before merge, a cached-against-cold comparison at every refit.* It compares slice 3's path
  against today's build path, the sort included, not the merging code against itself. It runs
  under:
  - lateness up to `HELD_MS`;
  - late copies;
  - late look-back receptions;
  - late status (NACp, TC31) receptions;
  - late extra hearers, which change `h` and with it `w0` for every pair;
  - reconnect backlogs;
  - site changes mid-run, including a location-only edit;
  - a late batch landing in a cached cut block's read span;
  - counter resets.

**Memory acceptance.** Slice 3 adds at most 0.5 MB a seat at world density, measured by the
counting allocator at the plan's seats. That covers held reads and events per second for the
window's 21 s in every area, and the sorted runs. Above that, it does not merge.

**Estimated cost (until slice 1 measures).** It is derived from §3's shares, which are
provisional.

| Part | Share today | Under slice 3 |
| --- | --- | --- |
| Reads | 0.23 | 0.035: only the changed seconds' read spans |
| Settle and sum | 0.14 | 0.14: canonical re-summing, as now |
| Passes | 0.11 | 0.11: unchanged |
| Block builds | 0.53 | 0.15 to 0.36 |
| **A refit** | **1.00** | **0.43 to 0.64** |

- *The floor.* Before any block build, the refit is 0.28 of today's.
- *The builds.* About 4 builds a refit instead of 6, or a factor of about 0.84 if late data is
  systemic. Formation and copy go, and the sort becomes nearly linear. The per-point line, MAD,
  residual, step and sum work stays.
- *The refit.* 2.17 to 3.23 ms a seat-second, plus about 0.08 ms for the shadow check: 2.25 to
  3.31 ms.
- *Seats.* With verifying left at 0.39 ms (the plan's figure; slice 3 does not change how
  neighbours' models are verified) and the other stages as planned, `tally-relay check` with the
  world relay's arguments plans 462 to 554 seats. With the shadow check at one in 16, it plans 445
  to 531.
- *The pipeline.* With everything else as now, it stays at 5.3 to 6.4 ms a seat-second.
- *Memory.* It may bind before cores (§4).

## §6 Fewer reference events (slice 4): a specification change, decided on its own

Lowering `threshold::REFERENCE_EVENTS_PER_BATCH` changes what is kept (crate docs, § Thinning,
`lib.rs` line 207), so it changes models: it is a specification change. So is a 4 s refit
(`tally_wire::budget::REFIT_EVERY`), which is not proposed.

It is decided in its own slice once it is measured. If it and anything else that changes models
(exact integer sums, a 4 s refit) are taken, they ride in the same version.

**What it scales:** the blocks' points (formation, pooling, steps, sums), the sync share of what
`Arrived` holds, and part of settling. Not the per-reception intake and classification (step
rest), nor reading the non-sync receptions.

**What it risks:** sparse pairs. At a cap of 12, a busy-to-distant pair keeps about 4.5 points a
window, against `SPAN_RECEPTIONS_LEAST` of 20, so such pairs stop being valid.

**Gates,** on LocaRDS and the shared-scene harness, at 32, 20, 16 and 12:

- valid pairs by baseline band;
- solved slots and yield;
- jump-detection rate on sparse pairs;
- coverage within 0.92 to 0.98 in every sweep scene.

Then the flag day of §7.

## §7 A specification change is a flag day

The network is ours and small: two feeders, KLAX-1 and the home Pi, and two relays, the dell-r640
k3s cluster and tally-relay-1 on Lightsail.

- If version 9 happens, the wire crate and the relays ship together in one release, and both
  relays are upgraded at once.
- Feeders are unaffected, because they send raw.
- Rollback is redeploying the previous release.
- If outside relay operators existed later, a change like this would need relays that judge both
  versions for a release, and a switch for which version a relay publishes, flipped once they had
  all upgraded.

## §8 Open questions and follow-on work

These are not proposed here.

**The 1 ms goal.** At 1.0 ms a seat-second the world relay's cores carry 2,946 seats; memory
binds well below that. A budget below parity would be:

| Stage | Budget, ms a seat-second |
| --- | --- |
| Refit | 0.30 |
| Step rest | 0.20 |
| Solving | 0.20 |
| Publishing | 0.10 |
| Verifying | 0.10 |
| Host | 0.10 |

Plans for each (classify once at ingest; verify fixes from the solve's factorisation; publish a
model only when it changed beyond tolerance; take a step's batches as one run) stay unestimated
until slice 1. One warm pass of the fixed point would save about 0.27 ms of the refit's 11%. The
4 s refit is not proposed, and nothing here counts it.

**Exact integer sums (slice 6, a later RFC if wanted).** This is proposed only if, after slice 3,
settling and summing still cost at least 0.3 ms a seat-second.

- *Integers only inside the sums* (critic 1's alternative) is declined. With each block's sums
  taken about its own floating-point line, moving them into a window's frame stays a per-unit
  floating-point transform, so add and drop are not exact. All it buys is order independence,
  which canonical re-summing already gives.
- *If the work is wanted, it is integers throughout, with a version bump,* and the first
  revision's no-accuracy-change claim is withdrawn. The normative requirements its RFC must meet
  are in Appendix D.

**The other stages' plans** for step rest, solving, publishing, verifying and host are follow-on
work. Each is measured before it is proposed.

## §9 Slices

0. **This PR.**
   - The first baseline (§2), with its limits stated.
   - The pair blocks written into the specification.
   - The warm-against-cold test made real.
   - The harness committed (`tools/mlat-baseline`).
   - No published byte changes.
1. **Measurement, go or no-go.** No specification or production change.
   - *The refit build split.* `BlockCache::update` split into point formation, pooled copy, sort,
     line and MAD, residuals, `steps()` and sums. Measured on a quiet host, warm-up excluded, in
     the solver test and on the relay, with raw output archived.
   - *Rebuild classification.* Every rebuild classed as first build, read-after or late, with a
     count of what per-(address, second) invalidation would have rebuilt.
   - *Slice 3's ceiling.* An oracle with all of slice 3's savings: held reads, skipping blocks
     whose read span did not change, the merge, and canonical re-summing. The shadow check's cost
     (one full refit in 64) is added to it. It is measured on the relay: `tally-load` at the world
     relay's plan, 2,000 feeders, a quiet host, three repeats. The solver test is a cross-check.
     Go only if the ceiling is at most 0.6 of the relay's measured refit: 3.0 ms on the 5.04 ms
     plan, 1.79 ms on the shared scene's 2.98 ms.
   - *Relay-side runs.* `//crates/load:plan_seats` at 2,000 feeders on a quiet host, warm-up
     excluded, at least three repeats with the spread reported.
   - *Memory.* #37's `Engine::bytes` breakdown, the area memos included.
   - *A fair mlat-server baseline.* Either change the scene's sync to under 10% of receivers in
     bad-sync timeout, or run mlat-server with the drop patched out
     (`patches/mlat-server-bad-sync-kept.diff`) as a sensitivity bound. Both are reported.
   - *Repeats.* At least three on a quiet host for every baseline point. The Tally 250 run is
     redone.
2. **The operator surface.**
   - `/mlat` shows held against planned seats, cuts with their reasons, shadow mismatches
     (slice 3) and unjudged models by specification version.
   - Suggested alerts: held seats below 80% of planned for 5 minutes, and any shadow mismatch.
   - `docs/relay-operators.md` gives per-seat memory and CPU for the world relay and for a small
     node like tally-relay-1.
3. **The incremental refit, engine only** (§5). Only on slice 1's go. With the sampled shadow
   check (its cost in the constants), the cached-against-cold gate against today's build path and
   the memory acceptance. The `cores` constants change only after #37.
4. **Fewer reference events** (§6). A specification change, its own decision, with its gates,
   shipped on §7's flag day.
5. **Verification measured.** Two relays split the world relay's areas, each verifying the
   other's models its fixes cite. This sets `MLAT_VERIFY_NANOS_PER_FEEDER`.
6. **Exact integer sums.** Only on §8's condition, in a later RFC.

## Appendix A: the baseline's method

**The server.** wiedehopf/mlat-server `c2d35b7` on Python 3.12.3, numpy 2.5.4, scipy 1.18.1 and
Cython 3.3.0. It ran on one CPU (`taskset -c 15`), with BLAS held to one thread, listening on
TCP. `patches/mlat-server.diff` changes:

- its CSV, which rotates at 4 GB instead of 10 MB and prints six decimals instead of four;
- `constants.Cair`, set to c. The scene propagates at c (`tally_mlat_solver::geo::C`), and
  leaving it at c / 1.00032 would charge mlat-server a 3.2e-4 range scale error the scene
  imposes on no one else.

`patches/mlat-server-bad-sync-kept.diff` is the sensitivity bound: receivers in bad-sync timeout
keep their mlat messages and are still asked for them.

**The load generator** (`tools/mlat-baseline/mlat-emu.rs`). It rebuilds tally-load's scene: its
reception probability is 0.5685 at 250 receivers, where tally-load printed 0.569. It plays the
scene in real time and runs mlat-client's coordinator logic per receiver (wiedehopf/mlat-client
`28ae4f7`):

- an aircraft is ten messages old before it is used;
- a sync goes out when an even and an odd are held within 5 s, with an altitude and NUCp of at
  least 6, for requested aircraft;
- an mlat message goes out for each DF11 and DF4 of a requested aircraft with no recent position;
- seen, lost and rate reports go out every fourth update;
- `start_sending` and `stop_sending` are honoured.

It speaks the v3 handshake and zlib2 both ways, flushes every 0.25 s, sends a heartbeat every
30 s and asks for results in the ecef format.

**Tally on the same scene.** tally-load runs with the world relay's arguments. The relay writes
every fix it publishes through `patches/tally-fix-dump.diff`. The scripts (`sweep.sh`,
`repeats.sh`, `sample_mlat.py`, `sample_tally.py`, `syncstat.py`, `profile.sh`, `setup.sh`) and
`patches/refit-timers.diff` sit beside it. Raw runs are archived in
`anvil:/data/johnny/tally-trees/mlat-baseline/runs`.

**Where the emulation is not faithful:**

- TCP only, not mlat-client's UDP;
- only DF17 airborne positions, DF11 and DF4 are fed to the client logic;
- GNSS receivers are announced as `dump1090`;
- counters are not wrapped at 48 bits;
- sends are quantised to 20 ms ticks and 0.25 s flushes. mlat-server stamps results by the
  arrival of their first copy, so "on track" error, which removes timing, is the comparable
  figure.

**The scene's properties that bear on mlat-server:**

- independent reception loss at 0.57, so a sync point needs both receivers to hold the same even
  and odd;
- a third of the aircraft are Mode S only, giving about 38 mlat messages a receiver-second at 250
  receivers, beside 8 syncs;
- pressure altitude differs from height by 100 m (one standard deviation), and mlat-server uses
  the altitude as height.

## Appendix B: what is measured and what is estimated

**Measured:**

- mlat-server's CPU, fixes, errors, bad-sync counts and pairs at each N above, once each, plus
  the repeats where stated;
- its own profile at 250;
- Tally's on-less-off CPU, fixes and errors at 250 (superseded) and 500;
- the refit's shares (provisional, §3);
- the per-seat plan (#38);
- the world relay's planned seats under each stated cost, from `tally-relay check` with its
  arguments (`tools/mlat-baseline/plan-seats.sh`). That includes slice 3's endpoints with the
  shadow check at one in 64 and one in 16, and the go threshold, all with verifying at 0.39 ms.
  The third revision's 1.6 to 2.8 ms range was partly planner-run and partly extrapolated; this
  revision's figures are all planner-run;
- the memory figures (#37, and the solver test's memos).

**Estimated:**

- slice 3's refit and its memory;
- fewer reference events' effect;
- the memory ceiling of 900 to 1,100 seats, from the measured components, with the memos
  possibly counted twice.

**Not established:**

- whether mlat-server's bad-sync rate comes from this scene or would happen on a real sky;
- what UDP would save it;
- every comparison of yield and accuracy between the two.

## Appendix C: design history

The second revision was read by four independent critics. Their findings, and what this revision
did with each:

**Structure.**

- *Make slice 1 a go/no-go measurement slice.* Done (§9, slice 1). It holds every requested item:
  the build split, rebuild classification, the oracle bound with its kill threshold, plan_seats
  repeats, #37's memory, the fair baseline, repeats, and quiet re-measurement.
- *Make slice 2 engine-only, behind a setting, with a shadow check, fallback, the listed gate
  conditions and a memory number.* Done, as slice 3 (§5), except the setting and the automatic
  fallback. The operator surface became slice 2.
- *Make version 9 conditional; choose between integers inside the sums only, and integers
  throughout with a bump.* Done (§8). Integers throughout was chosen, conditional on 0.3 ms a
  seat-second remaining. The alternative is declined, with the reason given. The normative
  requirements are listed for the RFC that would carry it; they are not written into `lib.rs`,
  because nothing here proposes version 9.
- *The mixed-fleet rollout* (dual judging, a publish setting, phased upgrades, version 10), *and
  the per-relay setting with automatic fallback.* Resolved by the network's actual size: two
  feeders and two relays, all ours. The founder directed a flag day instead (§7): ship together,
  upgrade both relays at once, roll back by redeploying, with one sentence on what outside
  operators would need. The sampled shadow check that counts mismatches is kept, since it is what
  catches carried-state bugs.
- *Treat fewer reference events and a 4 s refit as specification changes; decide fewer reference
  events alone, gated.* Done (§6). Each is measured before it is taken. If taken, they ride in the
  same version as any other model change. The 4 s refit is not proposed.
- *Scope to parity.* Done (§0, §4). The 1 ms goal, sub-parity budgets and stage plans moved to §8.
  The 4 s refit was removed from every estimate, and the warm-pass saving corrected to about
  0.27 ms.
- *Make #37 a prerequisite and restate the memory ceiling.* Done (header, §4, §9).

**Corrections.**

- *The headline range.* Now 1.6 to 2.8 ms (about 515 to 650 seats), with the 0.84 factor and the
  merge's limits stated (§5).
- *The refit base.* The shared scene's 2.98 ms a seat-second is now stated, and the refit gap is
  about 30 times, an upper bound. The refit split is marked provisional, against the
  uninstrumented 36.8 ms, and slice 1 re-measures it.
- *Baseline ratios.* Now upper bounds, with the profiling and receiver-set differences stated.
  "Robust" was dropped.
- *A fair mlat-server baseline and repeats.* Started in this revision: two quiet repeats of each
  point, and mlat-server with the bad-sync drop patched out as a sensitivity bound (§2), which
  puts it at 1.77 to 2.28 ms a receiver-second. The third repeat, the Tally 250 rerun and the
  scene-side fix stay in slice 1.
- *Yield and accuracy.* Marked unproven.
- *Invalidation.* The wrong claim was withdrawn, and the dependence written out (§5).
- *Jumps and scope changes.* Cut blocks are cached per kept start; a site change invalidates only
  touched pairs. Prefix sums for exact suffixes belong to the integer version only.
- *The running total.* Slice 3 keeps none. The invariants are listed for slice 6.
- *"Nothing carried enters a model."* Withdrawn. The true property is stated (§1), and the
  vacuous test was fixed and passes.
- *The block definition in `lib.rs`.* It now reads the receptions in the window's inputs and says
  the newest seconds differ between windows.
- *Accuracy gates.* For slice 4, the gates of §6. For slice 6, the paired comparison, new scenes
  and LocaRDS splits listed in §8.

**Operator surface.** Slice 2 (§9).

**Readability.** §0 opens with the decision. A glossary was added. B was renamed fewer reference
events. The method moved to Appendix A and the measured-against-estimated list to Appendix B. The
c-assumption note was added to §2.

**The harness.** `syncstat.py` read a key `clients.json` lacks, so it reported 0 receivers in
bad-sync timeout. It is fixed, and the corrected counts are in §2. The harness is committed under
`tools/mlat-baseline`. `mlat-emu` builds there and passes clippy and rustfmt. The relay's fix
dump and the refit timers are kept as patches, so the production code stays unchanged.

**The fourth revision.** It answers a second read by the performance and accuracy critics.

*Performance.*

- *Slice 3's estimate counted savings that moved to slice 6.* It was re-derived with canonical
  re-summing kept:
  - the floor before any build is 0.28 of today's refit;
  - the whole refit is 0.43 to 0.64 of today's, or 2.17 to 3.23 ms;
  - the shadow check adds about 0.08 ms at one in 64 (about 0.32 at one in 16), so the refit is
    2.25 to 3.31 ms;
  - `tally-relay check` was run at the endpoints: 462 to 554 seats, or 445 to 531 at one in 16;
  - verifying stays at 0.39 ms in the seat math (§0, §5).
- *The oracle measured less than slice 3, and its 0.4 contradicted the estimate.* It is now
  slice 3's ceiling: every saving plus the shadow cost, on the relay, quiet host, three repeats.
  The go threshold is at most 0.6 of the relay's measured refit: 3.0 ms on the 5.04 ms plan (486
  seats) or 1.79 ms on the 2.98 ms shared-scene figure (§9).
- *Say there is no path to parity.* §0 now says it plainly: slice 3 leaves the pipeline at 5.3 to
  6.4 ms.

*Accuracy.*

- *The cut-block cache key.* Now (second, `from_a`, `from_b`), held inside that second's held
  state, so it drops with any change in the second's read span (§5).
- *Site changes.* The full `BlockCache` clear on any scope change is kept, with the reasons; the
  finer rule and its full touched set are future work (§5).
- *The gate.* Extended to a location-only site edit and a late batch in a cached cut block's read
  span (§5).

*Should-fix.*

- *Merge order.* Merge by the exact key, recompute `x` in the block's frame, then an insertion
  pass with version 8's comparator. The gate compares against today's sorting build path (§5).
- *The shadow check.* Empty caches with the same warm model. On a mismatch it publishes the
  shadow's model and clears that area's caches (§5).
- *The re-read trigger.* A second is read again when any batch in its read span `[s - 2, s + 3)`
  changed (§5).
- *The archive.* The three instrumented runs' printed output is now archived. The text now says
  the phase timers counted warm-up in every phase (§3).
- *2.28 ms.* Called a sensitivity point, not a bound. Each ratio names its N: 2.68 times (250
  against 500), 2.59 times (both at 500), 2.08 times against the sensitivity point (§0, §2).
- *Nits.*
  - The version 9 list moved to Appendix D, with a pointer in §8.
  - Version 8's four unstated rules are now in `lib.rs`: slope when `mxr == mxl`, the even-count
    median, interval assignment with its single ±1 correction, and the tie rules.
  - The memos' possible double count is noted (§4).
  - The seat-planning script is committed as `tools/mlat-baseline/plan-seats.sh`.

## Appendix D: what an exact-integer-sums RFC must specify

This is recorded for slice 6, which this RFC does not propose. An RFC that proposes exact integer
sums, integers throughout under a new specification version, must give full normative text, in
the RFC and in `lib.rs`, covering:

- one exact unit in which both timebases are exact (1/3 ps, so a 12 MHz count is 250,000/3 ps);
- clock anchors on fixed global grids, so there is no per-refit rounding shift and add and drop
  equal a full re-sum exactly;
- every rounding rule (counts to the unit, `range_m / C`, the `2 / h` weight);
- the regressors as summed (`z = (1 - f, f, r, range_a, -range_b)` about the block line);
- exact re-centring before the single conversion to floating point, since raw-`y` sums lose the
  conditioning `PairSums::of` relies on and a verifier at `DERIVED_TOLERANCE` 1e-6 could
  disagree;
- a worst-case magnitude table with const asserts (the sums sit within about 2 bits of i128 on
  honest data and overflow on feeder-controlled counts or resets);
- an out-of-range rule (a block past the bounds has no inliers, so a feeder can neither overflow
  nor crash a relay);
- the edge cases, restating version 8's (now in `lib.rs`) for integers: slope when `mxr == mxl`, even-count medians, interval assignment from
  `la * ka - range_a` with its ±1 correction, ties to the first block and the earliest second;
- an exact, frame-independent sort key;
- the running total's invariants: it changes only by (old block, new block) swaps; cut blocks
  never enter it; a test asserts it equals a full re-sum; the engine may re-sum at any time; a
  sampled full re-sum check runs;
- the memory (a unit grows from 264 to about 500 bytes, `Sums` from 88 to 176);
- accuracy gates: paired against version 8 on identical inputs, with per-pair knot differences
  under 1e-3 σ, noise and rate differences, per-fix differences in centimetres, and an
  overflow-and-extremes fuzz test;
- new sweep scenes: ten times the curvature, a temperature step, `position_bias_m` aircraft and
  a correlated-bias (spoofing) burst, bad-sync bursts, sparse pairs, counter resets;
- LocaRDS against version 8's figures (yield 0.798, median 85.2 m, 0.970 on good sensors),
  split by trusted and untrusted aircraft and good and bad sensors, and required near-identical;
- the flag day of §7.
