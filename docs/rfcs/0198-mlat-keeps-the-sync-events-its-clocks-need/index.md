# RFC-0198: MLAT keeps the sync events its clocks need, and reads each once

- Status: proposed, for this review (2026-11-01)
- Builds on: RFC-0171 §3.8.1 (as amended 2026-10-24), RFC-0181 §10 ("MLAT in the cores")
- Measured on: `742ac7b` (main after #38), anvil, release build (`-c opt`)

## §0 The answer, in short

A hosted MLAT seat costs 8.10 ms of one core a seat-second (`cores::mlat_per_feeder`), and 5.04
ms of it is the area refits (`cores::MLAT_REFIT_NANOS_PER_FEEDER`), so the world relay
(`tests/world-relay.txt`, 16 cores, 4 MLAT threads) plans 363 seats. wiedehopf's mlat-server, which
adsb.lol runs, keeps each receiver pair's clock relation as a small running state updated per sync
observation, which this RFC estimates (not measures) at a tenth to half a millisecond a
receiver-second.

The hypothesis is half right. Tally refits from a window because a published clock model must
be a function of the raw it cites, so any relay holding that raw can rebuild and check it, two
relays holding the same batches publish the same model, and clients match models by the hash of
their inputs (RFC-0171 §3.8.1; §7 killed the mlat-server bridge for exactly this). An incremental
filter's state is a function of everything it has seen and when it saw it, so it breaks all
three. But the window is a contract on what a model is, not on how an engine computes it. The
specification says so ("any engine whose models pass is honest, whatever path it took to them: a
warm start, another order of passes, work reused from an earlier refit", `tally_mlat_solver` crate
docs, "Determinism"), and the pair blocks of 2026-10-27 already reuse work between refits. The
refit is dear for two reasons the window does not require: it keeps about two and a half times
the sync points per pair-second that mlat-server uses (12.8 against at most 5), and it touches each
of them about fifteen times over its life in the window, re-reading and re-pooling.

This RFC recommends **option B**: lower `threshold::REFERENCE_EVENTS_PER_BATCH` from 32 to the
least value the pair sweep's calibration holds, about 12, as specification version 9. It is one
constant, it keeps every property the window serves, and it is estimated to take the refit
from 5.04 to 2.3 to 2.8 ms a seat-second and the world relay from 363 seats to 521 to 576. Option A,
the engine-only work that reads each reception once, can follow, and the two together are
estimated at 641 to 689 seats. §5 compares the options, and §8 says what is measured and what is
estimated.

## §1 Why a window: the question asked first

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
  cited raw: any relay holding that raw shows it." With no cited raw, no fault can be shown.
- *Relays agree, so clients can merge.* "Two relays holding the same batches fit the same inputs
  at the same edge whatever their paths' delays" (the 2026-10-24 amendment, held by
  `the_same_batches_in_any_order_and_copies_publish_the_same_models`), and "clients merge by the
  hash of a model's inputs, never its bytes".

**Why an incremental filter breaks it.** RFC-0171 §3.8.1 says it of mlat-server directly: "The
mlat-server bridge (`tally-mlat` as first built) could not take part: mlat-server's clock sync is
private and stateful, so its outputs could be neither deduplicated nor verified." §7 kills
"Bridging to mlat-server: its private clock state makes its positions unmergeable and
unverifiable", and kills "Adding MLAT summaries" (information-form sums) as "not idempotent, exact
only at one linearization point, ... and unverifiable". Reading mlat-server's source shows how
deep the dependence runs (`mlat/clocktrack.pyx`, wiedehopf/mlat-server at `c2d35b7`):

- `ClockPairing.update` predicts the peer's time from the pair's running state and calls a sync
  an outlier when the prediction misses by more than 1.5 µs (`outlier_threshold`), so what is
  accepted depends on the state before it.
- The drift is a proportional-integral loop on the ratio of two intervals (`_update_drift`, `KP`
  0.06, `KI` 0.008, faster for a young pair), and the offset an exponentially weighted average of
  the last points (`_update_offset`, a ring of `cp_size` 32): both are functions of every update
  since the pair's last reset.
- Which pairs update at all depends on arrival order at the server: a receiver's report is paired
  only with receivers that reported the same sync point before it (`_add_to_existing_syncpoint`
  loops over `syncpoint.receivers`), and a pair updated in the last 0.2 s of the server's wall
  clock is skipped (`pairing.n > 8 and now - pairing.update_attempted < 0.2`).
- Validity reads the server's wall clock (`now - self.updated < 35.0`), and pairs are created and
  dropped by per-receiver caps by distance (32, 32, 16 and 16 peers in 50 km bands, `get_limit`).

So two mlat-server instances fed the same receptions in different orders or at different times
hold different clock states, and nothing a third party holds can reproduce either. The
hypothesis is confirmed on that point.

**What the window does not require.** The specification asks for a result, not a procedure:
"The contract between engines and verifiers is 'an optimum within tolerance' ... Any engine whose
models pass is honest, whatever path it took to them: a warm start, another order of passes,
work reused from an earlier refit" (`tally_mlat_solver` crate docs, "Determinism"). The pair
blocks (`pair/blocks.rs`) are already such reuse: each second's block of each pair is "a function
of the raw of the seconds it reads alone, so it is held between refits by what it read
(`BlockCache`), built again only when that changed, and the same in every window holding it".
So the hypothesis is refuted on its second half: the refit's cost is mostly the engine's choice
and the specification's point density, and the window property can be kept at a fraction of it.

**The pair blocks have no specification.** No RFC introduces them; RFC-0181 §10 records only
their cost. `blocks.rs`, `sync.rs` and `pair.rs` each cite "crate docs, § The pairwise path,
blocks", and the crate docs have no such section. The crate docs still describe the fit the
blocks replaced: "`pair::HUBER_PASSES` (3) passes Huber-weighted at `sync::HUBER_K`, then passes
with points past `sync::SYNC_CUTOFF` ...", constants no longer in the code, and "the points are not
carried ... no sum over them survives the slide of the window, and each refit forms them again",
which the blocks no longer do. Since the crate docs are the specification (RFC-0171 §3.8.1), an
independent verifier cannot be written from them today. Slice 0 (§7) fixes this before anything
else changes.

## §2 What a refit costs now

The load test measured a refit at 24.8 ms and 68 refits a second over 335 seats on a quiet anvil
(2026-10-31, `cores.rs`). That is 0.203 refits a seat-second, against the pair sweep's 0.056:
the load's seats lie over more areas each. This RFC split one refit into its parts with timers
added to `pair::fit` for the measurement only (not committed), running
`a_refits_cost_follows_its_points` (world density, seed 9000, 120 s, 624 refits measured) and
`pairwise_path_sweep` (world density, 60 s) on 2026-11-01. Anvil was not quiet (load average 18
to 36 on 32 cores): the sweep's refit read 31.8 ms there (read 22.0, fit 9.8) against 15.6 ms on a
quiet host (RFC-0181 §10), so the absolute times below are about twice a quiet run's, and the
shares are what this RFC uses.

| Part of one refit | ms (loaded host) | Share | Scales with |
| --- | --- | --- | --- |
| Gathering the area's window from `Arrived` (`area_inputs_over`) | 3.2 | 7% | the window's receptions, every refit |
| Reading it into events (`sync::Reader::new`) | 5.0 | 11% | the window's receptions, every refit |
| Each second's digest, the window's clocks and their pairs, gathering the blocks | 2.4 | 5% | the window's receptions, every refit |
| Building the blocks whose digest changed (`BlockCache::update`) | 24.6 | 53% | 6 seconds a refit, each pooling 5 seconds of every pair's points |
| Settling jumps and summing each pair's blocks (`settle`, `PairSums::of`) | 6.4 | 14% | pairs times blocks times knots and aircraft |
| The fixed point's passes and assembling the model | 5.2 | 11% | pairs times passes |
| A refit | 46.8 | | |

What the refit sees at world density (measured, a refit's mean): 58 clocks, 1,042 events, 337
valid pairs, 64,511 pair points (191 a pair over the 15 s window, so 12.8 a pair-second), and of
the window's 15 seconds 5.97 blocks built and 9.03 held from the last refit. The sweep agrees
(5.9 built, 9.1 held, a model's verification passing every time).

**Where the pair blocks put the cost.** Before them, the 15 s window read in 3.9 ms and fitted in
11.7 (RFC-0171 §3.8.1's table, quiet). With them it reads in 22.0 and fits in 9.8 (this run's
sweep, loaded): the fit got a little cheaper and the read about five times dearer, because the
read now builds the blocks. A block of second `s` pools the points of seconds `s - 4` to `s`
(`LINE_BLOCKS`, 5) for its robust line, reads events from `READ_BACK_MS` (6 s) before it and
`READ_AFTER_S` (2 s) after, and is built again whenever any of those seconds' receptions changed
(one digest a second over every reception, `BlockCache::digests`). Two new seconds at each edge
change the blocks of the newest four, and late batches the rest, hence about six. A point sits in
five blocks' pools, and each block is built about three times in its life (5.97 builds a refit
over 15 seconds, one refit each 2 s for 15 s), so each pair point is pooled, sorted and scored
about fifteen times. Each reception is also gathered and read once a refit for the 21 s from its
read-back to its leaving the window, about ten times, and once for every area it is a member of
(5.84 areas a receiver at world density).

**Points a pair needs.** The crate docs say it: "Sync events are massively redundant: a window
holds thousands, and what they say about the clocks saturates long before." A pair's fit has at
most five knots (`PAIR_KNOTS_MOST`; three or four over the 15 s window), each a value and a
slope against a curvature prior. 191 points fit them. mlat-server keeps at most 32 points a pair
(`cp_size`) and updates a pair at most five times a second once it has eight.

## §3 What mlat-server pays

**Read, not measured.** `ClockPairing.update` is compiled Cython; per sync observation of a pair
it does a prediction, an outlier test, a drift update, an offset update and a validity check: a
few dozen floating-point operations and a handful of Python attribute updates (`num_syncs`,
`sync_good`, `last_sync`). The loop around it (`_add_to_existing_syncpoint`) builds a key tuple
and looks the pairing up in a dict for each receiver already on the sync point. A new sync point
also decodes the even and odd messages, decodes CPR and converts to ECEF once.

**Estimated, not measured.** About 1 to 3 µs a pair update with its loop (Python object access at
tens to hundreds of nanoseconds each), and at most about five updates a pair-second once a pair
is established. With a receiver keeping at most 96 peers (`get_limit`), new pairs accepted only
under 0.7 of that (about 67), each update shared by two receivers, the clock tracking is at most
about 170 updates a receiver-second, so 0.2 to 0.5 ms of one core a receiver-second at that bound,
and less in practice, since a pair updates only when both ends hear the same even-odd pair the
client chose to send. Call it 0.1 to 0.5 ms a receiver-second for clock sync, against Tally's
5.04 ms a seat-second in the load test and 0.87 in the pair sweep's even scene. The claim that one
instance carries hundreds to thousands of receivers is reported, not verified here; this RFC did
not run mlat-server.

**Where the gap comes from**, as far as the figures above can split it: Tally keeps about 2.5
times the points a pair-second (12.8 against at most 5); touches each point about fifteen times
in the blocks and reads each reception about ten times per area, where mlat-server touches each
once; pays a fixed point over every clock's noise and rates each refit, which mlat-server does
not have (it pays an equivalent in its per-solve clock normalisation); and in the load test's
geography pays 0.203 refits a seat-second where the sweep's world density pays 0.056. The first
two are what the options below cut.

## §4 The options

Every option is judged against the four properties of §1. "Seats" is what `tally-relay check`
prints for the world relay's arguments with the option's per-seat costs put into `cores.rs`
(run 2026-11-01; baseline 363; every other constant unchanged, the 25% MLAT share kept unless the
option is the share). The costs in the table are estimates from §2's split unless marked measured.

| Option | Refit, ms a seat-second | Verify | Total | World relay seats | Spec | What it costs in trust or accuracy |
| --- | --- | --- | --- | --- | --- | --- |
| Today (measured) | 5.04 | 0.39 | 8.10 | 363 | 8 | |
| A. Read each reception once (engine only) | 2.67 to 3.58 | 0.23 to 0.29 | 5.6 to 6.5 | 450 to 528 | 8 | none: the same bytes |
| **B. Keep the sync events the clocks need** | 2.27 to 2.77 | 0.17 to 0.21 | 5.1 to 5.7 | **521 to 576** | 9 | wider pair covariances; accepted only if calibration holds |
| A and B together | 1.46 to 1.76 | 0.14 to 0.16 | 4.3 to 4.6 | 641 to 689 | 9 | B's |
| C. Checkpointed incremental pair state | 0.8 to 1.5 | about 0.1 | 3.5 to 4.3 | about 690 to 830 (by the plan's formula, not run) | 9 | a model is no longer a function of its cited raw |
| D. Refit every 4 s | about 2.8 | 0.39 | about 5.7 (publishing 0.35) | 517 | 9 | fixes carried 1 s longer on average |
| E. Spot-check neighbours' models | 5.04 | about 0.1 | 7.8 | 377 | 8 | a forged pair passes most verifiers |
| F. A 40% MLAT share (no cost cut) | 5.04 | 0.39 | 8.10 | 582, connections 10,124 to 8,099 | 8 | none; it is a trade |
| Refit only pairs whose data changed | no change | | | 363 | 8 | |
| Warm-started fits | at most 5% less | | | about 375 | 8 | |

**A. Read each reception once (engine only, specification version 8).** Hold what the refit
reads per second, not per window: the gathered receptions and `sync::Reader`'s events of a second
held by the second's digest, as the blocks already are, so a refit reads only the seconds that
changed; keep the digests per batch as `Arrived` admits it rather than over every reception each
refit; build a block from per-second runs of each pair's points sorted once and merged (the same
multiset gives the same medians to the bit, so the inliers do not move), with no `BTreeMap` per
block, unit or aircraft; and hold each pair's sums of its unchanged blocks between refits. What a
block pools, reads and decides is unchanged, so the bytes are unchanged. Estimated: the window's
reads (23% of a refit) to 30% to 50% of themselves, the block builds (53%) to 50% to 70% (the
five-fold pooling and the roughly six builds a refit are the specification's and stay), the
settling (14%) to 60% to 80%, the passes (11%) unchanged: a refit at 0.53 to 0.71 of today's.
Verifying a neighbour's model reads and builds the same way (`Engine::verify_model` uses the
area's `PairCache`) and gains about as much. It costs nothing in trust: every test that holds the
bytes (`the_same_batches_in_any_order_and_copies_publish_the_same_models`,
`a_warm_refit_publishes_what_a_cold_refit_publishes`, the pair model golden) must pass unchanged.

**B. Keep the sync events the clocks need (specification version 9).** Lower
`threshold::REFERENCE_EVENTS_PER_BATCH` from 32 to the least value the calibration holds,
expected near 12. A busy batch of one receiver keeps each reference event at the rate
`min(1, REFERENCE_EVENTS_PER_BATCH / c)` by the message's key (`threshold::batch_sync_keep`), so a
pair keeps an event both its ends heard at the lower of their two rates: where both caps bind,
which they do at world density, a pair's points fall in proportion, 12.8 to about 4.8 a
pair-second at 12, near mlat-server's five. The reads and the blocks (76% of a refit) fall in
proportion, the settling (14%) in part, the passes (11%) not at all: a refit at 0.45 to 0.55 of
today's, with verification at about half. It keeps every property of §1: it is a hash threshold, a function of one batch alone,
so a holder of more batches still keeps a superset and two holders of the same batches keep the
same events. It is a new specification version because the same raw then gives a different
model: a verifier judges only its own version and counts another's unjudged, never failed
(`tally_mlat_solver::judges`), so relays part-way through the upgrade convict nobody. It costs
accuracy, by an amount only the calibration can say: a pair's covariance widens as its points
fall (about 1.6 times in standard deviation at 12), but a fix of 30 receptions is normalised
over many pairs, and its reception noise does not change. It also shrinks what `Arrived` holds of
sync raw, which bears on #37 (the arrived store over its plan), by an amount not estimated here.

**A and B together.** A's gain applies to what B leaves: a refit at about 0.29 to 0.35 of
today's, 3 to 3.5 times cheaper.

**C. Checkpointed incremental pair state** (the founder's first suggestion). Each pair's sums
carried from the area's previous published model, with the window shortened to a few seconds of
new raw, and the inliers judged against the previous model's prediction, as mlat-server judges
against its own: each point read and judged once, so the refit cost would follow the new raw
alone. A model is then a function of its cited raw and the model before it, and that one of its
own predecessor, without end. A verifier holding only the window cannot rebuild it; it must take
the predecessor as given, so a model's honesty rests on a chain no relay holds the raw for past
32.5 s. Two relays that once differed (one restarted, or held one late batch the other did not)
differ for good, so clients match fewer models by inputs and more fixes become incomparable
sets. It is RFC-0171 §7's "MLAT summaries" again, made verifiable one link at a time but not as a
whole. Not proposed.

**D. Refit every 4 s.** `REFIT_EVERY` is a grid every relay shares, so it is a specification
change. Half the refits a second; each sees four new seconds instead of two, so about 0.55 of
today's refit cost, and half the clock models published (5.48 KB a seat-second published on
2026-10-31, about two thirds of it models), so publishing to about 0.35 ms (estimated). Every fix
is carried a second longer on average from its models' edge (still at most `MAX_CARRY`), and its
clock component grows with the carry by each pair's process noise. The pair sweep would measure
it; not proposed now, and worth asking again after B.

**E. Spot-check neighbours' models.** Check a hash-chosen part of a neighbour model's pairs
instead of all of them. A fix's verifier reads the models it cites as given, so a forged pair
that the spot check missed moves every fix that uses it, and no client can tell. It saves at most
the 0.39 ms verifying costs (377 seats). Not proposed.

**F. A larger MLAT share of the cores.** `cores::MLAT_SHARE_PERCENT` at 40 instead of 25 gives
MLAT 7 threads instead of 4 and 582 seats, and takes the connections from 10,124 to 8,099. It
cuts nothing; it chooses seats over connections, and is an operator's question, not this RFC's.
With A and B it would plan about 1,066 seats.

**Refit only the pairs whose data changed.** In the steady state there are none: each pair has
points in every second (12.8 a second), so a window that slides by two seconds changes every
pair. No gain.

**Warm-started fits.** Already done: 6,800 of 6,800 refits in the 2026-10-31 load were warm
(`fits_warm`), and a refit runs 1.98 passes of the fixed point in the sweep. The passes and
assembly are 11% of a refit; one pass instead of two would save at most about 5%.

## §5 The recommendation

**B**, then A. B is one constant and a version, keeps every property the window serves, and is
estimated to cut the refit by about half and plan 521 to 576 seats on the world relay against
363, with A worth doing after it if the plan still asks for seats (641 to 689 together). B is
accepted only on the calibration's evidence (§7, slice 1); if no value below 32 holds it, A alone
is the fallback (450 to 528 seats).

## §6 The trust and signing overhead

Of 8.10 ms a seat-second, what trust costs today:

- **Verifying neighbours' models, 0.39 ms** (`cores::MLAT_VERIFY_NANOS_PER_FEEDER`). Not measured
  in the load test (a relay alone verifies none, `models_verified` 0), and the figure predates the
  pair blocks: the sweep's "a holder of the window verifying each model" read 0.602 ms a
  feeder-second against a refit's 0.872 when it was set; on 2026-11-01 it read 1.594 against
  1.695, so a verification now costs 0.94 of a refit where it cost 0.69. The constant was also
  never scaled to the load's geography the way the refit was (0.87 in the sweep, 5.04 in the
  load). So 0.39 likely understates what a relay with neighbours pays; by how much depends on how
  many of its fixes cite another relay's models, which only a load with two relays can measure
  (slice 4). A and B cut it as they cut the refit, since it reads and builds the same way. Keep it
  whole: E is the alternative, and §4 says why not.
- **Verifying every fix before publishing it**, inside solving's 0.63 ms. RFC-0171 §3.8.1
  measured it at 20% of solving time on the windowed engine, so about 0.1 ms (estimated). It is
  what keeps an honest relay from signing a fault; keep it.
- **Publishing, 0.48 ms** (`cores::MLAT_PUBLISH_NANOS_PER_FEEDER`, measured): signing each step's
  records (a model manifest per refit, and each step's positions record raw and tagged, each a
  record signed whole, many fixes to a record), forwarding them, and the consistency checks of what
  was published. The signatures are few: in the 2026-10-31 load, 6,801 models, 964 positions and
  964 tagged positions records in 100 s over 335 seats, about 0.26 a seat-second, a few
  microseconds at a typical Ed25519 signing cost (estimated). So signing is not where publishing
  costs, and batching signatures, which would need a new wire version and fault proofs that carry
  a path, would save nothing worth it. What publishing pays for is bytes forwarded and checked:
  D halves the models, and models were 68% of the bytes published (1.25 of 1.84 MB/s).
- **The consistency checks** are inside publishing's 0.48 ms and were already cut once (0.64
  before each positions record's keys were checked once for its five readers, RFC-0181 §10).
  Nothing further is proposed.

So the trust overhead is about 1 ms of 8.10, and the refit's 5.04 is where the cost is.

## §7 Measurement plan and slices

The harness is the one `cores.rs` describes: `tally-load` with 2,000 feeders sending the
measured mix against the world relay's plan (`--relay-mlat --relay-cores 16`, its memory and
connection caps), a 60 s ramp, 60 s warm-up and 120 s measured, each thread's CPU from
`/proc/<pid>/task/*/stat` and the steps' `fit_ms` and `solve_ms` from `GET /mlat` (`steps_total`)
at both ends of the window, the seats every second, on a quiet anvil (load under 3 for four
minutes); then `//crates/load:plan_seats` (manual, `-c opt`), which must settle within 15% of the
seats the plan prints. The solver-level measures are `a_refits_cost_follows_its_points` and
`pairwise_path_sweep` (`-c opt`, `--ignored --nocapture`).

0. **The specification catches up, and the refit is measured in parts.** Write "§ The pairwise
   path, blocks" into the crate docs as the code does it, and correct the fit's description (no
   Huber passes, the points carried as blocks). Add the refit's parts (gather, read, blocks built
   and held, build, settle, passes) and its points, clocks and members to `pair::Stats`, to
   `/mlat`'s `steps_total` and to `a_refits_cost_follows_its_points`, so the load test reports
   them. Measure the baseline on a quiet anvil. No change to any byte published.
1. **B.** Run `pairwise_path_sweep` (every scenario, three seeds) at `REFERENCE_EVENTS_PER_BATCH`
   32, 20, 16 and 12, and `tally-mlat-calibrate` over the LocaRDS hour at the value chosen. Take
   the least value at which every scene's coverage stays within 0.92 to 0.98, world density's
   median and 95th percentile horizontal error move by no more than 10%, no false jump appears,
   every model passes its verifier and every sampled fix the cold verifier, and LocaRDS coverage
   stays within 0.01 of version 8's 0.954. Make it specification version 9, remake the pair model golden, and
   amend RFC-0171 §3.8.1's thinning paragraph and table. Then measure with `tally-load`, set the
   `cores` constants, regenerate `world-relay.txt` and `cores-10.txt`, amend RFC-0181 §10, and
   pass `plan_seats`.
2. **A, the reads.** The gathered receptions, the reader's events and the digests held per second
   and per batch. Byte-identical: the three tests named in §4 pass unchanged.
3. **A, the blocks and sums.** Per-second sorted runs merged, no per-block maps, each pair's sums
   of unchanged blocks held. Byte-identical. After 2 and 3, measure with `tally-load` again, set
   the constants and pass `plan_seats`.
4. **Verification measured.** A load with two relays splitting the world relay's areas, so each
   verifies the other's models its fixes cite, and `MLAT_VERIFY_NANOS_PER_FEEDER` set from what it
   costs.

D and F are left for after slice 4, when the costs they would trade against are measured.

## §8 What is measured and what is estimated

Measured:

- The per-seat costs and 363 seats (Tally #38, `cores.rs`, 2026-10-31, quiet anvil).
- A refit's split into parts, and its points, pairs, clocks, events and blocks built and held
  (2026-11-01, anvil at load 18 to 36, timers added for the run and not committed; shares used,
  absolute times about 1.9 times a quiet run's).
- The verification-to-refit ratio of 0.94 in the 2026-11-01 sweep, against 0.69 in the figures
  the constant came from.
- Every "World relay seats" figure but option C's: `tally-relay check` with the world relay's
  arguments, rebuilt with each option's costs put into `cores.rs` (2026-11-01).

Estimated, and how:

- Each option's refit and verification factors, from the measured shares of §2 and what each
  option removes from each share (§4 gives the ranges and their reasons).
- Option C's seats, from the plan's formula (seats in proportion to the inverse of a seat's
  cost), not run.
- Publishing under D, and the signing share of publishing.
- mlat-server's cost, from reading its source; it was not run or profiled. Its capacity per
  instance is reported, not verified.
- B's accuracy cost is not estimated at all: slice 1 measures it, and B is taken only if it
  holds.
