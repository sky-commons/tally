//! Tally's native MLAT mathematics (RFC-0171 §3.8, §3.8.1 as amended 2026-10-24; RFC-0174 §2.3,
//! §2.4): pure, deterministic, no I/O.
//!
//! An MLAT engine holds its region's raw receptions as they arrive and, every `REFIT_EVERY`, fits
//! each area it owns a pair model over a trailing window of the sync raw its members' batches have
//! brought (the ADS-B positions they heard): every pair of nearby receivers' clocks, each fitted
//! in closed form, and every clock's noise and rate at the fixed point of the pairs fitted under
//! them (§ The pairwise path). A second after a transmission's first reception arrived, it groups
//! the receptions of it that had arrived (what it considered) under the models of the areas its
//! hearers are in (§ Areas), puts them on one timeline through the pairs among their hearers,
//! solves it (§ Solving), and publishes the fix with the id of each model it cites. Any holder of
//! an area's window verifies its model once a refit, and anyone holding the verified models and a
//! fix's own receptions verifies the fix. This crate is that mathematics; `tally-mlat` is the
//! engine around it.
//!
//! This documentation is the specification (version [`clock::SPEC_VERSION`]). Versions 1 to 7
//! were a joint clock model fitted per tile (version 4 stopped trusting a receiver's declaration
//! of GNSS discipline beyond its timebase; version 5 dated a free-running gauge by every cited
//! reception of its clock and rejected a sync message a receiver heard twice; version 6 named
//! each member's site record by its site id; version 7 fitted over a trailing window of what had
//! arrived, cited by frontiers, and solved every fix a second after it was heard). Version 8 is
//! the pairwise path alone: one pair model an area at each edge of one refit grid, and fixes that
//! cite one model for each area of their used hearers. A verifier judges its own version alone
//! ([`verify::judges`]). It is written so an independent implementation makes the same discrete
//! decisions: holding, windows, areas, members, the pair network and the models a fix cites are
//! decided by content in integers and signed site records, and the feasibility screen is exact
//! integer arithmetic on raw counters; the floating-point decisions (a pair's weights, jumps,
//! noise, rates, the outlier rule) are stated with their constants, and the verifiers allow
//! stated bands.
//!
//! # What verification means
//!
//! The protocol's rule is optimality within tolerance, not bytes: a published pair model is honest
//! when, rebuilt from the raw its frontiers cite, every pair is an optimum of its own inliers and
//! the noise and rates the fixed point of the pairs fitted under them, each within the model
//! verifier's tolerance, and its other checks pass (§ The pairwise path, verifying a model); a fix
//! is honest when it cites exactly one verified model for each area its used hearers are in, is
//! the optimum of the receptions it used on the timeline those models give, and omits none of what
//! it considered that the outlier rule would keep (§ Verifying a fix). A fault is "this signed
//! model (or fix) fails verification on its cited raw". Byte identity is a property of the
//! reference implementation (the same raw, arriving in the same batches, in any order and on any
//! threads, gives the same bytes, and its tests hold it to that), never what a consumer relies on:
//! consumers merge by inputs id, not model bytes. This is what lets an engine choose among
//! optima-within-tolerance without being in fault: the reference engine seeks each refit's fixed
//! point from the area's previous model (§ The pairwise path, the fixed point), which a cold fit
//! would land within tolerance of.
//!
//! **Determinism.** The contract between engines and verifiers is "an optimum within tolerance",
//! exactly as [`verify`] judges it: each pair's Gauss-Newton step at its published knots within
//! `pair::PAIR_OPTIMALITY_TOLERANCE`, the rates' within `pair::RATE_OPTIMALITY_TOLERANCE`, and
//! each noise within `verify::NOISE_BAND` of the rule's estimate. Any engine whose models pass is
//! honest, whatever path it took to them: a warm start, another order of passes, work reused from
//! an earlier refit. That the same raw in the same batches gives the same bytes is the reference
//! engine's own property, held by fixed loop orders (every sum over points, pairs and clocks in
//! one canonical order, no fused multiply-add, no choice of instructions at run time, `libm`'s
//! transcendental functions); no consumer relies on it.
//!
//! What one holder can judge is what it holds. A holder missing a batch at or below a model's
//! frontier cannot rebuild its inputs and says so ([`verify::PairModelFailure::Unjudged`], never a
//! failure); a fix is judged only on what it considered, so an engine that solved before a
//! reception arrived is never convicted for leaving it out.
//!
//! # Units and identities
//!
//! - An observation's identity ([`ObservationId`]) is (receiver key, counter epoch, raw counter,
//!   Blake2s-256 of the message bytes), ordered in that order. Every list of identities is kept
//!   sorted, and every computation iterates its inputs in a canonical order, so outputs do not
//!   depend on input order. Of two copies of one observation (two batches carrying it), the one
//!   whose batch wall clock is earlier is kept; its wall clock is the observation's.
//! - Clocks ([`clock::Timebase`]): `Dump1090`, `Beast` and `Radarcape12Mhz` are 12 MHz counters
//!   (a count is 250000/3 ps); `RadarcapeGps` stamps are UTC seconds of the day in the upper 18
//!   bits and nanoseconds in the lower 30, made linear as nanoseconds of the day (a count is
//!   1000 ps). `Unknown` and `Other` are never used. Within one fit, a GPS epoch whose stamps span
//!   more than half a day crossed midnight, and its stamps before noon move forward a day; a
//!   lookup through a model moves a stamp by whole days to within half a day of its clock's
//!   lowest count in the model.
//! - Receivers: a site whose declared precision is above 30 m, whose clock is unknown, or which is
//!   described twice takes no part. Its antenna is converted to ECEF (WGS84) and rounded to whole
//!   millimetres; that rounded position is used by everything after. Its precision `p` adds
//!   `(p / sqrt 3)^2` to each reception's variance.
//!
//! # Holding raw ([`arrived`])
//!
//! One pool ([`Arrived`]) for every receiver a holder takes raw of, held in one-second slices of
//! signed wall clock, with each receiver's frontier of batches and the transmissions still
//! settling. One implementation for every holder (an engine solving, a relay judging a model or a
//! fix it holds the raw of), so two holders of the same batches hold the same receptions and
//! rebuild the same inputs.
//!
//! - **What is held** is decided by the message and its own batch alone: the Mode S replies MLAT
//!   solves (DF0, 4, 5, 11, 16, 20, 21 with an address), and of DF17/18 only what syncs clocks (an
//!   airborne position with an altitude) or gives a sync position its prior (an operational status
//!   with a NACp), each by its threshold (§ Thinning). Identification, velocity, surface
//!   positions, Mode A/C and UAT are never held. A reply of an aircraft its own batch carries an
//!   ADS-B position of is dropped (it is no MLAT target), unless the aircraft is in the
//!   calibration sample ([`arrived::sampled`]: the first byte of BLAKE2s-256 over `"tally
//!   calibration sample" 0x00`, the address and the five-second sample period, below 256 / 16).
//!   Nothing a later batch, another receiver or the arrival order says changes what one batch
//!   keeps, so a holder of more batches holds a superset of what a holder of fewer holds.
//! - An observation is held once, by identity; of copies, the earliest batch wall clock. A
//!   reception is 16 bytes in its slice, its message an index into the slice's messages, each held
//!   once with its hash.
//! - **Frontiers** ([`Frontier`]): per receiver, its newest boot's batches held with no gap from
//!   the first this holder took of the boot, through the highest sequence so held. A batch above a
//!   gap is held but cited by no model until the gap fills, or until nothing the gap held could be
//!   in any window ([`HELD_MS`]), when it is passed.
//! - **Bounded, whole**: one pool of bytes for every receiver, and a cap on what one receiver
//!   holds in a slice. A batch beyond either is refused whole and counted, never trimmed by rank;
//!   it is a gap in its receiver's frontier like any batch that never came. Every byte reported is
//!   a capacity actually allocated.
//! - **Never ahead, never late**: a batch signed more than `MLAT_AHEAD` (7.5 s) past its arrival
//!   is refused; one signed more than [`HELD_MS`] (a trailing window, `SIGNED_LAG` and a step)
//!   before it is older than every window, refused, and passes its frontier.
//!
//! # The trailing window ([`scope::Trailing`])
//!
//! An area's model is fitted at a trailing edge `edge`, Unix milliseconds by the signed wall
//! clocks of its raw: its inputs are its members' held sync receptions with a wall clock in
//! `[edge - W, edge]`, `W = budget::TRAILING_WINDOW_MS` (15 s), from each member's batches at or
//! below its frontier at the edge ([`Arrived::area_inputs`]): the newest batch of its contiguous
//! run holding a reception signed at or before the edge, so nothing that arrived after the edge's
//! raw is cited. The edges are one grid for every relay: the newest multiple of `REFIT_EVERY`
//! (2 s) at least `budget::FIT_LAG` (2 s) below the engine's clock ([`Trailing::fitted_at`]), by
//! when every honest receiver's raw of the edge whose signed clock is on the relay's has arrived.
//! The engine refits every area it owns at every edge of the grid, warm, and solves each step
//! (1 s) under the newest edge's models. So a model's inputs are a function of its area, its edge
//! and the raw alone: two relays holding the same batches fit the same inputs at the same edge,
//! whatever order or delay they arrived in, and its frontiers say exactly which, so a verifier
//! holding those batches rebuilds the same inputs whenever it got them ([`Arrived::rebuild`]); and
//! the models of neighbouring areas, fitted by other relays, share the edges a fix citing several
//! of them needs. A feeder lagging the relay's clock by more than `FIT_LAG` may be cited
//! differently by two relays, never wrongly.
//!
//! A set of receptions of the same bytes is due `FIX_SETTLE` (1.1 s) after its first arrived, and
//! again at each seal after more of them arrive (within `arrived::JOIN_MS` of the first), with
//! every reception of them that had arrived by then ([`Arrived::due`], [`Considered`]); the models
//! split it into transmissions ([`publish::transmissions`]), of which one an aircraft a slot is
//! solved (§ Solving, how many), and again only when its considered set grew since its last fix
//! ([`publish::solve_transmission`]'s `published`): its fix considers all the earlier one did and
//! supersedes it ([`standing`]), while one that did not grow is not solved again, since a fix of
//! the same set under newer models supersedes nothing. A reception arriving after a take is not
//! part of that take's fixes, and none of them is judged on it.
//!
//! # Areas ([`area`])
//!
//! The unit of fitting, publishing and citing is the RFC-0174 area: an H3 cell at
//! `tally_wire::rendezvous::AREA_RESOLUTION` (3). Each rule here is a function of signed site
//! records and of a fix's own hearers alone, so every holder of the same records decides it the
//! same.
//!
//! - **A receiver's area** ([`area::of`]) is its public cell's area, never the area its site lies
//!   in (H3 cells do not nest exactly, and the two can differ).
//! - **An area's members** ([`Sites::members`]) are its usable receivers and every receiver one of
//!   them keeps as a pair's other end (§ The pairwise path, the network): every receiver within
//!   `pair::PAIR_BASELINE_MM` (600 km) of the area's own that is among their nearest. Never a
//!   function of whose raw arrived. A boundary receiver is kept by receivers of each area beside
//!   it, so it is a member of each, and its clock may be published by two models (or more); its
//!   area's model is still the one that publishes its pairs to its own area's receivers, and a
//!   reader takes it from one by the rule below. The 600 km band is the raw band a relay holds
//!   for an area: every cell that could hold a point within the baseline of a point of the area
//!   (`tally_mlat::area`), so it holds every member's raw.
//! - **What a model publishes** ([`pair::Network::of_area`]): only the pairs with an end in its
//!   area. A pair whose ends are in two areas is published by both models, each fitting it from
//!   the same raw, and read from one by the rule below.
//! - **Who solves a transmission**: the relays of the area most of its hearers are in, ties to
//!   the lowest area (`tally_mlat::area::owner`). It is the engine's division of work, not part of
//!   what a fix is.
//! - **The models a fix cites** ([`pair::Models`], `tally_wire::Fix::models`): one verified model
//!   of each area its used hearers are in, every one at one edge, and no other, listed by id
//!   strictly ascending. A verifier refuses a fix whose list misses one or has an extra
//!   ([`verify::Failure::Area`]), or whose models are not the ones it lists
//!   ([`verify::Failure::Models`]). The engine solves a set under the models of every area its
//!   hearers are in at the newest edge where it holds all of them (else the owner's newest edge,
//!   with what it holds there), then again under only its used hearers' areas' models while those
//!   are fewer, until the areas it used are the areas it was solved by; a fix that used a hearer
//!   of an area with no model held is not published ([`Unpublished::Unheld`]). A fix is never
//!   carried further past its models' edge than [`MAX_CARRY_PS`] (`budget::MAX_CARRY`, 14.6 s).
//! - **Reading several models as one** ([`pair::Models`]): a clock is read from the model that
//!   best informs its noise (one that identifies it, then the most information, then its own
//!   area's, then the lowest area), and a pair from the model of its lower end's area when that
//!   model is cited and publishes it, else its upper end's.
//! - **Dating** (§ The pairwise path, the adjustment): a fix's timeline is dated by its reference
//!   clock: a GNSS-disciplined one by its reading on the UTC day its batch's wall clock is in, a
//!   free-running one by its model's `heard_ns` (the latest its lowest count in the window can
//!   have been heard, by the wall clocks of the batches that carried it) and its nominal time
//!   since. So two models publishing one clock date it alike when their windows are alike, and a
//!   reception's own batch wall clock never moves a free-running fix.
//!
//! Measured over the sweep's world density (`pair_tests`, 120 receivers in 12 areas, 60 s,
//! 2026-10-26): a receiver is a member of 5.84 areas' models on average; a published fix cites
//! 8.04 areas, and its models hold 0.983 of the network's pairs among its used hearers; 714
//! considered sets had a hearer's area with no model held and were not solved.
//!
//! # Thinning ([`threshold`])
//!
//! Sync events are massively redundant: a window holds thousands, and what they say about the
//! clocks saturates long before. What is kept is decided by hash thresholds, each a function of
//! one batch or one message alone, the same for every engine and verifier holding the same
//! batches, so a holder of more batches keeps a superset (`Threshold::keeps`: the first eight bytes
//! of a BLAKE2s-256 key, big-endian, below the threshold's rate of 2^64):
//!
//! 1. Reference aircraft ([`threshold::reference`]): an aircraft's sync events are all kept when
//!    its key (over `"tally sync aircraft" 0x00` and its address) is below `REFERENCE_KEEP`, and
//!    none otherwise. `REFERENCE_KEEP` keeps every aircraft heard with ADS-B. It stays a
//!    threshold, so a holder of fewer batches keeps a subset.
//! 2. A batch of one receiver carrying `c` of its reference aircraft's sync receptions keeps each
//!    at the rate `min(1, REFERENCE_EVENTS_PER_BATCH / c)` by its message's key
//!    ([`threshold::batch_sync_keep`]), so a busy batch keeps about `REFERENCE_EVENTS_PER_BATCH`
//!    and never falls off a cliff at one event more; and every reply when it carries at most
//!    `REPLIES_PER_BATCH`, else those below `KEPT_KEEP`. Status of a reference aircraft is kept.
//! 3. An area's inputs ([`Arrived::area_inputs`]) are, of its members' kept sync receptions in the
//!    window, deduplicated by identity, every event two or more members heard, with every member's
//!    reception of it; and every member reception in the window of an operational status message
//!    of a kept event's aircraft, which give the events' priors.
//!
//! The inputs are cited together as a [`scope::Citation`]: their count, and BLAKE2s-256 over
//! `"tally clock model inputs" 0x00` and each part of a cited batch they are read from (its kept
//! sync and status receptions of one slice of signed wall clock, one with none left out; each
//! member's in the frontier's order, a member's by sequence, then slice) as receiver key (32),
//! boot (8), sequence (8), slice (8) and the part's digest (32), big-endian
//! ([`scope::Part`]). A part's digest is BLAKE2s-256 over `"tally sync part" 0x00` and each of its
//! receptions as epoch (4), counter (6), message hash (32) and milliseconds into the slice (2),
//! big-endian, ascending by those bytes: a function of the batch's receptions alone, whatever
//! order it carries them in, so a holder computes it once, as the batch arrives, however many
//! windows and areas read it. The inputs are a function of the
//! cited parts (and the window, the members and the frontiers the model states), so two holders
//! citing the same hash hold the same inputs.
//!
//! **Honesty rests on measured calibration**, not on an argument. Each clock's noise and the
//! robust weights are estimated from the window itself, so they can be understated (a noise
//! estimate from a few dozen points is low as often as high). What the published covariance is
//! worth is what the simulator measures (the pairwise sweep's coverage, `pair_tests`), and what a
//! calibration against real receivers' truth shows (RFC-0171 §3.8.1, `tally-mlat-calibrate` over
//! OpenSky's LocaRDS: the truth there, each aircraft's own ADS-B position, is itself off by tens
//! of metres, so it bounds what can be said).
//!
//! # Sync events
//!
//! 1. The sync material (§ Thinning) is deduplicated by identity.
//! 2. A sync message is a DF17/18 with an address, a zero CRC residual, an airborne position
//!    (TC 9-18 barometric, TC 20-22 GNSS height) and an altitude.
//! 3. Each address gets one CPR reference: from every receiver's (epoch's) receptions of the
//!    address, every pair of an even and an odd message whose linear counts are at most 10 s apart
//!    is a candidate `(even bytes, odd bytes, odd is later)`; candidates are tried in ascending
//!    lexicographic order and the first that decodes globally ([`modes::cpr_global`]) is the
//!    reference. The reference only picks the zone a local decode lands in: any reference within
//!    the local decode's reach gives every message the same position to the bit, so which pair the
//!    window happens to hold changes no prior
//!    (`sync::tests::the_cpr_reference_chosen_cannot_change_a_decoded_position`).
//! 4. Each distinct sync message is decoded locally ([`modes::cpr_local`]) against its address's
//!    reference, and dropped if it lands more than 100 km from it. Its height is the reported
//!    altitude in metres.
//! 5. A message's prior is its decoded position at its reported altitude. It is used only when its
//!    declared accuracy is good enough: `max(EPU(NACp) / 2.448, 5 m)` per horizontal axis at most
//!    100 m, NACp being the one in force at the message: of the operational status (TC 31)
//!    receptions of the address on the clocks that heard the message, the latest at or before one
//!    of its receptions on the same clock, nearest in that clock's nominal time, else the earliest
//!    after, nearest, of equals the lower value (each clock's counts are compared with its own
//!    only, so a message's prior is fixed by what was heard around it, whatever else the window
//!    holds); with none, the containment radius of its type code taken at its worst. An aircraft's
//!    GNSS error is nearly constant over a minute, so what its position bias adds to a pair is
//!    measured, not assumed: each pair's between-aircraft inflation (§ The pairwise path,
//!    inflation).
//! 6. An event is a sync message with its receptions; a reception by a receiver more than 600 km
//!    from the prior is dropped, and an event needs two receptions. A clock that heard the event
//!    twice (the same bytes again, a repeat or a replay) is left out of it.
//!
//! # Clocks
//!
//! A clock ([`clock::ClockKey`]) is (receiver, counter epoch): a counter jump inside the epoch is a
//! jump of the one clock (§ The pairwise path, jumps), never a new clock. A clock's timing noise
//! starts at its timebase's default (`Timebase::default_noise_s`, 500 ns for any clock, whatever it
//! declares, until its pairs estimate it), and is held to `Timebase::noise_ceiling_s`
//! (`sync::GAUGE_NOISE_MOST_S`, 5 µs). A GNSS declaration is the feeder's word, not a measurement:
//! nothing ties a GNSS-disciplined clock to another's stamps, and its discipline shows only as its
//! timebase's tighter curvature and rate prior. Over real receivers (LocaRDS, RFC-0171 §3.8.1) a
//! GRX1090 stamps 120.6 µs after a Radarcape (the end of a long message, not its start), and some
//! Radarcapes declaring GPS run without a lock (one 0.7 s off and drifting 0.09 ppm, three with
//! stamps jittering by hundreds of microseconds).
//!
//! **Curvature.** Every clock wanders as an integrated random walk whose second difference over
//! consecutive knots `KNOT_PS` (5 s) apart has standard deviation
//! `sqrt((rate noise x 5 s)^2 + 2 phase noise^2)` (rate 0.005 ppm and phase 10 ns per interval for
//! 12 MHz, 0.0005 ppm and 5 ns for GPS: 28.7 ns and 7.5 ns, `Timebase::curvature_sigma_s`).
//!
//! # Solving ([`solve`])
//!
//! **How many** ([`backoff`]): mlat-server solves an aircraft at most once every 0.7 s
//! (`RESOLVE_BACKOFF`), and so does this engine, by a rule of the transmissions alone. A
//! transmission's slot is its aircraft's address and its heard time
//! ([`pair::Models::heard_unix_ns`]: the Unix time of its reception by its lowest-keyed
//! GNSS-disciplined hearer's clock, else its lowest-keyed clock's) in whole `backoff::SLOT_MS`
//! (700 ms) since the Unix epoch; of a slot's transmissions, the one of most distinct receivers
//! the models locate is solved, ties to the lower message hash, then the lower lowest reception.
//! A slot is decided at the first step `SLOT_MS` after its earliest candidate fell due (its set's
//! first arrival and `FIX_SETTLE`): another of the slot was sent within the slot's length of it
//! and falls due within as much. A transmission not chosen is never solved or verified, and
//! counted (`tally_mlat`'s `Report::backed_off`); one chosen is solved again once, bigger, once
//! its raw has come (`arrived::Considered::come_ms`) or as its set closes (its complete fix). mlat-server's early solve when a group has more degrees of
//! freedom than its last result less the time since depends on the order its results were reached
//! in, so it is left out. Which transmission is solved is the engine's division of work: a fix is
//! judged by the models it cites and its own receptions, never by its slot.
//!
//! **The cap**: a transmission heard by more than `pair::HEARERS_MOST` (32) receivers is solved
//! from that many ([`pair::Models::capped`]), chosen by their sites alone: the lowest-keyed
//! receiver with a GNSS-disciplined clock heard (else the lowest keyed), then each time the one
//! whose nearest chosen receiver is farthest (squared integer millimetres, ties to the lowest key).
//! Its fix considers every reception of the transmission; it is solved, and judged for omission,
//! over the capped receivers' alone. 32 is the knee of accuracy against cost at world density
//! (`pairwise_path_sweep`, seed 9000, 60 s, 2026-10-26): from mlat-server's 15 (`MAX_GROUP`, set
//! for its Python solver's cost) to 24 to 32 to no cap, the horizontal p50 is 35.0, 27.6, 25.1 and
//! 21.8 m and the fixes cost 2.207, 2.271, 2.285 and 2.451 ms a feeder-second: up to 32 a metre of
//! p50 costs about 0.008 ms, past it about 0.05, six times as much, while the p95 stops improving
//! at 32 (149.9 m either way).
//!
//! 1. Screen (integer): a pair is feasible when
//!    `|t_i - t_j| [ps] * 299792458 <= (baseline [mm] + 10^6) * 10^9`, the baseline being the
//!    floored integer square root of the squared millimetre difference of the stored sites.
//!    While a pair is infeasible, remove the reception in the most infeasible pairs, ties to the
//!    lowest identity.
//! 2. The measurements are `z_i = c * (t_i - t_min)`, each reception's arrival on the timeline
//!    the models give (§ The pairwise path, the adjustment); their covariance is each clock's
//!    within noise plus its site's variance on the diagonal plus `c^2` times the adjustment's
//!    timing covariance: the clock error is propagated jointly, never as independent variances.
//!    Residuals are whitened by its Cholesky factor. The
//!    message's own altitude (AC13, or a DF17 airborne position's) is a pseudo-measurement of
//!    height above the ellipsoid with 100 m (barometric) or 15 m (GNSS).
//! 3. Levenberg-Marquardt over (X, T): damping starts at 10^-3 and is multiplied by
//!    `1 + lambda` on the diagonal; a step that does not raise the cost is taken and the damping
//!    divided by 10, otherwise multiplied by 10; converged when every component of a taken step
//!    is below 10^-4 m; at most 50 iterations. Starts: the previous subset's solution (if any),
//!    Bancroft's two roots (four or more receptions), the receivers' centroid lifted to the
//!    altitude (9 km without one), and, with fewer than four receptions, a ring about the
//!    centroid at the altitude (100 km and 300 km, every 45 degrees from north). The lowest-cost
//!    converged fit with height between -1500 m and 25 000 m and every used receiver within
//!    600 km wins, unless another such fit costs at most 9 more and lies outside the winner's
//!    10^-6 ellipsoid (its four parameters' squared Mahalanobis distance under the winner's
//!    information above the 4-degree quantile): then the transmission is ambiguous and not
//!    solved. An exactly determined transmission (three receptions and the altitude) generally
//!    has two roots that both fit perfectly, and a covariance about either describes neither.
//! 4. Outlier rule: `z = |residual| / sqrt(Sigma_ii)` for every screened reception against the
//!    current solution. If an included one exceeds 5, remove the largest (ties to the lowest
//!    identity) and re-solve; else if an omitted one is at most 5, readmit the smallest and
//!    re-solve; else stop. At most `2n + 2` solves, at least 4 receptions (3 with an altitude).
//! 5. The chi-square of the whitened residuals must not exceed the published limit
//!    ([`solve::published_chi2_limit`]): the Wilson-Hilferty quantile at tail 10^-6 for
//!    `n + altitude - 4` degrees of freedom (0 at zero: the optimum then explains every reception
//!    exactly), widened by what writing the solution to the wire can add, `(sqrt(q) + r)^2`,
//!    where `r` bounds the whitened residuals' move under the wire's rounding of position and
//!    transmit time ([`solve::rounding_norm`], [`solve::ROUNDING_M`]). The solver and the
//!    verifier evaluate this one limit, and a fix leaves the engine only through
//!    [`publish::solve_transmission`], which reads it back from its wire bytes and runs the
//!    verifier on it. Each transmission the models group a due set into (identical bytes sent
//!    again within seconds are several transmissions, which only the timeline separates) is its
//!    own fix, considering its own transmission's receptions and citing the models of its used
//!    hearers' areas (§ Areas). Nothing is published that a verifier holding the same raw would
//!    refuse.
//! 6. The covariance of (X, T) is the inverse of the whitened `J^T J` at the solution. The
//!    published position covariance is its 3x3 ECEF block with its standard deviations times 1.1,
//!    plus 5 m squared on each axis (`solve::ERROR_INFLATION`, `ERROR_FLOOR_M`): the simulator
//!    calibrates the mathematics without them (the calibration tests strip them), but real
//!    receivers carry what it does not model (tropospheric delay differences of a metre or two
//!    between sites, antenna phase centres off their declared sites, multipath), so a fix claims a
//!    little less than the mathematics alone. The calibration over real receivers (RFC-0171 §3.8.1,
//!    `tally-mlat-calibrate`) finds the mathematics honest where receivers and truth are what they
//!    say (0.94 to 0.97) and short with unverified crowdsourced receivers (0.895), not uniformly,
//!    so it leaves these as they are. A fix whose standard deviation on any axis would exceed 1.5
//!    km is not published: there the Gaussian no longer describes the error (a transmission with no
//!    altitude over a flat network leaves the height nearly free; measured, a DF11 6 km below its
//!    aircraft at 58 squared standard deviations).
//!
//! # Verifying a fix ([`verify::verify_pair_fix`])
//!
//! Given the wire fix, the receptions of its message the verifier holds, and the verified models it
//! lists: the models must be the ones it lists (`Failure::Models`) and exactly one of each area its
//! used hearers are in (`Failure::Area`); its considered and used sets must be sorted, every used
//! reception within the considered set (`Failure::NotConsidered` otherwise) and known; of what the
//! verifier holds, only the considered receptions are judged, and a reception outside the
//! considered set is never judged, whatever the verifier holds; the considered receptions must
//! regroup to exactly one transmission whole, every used reception must be of a receiver the cap
//! chooses of it (§ Solving, the cap; `Failure::Uncapped`), and the capped receptions must
//! normalise keeping every reception it used (§ The pairwise path, grouping and the adjustment);
//! the used ones must be at least the minimum and pass
//! the screen; the chi-square at the claimed (X, T) must pass step 5; the Gauss-Newton step from
//! the claim must have squared Mahalanobis length at most 10^-4; the claimed covariance must match
//! the recomputed (published) one within 10^-3 relative (Frobenius); every used reception must
//! have `z <= 5.05` and every screened capped one it left out `z >= 4.95`. Nothing but the
//! models and the fix's own receptions is read. The grouping, the heard time, the cap and the
//! normalisation are functions of their receptions as a set, the same in any order (a property
//! test holds it), so the engine's own check of a fix it solved judges the normalisation it solved
//! on (`verify::verify_solved`), which the regrouping of its sorted considered set rebuilds
//! exactly.
//!
//! # Publishing ([`publish`])
//!
//! **A model is relay-only; a client is sent its summary.** A pair model's scope, clocks and
//! pairs, with the aircraft's published positions, narrow every receiver's site, and a receiver's
//! exact site is never readable by a client. The site id (`tally_wire::SiteId`) names the
//! site-bearing record the engine placed the receiver by (its `ReceiverSite`, or an old feeder's
//! format 1 `ReceiverInfo`) without revealing it, and enters only the inputs id. Beside each model
//! the engine signs a `tally_wire::ClientClockModel` ([`publish::client_model`], format 2): the
//! model's id, its inputs id and its trailing window (edge and span), and nothing of its scope or
//! frontiers. A client is sent that and tagged fixes (`tally_wire::TaggedFix`, positions format 8,
//! each reception its `ReceptionTag` under the receiver's relay-only `ReceptionKey`); a relay keeps
//! the models and the raw fixes (format 7), and rematches a tagged fix against the raw it holds
//! ([`publish::rematch`]). The engine sends each of its own models a fix cites first, then the raw
//! fixes citing them, then their tagged twins, back to back.
//!
//! A model's inputs id ([`publish::inputs_id`], carried by the manifest) is BLAKE2s-256 over
//! `"tally pair model inputs id" 0x00`, the specification version (two bytes) and the encoding's
//! first part (area, trailing window, each scope entry as key, clock, site id, precision and
//! frontier, and the input citation): no site. Consumers merge by it, never by model bytes.
//!
//! A fix on the wire ([`publish::to_wire_at`], `tally_wire::Fix`) carries its considered set and
//! its used set (a mask over the considered), the ids of the models it cites, strictly ascending,
//! its transmit time on the timeline's Unix origin, in Unix picoseconds; latitude and longitude
//! rounded to 10^-7 degree; height above the ellipsoid rounded to the millimetre; the covariance
//! rotated to east, north, up at the fix, as binary32. Its identity (`tally_wire::Fix::identity`)
//! is over its models' ids and its considered set. A verifier rebuilds the claim from it
//! ([`publish::claim_at`]): position and transmit time read back, the covariance rotated back, the
//! degrees of freedom from the used count and the message's altitude. Those roundings move the
//! claim far less than the verifier's tolerances; a nanosecond would not (half of one is 15 cm of
//! light travel, beyond the optimality bound for a well-observed transmission).
//!
//! # The pairwise path ([`pair`])
//!
//! mlat-server's shape (one clock pairing for each two receivers that hear the same aircraft, a fix
//! normalised over the pairings among its hearers), made bounded and verifiable: each refit fits
//! every pair of an area in closed form from the window's raw alone, publishes them with every
//! clock's noise and rate as one model ([`pair::PairModel`], [`pair::fit`]), and a fix cites the
//! models of its used hearers' areas by their ids (§ Areas). A holder of the window verifies a
//! model once a refit ([`verify::verify_pair_model`]); a verifier holding the verified models and a
//! fix's own receptions verifies the fix ([`verify::verify_pair_fix`]), reading no other raw.
//! What a refit carries from the last is where the fixed point is sought from (the previous model's
//! noise and rates, each kept while within half the verifier's band of its new estimate) and, as
//! the holder's cache, the blocks whose raw did not change (§ The pairwise path, blocks). The cache
//! changes nothing published; the start may change a model's bytes, never whether it passes
//! verification against its cited raw, which is the property a model has.
//!
//! **The network** ([`pair::Network`]). Which pairs of receivers exist is decided by their site
//! records alone: each usable receiver keeps its `pair::PAIR_NEIGHBOURS` (40) nearest usable
//! receivers within `pair::PAIR_BASELINE_MM` (600 km), by exact integer squared distance between
//! millimetre sites, ties to the lower key, and two receivers are a pair when either keeps the
//! other. A receiver joining or leaving changes only the pairs of the receivers that count it
//! among their nearest. The reference engine finds the nearest through cubes of a quarter of the
//! baseline, searched ring by ring until every site nearer than the ring's reach is in hand, so
//! building the network costs the neighbourhoods, never every two sites.
//!
//! **The window** ([`Arrived::area_inputs`]). Every refit reads one trailing window (§ The trailing
//! window) of the area's members' sync receptions, each receiver cited through its
//! frontier, read as the clock model reads its inputs (§ Sync events: the events, their priors,
//! each receiver's linear counts), with one change: the model names each aircraft's CPR reference
//! (its address, the BLAKE2s-256 message hashes of the even and the odd position that decode
//! globally to it, and whether the odd is the later), the one the search of § Sync events, 3
//! finds. Any reference within the local decode's reach gives every message the same position to
//! the bit, so a verifier checks only that the named pair was heard by one clock within its pair
//! window in the order named and decodes globally, and that no address it does not name has a
//! reference the search would find. A clock that heard an event twice is left out of it. A
//! clock's lowest linear count over its sync receptions in the window is what a fix's raw is
//! unwrapped near.
//!
//! **A pair's points.** Each event of a block (below) gives each pair of its hearers `a < b` (by
//! clock key) that the network names one point: `x` is `a`'s nominal nanoseconds from a reference
//! count less its range from the event's prior in nanoseconds of light time, `y` the same for `b`
//! less `x`. A clock's rate scales its range term, which the fit carries as two regressors of their
//! own (`range_a` and `-range_b`, their coefficients the two rates), so nothing a block holds moves
//! with the rates. A point weighs `2 / (h (sigma_a^2 + sigma_b^2))`,
//! `h` the event's hearers, from the pair's two clocks and the raw alone: at equal noise it is
//! `w_a w_b / W` with `w_k = 1 / sigma_k^2` and `W` the sum over the hearers, and by the identity
//! `sum_k w_k (t_k - T)^2 = sum_{i<j} w_i w_j / W (t_i - t_j)^2` at the weighted mean transmit time
//! `T` the pairs of an event together carry a joint fit's information with its transmit time
//! eliminated. A point's own variance is `sigma_a^2 + sigma_b^2`. The weight's `w0 = 2 / h` is the
//! raw's; the noise enters only when a pair is solved.
//!
//! **Blocks** (`pair::blocks`). A pair's points are taken one second of signed wall clock at a
//! time, as blocks. The block of a pair at second `s` holds the points of the sync events new in
//! `s`: each reference aircraft's position message heard by a member in `s` and by none in the
//! `sync::LOOK_BACK_S` (2) seconds before it, with every member's reception of it within
//! `sync::SPAN_AFTER_S` (2) seconds after `s` (a clock that heard it twice there left out), its
//! prior read from its aircraft's CPR reference (§ The window) and NACp found in that span, and
//! at least two hearers within `sync::MAX_RANGE_M` of the prior. A block's robust line is drawn
//! through its pooled points: those of `s` and of the `pair::LINE_BLOCKS - 1` (4) seconds before
//! it, less any before either clock's kept segment start (§ Jumps), sorted by `x` then `a`'s count,
//! `b`'s count, the address and the second, each read from the first of the block's own points
//! (least `a` count, then `b`). The line passes through the medians, `x` and `y` taken
//! separately, of the first `n / 2` pooled points and of the rest, and its scale is `1.4826` times
//! the median absolute residual about it, at least `sync::MIN_NOISE_S` times the square root of
//! two; with fewer than `pair::LINE_LEAST` (4) pooled points the block has no inliers. The block's
//! own points within `sync::SYNC_CUTOFF` (10) scales of its line are its inliers, and the rest
//! are outliers for every window that holds the block. Its inliers are summed by interval of
//! `a`'s knot grid (`Timebase::knot_counts`, 5 s of nominal counts from count zero, so the grid is
//! the same in every window): per interval the block line's value at the interval's start and its
//! change across it, the upper triangles of `sum w0 z zᵀ` and `sum z zᵀ` over the regressors `z =
//! (1 - f, f, r, range_a, -range_b)` (`f` the point's place in its interval, `r` its residual about
//! the block's line), `sum w0²`, and per aircraft `sum z`, `sum w0 z` and `sum w0²`. Its steps are
//! those of its pooled residuals about its line past `sync::JUMP_THRESHOLD` (§ Jumps), the largest
//! located in each second. So a block is a function of the receptions of seconds `s -
//! pair::READ_BACK_MS / 1000` to `s + sync::SPAN_AFTER_S` among the window's inputs alone: the
//! same in every window whose inputs hold the same receptions of that span, which the newest
//! seconds' blocks are not, since a window's inputs end at its edge (`Trailing::reads`). A holder
//! may keep blocks between refits by a digest of the receptions they read,
//! under a key of its own (the reference engine's `BlockCache`), and build one again only when they
//! changed; whether a block was kept or built changes nothing it holds. A block whose pooled points
//! reach before either clock's kept segment start is built again from the kept points alone, and
//! one whose own points all lie before it is dropped.
//!
//! **A pair's fit**, from its blocks' sums alone: `y` as a function of `x`, linear between knots
//! on `a`'s grid, from the start of the lowest interval its blocks' inliers fall in to the end of
//! the highest (at most `pair::PAIR_KNOTS_MOST`, 5, knots; more, and the pair is not valid). The
//! first knot is at `a`'s count of that interval's start, and `b`'s anchor is `b`'s count where it
//! reads what `a` reads there, by the first block's first point; each block's sums are moved to
//! these anchors by the difference of its own reference counts and summed in ascending block order.
//! The second difference of consecutive knots is held by the curvature prior `sigma_c^2 =
//! curvature_a^2 + curvature_b^2` (§ Clocks, curvature), scaled by the inliers' `sum w0 / sum 1`
//! over `sigma_c^2`, so the prior keeps the pair's own strength. The inliers are the blocks'; there
//! is no robust pass at the pair. Under given noise and rates the knots are the weighted
//! least-squares solution of the summed normal equations, in closed form. So the published knots
//! are the optimum of their blocks' inliers under the published noise and rates, which is what a
//! verifier checks: at the knots, the inliers' normal equations hold within
//! `pair::PAIR_OPTIMALITY_TOLERANCE` (the Gauss-Newton step's squared Mahalanobis length). Its
//! covariance is the inverse of that normal matrix; its share is `sum w^2 var / sum w` over its
//! inliers, what its curve's variance is from its own points alone, under their own variances, as
//! a multiple of that covariance's (exact for a constant; the weights split an event's information
//! among its hearers' pairs, so the covariance alone is each pair's part of the network's joint
//! information, not its own variance). A pair with fewer than `sync::SPAN_RECEPTIONS_LEAST` points
//! (its blocks' own points, inliers and outliers) is not valid.
//!
//! **The warm start.** A refit seeks the fixed point (below) from the noise and rates of the area's
//! previous model where it holds a clock, else each timebase's default noise and no rate. No knot
//! is carried: each pass solves every pair in closed form from its sums. A clock's noise is kept
//! while within `verify::NOISE_BAND / 2` of its estimate, so a model's bytes may depend on the
//! start; from either start it passes its verifier, with the same pairs
//! (`a_warm_refit_publishes_what_a_cold_refit_publishes`).
//!
//! **Jumps.** A pair's jump is the largest of its blocks' steps in the window's seconds. A block's
//! step is, in its pooled points' order, the change between the medians of the `sync::JUMP_SIDE`
//! (5) residuals about its line before and after a point, scored against the residuals'
//! consecutive scatter (`1.4826 * median |r_{i+1} - r_i| / sqrt 2`, at least 10 ns, times the
//! spread of two medians of five), above `sync::JUMP_THRESHOLD`; it lies on each of its clocks
//! between the counts of the two points either side. A jump is the clock's when its pairs agree on
//! its time: each refit starts from no jump at all, fits every pair, and gives a clock whose pairs'
//! intervals (`(last count before, first count after]` on that clock) are contained, at least
//! `pair::JUMP_AGREE_LEAST` (2) of them, in one place the first count after of the one most others
//! contain (ties to the earliest), when it is later than the clock's kept segment's start; that
//! clock's pairs are fitted again from it, at most `pair::JUMP_ROUNDS_MOST` (4) rounds. The model
//! publishes each clock's kept segment's start (`from`). A pair with a jump no clock is given is
//! not valid. A verifier replays the rounds over every candidate pair of a clock with a jump and
//! every candidate the model does not publish, and must find the same starts and the same pairs.
//!
//! **Inflation.** Each aircraft's weighted mean residual in the pair, squared over its own
//! variance (`sum w^2 var / (sum w)^2`), summed over the aircraft, is the pair's between-aircraft
//! chi-square on one less than its aircraft; the pooled inflation is every valid pair's chi-square
//! over every valid pair's degrees of freedom, and a pair's is its own shrunk toward the pooled by
//! `pair::KAPPA_PRIOR_DOF` (20) degrees of freedom, at least one: what an aircraft's position bias
//! adds that the points' noise does not.
//!
//! **Noise.** Each clock's noise estimate is the weighted least-squares split of its valid pairs'
//! inlier scatter (`sigma_a^2 + sigma_b^2` against a pair's mean squared inlier residual, weighed
//! by its degrees of freedom over the square of `sigma_a^2 + sigma_b^2` at the estimate itself:
//! the variance of a variance, read at the noise it is of and never at the pair's own scatter,
//! which would weigh a pair the more the less it happened to scatter and bias every clock's noise
//! low; from each timebase's default noise, weighed again at the last estimate until no clock's
//! variance moves by more than `1e-9` of itself, at most `pair::NOISE_REWEIGHTS_MOST` (50) times,
//! so it is a function of the pairs alone), with a weak prior at its
//! timebase's default noise (a thousandth of a pair's weight), held to `[sync::MIN_NOISE_S,
//! sync::GAUGE_NOISE_MOST_S]`. Where the split is underdetermined (a component of the pair graph
//! that is a tree or bipartite), the prior's value decides the free direction, and the estimate is
//! still the rule's. Two scatters: the whole (what weighs the points and bounds the robust tests,
//! an aircraft's position bias in), and within each aircraft (each aircraft's mean residual
//! removed: a reception's own noise, what a fix's receptions carry). A scatter's degrees of
//! freedom are its inliers' less what the fit took of them, as a weighted least-squares fit's
//! residual degrees of freedom are counted: the trace of the hat matrix of the knots under the
//! curvature prior (`sum w b^T N^-1 b` over the inliers), and within each aircraft also the
//! aircraft means, less what of the knots' fit lies in them (`tr(H M)`, `M` the means'
//! projector). The within estimate is then read as a fix reads it: times `nu / (nu - 2)`, the
//! variance of Student's t at the estimate's own degrees of freedom, `nu = sigma^4 / [N^-1]_kk`
//! of the split's normal matrix `N` (each pair's mean square has variance `2 s^2 / dof`, so the
//! estimates' covariance is `2 N^-1`), at least `pair::WHITE_DOF_LEAST` (4): an error read
//! against an estimated variance is covered as one read against the true variance would be.
//! A verifier refuses a clock whose published noise of either kind is more than
//! `verify::NOISE_BAND` below the rule's estimate from the published pairs.
//!
//! **Rates.** Each clock's absolute rate error `rho_k` is the optimum of one system: a prior of
//! `pair::GNSS_RATE_SIGMA` on a GNSS-disciplined timebase and `pair::FREE_RATE_SIGMA` on a
//! free-running one, every valid pair's slope over its span (`rho_b - rho_a`, against its variance
//! times its inflation), and every valid pair's points' ranges: a rate scales a clock's range
//! correction, so each pair's weighted sum of squares, its knots profiled out, informs its two
//! rates (the Schur complement `S = dᵀWd - dᵀWΦ N⁻¹ ΦᵀWd` of its ranges' regressors `d`, over its
//! inflation, and the gradient reduced by the knots'). That is the gauge rule of a group with no
//! GNSS-disciplined clock: what fixes its common rate is the sync aircraft's ranges and the
//! free-running prior, never one clock's say. A verifier checks the rates at their published value
//! by the Newton step's squared length over the system, at most `pair::RATE_OPTIMALITY_TOLERANCE`
//! a clock. Each clock's published rate variance is the inverse of its row's diagonal, and its
//! component's common variance the inverse of the component's `1ᵀ H 1`.
//!
//! **The fixed point.** The noise and rates are those the pairs fitted under them give, within the
//! verifier's tolerance; where the search starts (the area's previous model, or each timebase's
//! default noise and no rate) is a warm start, never part of the result. The first pass fits every
//! pair under the starting noise and rates; each later pass fits again only the pairs the last one
//! moved: those of a clock whose whole noise changed (a point's weight reads only its pair's two
//! clocks) and those the rates have moved from their optimum, since they were fitted, by more than
//! a tenth of `pair::PAIR_OPTIMALITY_TOLERANCE` (`Δᵀ (dᵀWd - S) Δ`, the knots' own share of the
//! ranges); a new jump among them settles every pair again. Each pass takes each clock's noise as
//! its estimate unless the present one is within `verify::NOISE_BAND / 2` of it either way, and the
//! rates' Newton step, each pair's range gradient carried from the rates it was fitted at to the
//! present ones (`+ S Δ`, exact for a quadratic). The pass settles when no clock's whole noise
//! changed and the stepped rates move no pair further than that tenth. What is then published of
//! each pair is the verifier's own computation: its points assessed at its knots under the
//! published noise and rates (inflation, covariance, slope, and the rates' variances from those),
//! and the jumps and drops replayed exactly as the verifier replays them; a pair that assessment
//! finds off its optimum or with a jump is fitted again, a replayed decision that differs is taken
//! (the pairs of a clock whose jump changed fitted again), and the pass repeats, at most
//! `pair::PASSES_MOST` (6), after which none is published.
//!
//! **Solving the clocks' systems.** The noise and the rates are sparse systems over the clocks,
//! one entry a pair: solved by conjugate gradients in one fixed order, preconditioned by their
//! diagonal plus each connected component's constant (the common rate a component's slopes cannot
//! see), to a relative residual of `1e-14`.
//!
//! **The model** ([`pair::PairModel`], [`publish::encode_pairs`]). Relay-only: the specification
//! version; the area (H3 index, eight bytes: a relay routes a model by its first ten bytes,
//! [`publish::area_of`]); the trailing window; the scope, each member as receiver key, clock, site
//! id, site and precision, with its frontier; the input citation; the references; the pooled
//! inflation; each clock (its receiver by its index in the scope and its epoch, lowest count,
//! `heard_ns`, `from` or none, whole and within noise, rate, rate variance, common variance); each
//! valid pair (its clocks by index, anchors, first knot's `x`, knots, the upper triangle of their
//! covariance, slope, slope variance, inflation, share).
//! Counts are four bytes but the scope's, the clocks' and a pair's clock indices (two), floats
//! their IEEE 754 bits, every list strictly ascending. What a fix or a check reads as a datum (the
//! noise, the rates, `x`, the knots, the slope) is double precision; what only weighs (the
//! inflations, the variances and covariance, the share) is single, rounded once when the model is
//! assembled, so the engine solves under exactly what it publishes and a single's own rounding (a
//! relative 2⁻²⁴) sits far inside the verifier's tolerances. Its id, which
//! fixes cite, is the BLAKE2s-256 of `"tally pair model id" 0x00` and its bytes
//! ([`publish::pair_model_id`]).
//!
//! **Grouping** ([`pair::Models::transmissions`]). A considered set's receptions are mapped to one
//! clock's time through their direct pair with it (the clock with the most pairs to the set's
//! others, ties to the lowest key), or, with none, through the lowest-keyed clock of the model with
//! a pair to both; sorted, and cut where consecutive ones are more than `group::GATE_PS` apart.
//! Each part is split again by the same rule over its own clocks until every part is its own
//! split, so a fix's considered set is one the rule returns whole, which the verifier checks.
//!
//! **The adjustment** ([`pair::Models::normalise`]). A transmission's hearers are the nodes, every
//! published pair between two of them an edge. When the hearers split, the lowest-keyed clock that
//! heard nothing but has pairs into the largest part and into a hearer of another joins as a
//! bridge, at most `pair::BRIDGES_MOST`; hearers outside the largest part are left out. The
//! unknowns are each node's reading at the reference's arrival less its reading at its own
//! (`theta`, nominal nanoseconds), the reference the lowest-keyed GNSS-disciplined clock that heard
//! it, else the lowest-keyed (`theta = 0`). An edge `a < b` at `a`'s reading `x_a` says `theta_b -
//! (1 + g'(x_a)) theta_a = x_a + g(x_a) - x_b`, with the variance of `g(x_a)` from the pair's
//! covariance times its inflation, carried past its last knot along its last interval with the two
//! clocks' process noise. The weighted least-squares solution gives `theta` and its covariance;
//! while the worst edge's normalised residual is above `pair::LOOP_Z`, the graph has more edges
//! than unknowns and leaving it out keeps it connected, the edge is left out (at most
//! `pair::LOOP_REJECTS_MOST`). The edges are not independent: every edge at a clock carries that
//! clock's own error, so `theta`'s covariance is not the solution's inverse normal matrix (which
//! reads them as independent and is about twice too large at eight or more hearers). An edge's own
//! variance is its `g(x_a)` variance from the pair's points alone (the fitted part times the
//! pair's share, plus what is carried past the last knot); each node's clock variance is the least,
//! over its used edges, of that edge's own variance times the node's share of the two clocks'
//! white noise (`sigma_k^2 / (sigma_a^2 + sigma_b^2)`); each used edge's remainder (its own variance
//! less its two nodes' clock variances, at least zero) is independent across edges. `theta`'s
//! covariance is the nodes' clock variances on the diagonal plus `N^-1 (sum_e w_e^2 delta_e d_e
//! d_e^T) N^-1` (`N` the solution's normal matrix, `w_e` an edge's weight, `delta_e` its remainder,
//! `d_e` its row), all inflated by the residuals' chi-square a degree of freedom when above one.
//! Each hearer's arrival after the reference's is `tau_k = -theta_k / (1 + rho_k)`; its timing
//! covariance is `theta`'s, scaled, plus `theta_k theta_l cov(rho_k, rho_l)`
//! with `cov(rho_k, rho_l)` the rate variance of `k` when `k = l` plus the common variance, and
//! zero when either clock is GNSS-disciplined (its rate is known to `pair::GNSS_RATE_SIGMA`, which
//! moves no fix); its noise is the clock's within noise plus its site's variance. That is the
//! problem `solve` solves (§ Solving), unchanged. The timeline's zero is the reference's arrival:
//! its reading on the UTC day its batch's wall clock is in for a GNSS-disciplined reference
//! (`sync::origin_unix_ns`), and for a free-running one the model's `heard_ns` for its lowest count
//! plus its nominal time from there (§ Areas, dating), which dates the fix's transmit time.
//!
//! **Publishing a fix** ([`publish::solve_transmission`]): a format 7 fix whose `models` are the
//! ids of the models it cites (§ Areas), published only when the verifier passes the claim read
//! back from its bytes.
//!
//! **Verifying a model** ([`verify::verify_pair_model`]), by a holder of the window: its inputs are
//! the window's; its references stand; every published clock is a clock of the window with its
//! lowest count; every published pair is a candidate (both clocks a network pair, enough points),
//! its anchors, first knot and knot count the rule's, its knots optimal under its inliers at them,
//! no jump in its kept segment, and its covariance, slope and share its own within
//! `pair::DERIVED_TOLERANCE`, its inflation and the pooled within `pair::KAPPA_TOLERANCE`; the
//! noise within the band; the rates optimal and their variances the system's; and the jump rounds,
//! replayed, give the same starts and the same pairs.
//!
//! **Verifying a fix**: § Verifying a fix, by a holder of the verified models it cites and the
//! fix's receptions alone.

// It reaches keys (`tally_wire::Identity`): no `unsafe` code at all, forbidden, so no module
// can allow it.
#![forbid(unsafe_code)]
// Matrix code reads as the algebra it implements: index loops over rows and columns.
#![allow(clippy::needless_range_loop)]

pub mod area;
pub mod arrived;
pub mod backoff;
pub mod clock;
pub mod gate;
pub mod geo;
pub mod linalg;
pub mod modes;
pub mod obs;
pub mod pair;
pub mod publish;
pub mod scope;
pub mod sim;
pub mod solve;
pub mod standing;
pub mod sync;
pub mod threshold;
pub mod verify;

pub use arrived::{Admitted, Arrived, BatchId, Considered, HELD_MS, TransmissionKey};
pub use clock::{ClockKey, MAX_CARRY_PS, SPEC_VERSION, Timebase};
pub use obs::{ModeS, ObservationId, Reception, Site};
pub use pair::{GATE_PS, PairCache, PairModel, Prepared};
pub use publish::{
    PublishError, Stated, Transmission, Unpublished, solve_transmission, transmissions,
};
pub use scope::{Citation, Frontier, Inputs, Sites, Trailing};
pub use solve::{Solution, SolveError};
pub use threshold::{KEPT_KEEP, REFERENCE_KEEP, Threshold, sync_key};
pub use verify::{
    Failure, PairModelFailure, PairModelVerdict, Verdict, judges, verify_pair_fix,
    verify_pair_model, verify_pair_model_held,
};

#[cfg(test)]
mod tests;
