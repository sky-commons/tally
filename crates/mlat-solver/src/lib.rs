//! Tally's native MLAT mathematics (RFC-0171 §3.8, §3.8.1): pure, deterministic, no I/O.
//!
//! An MLAT engine takes a region's raw receptions and, for each window, fits one clock model per
//! canonical tile (a cube of space and its footprint of receivers) from the ADS-B positions its
//! members heard, shared by every aircraft assigned the tile; groups each aircraft's receptions
//! into transmissions, solves them, and publishes models and solutions anyone can verify against
//! the same raw observations. This crate is that mathematics; `tally-mlat` is the engine around
//! it.
//!
//! This documentation is the specification (version [`clock::SPEC_VERSION`]; version 4 trusts no
//! receiver's declaration of GNSS discipline beyond its timebase, from the calibration over real
//! receivers, § The least-squares problem; version 5 dates a free-running gauge's origin by every
//! cited reception of its clock and rejects a sync message any receiver heard twice in the
//! window). A verifier judges its own version alone ([`verify::judges`]). It is written so an
//! independent implementation makes the same discrete decisions: holding, windows, tiles,
//! members and assignment are decided by content in integers (the tile module refuses floating
//! point at compile time), grouping and the feasibility screen are exact integer arithmetic on raw
//! counters and the fixed-point model; the floating-point decisions (sync weights, jumps, noise,
//! the outlier rule) are stated with their constants, and the verifiers allow stated bands.
//!
//! # What verification means
//!
//! The protocol's rule is optimality within tolerance, not bytes (and the same for a provisional
//! solution, § Provisional solutions): a published model is honest
//! when, rebuilt from its cited raw, it is an optimum of its own inputs within the model
//! verifier's tolerance and passes its other checks (§ Verifying a model); a solution is honest
//! when it is the optimum of its cited receptions under the model it cites and the tile it cites
//! is the one the assignment rule gives (§ Verifying a solution). A fault is "this signed model
//! (or solution) fails verification on its cited raw", and two signed models of one inputs hash
//! that differ are a fault only because the reference engine is deterministic. Byte identity is
//! a property of the reference implementation (the same raw, in any order and on any threads,
//! gives the same bytes, and its tests hold it to that), never what a consumer relies on:
//! consumers merge by inputs hash, not model bytes. This is what lets an engine choose among
//! optima-within-tolerance (a warm start would be one) without being in fault; the reference
//! engine fits cold (a warm start was measured, § The clock model, and did not pay).
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
//!   lookup through a model moves a stamp by whole days to within half a day of the epoch's first
//!   piece's knot 0.
//! - Receivers: a site whose declared precision is above 30 m, whose clock is unknown, or which is
//!   described twice takes no part. Its antenna is converted to ECEF (WGS84) and rounded to whole
//!   millimetres; that rounded position is used by everything after. Its precision `p` adds
//!   `(p / sqrt 3)^2` to each reception's variance.
//!
//! # Holding raw ([`held`])
//!
//! - **What is held** is decided by the message alone: the Mode S replies MLAT solves (DF0, 4, 5,
//!   11, 16, 20, 21 with an address), and of DF17/18 only what syncs clocks (an airborne position
//!   with an altitude) or gives a sync position its prior (an operational status with a NACp).
//!   Identification, velocity, surface positions, Mode A/C and UAT are never held.
//! - An observation is held once per bin, by identity; of copies, the earliest batch wall clock.
//!   While its bin is open it is 28 bytes in its receiver's own list (the message inline, chunks
//!   that are never copied), so raw split by receiver has independent owners. Sealed, it is 24
//!   bytes (counter and milliseconds into its bin in one word, receiver, epoch and message as
//!   indices into the bin's tables), and a message's bytes and hash are held once per bin.
//!   Measured at world scale, with the bin's index, 30 to 35 bytes an observation, every byte
//!   counted as allocated.
//! - A bin is open until its raw is complete, then sealed: each receiver's raw sorted on its own,
//!   in parallel, the messages gathered once, the receivers merged in key order, then
//!   deduplicated, thinned, and indexed once (per address its records; the sync candidates, a
//!   position with an altitude heard by two or more, by message hash; per receiver its
//!   candidates and whether it is sync-active; per address its status messages; the aircraft
//!   heard with ADS-B). Any split of a bin's raw by receiver seals to the same bytes, on any
//!   number of threads (`Bin::seal_from`). A window is assembled from its sealed bins without a
//!   copy, and every reader of a holder's raw shares its sealed bins (`SealedBins`).
//! - **Ingest thinning at sealing**, the same for every holder: each receiver keeps its
//!   `SYNC_PER_RECEIVER = 32` lowest-hash sync candidates of the bin (more than any tile keeps of
//!   it there: ten, and one with each partner); a reply of an aircraft heard with ADS-B in the bin
//!   is dropped (it is no MLAT target), unless the aircraft is in the calibration sample (the
//!   first byte of BLAKE2s-256 over `"tally calibration sample" 0x00`, address and bin, below
//!   256 / 16: one in sixteen), whose receptions are all kept; status is kept. And no receiver
//!   keeps more than `KEPT_PER_RECEIVER_BIN = 1500` records of a bin (`KEPT_CEILING_PER_S = 300`
//!   a second, twice the measured mean): its sync, status and sample records first, then its
//!   replies, each lowest message hash first, so a busy receiver loses its highest-hash replies,
//!   the same ones on every holder.
//! - Memory is bounded, and refusal is whole: a receiver's raw of a bin beyond its share, or
//!   beyond the bytes held, is refused entire and counted, never partly by arrival order
//!   (`Limits`); what one receiver costs is `Rates::cost`, for admission to reserve: its sealed
//!   raw at the kept ceiling, so a holder sized for its receivers never refuses one whole at a
//!   seal.
//!
//! # Windows and the stride ([`scope`])
//!
//! Wall time is cut into 5 s grid bins; an observation's bin is its batch wall clock (milliseconds)
//! divided by 5000. Nothing about when anything arrived enters any rule. A transmission's bin is
//! the bin of the lower median of its receptions' wall clocks. Windows are strided: with `s = 8`
//! (`STRIDE`) and `ks` the least multiple of `s` at or above a bin, the window
//! `[ks - 11 - (s - 1), ks + 1]` solves bins `ks - (s - 1)` to `ks`, each with at least eleven
//! bins (55 s) of history and one after, and each tile is fitted once a window. Measured (a
//! hundred receivers, a hundred aircraft): per solved bin 21.4 fits and 0.86 s at `s = 1`, 11.0
//! and 0.45 s at 2, 5.7 and 0.24 s at 4, 2.9 and 0.13 s at 8, coverage 0.958 to 0.963 at every
//! stride; a final position comes on average 14.5 s, 17, 22 and 32 s after its transmission. At
//! world scale, at an eighth of the real reception rate, `s = 4` needed 34 cores and `s = 8` 26;
//! at the real rate `s = 8` needs 41 (RFC-0171 §3.8.1): the baseline takes `s = 8`, and the
//! provisional stream covers the latency. The engine solves a window when its
//! own clock has passed the end of the window's last bin and a settling time; that decides only
//! whether late raw makes it in.
//!
//! # Tiles ([`tile`])
//!
//! Four levels `l = 0..3` of footprint radius `R` = 50, 100, 200, 400 km. A tile is a level and an
//! integer ECEF cube of edge `R / 2` (millimetres; its centre is the cube's, whole millimetres);
//! its footprint is every usable receiver whose millimetre site is within `R` plus half the cube's
//! diagonal (rounded up by integer square root) of the centre, by exact integer squared distance.
//! Its members in a window: the footprint's sync-active receivers (a reception of a sync
//! candidate in a bin of the window), all of them when at most `M = 48`, else `M` by
//! farthest-point selection on the millimetre sites (the candidate whose squared distance to the
//! nearest chosen is largest, ties to the lowest key; the first, the lowest key). Members depend
//! on site descriptions and the window's sync material only, never on one aircraft. The gauge and
//! the clocks' component are per tile (§ The clock model, the component holding the most
//! members).
//!
//! # Assignment ([`scope::WindowIndex::assign`])
//!
//! An aircraft's hearers in a window are the usable receivers with a reception of a message
//! naming it. At each level, its tile is the one whose cube contains the coordinate-wise lower
//! median of its hearers' millimetre sites; of the four, it is assigned the one with the most
//! hearers among its members, ties to the lower level. Its scope is its hearers among the tile's
//! members. Integer only. A verifier recomputes it (§ Verifying a solution): an engine cannot
//! choose a convenient tile.
//!
//! # Targets ([`scope::WindowIndex::addresses`], [`scope::chosen`])
//!
//! A window solves an aircraft heard (not by an ADS-B position) in a bin it solves when no ADS-B
//! position of it is anywhere in the window, or when it is in that bin's calibration sample (one
//! in sixteen ADS-B aircraft, solved from its replies so the published covariance can be measured
//! against its own GNSS position). Its ADS-B positions are never solved; they sync the clocks.
//! Of its transmissions in each solved bin, at most five (about one a second) are solved, the
//! lowest by rank (BLAKE2s-256 over `"tally transmission rank" 0x00` and the identity of its
//! lowest-identity reception).
//!
//! # Thinning ([`scope::WindowIndex::inputs`])
//!
//! Sync events are massively redundant: a window holds thousands, and what they say about the
//! clocks saturates long before. A tile keeps a canonical subset, the same for every engine and
//! verifier holding the same raw:
//!
//! 1. Candidates: per bin, the sealed bin's sync candidates (after ingest thinning) that two or
//!    more members heard, each with the members' receptions of it. A message any receiver (member
//!    or not) heard more than once in the window, in one bin or across bins, is no candidate in
//!    any bin: its bytes were sent more than once (an aircraft repeating a position byte for byte,
//!    a replay), and which reception is of which transmission cannot be told, so an event of it
//!    would mix receptions seconds apart. Judged over every receiver's records before any tile
//!    thins, so every tile and engine rejects the same messages.
//! 2. Sync aircraft: of the candidates' aircraft, at most `A_max = 16`, the lowest by rank
//!    (BLAKE2s-256 over `"tally sync aircraft rank" 0x00`, the address and the window's first and
//!    last bins); only their candidates are kept. Measured (100 receivers, 60 ADS-B and 40 Mode S
//!    aircraft, before the stride): coverage 0.964 at 8 for a median error of 52.6 m (too few
//!    aircraft: overstated and imprecise), 0.946 and 36.1 m at 16, 0.949 and 33.6 m at 32, 0.953
//!    and 36.1 m with no cap, for 20, 31, 45 and 49 s of work. 16 is the least that keeps the
//!    precision of no cap, at about three fifths of its cost: the cap bounds the fit's dense border
//!    (three biases per sync aircraft), whatever the traffic.
//! 3. In each bin, in rank order (ascending message hash), a candidate is kept when one of its
//!    members has kept fewer than `K = 10` there, or one pair of them fewer than `P = 1`
//!    together; keeping it counts it for every member and pair in it. (`K` was measured with
//!    per-aircraft scopes in version 2: with every event a fit took about 1 s, at 10 about 50 ms,
//!    for coverage within the simulator's sampling noise of every event's.) The pair rule keeps
//!    every two members that hear one aircraft tied in every bin.
//!
//! The model's inputs, cited together as a [`scope::Citation`], are the sync material: the
//! members' receptions of the kept events, and of each distinct ADS-B operational status message
//! of a kept event's aircraft its lowest-identity member reception in the window, which give the
//! events' priors. The citation is the count and BLAKE2s-256 over `"tally clock model inputs"
//! 0x00` and each distinct (identity, wall clock) in order as receiver key, epoch (4), counter (6),
//! message hash (32) and wall clock (8), big-endian. A solution cites its aircraft's receptions
//! in the window (every usable receiver's, which chose its tile) the same way.
//!
//! **Honesty rests on measured calibration**, not on an argument. A tile's fit leaves out
//! receivers and events, and it might be thought that a subset only enlarges the posterior, so a
//! scoped fit is never overconfident. That holds for a fixed model with known noise; here each
//! clock's noise and the robust weights are estimated from the subset itself, so a subset can
//! understate them (a noise estimate from a few dozen receptions is low as often as high). What
//! the published covariance is worth is what the simulator measures (§ The clock model, the noise
//! margin; the calibration tests: single, by level, by altitude band, at the tile's edge, and
//! jointly for solutions sharing a tile), and what a calibration against real receivers' truth
//! shows (RFC-0171 §3.8.1, `tally-mlat-calibrate` over OpenSky's LocaRDS: the truth there, each
//! aircraft's own ADS-B position, is itself off by tens of metres, so it bounds what can be said).
//!
//! # The clock model ([`sync::fit`])
//!
//! ## Sync events
//!
//! 1. The sync material (§ Thinning) is deduplicated by identity.
//! 2. A sync message is a DF17/18 with an address, a zero CRC residual, an airborne position
//!    (TC 9-18 barometric, TC 20-22 GNSS height) and an altitude.
//! 3. Each address gets one CPR reference: from every receiver's (epoch's) receptions of the
//!    address, every pair of an even and an odd message whose linear counts are at most 10 s apart
//!    is a candidate `(even bytes, odd bytes, odd is later)`; candidates are tried in ascending
//!    lexicographic order and the first that decodes globally ([`modes::cpr_global`]) is the
//!    reference.
//! 4. Each distinct sync message is decoded locally ([`modes::cpr_local`]) against its address's
//!    reference, and dropped if it lands more than 100 km from it. Its height is the reported
//!    altitude in metres.
//! 5. A GNSS position's error is nearly constant over a minute, so a sync aircraft's reported
//!    positions share one horizontal bias, east and north, one pair of parameters per address
//!    with the prior `max(EPU(NACp) / 2.448, 5 m)` per axis (NACp being the smallest seen in the
//!    window in an operational status (TC 31) of the address, else `max(Rc(TC) / 2.448, 5 m)` with
//!    the containment radius of the type code taken at its worst; of an address's messages, the
//!    widest). A message whose prior would exceed 100 m is not used. Each message's own
//!    horizontal prior is 3 m per axis about the decoded position plus the bias (GNSS noise, the
//!    CPR resolution, latency). Taking the declared accuracy as each message's own independent
//!    error instead would average a constant error away and understate the clocks' uncertainty.
//! 6. Its vertical prior is 15 m about the reported altitude plus the aircraft's vertical bias,
//!    one parameter per address and altitude kind: 100 m for a barometric altitude (pressure
//!    against height), 1.5 times the horizontal prior for a GNSS height.
//! 7. An event is a sync message with its receptions; a reception by a receiver more than 600 km
//!    from the prior is dropped; an event in which one receiver key appears twice is dropped; an
//!    event needs two receptions.
//!
//! ## Clocks, the gauge and the knots
//!
//! A clock ([`clock::ClockKey`]) is (receiver, counter epoch, piece), the piece counting the
//! declared jumps before it. Clocks are connected when they share an event. The fit takes the
//! connected component holding the most members of the tile, ties to the component whose lowest
//! clock key is lowest. Its gauge is its lowest-keyed GNSS-disciplined clock, else its
//! lowest-keyed clock. The gauge's anchor is its earliest sync reception's linear count.
//!
//! Every clock's knot 0 (its `base`) is the gauge's anchor mapped into its counts: the gauge's is
//! the anchor; then, repeatedly, the unmapped clock of lowest key that shares an event with a
//! mapped one takes it from the mapped one it shares most events with (ties to the lowest key), as
//! the lower median over their shared events of `x_j - counts_j(elapsed_i(x_i - base_i))` (each
//! clock's linear count, integers). Knot `k` of a clock sits at `base + k` 5 s of its nominal
//! counts; its knots run from the interval of its earliest to one past the interval of its
//! latest sync reception. A clock's offset (from the gauge) is continuous and piecewise linear
//! between its knots: model time at linear count `x` is `e + o_k + (o_{k+1} - o_k) u / 5 s`,
//! `e` the nominal picoseconds since knot 0, `k = floor(e / 5 s)`, `u = e - 5 s k`. The gauge's
//! offsets are zero, and that time `t` (the gauge's nominal time from its anchor) is made model
//! time by one more parameter, the gauge's rate `r`: model time is `t (1 + r)`. A free-running
//! gauge's counter is off its nominal frequency (tens of ppm); without `r` every time difference
//! under the model would carry that error (30 ppm of a 2 ms spread is 60 ns, 18 m). It is seen
//! through the sync ranges: an event's arrival differences are known distances. Because the
//! offset is continuous, so is its uncertainty: there is no step at a knot.
//!
//! An event is used when its receptions on the component's clocks are at least two and their
//! intervals are within one of each other, so an event couples knots at most two apart.
//!
//! ## The least-squares problem
//!
//! Unknowns: every non-gauge knot's offset; the gauge's rate; every sync aircraft's biases; every
//! event's transmit time `T` and position `X`. Rows, each weighted by the inverse of its variance:
//!
//! - a reception: `t + r (t - t_e) - T - |X - site| / c`, `t` the clock's time and `t_e` the
//!   nominal time of the event's first reception (so the rate's column is a time difference
//!   within the event, and `T` absorbs `r t_e` exactly), with the clock's timing noise plus its
//!   site variance (a clock's noise starts from its residuals' robust scale, and is 500 ns for any
//!   clock, whatever it declares, until its receptions estimate it);
//! - an event's position prior: east and north of the decoded position plus the aircraft's
//!   horizontal bias, and up about the reported altitude plus its vertical bias;
//! - curvature: every clock, the gauge too, wanders as an integrated random walk whose second
//!   difference over consecutive knots has standard deviation
//!   `sqrt((rate noise x 5 s)^2 + 2 phase noise^2)` (rate 0.005 ppm and phase 10 ns per interval
//!   for 12 MHz, 0.0005 ppm and 5 ns for GPS: 28.7 ns and 7.5 ns). An offset is from the gauge,
//!   so at each knot the second differences of the offsets there are jointly normal with
//!   covariance `diag(sigma_j^2) + sigma_gauge^2 1 1ᵀ`, entered by its exact precision
//!   (Sherman-Morrison);
//! - each clock's first interval's rate: 0 with 200 ppm; the gauge's rate: 0 with 200 ppm when it
//!   runs free, 0.001 ppm when it is GNSS-disciplined;
//! - each bias: 0 with its prior (§ Sync events).
//!
//! Nothing ties a GNSS-disciplined clock to the gauge's stamps: its offset and rate are fitted
//! from the sync events as any clock's are, and its discipline shows only as its timebase's
//! tighter curvature. A declaration is the feeder's word, not a measurement. Version 3 held every
//! disciplined clock to the stamp difference with 100 ns and its rate with 0.001 ppm; over real
//! receivers (LocaRDS, RFC-0171 §3.8.1) a GRX1090 stamps 120.6 µs after a Radarcape (the end of a
//! long message, not its start), some Radarcapes declaring GPS run without a lock (one 0.7 s off
//! and drifting 0.09 ppm, three with stamps jittering by hundreds of microseconds), and holding
//! them to the gauge made half of all fits there singular; when such a receiver was the gauge,
//! every honest GNSS clock of the tile was held to it.
//!
//! It is solved by Gauss-Newton. Each event's four parameters are eliminated by Schur complement;
//! the reduced system is block-banded: one block per knot (time slice), every clock's offset at
//! that knot in key order, coupled to the two knots either side, with the gauge's rate and the
//! biases (rate first, then by address and kind) as a dense border last ([`banded`]). It is
//! factored by block Cholesky in that order (slices first to last, then the border; a border
//! eliminated earlier would fill the band; only the lower triangle a factorisation reads is
//! formed), and the event parameters
//! are recovered by back-substitution. Covariances are taken from the selected inverse (Takahashi's
//! recurrence over the factor's pattern: the band and the border), never the full inverse. Every
//! loop runs in one fixed order, with no fused multiply-add and no choice of instructions at run
//! time, and the transcendental functions are `libm`'s, so results are identical to the bit on
//! every platform (a test holds a model's bytes to a committed golden made on x86).
//!
//! ## Robustness, jumps and noise
//!
//! A round is one robust step and two Huber steps (`k = 3`). The robust step starts from each
//! event settled on its own at the starting clocks (as a published model's are), takes each
//! clock's scale as 1.4826 times the median absolute residual of its receptions there (at least
//! its nominal noise), and weighs every reception as the final steps do against that scale: one
//! beyond 10 of them carries no weight, so a reception of another transmission of the same bytes
//! seconds away costs its event, never the fit. Then each clock's reception
//! residuals in linear-count order are scanned: at every split with at least 5 receptions on each
//! side (and distinct counts across it), the step is the median of the 5 after minus the median
//! of the 5 before, in standard deviations of the clock's own robust noise (1.4826 times the
//! median absolute consecutive difference of its residuals, over the square root of two: a jump
//! moves one difference only, so a jump cannot hide itself; floored at 10 ns with its site); the
//! largest, if above 8, is a jump: the epoch is split at the first reception after it into a new
//! piece, and the fit starts over. Against the nominal noise instead, a dump1090-class clock's
//! 500 ns would raise false jumps over a window's hundred splits on 48 clocks nearly surely. A
//! fit declares at most 4 jumps; a fifth drops the clock with the most (this one counted, ties
//! to the lowest key) from the tile, its jumps with it, and the fit goes on without it: one bad
//! receiver costs the tile that receiver, never the tile. Dropped clocks are published.
//!
//! The same holds for a clock nothing places: before each system is factored, a clock other than
//! the gauge none of whose receptions carries weight in an event whose own parameters are
//! determined (every one beyond the cut-off, or in events left with none) has a free offset, so
//! the system is singular. Every such clock is dropped from the tile (its whole epoch, as for
//! jumps), its jumps with it, and the fit starts over; each pass drops at least one, so it ends.
//! Over real receivers this is a receiver whose stamps agree with nothing (OpenSky's data has
//! several), or one left with no event usable against the rest.
//!
//! And a group: two clocks are joined when both carry weight in one such event (an event's
//! transmit time absorbs any level its receptions share, so a reception alone with weight in its
//! event places nothing). When robust weights split the clocks into more than one joined group,
//! each group but one has its level free against the gauge, and every clock of each such group
//! is dropped as above (`FitError::Disconnected`, distinct from `FitError::Uninformed`, and never
//! `FitError::Singular`): the group kept is the one holding the most receivers, ties to the
//! gauge's, then to the one whose lowest clock key is lowest; when the gauge's group is not kept,
//! the next pass takes its gauge from what is left.
//!
//! Then the noise: each clock starts from its residuals' robust scale (1.4826 times their median
//! absolute value), then rounds of a final-weighted step and an estimate, at least two, until no
//! clock's estimate moves by more than 5%, at most three: each clock with at least 20 receptions
//! of weight above zero (weights 1 to 3 sigma, `3 / z` to 10 sigma, 0 beyond) gets
//! `sum r^2 / sum (1 - h)` over them, `h` the reception's exact leverage in that step (through
//! the event's own block and the selected inverse), less its site variance, floored at 10 ns,
//! and raised by half its standard error (the variance times `1 + 0.5 sqrt(2 / sum (1 - h))`: an
//! estimate from a few dozen receptions is low as often as high, and a low one makes every
//! solution through it overconfident; measured, none left coverage at 0.936, a whole standard
//! error 0.967, half 0.953). Then final steps: at least two, until one moves the estimate by at
//! most 10^-6 squared standard deviations (its squared Mahalanobis length), at most twelve. The
//! scan is made again at the final estimate: a jump there is split too and the fit starts over.
//! The published (rounded) model's events are then settled from their priors as a verifier will
//! (§ Output), and while the step there is not negligible the final steps go on from it (at most
//! three times). The scan is made a last time there, at the estimate a verifier scans: a jump only
//! the settled events show (a clock whose stamps are noise can) is split and the fit starts over.
//! And where the noise the rule estimates at the published estimate is more than
//! 12.5% above a clock's published noise, the noise is taken from there and the final steps run
//! again (at most twice). The step at the published estimate is the model's calibration: its
//! factor's selected inverse is what solving under it needs, so an engine never forms it again.
//! Each pass starts from the event priors and zero clocks; each step from where the last ended.
//!
//! ## Output
//!
//! A [`ClockModel`]: the tile, the window, the members as their receivers signed their sites,
//! the input citation, the gauge, the origin, per clock its timebase, piece boundaries, site,
//! noise, knot 0 and knots, each knot's offset rounded to the picosecond; the gauge's rate in
//! parts per 10^15; each bias rounded to the millimetre; the jumps; the dropped clocks. [`ClockModel::time`] applies the rate in
//! integers: `t + floor(t r / 10^15)`. No covariance: whoever solves under the model forms the normal
//! equations once at its estimate from the raw it cites ([`sync::calibrate`]) and takes the
//! covariance from their factorisation. Each event's transmit time and position there are its own
//! optimum with the clocks and biases held: from its prior position and the lower median of its
//! receptions' model times less their ranges, three Huber-weighted and eight final-weighted
//! Gauss-Newton steps of its four parameters.
//!
//! Model time zero is a Unix time (`origin`), from the wall clock of the gauge's anchor: the least,
//! over the receptions of the gauge's clock (its piece) the inputs cite, of its batch's wall clock (milliseconds,
//! as nanoseconds) less the gauge's nominal time from the anchor to it (a batch is signed after
//! what it carries, so this is the latest the anchor can have been heard). For a GNSS-disciplined
//! gauge, model time zero is its anchor (nanoseconds of the UTC day) on the day that lies within
//! half a day of that wall clock; for a free-running gauge, that wall clock itself.
//!
//! # Grouping ([`group::group`])
//!
//! A reception maps to model time ([`ClockModel::time`]), or to nothing outside its clock's knots.
//! Receptions are partitioned by message bytes, sorted by (model time, identity), and clustered:
//! a reception joins the open cluster when it is at most 3 ms after the cluster's first. A cluster
//! in which a receiver appears twice is ambiguous and not solved.
//!
//! # Solving ([`solve::solve`])
//!
//! 1. Screen (integer): a pair is feasible when
//!    `|t_i - t_j| [ps] * 299792458 <= (baseline [mm] + 10^6) * 10^9`, the baseline being the
//!    floored integer square root of the squared millimetre difference of the stored sites.
//!    While a pair is infeasible, remove the reception in the most infeasible pairs, ties to the
//!    lowest identity.
//! 2. The measurements are `z_i = c * (t_i - t_min)`; their covariance is each clock's noise plus
//!    site variance on the diagonal plus `c^2 G Σ Gᵀ`, `G_i` the reception's two interpolation
//!    weights over its interval's knots and `Σ` the model's covariance (from the selected
//!    inverse, which holds every pair of knots a transmission's receptions touch): the clock error
//!    is propagated jointly, never as independent variances, the gauge rate's part with its lever
//!    `t_i - t_min`. Residuals are whitened by its
//!    Cholesky factor. The message's own altitude (AC13, or a DF17 airborne position's) is a
//!    pseudo-measurement of height above the ellipsoid with 100 m (barometric) or 15 m (GNSS).
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
//!    verifier evaluate this one limit, and a solution leaves the engine only through
//!    [`publish::solve_published`], which reads it back from its wire bytes and runs the
//!    verifier on it: nothing is published that a verifier holding the same raw would refuse.
//! 6. The covariance of (X, T) is the inverse of the whitened `J^T J` at the solution. The
//!    published position covariance is its 3x3 ECEF block with its standard deviations times
//!    1.1, plus 5 m squared on each axis (`solve::ERROR_INFLATION`, `ERROR_FLOOR_M`): the
//!    simulator calibrates the mathematics without them (the calibration tests strip them), but
//!    real receivers carry what it does not model (tropospheric delay differences of a metre or
//!    two between sites, antenna phase centres off their declared sites, multipath), so a fix
//!    claims a little less than the mathematics alone. The calibration over real receivers
//!    (RFC-0171 §3.8.1, `tally-mlat-calibrate`) finds the mathematics honest where receivers and
//!    truth are what they say (0.94 to 0.97) and short with unverified crowdsourced receivers
//!    (0.895), not uniformly, so it leaves these as they are. A fix whose standard deviation on any axis would exceed 1.5 km is
//!    not published: there the Gaussian no longer describes the error (a transmission with no
//!    altitude over a flat network leaves the height nearly free; measured, a DF11 6 km below its
//!    aircraft at 58 squared standard deviations).
//!
//! # Verifying a model ([`verify::verify_model`])
//!
//! Given the model and the verifier's own raw, rebuilt into the inputs of the model's tile and
//! window (its members from the footprint, § Tiles): the tile, window, members (keys and signed
//! sites) and input citation must be exactly the raw's; the clocks, gauge, knot 0s, knot ranges,
//! sites and origin must be what the rules above derive (with the model's declared jumps and
//! dropped clocks); at the model's estimate, the Gauss-Newton step
//! under the final weights the estimate itself gives (the robust weights' fixed point) must have
//! squared Mahalanobis length at most 10^-4; no clock's noise may be more than 25% below the
//! rule's estimate there (understated noise makes every solution under the model overconfident;
//! overstated only makes them conservative, and is not refused); and no clock's residuals may
//! step by more than 8.05 of its robust standard deviations where no jump is declared. A model
//! that passes is calibrated by the same factorisation, which solving and verifying solutions
//! under it use.
//!
//! # Verifying a solution ([`verify::verify`])
//!
//! Given the claim, every candidate reception of the message, and the calibrated model: the cited
//! identities must be sorted, known, exactly inside one regrouped transmission, at least the
//! minimum, and pass the screen; the chi-square at the claimed (X, T) must pass step 5; the
//! Gauss-Newton step from the claim must have squared Mahalanobis length at most 10^-4; the
//! claimed covariance must match the recomputed (published) one within 10^-3 relative
//! (Frobenius); every cited reception must have `z <= 5.05` and every screened omitted one
//! `z >= 4.95`. And the tile ([`verify::verify_assignment`]): the solution's addressed citation
//! must be the verifier's raw's (else it does not hold what chose the tile, and cannot say), and
//! the assignment rule on that raw must give the model's tile.
//!
//! # Publishing ([`publish`])
//!
//! The encoding, every integer big-endian:
//!
//! ```text
//! tile level u8 | tile cube x, y, z i64 | window first i64 | window last i64
//! | scope count u16 | count x (key [32], clock u8, site id [32], lat_e7 i32, lon_e7 i32,
//!                              alt_m i32, precision_m u32)             strictly ascending by key
//! | input citation hash [32] | count u32
//! | gauge clock | origin unix ns u64 | gauge rate i64 (parts per 10^15)
//! | piece count u16 | count x piece                                    strictly ascending by clock
//! | bias count u16 | count x (address u32, kind u8, bias mm i64)       strictly ascending by
//!                                                                      (address, kind)
//!
//! kind = 0 east | 1 north | 2 barometric | 3 GNSS height
//! | jump count u16 | count x (receiver key [32], epoch u32, at i64, step ps i64)   ascending
//! | dropped count u16 | count x (receiver key [32], epoch u32)                     ascending
//!
//! clock = receiver key [32] | epoch u32 | piece u16
//! piece = clock | timebase u8 (0 12 MHz, 1 GPS nanoseconds)
//!       | begins i64 | ends i64 (i64::MIN for none) | site x, y, z i64 mm | site sigma i64 mm
//!       | noise i64 ps | base i64 | first knot i32 | knot count u16 (>= 2) | count x offset i64 ps
//! ```
//!
//! A reader refuses anything not in this one form, so a model read back encodes to the same
//! bytes. A tile's model is a few kilobytes (about 2 KB at 10 members, under 15 KB at 48): it
//! fits its manifest.
//! The model's inputs id ([`publish::inputs_id`], carried by the manifest) is BLAKE2s-256 over
//! `"tally clock model inputs id" 0x00`, the specification version (two bytes) and the encoding's
//! first part (tile to input citation) with each scope entry as key, clock, site id and
//! precision only: no site. Consumers merge by it, never by model bytes; the
//! reference engine publishes the same bytes for one inputs id, but two models of one inputs id
//! that differ are no fault (§ What verification means).
//!
//! **A model is relay-only; a client is sent its summary** (wire version 3). A scope entry's site,
//! a piece's `site_mm` and its offsets, with the aircraft's published positions, give every
//! receiver's site, and a receiver's exact site is never readable by a client. The site id
//! (`tally_wire::SiteId`) names the site-bearing record the engine placed the receiver by (its
//! `ReceiverSite`, or an old feeder's format 1 `ReceiverInfo`) without revealing it, and enters
//! only the inputs id. Beside each model the engine signs a `tally_wire::ClientClockModel`
//! ([`publish::client_model`]): the model's id, its inputs id and its window, and nothing of its
//! scope, since a tile's members are chosen by their exact sites (the tile's sphere and the
//! farthest-point choice) and the tiles a receiver is in, over time, narrow its site. A client is sent
//! that and tagged solutions (`tally_wire::TaggedSolution`, each reception its `ReceptionTag` under
//! the receiver's relay-only `ReceptionKey`); a relay keeps the model and the raw solutions, and
//! rematches a tagged solution against the raw it holds ([`publish::rematch`]).
//!
//! A solution on the wire ([`publish::to_wire`]) carries its transmit time as the origin plus its
//! model time, in Unix picoseconds; latitude and longitude rounded to 10^-7 degree; height above
//! the ellipsoid rounded to the millimetre; the covariance rotated to east, north, up at the
//! solution, as binary32. A verifier rebuilds the claim from it ([`publish::claim`]): position
//! and transmit time read back, the covariance rotated back, the degrees of freedom from the count
//! and the message's altitude. Those roundings move the claim far less than the verifier's
//! tolerances; a nanosecond would not (half of one is 15 cm of light travel, beyond the optimality
//! bound for a well-observed transmission).
//!
//! # Provisional solutions ([`clock::Reach`])
//!
//! A final solution is published when its window is (7 to 47 s after its transmission at `s = 8`).
//! A provisional one is solved about a second after the transmission, under an older model of a
//! tile holding its receivers, carried past its knots, and is superseded by the final one. It is
//! the same mathematics with one change, so it is a deterministic function of its model, its
//! receptions and the spec as a final one is, and is verified and proved faulty the same way:
//!
//! 1. **Mapping** ([`ClockModel::time_reach`] with [`Reach::Carried`]): a count past the last knot
//!    `L` of its epoch's last piece (a piece that ends at a jump is never carried), by at most
//!    `MAX_CARRY_PS = 90 s` of nominal time, takes the piece's last interval `k = L - 1`, and
//!    model time is that interval's line extended: `t = e + o_k + floor((o_L - o_k) u / 5 s)` with
//!    `u = e - 5 s k` past 5 s, then the gauge's rate as always. Inside the knots it is `time`
//!    exactly. 90 s covers the longest a tile's newest model is behind a reception it maps: the
//!    stride and the window's last bins (45 s at `s = 8`), the settling before the window is
//!    solved (11.5 s), the ripening before its model is used (15 s), how far a reception may run
//!    ahead (7.5 s) and a bin of rounding (5 s), 84 s in all (asserted in `tally_mlat::engine`).
//! 2. **Covariance**: the clock covariance of two receptions is the model's (the last interval's
//!    two knots' weights, now `1 - f` and `f` with `f > 1`, so the line's slope error grows with
//!    the carry) plus the curvature prior's integrated random walk past the last knot. With `n`
//!    knot intervals carried (fractional, `carried / 5 s`) and second differences of standard
//!    deviation `sigma` (§ The least-squares problem: 28.7 ns for 12 MHz, 7.5 ns for GPS), a
//!    clock's offset `n` intervals on is off the line by `sum_{j <= n} (n - j + 1) d_j`, so two
//!    receptions of one clock carried `m <= M` covary by
//!    `sigma^2 (m (m + 1) (2m + 1) / 6 + (M - m) m (m + 1) / 2)`. An offset is from the gauge,
//!    whose own walk moves every other clock alike: every pair of receptions on clocks other than
//!    the gauge adds that term with the gauge's `sigma`, a pair on one clock its own as well, and a
//!    reception on the gauge nothing.
//! 3. **Grouping, solving, the floor and inflation and the 1.5 km cap** are as for a final one
//!    ([`group_reach`], [`solve()`]); a fix whose carried covariance passes 1.5 km a side is not
//!    published.
//! 4. **Verifying** ([`verify_reach`] with `Reach::Carried`): as a final solution, against the
//!    receptions it was solved from (a provisional is solved from what had arrived a second after
//!    the transmission, so omission is judged among those); no assignment is checked (a
//!    provisional names none: its engine solves it under the newest model holding the most of its
//!    receivers). Two signed solutions of one observation set, model and spec, provisional or
//!    final, that disagree beyond tolerance are a fault: where the model reaches every reception
//!    both map alike.
//!
//! Measured over the simulator (six 170 s scenarios, the default clock mix, each window's models
//! carried over the replies after it, one an aircraft a second): with the floor and inflation
//! stripped the truth is inside the 95% ellipsoid for 0.940 carried up to 20 s, 0.947 from 20 to
//! 45 s and 0.975 from 45 to 90 s (0.956 of 5,076 overall; 0.982 published), for median
//! horizontal errors of 124, 237 and 468 m. The carry costs precision, not honesty.

// It reaches keys (`tally_wire::Identity`): no `unsafe` code at all, forbidden, so no module
// can allow it.
#![forbid(unsafe_code)]
// Matrix code reads as the algebra it implements: index loops over rows and columns.
#![allow(clippy::needless_range_loop)]

pub mod arrived;
pub mod banded;
pub mod clock;
pub mod gate;
pub mod geo;
pub mod group;
pub mod held;
pub mod linalg;
pub mod modes;
pub mod obs;
pub mod publish;
pub mod scope;
pub mod sim;
pub mod solve;
pub mod standing;
pub mod sync;
pub mod threshold;
pub mod tile;
pub mod verify;

pub use arrived::{Admitted, Arrived, BatchId, Considered, HELD_MS, TransmissionKey};
pub use clock::{ClockKey, ClockModel, MAX_CARRY_PS, Reach, SPEC_VERSION, Timebase};
pub use group::{Grouping, Transmission, group, group_reach};
pub use obs::{ObservationId, Reception, Site};
pub use publish::{PublishError, Unpublished, solve_fix, solve_published};
pub use scope::{
    Assignment, Citation, Frontier, Inputs, Sites, Trailing, TrailingInputs, Window, WindowIndex,
};
pub use solve::{Solution, SolveError};
pub use sync::{Assessment, Calibrated, FitError, calibrate, fit, fit_calibrated, fit_trailing};
pub use threshold::{KEPT_KEEP, PAIR_KEEP, REFERENCE_KEEP, SYNC_KEEP, Threshold, sync_key};
pub use tile::Tile;
pub use verify::{
    Failure, ModelFailure, ModelVerdict, Verdict, judges, verify, verify_assignment, verify_fix,
    verify_model, verify_reach, verify_trailing_model,
};

#[cfg(test)]
mod tests;
