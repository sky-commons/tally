//! The native MLAT's calibration over real receivers (RFC-0171 §3.8.1, §10 step 7): an open
//! dataset of real receptions replayed through the engine a relay hosts, with a sample of ADS-B
//! aircraft withheld, each of their transmissions solved as an MLAT target and scored against the
//! aircraft's own report of where it was.
//!
//! # The dataset
//!
//! LocaRDS (Strohmeier, Schäfer, Pinheiro, Lenders, Martinovic, "LocaRDS: A Localization
//! Reference Data Set", Sensors 2021), the OpenSky Network's reference set for aircraft
//! localization and the base of its 2020 Aircraft Localization Competition: eight one-hour subsets
//! of real receptions over Europe, each row an ADS-B airborne position heard by two or more of
//! some 320 crowdsourced sensors, with every sensor's own nanosecond timestamp, the sensors'
//! declared sites and types, and the decoded position as truth. CC BY-SA 4.0. Zenodo
//! 10.5281/zenodo.4739276; `fetch.sh` downloads a subset and checks it. What a row holds is
//! `locards`'.
//!
//! # The mapping (`mapping`)
//!
//! LocaRDS carries timestamps and decoded positions, not the messages, so each reception is
//! given the Mode S message a feeder would have sent, and its timestamp the raw counter:
//!
//! - **Receivers.** Every sensor with a location (not 0, 0) is a feeder, described at the start
//!   with its declared site, exact (precision 0, as an owner's survey is declared). OpenSky's
//!   heights are as their owners entered them, often 0, and are used as given: a wrong height is
//!   the engine's problem in the field too. `--good-sensors` keeps only those LocaRDS verified.
//! - **Clocks.** A sensor's class is read from its hour of stamps (`mapping::Survey`): GNSS when
//!   at least 99.9% of them lie within -1 to 5 s of the server's arrival time and they are not on
//!   the 12 MHz grid, otherwise free-running. (Radarcapes and GRX1090s with GPS put whole
//!   nanoseconds of a common UTC scale; dump1090s put their 12 MHz counts as nanoseconds, aligned
//!   by OpenSky to an offset of its own, which drifts.) A GNSS stamp becomes a Radarcape GPS
//!   counter (seconds of the day above nanoseconds) and the receiver declares
//!   `Clock::RadarcapeGps`; a free stamp becomes a 12 MHz count, `(ns + 10^12) * 0.012` rounded,
//!   which is the dump1090 count again (up to a constant), and declares `Clock::Dump1090`. OpenSky
//!   unwrapped the counters' overflows; where it got one wrong the counter jumps, and the engine
//!   meets that as it would meet a real one.
//! - **Sync aircraft.** A report of an aircraft not withheld is a DF17 airborne position, type
//!   code 11 (barometric; NIC 8, what most airliners send), its position the dataset's decoded one
//!   CPR-encoded again, even and odd alternating, its altitude the barometric one to 25 ft. No
//!   operational status is sent unless `--nacp` says what to declare: LocaRDS does not say, so by
//!   default the engine takes the type code's containment radius at its worst (185 m, a 76 m prior
//!   a side), as it does for an aircraft whose status it has not heard.
//! - **Withheld aircraft** (one in `--withhold` by hash of the LocaRDS id, all hour): every report
//!   is sent as a Mode S reply instead (DF4 with the barometric altitude as AC13, or DF11 with no
//!   altitude under `--reply df11`), so the aircraft has no ADS-B position anywhere and is an MLAT
//!   target, solved exactly as a target is. Its reports are the truth: latitude and longitude,
//!   and the GNSS height for 3D. Addresses are `0x400000` plus the LocaRDS id (the dataset hides
//!   the real ones).
//! - **Feeding.** Each sensor seals a batch once a second at a phase of its own and its batch
//!   reaches the engine 40 to 250 ms later, as `tally_mlat::replay` does for the simulator; a
//!   reception's arrival at the feeder is the row's `timeAtServer`. The engine is
//!   `tally_mlat::engine::Engine` with the relay's settings (settle 2 s), stepped and asked for
//!   provisional work every 100 ms of a virtual clock: every model and solution it publishes went
//!   through `publish::solve_published` and the verifier, as on a relay.
//!
//! ## What it does and does not test
//!
//! It tests the clock model, the solver, the covariance and the provisional carry on real
//! receivers: real sites (with their survey errors), real timing noise, real oscillators drifting
//! and stepping, real multipath, real geometry and real reception patterns, against a truth that
//! is the aircraft's own GNSS. It does not test decoding real bytes or Mode S replies' own
//! reception (the replies here are ADS-B squitters' timings: the same 1090 MHz pulses, but real
//! replies come at interrogators' rates, not ADS-B's 2 Hz), operational status (unless
//! `--nacp`), real feeders' batching, or OpenSky's preprocessing (its deduplication, its
//! unwrapping, and the internet delay in `timeAtServer`) as distinct from the receivers.
//!
//! # The truth's own error (`reference`)
//!
//! The truth is each aircraft's own ADS-B report, and it is off by about as much as the fixes
//! are. A textbook solver that needs no clock model (`reference`: the receptions of LocaRDS-verified
//! GNSS Radarcapes alone, 70 ns each, the report's GNSS height as a 15 m pseudo-measurement), whose
//! residuals fit their noise (a median chi-square per degree of freedom of 0.63 over 214,000 fixes,
//! where 0.45 to 0.69 is expected), covers the reported position 0.47 of the time: the report lags
//! the aircraft along its track by a median 32 m (an ADS-B position some tenths of a second old)
//! and scatters by more than its NACp would say. So every fix is also judged against the truth
//! widened by what the reference shows (`score::TruthModel`): the median lag taken off along the
//! track, and the least standard deviations along (118 m) and across (39 m) the track for which
//! the reference's own 95% intervals hold the truth 95% of the time; judged so, the reference
//! covers 0.947. A fix whose covariance is honest covers as the reference does. The model is
//! Gaussian where the truth's error is not, so this says within a few points, not to the third
//! decimal, and across the track alone (one degree of freedom, raw truth) is reported beside it.
//!
//! # What is measured (`score`)
//!
//! Every final and provisional solution of a withheld transmission is scored against its truth in
//! its own east-north-up frame: against the truth model (above); and against the raw truth, inside
//! the 95% ellipse of the east-north block (horizontal, two degrees of freedom), across the track
//! alone, and inside the 95% ellipsoid (3D, with the GNSS height), each under the mathematics' own
//! covariance (floor and inflation stripped, what the simulator's calibration measures) and under
//! the published one; the horizontal error's median and 95th percentile and the along-track
//! error's median; overall, for the aircraft LocaRDS verified, by altitude band, by receptions
//! used, by tile level and by how many of the receivers used are GNSS-disciplined. The solved
//! fraction is over (aircraft, bin) pairs, the bin the engine's own (the lower median of the
//! receptions' wall clocks), with a transmission heard by three or more receivers after the first
//! 65 s. `--samples` writes every scored solution for analysis; `--unverified-precision` has the
//! sensors LocaRDS did not verify declare their sites to that precision.

// Matrix code reads as the algebra it implements: index loops over rows and columns.
#![allow(clippy::needless_range_loop)]

pub mod locards;
pub mod mapping;
pub mod reference;
pub mod run;
pub mod score;

pub use run::{Outcome, Settings, run};
