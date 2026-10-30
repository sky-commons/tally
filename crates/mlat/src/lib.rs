//! A Tally MLAT engine (RFC-0171 §3.8, §3.8.1 as amended 2026-10-24, "MLAT in seconds"), a library.
//! A relay hosts it for the areas it is an MLAT relay for (RFC-0174 §2.1, §2.3:
//! `tally_relay::mlat_host`, one program), fed the raw its own feeders and its neighbours pass it;
//! there is no engine program and no engine run on its own. It holds what has arrived of every
//! signed observation MLAT uses once however many paths delivered it, and once a second solves
//! every transmission whose first reception arrived a second and a tenth before, from the
//! receptions that had arrived: each owned area's pair model refit every `REFIT_EVERY` over its
//! trailing window of sync raw at the edge of the refit grid (`tally_mlat_solver` crate docs,
//! § Areas), each target taken up by the relays of the area most of its hearers are in and solved
//! under the models of its hearers' areas, every fix checked with the verifier anyone else would
//! use before it is published. It publishes a signed `ClockModel` (a pair model) per owned area and
//! refit, then `Positions` of fixes (format 7, and its tagged twin format 8, back to back) whose
//! every fix names the receptions it considered and those it used, the ids of the models it cites
//! (one per area of its used hearers) and the solver specification's version. The mathematics is
//! `tally_mlat_solver`'s; this crate is the engine around it.
//!
//! - `engine`: the state: the receivers, the arrived pool, each area's held models (its own and
//!   its neighbours', judged when a fix cites them), what was solved; one step a second.
//! - `intake`: the receivers, split by receiver (an engine holds one, a relay one per raw shard):
//!   who takes part, which batches are used, what each one holds.
//! - `fix`: what a step chooses, refits, solves and publishes, spread over threads, the same bytes
//!   on any number of them.
//! - `area`: what a relay hosting the engine holds for the areas it solves (RFC-0174 §2.3): each
//!   area's border band, the cells within the pair baseline of it, and which area's relays take a
//!   transmission up.
//! - `replay`: the engine driven over the simulator on a virtual clock, as a relay drives it.

// No `unsafe` at all, forbidden, so no module can allow it: the engine signs through a `Signer`
// (`tally_wire::Signs`), and nothing here can forge its way past wire's seal with a `transmute`.
#![forbid(unsafe_code)]

pub mod area;
pub mod engine;
pub mod fix;
pub mod intake;
pub mod replay;

/// The unit tests hold what the engine's tables are charged to what they really allocate, each
/// test on its own thread's count (`tally_counting::Counting`, test support outside every
/// production build).
#[cfg(test)]
#[global_allocator]
static COUNTING: tally_counting::Counting = tally_counting::Counting;
