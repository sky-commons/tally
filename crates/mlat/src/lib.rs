//! A Tally MLAT engine (RFC-0171 §3.8, §3.8.1), a library. A relay hosts it for the areas it is
//! an MLAT relay for (RFC-0174 §2.1, §2.3: `tally_relay::mlat_host`, one program), fed the raw its
//! own feeders and its neighbours pass it; there is no engine program and no engine run on its own.
//! It holds every signed observation MLAT uses once however many paths delivered it, and for every
//! window that is due assigns each MLAT target its canonical tile, fits each distinct tile's shared
//! clock model once (only a tile whose whole footprint its regions cover), solves the targets under
//! them, checks every one of its own solutions with the verifier anyone else would use before it
//! publishes it, and publishes a signed `ClockModel` per tile and window and `Positions` (format 3)
//! whose every solution names its observation set, the tile model it used, the aircraft's
//! receptions that chose the tile, and the solver specification's version. The mathematics is
//! `tally_mlat_solver`'s; this crate is the engine around it.
//!
//! - `engine`: the state: receivers, the held observations (sealed per bin), the windows solved;
//!   ingest and eviction by bin.
//! - `window`: one step, a pure function of what it is handed, run off the ingesting thread and
//!   spread over threads: the tiles fitted in parallel, then the targets solved in parallel.
//! - `provisional`: each target's transmissions solved about a second after they are heard, under
//!   the newest published model of a tile holding their receivers, carried forward; published as
//!   `Record::Provisional` and superseded by the final positions.
//! - `area`: what a relay hosting the engine holds for the areas it solves (RFC-0174 §2.3): each
//!   area's border band, derived from the tiles' footprints, and the one projection of a tile's
//!   centre into the area tree.
//! - `replay`: the engine driven over the simulator on a virtual clock, as a relay drives it.

pub mod area;
pub mod engine;
pub mod provisional;
pub mod replay;
pub mod window;
