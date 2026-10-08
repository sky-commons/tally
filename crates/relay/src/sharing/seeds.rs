//! Fixed seeding (RFC-0174 §2.5): a source sends each record into its cell's group once, to the
//! seed of the record's stripe, however many members want it, so a popular area never raises its
//! sources' upload. One copy is what the striping needs: the stream is cut into `DATA_STRIPES`
//! stripes, each entering at its own seed, and the parity stripe beside them rebuilds any one
//! stripe whose seed or parent failed, with no second copy and no round trip. A source therefore
//! sends [`SEED_COPIES`] copy of its stream plus the parity, [`seeded_bytes`] in all. The seeds are the stripes' roots (`stripes`): one per stripe, each an interior
//! candidate of its stripe and so a different member for each stripe, `min(STRIPES, members)` in
//! all. They rotate every [`SEED_ROTATION_SECONDS`] by a rendezvous over (cell, product, stripe,
//! epoch, key), so anyone holding the members can check who a seed must be ([`is_seed`]).

use tally_wire::{PublicKey, Region, Streams};

use super::stripes::{DATA_STRIPES, Layout, STRIPES};

/// How long one set of seeds lasts.
pub const SEED_ROTATION_SECONDS: u64 = 60;

/// How many distinct seeds a source sends a cell's product to: one per stripe, so the stream
/// enters the group once, cut, whatever the group's size (fewer in a group with fewer members).
pub const SEEDS: usize = STRIPES as usize;

/// The copies of its stream a source sends into its group: one, cut into the data stripes, the
/// parity stripe beside it standing in for a second copy (see the module).
pub const SEED_COPIES: usize = 1;

/// What a source sends into its group for `stream_bytes` of its own stream: [`SEED_COPIES`]
/// copies and the parity stripe, one stripe's worth (`STRIPES / DATA_STRIPES` of the stream).
/// What hosting a feeder costs a relay and gives the network (`credit::FEEDER_CREDIT`).
pub const fn seeded_bytes(stream_bytes: u64) -> u64 {
    stream_bytes * SEED_COPIES as u64 * STRIPES as u64 / DATA_STRIPES as u64
}

/// The rotation epoch of a second.
pub fn epoch_of(second: u64) -> u64 {
    second / SEED_ROTATION_SECONDS
}

/// Each stripe's seed for records of `second`, as (stripe, seed); a stripe with no member has
/// none.
pub fn seeds(layout: &Layout, second: u64) -> Vec<(u8, PublicKey)> {
    let epoch = epoch_of(second);
    (0..STRIPES)
        .filter_map(|stripe| layout.seed(stripe, epoch).map(|seed| (stripe, seed)))
        .collect()
}

/// The members a source seeds a cell's product to in `second`, without repeats.
pub fn seed_members(
    cell: Region,
    product: Streams,
    members: &[PublicKey],
    second: u64,
) -> Vec<PublicKey> {
    let layout = Layout::new(cell, product, members, &[]);
    let mut keys: Vec<PublicKey> = seeds(&layout, second)
        .into_iter()
        .map(|(_, key)| key)
        .collect();
    keys.sort();
    keys.dedup();
    keys
}

/// Whether `claimed` is the seed of `stripe` for `second` over `members`.
pub fn is_seed(
    cell: Region,
    product: Streams,
    members: &[PublicKey],
    stripe: u8,
    second: u64,
    claimed: &PublicKey,
) -> bool {
    Layout::new(cell, product, members, &[]).seed(stripe, epoch_of(second)) == Some(*claimed)
}
