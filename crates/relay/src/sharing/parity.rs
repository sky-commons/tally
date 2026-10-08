//! The parity stripe (RFC-0174 §2.5, churn): per origin and second, the XOR of the data stripes'
//! slices, so a member that lost any one stripe (its parent in it left or stopped forwarding)
//! rebuilds that stripe's records from the others with no round trip.
//!
//! One parity per origin manifest (an origin's records of one cell's product in one second). A
//! slice is the stripe's records of the manifest, in the manifest's
//! order (ascending hash), each as its encoded record (self-delimiting: a header and a length), end
//! to end. The parity is the slices XORed together, each padded with zeros to the longest, and
//! every slice's length. A rebuilt record is checked against the origin's signed manifest by its
//! own hash, so parity needs no signature: a wrong parity rebuilds nothing.

use tally_wire::batch::Hash;
use tally_wire::sharing::receipt_digest;
use tally_wire::{Record, Region, Streams};

use super::stripes::{DATA_STRIPES, data_stripe, domain_block};

const PARITY: &[u8] = b"tally sharing parity";

/// The parity of one origin manifest's records.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Parity {
    /// The hash of the origin's signed `PieceManifest` it covers.
    pub manifest: Hash,
    pub cell: Region,
    pub product: Streams,
    pub second: u64,
    /// Each data stripe's slice length.
    pub lens: [u32; DATA_STRIPES as usize],
    pub xor: Vec<u8>,
}

impl Parity {
    /// What names this parity: the manifest it covers, under a domain of its own.
    pub fn id(&self) -> Hash {
        id_of(&self.manifest)
    }

    /// The parity of the records one manifest lists (each with its hash, in any order).
    pub fn build(
        manifest: Hash,
        cell: Region,
        product: Streams,
        second: u64,
        pieces: &[(Hash, &[u8])],
    ) -> Self {
        let slices = slices(pieces);
        let longest = slices.iter().map(Vec::len).max().unwrap_or(0);
        let mut xor = vec![0u8; longest];
        for slice in &slices {
            for (out, byte) in xor.iter_mut().zip(slice) {
                *out ^= byte;
            }
        }
        let mut lens = [0u32; DATA_STRIPES as usize];
        for (len, slice) in lens.iter_mut().zip(&slices) {
            *len = u32::try_from(slice.len()).unwrap_or(u32::MAX);
        }
        Self {
            manifest,
            cell,
            product,
            second,
            lens,
            xor,
        }
    }

    /// The encoded records of stripe `missing`, rebuilt from the records of every other data
    /// stripe (each with its hash; exactly the manifest's, in any order). `None` when the
    /// lengths do not add up. The caller checks each record's hash against the manifest.
    pub fn rebuild(&self, missing: u8, others: &[(Hash, &[u8])]) -> Option<Vec<Vec<u8>>> {
        let len = usize::try_from(*self.lens.get(usize::from(missing))?).ok()?;
        let slices = slices(others);
        let mut slice = self.xor.clone();
        for (stripe, other) in slices.iter().enumerate() {
            if stripe == usize::from(missing) {
                if !other.is_empty() {
                    return None;
                }
                continue;
            }
            let expected = usize::try_from(self.lens[stripe]).ok()?;
            if other.len() != expected {
                return None;
            }
            for (out, byte) in slice.iter_mut().zip(other) {
                *out ^= byte;
            }
        }
        slice.truncate(len);
        if slice.len() != len {
            return None;
        }
        let mut records = Vec::new();
        let mut rest = slice.as_slice();
        while !rest.is_empty() {
            let (_, used) = Record::decode(rest).ok()?;
            if used == 0 || used > rest.len() {
                return None;
            }
            records.push(rest[..used].to_vec());
            rest = &rest[used..];
        }
        Some(records)
    }

    /// Its size on the wire, near enough, for accounting.
    pub fn len(&self) -> usize {
        32 + 8 + 1 + 8 + 4 * usize::from(DATA_STRIPES) + self.xor.len()
    }

    pub fn is_empty(&self) -> bool {
        self.xor.is_empty()
    }
}

/// The id of the parity of the manifest whose hash is `manifest`.
pub fn id_of(manifest: &Hash) -> Hash {
    receipt_digest(&[domain_block(PARITY), *manifest])
}

/// Each data stripe's slice of `pieces`.
fn slices(pieces: &[(Hash, &[u8])]) -> Vec<Vec<u8>> {
    let mut sorted: Vec<&(Hash, &[u8])> = pieces.iter().collect();
    sorted.sort_by_key(|(hash, _)| *hash);
    sorted.dedup_by_key(|(hash, _)| *hash);
    let mut slices = vec![Vec::new(); usize::from(DATA_STRIPES)];
    for (hash, bytes) in sorted {
        if let Some(slice) = slices.get_mut(usize::from(data_stripe(hash))) {
            slice.extend_from_slice(bytes);
        }
    }
    slices
}
