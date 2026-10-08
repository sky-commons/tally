//! Sharing groups (RFC-0174 §2.5): per area and product, the relays that take the area forward it
//! over striped trees. A stream is cut into stripes by record hash ([`stripe_of`]); a member asks
//! its parent for the stripes it takes (`StripeAssignment`), learns what each second holds from
//! the origin's signed `PieceManifest` (the hashes of the records of one cell, one product, one
//! second), says what it has (`HaveSummary`), and signs a `StripeReceipt` for each slice it
//! received: the evidence a relay's firehose credit is made of (§2.1).
//!
//! The stripes (`stripes_of`, 4 in `tally-relay`'s groups) count the parity stripe: the data
//! records are cut into the data stripes by `stripe_of(hash, data stripes)` (3), and the last
//! stripe carries `ParityChunk`s, the XOR of the data stripes' slices per origin manifest, so a
//! member that lost any one stripe rebuilds it without a round trip. A relay that offers a parent
//! cell as a bundle (§2.6) signs a `BundleIndex` per second: every child with the digest of the
//! origin manifests under it, so a bundle that leaves a child out is caught.

use blake2::{Blake2s256, Digest};

use crate::WireError;
use crate::batch::Hash;
use crate::directory::{MAX_STRIPES, check_stripes};
use crate::key::{KEY_LEN, PublicKey};
use crate::record::{Body, Streams};
use crate::region::Region;
use crate::signed::{Check, Checked, Fields, Unchecked, count_u16, read_count, signed_record};

/// The most record hashes one manifest names (it fits one record).
pub const MAX_PIECES: usize = 1_800;
/// The most seconds one have-summary covers.
pub const MAX_HAVE_SECONDS: usize = 512;
/// The most XOR bytes one parity chunk carries: a parity longer than this travels as several.
pub const MAX_PARITY_CHUNK: usize = 60 * 1024;
/// The most a parity may be in all (it is reassembled before it is used).
pub const MAX_PARITY_LEN: u32 = 16 << 20;
/// The most children a cell has in the H3 tree (a pentagon has six).
pub const MAX_CHILDREN: usize = 7;
/// The longest span one stripe receipt covers, in seconds. A receipt is for a few seconds' slice
/// (`tally-relay` signs one per 5 s window); an hour is far above that and keeps every rate a
/// reader derives from a receipt (bytes over [`StripeReceiptContent::seconds`]) over a span that
/// is at least one second and never wraps.
pub const MAX_RECEIPT_SPAN_SECONDS: u64 = 3_600;

/// A sharing record names one product: exactly one `Streams` bit.
fn check_one_product(product: Streams) -> Result<(), WireError> {
    if product.0.count_ones() != 1 {
        return Err(WireError::Invalid {
            field: "one product",
            value: u64::from(product.0),
        });
    }
    Ok(())
}

/// The stripe a record is in, of `stripes_of`: its hash's first four bytes, big-endian, modulo the
/// count. Every member computes the same, so the trees agree without asking.
pub fn stripe_of(record: &Hash, stripes_of: u8) -> u8 {
    let word = u32::from_be_bytes([record[0], record[1], record[2], record[3]]);
    (word % u32::from(stripes_of.clamp(1, MAX_STRIPES))) as u8
}

/// A member's request to its parent for some stripes of one cell's product (unsigned: it is the
/// session's). An empty `stripes` withdraws.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StripeAssignment {
    pub cell: Region,
    /// One product.
    pub product: Streams,
    pub stripes_of: u8,
    pub stripes: u32,
}

impl Check for StripeAssignment {
    /// One product, and stripes inside their count (none withdraws).
    fn check(&self) -> Result<(), WireError> {
        check_one_product(self.product)?;
        check_stripes(self.stripes_of, self.stripes)
    }
}

impl Fields for StripeAssignment {
    fn write(assignment: Checked<'_, Self>, out: &mut Vec<u8>) -> Result<(), WireError> {
        out.extend_from_slice(&assignment.cell.as_u64().to_be_bytes());
        assignment.product.write(out);
        out.push(assignment.stripes_of);
        out.extend_from_slice(&assignment.stripes.to_be_bytes());
        Ok(())
    }

    fn read(reader: &mut Body<'_>) -> Result<Unchecked<Self>, WireError> {
        Ok(Unchecked::new(Self {
            cell: Region::from_u64(reader.u64()?)?,
            product: Streams::read(reader)?,
            stripes_of: reader.u8()?,
            stripes: reader.u32()?,
        }))
    }
}

/// What one second of one cell's product holds, as its origin relay signs it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PieceManifestContent {
    pub cell: Region,
    pub product: Streams,
    /// Unix seconds, by the records' own signed wall clocks.
    pub second: u64,
    /// The records' hashes, ascending, without repeats.
    pub hashes: Vec<Hash>,
}

impl Check for PieceManifestContent {
    /// One product, and at most `MAX_PIECES` hashes, strictly ascending.
    fn check(&self) -> Result<(), WireError> {
        check_one_product(self.product)?;
        if self.hashes.len() > MAX_PIECES || self.hashes.windows(2).any(|pair| pair[0] >= pair[1]) {
            return Err(WireError::Invalid {
                field: "manifest order",
                value: self.hashes.len() as u64,
            });
        }
        Ok(())
    }
}

impl Fields for PieceManifestContent {
    fn write(manifest: Checked<'_, Self>, out: &mut Vec<u8>) -> Result<(), WireError> {
        out.extend_from_slice(&manifest.cell.as_u64().to_be_bytes());
        manifest.product.write(out);
        out.extend_from_slice(&manifest.second.to_be_bytes());
        count_u16(out, manifest.hashes.len(), MAX_PIECES)?;
        for hash in &manifest.hashes {
            out.extend_from_slice(hash);
        }
        Ok(())
    }

    fn read(reader: &mut Body<'_>) -> Result<Unchecked<Self>, WireError> {
        let cell = Region::from_u64(reader.u64()?)?;
        let product = Streams::read(reader)?;
        let second = reader.u64()?;
        let count = read_count(reader, MAX_PIECES)?;
        let hashes = (0..count)
            .map(|_| reader.array())
            .collect::<Result<Vec<Hash>, _>>()?;
        Ok(Unchecked::new(Self {
            cell,
            product,
            second,
            hashes,
        }))
    }
}

signed_record!(
    /// An origin relay's signed `PieceManifestContent`.
    PieceManifest,
    PieceManifestContent,
    b"tally piece manifest",
    1,
    1 + 32 + 8 + 2 + 8 + 2 + MAX_PIECES * 32 + 64
);

/// Which seconds of a cell's product a member holds whole (unsigned: the session's).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HaveSummary {
    pub cell: Region,
    pub product: Streams,
    pub first_second: u64,
    /// Bit `i` (of byte `i / 8`, most significant first): second `first_second + i` held whole.
    pub seconds: Vec<u8>,
}

impl HaveSummary {
    /// The second after the last it can name: `first_second` plus a bit a second.
    pub fn end_second(&self) -> u64 {
        self.first_second
            .saturating_add(self.seconds.len() as u64 * 8)
    }
}

impl Check for HaveSummary {
    /// One product, at most `MAX_HAVE_SECONDS` seconds, and none past `u64::MAX`.
    fn check(&self) -> Result<(), WireError> {
        check_one_product(self.product)?;
        let bits = self.seconds.len() as u64 * 8;
        if self.seconds.len() > MAX_HAVE_SECONDS / 8
            || self.first_second.checked_add(bits).is_none()
        {
            return Err(WireError::Invalid {
                field: "have summary span",
                value: self.first_second,
            });
        }
        Ok(())
    }
}

impl Fields for HaveSummary {
    fn write(have: Checked<'_, Self>, out: &mut Vec<u8>) -> Result<(), WireError> {
        out.extend_from_slice(&have.cell.as_u64().to_be_bytes());
        have.product.write(out);
        out.extend_from_slice(&have.first_second.to_be_bytes());
        count_u16(out, have.seconds.len(), MAX_HAVE_SECONDS / 8)?;
        out.extend_from_slice(&have.seconds);
        Ok(())
    }

    fn read(reader: &mut Body<'_>) -> Result<Unchecked<Self>, WireError> {
        let cell = Region::from_u64(reader.u64()?)?;
        let product = Streams::read(reader)?;
        let first_second = reader.u64()?;
        let count = read_count(reader, MAX_HAVE_SECONDS / 8)?;
        Ok(Unchecked::new(Self {
            cell,
            product,
            first_second,
            seconds: reader.bytes(count)?.to_vec(),
        }))
    }
}

/// A child's signed word that its parent delivered it one stripe's slice over some seconds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StripeReceiptContent {
    /// Who delivered.
    pub parent: PublicKey,
    pub cell: Region,
    pub product: Streams,
    pub stripe: u8,
    pub stripes_of: u8,
    pub first_second: u64,
    pub last_second: u64,
    /// Records received in the slice, and their bytes.
    pub records: u32,
    pub bytes: u64,
    /// [`receipt_digest`] of the records' hashes in the order received.
    pub digest: Hash,
    pub issued_ms: u64,
}

impl StripeReceiptContent {
    /// The seconds it covers, `first_second` to `last_second` inclusive: at least 1, and exact for
    /// a receipt that passed its check (at most `MAX_RECEIPT_SPAN_SECONDS`), so a rate over it
    /// never divides by zero. Saturating for a value built by hand that would not pass.
    pub fn seconds(&self) -> u64 {
        self.last_second
            .saturating_sub(self.first_second)
            .saturating_add(1)
    }
}

impl Check for StripeReceiptContent {
    /// One product; a stripe below its count, which is 1 to `MAX_STRIPES`; and a span ending no
    /// earlier than it starts, of at most `MAX_RECEIPT_SPAN_SECONDS`.
    fn check(&self) -> Result<(), WireError> {
        check_one_product(self.product)?;
        check_stripes(self.stripes_of, 0)?;
        if self.stripe >= self.stripes_of {
            return Err(WireError::Invalid {
                field: "receipt stripe",
                value: u64::from(self.stripe),
            });
        }
        let span = self
            .last_second
            .checked_sub(self.first_second)
            .and_then(|span| span.checked_add(1));
        if span.is_none_or(|span| span > MAX_RECEIPT_SPAN_SECONDS) {
            return Err(WireError::Invalid {
                field: "receipt span",
                value: self.last_second.wrapping_sub(self.first_second),
            });
        }
        Ok(())
    }
}

impl Fields for StripeReceiptContent {
    fn write(receipt: Checked<'_, Self>, out: &mut Vec<u8>) -> Result<(), WireError> {
        out.extend_from_slice(receipt.parent.as_bytes());
        out.extend_from_slice(&receipt.cell.as_u64().to_be_bytes());
        receipt.product.write(out);
        out.push(receipt.stripe);
        out.push(receipt.stripes_of);
        out.extend_from_slice(&receipt.first_second.to_be_bytes());
        out.extend_from_slice(&receipt.last_second.to_be_bytes());
        out.extend_from_slice(&receipt.records.to_be_bytes());
        out.extend_from_slice(&receipt.bytes.to_be_bytes());
        out.extend_from_slice(&receipt.digest);
        out.extend_from_slice(&receipt.issued_ms.to_be_bytes());
        Ok(())
    }

    fn read(reader: &mut Body<'_>) -> Result<Unchecked<Self>, WireError> {
        Ok(Unchecked::new(Self {
            parent: PublicKey::from_slice(reader.bytes(KEY_LEN)?)?,
            cell: Region::from_u64(reader.u64()?)?,
            product: Streams::read(reader)?,
            stripe: reader.u8()?,
            stripes_of: reader.u8()?,
            first_second: reader.u64()?,
            last_second: reader.u64()?,
            records: reader.u32()?,
            bytes: reader.u64()?,
            digest: reader.array()?,
            issued_ms: reader.u64()?,
        }))
    }
}

signed_record!(
    /// A child's signed `StripeReceiptContent`.
    StripeReceipt,
    StripeReceiptContent,
    b"tally stripe receipt",
    1,
    256
);

/// BLAKE2s-256 over `"tally stripe receipt digest" 0x00` and the hashes in order.
pub fn receipt_digest(hashes: &[Hash]) -> Hash {
    let mut hasher = Blake2s256::new();
    hasher.update(b"tally stripe receipt digest");
    hasher.update([0]);
    for hash in hashes {
        hasher.update(hash);
    }
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::directory::tests::cell;
    use crate::key::Identity;

    #[test]
    fn sharing_records_round_trip_and_stripes_agree() -> Result<(), WireError> {
        let mut hash = [0; 32];
        hash[3] = 5;
        assert_eq!(stripe_of(&hash, 4), 1);
        let assignment = StripeAssignment {
            cell: cell()?,
            product: Streams::RAW,
            stripes_of: 4,
            stripes: 0b1001,
        };
        assert_eq!(
            StripeAssignment::from_body(&assignment.to_bytes()?)?,
            assignment
        );
        let origin = Identity::generate()?;
        let manifest = PieceManifestContent {
            cell: cell()?,
            product: Streams::RAW,
            second: 1_791_244_800,
            hashes: vec![[1; 32], [2; 32]],
        };
        let signed = PieceManifest::sign(&origin, &manifest)?;
        signed.verify()?;
        assert_eq!(signed.content()?, manifest);
        let unsorted = PieceManifestContent {
            hashes: vec![[2; 32], [1; 32]],
            ..manifest
        };
        assert!(PieceManifest::sign(&origin, &unsorted).is_err());
        let have = HaveSummary {
            cell: cell()?,
            product: Streams::POSITIONS,
            first_second: 10,
            seconds: vec![0xff, 0x01],
        };
        assert_eq!(HaveSummary::from_body(&have.to_bytes()?)?, have);
        let child = Identity::generate()?;
        let receipt = StripeReceiptContent {
            parent: origin.public(),
            cell: cell()?,
            product: Streams::RAW,
            stripe: 3,
            stripes_of: 4,
            first_second: 100,
            last_second: 160,
            records: 900,
            bytes: 1 << 20,
            digest: receipt_digest(&[[1; 32]]),
            issued_ms: 170_000,
        };
        let signed = StripeReceipt::sign(&child, &receipt)?;
        signed.verify()?;
        assert_eq!(signed.content()?, receipt);
        assert_eq!(signed.signer()?, child.public());
        assert_eq!(receipt.seconds(), 61);
        Ok(())
    }

    #[test]
    fn a_hostile_receipt_is_refused_on_both_sides() -> Result<(), WireError> {
        let child = Identity::generate()?;
        let receipt = StripeReceiptContent {
            parent: child.public(),
            cell: cell()?,
            product: Streams::RAW,
            stripe: 0,
            stripes_of: 4,
            first_second: 100,
            last_second: 104,
            records: 1,
            bytes: 1,
            digest: [0; 32],
            issued_ms: 1,
        };
        let hostile = [
            // Inverted, and the whole of u64: either would divide a rate by zero downstream.
            StripeReceiptContent {
                first_second: 5,
                last_second: 4,
                ..receipt
            },
            StripeReceiptContent {
                first_second: 0,
                last_second: u64::MAX,
                ..receipt
            },
            StripeReceiptContent {
                last_second: 100 + MAX_RECEIPT_SPAN_SECONDS,
                ..receipt
            },
            StripeReceiptContent {
                stripe: 4,
                ..receipt
            },
            StripeReceiptContent {
                product: Streams::RAW.with(Streams::POSITIONS),
                ..receipt
            },
        ];
        for bad in hostile {
            assert!(StripeReceipt::sign(&child, &bad).is_err(), "{bad:?}");
            // Written past the check, as a hostile signer would: refused on reading too.
            let mut body = Vec::new();
            StripeReceiptContent::write(Checked::forged(&bad), &mut body)?;
            let signed = crate::signed::Signed::sign(
                StripeReceipt::DOMAIN,
                StripeReceipt::FORMAT,
                &child,
                &body,
                StripeReceipt::MAX_LEN,
            )?;
            let read = StripeReceipt::from_bytes(signed.as_bytes().to_vec())?;
            read.verify()?;
            assert!(read.content().is_err(), "{bad:?}");
        }
        assert!(StripeReceipt::sign(&child, &receipt).is_ok());
        // A have-summary whose bits run past u64::MAX is refused.
        let have = HaveSummary {
            cell: cell()?,
            product: Streams::RAW,
            first_second: u64::MAX - 3,
            seconds: vec![0xff],
        };
        assert!(have.to_bytes().is_err());
        Ok(())
    }
}

/// One chunk of the parity of one origin manifest (unsigned: a wrong parity rebuilds nothing,
/// since every rebuilt record is checked against the origin's signed manifest by its hash).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParityChunk {
    /// The hash of the origin's `PieceManifest` the parity covers.
    pub manifest: Hash,
    pub cell: Region,
    pub product: Streams,
    pub second: u64,
    /// Each data stripe's slice length.
    pub lens: Vec<u32>,
    /// The whole XOR's length, and where this chunk's bytes start in it.
    pub total: u32,
    pub offset: u32,
    pub bytes: Vec<u8>,
}

impl ParityChunk {
    /// A parity of `xor` cut into chunks of at most `MAX_PARITY_CHUNK`, in order (one, empty, for
    /// an empty parity).
    pub fn chunks(
        manifest: Hash,
        cell: Region,
        product: Streams,
        second: u64,
        lens: Vec<u32>,
        xor: &[u8],
    ) -> Result<Vec<Self>, WireError> {
        let total = u32::try_from(xor.len()).map_err(|_| WireError::Oversize(xor.len()))?;
        if total > MAX_PARITY_LEN {
            return Err(WireError::Oversize(xor.len()));
        }
        let mut out = Vec::new();
        let mut offset = 0;
        loop {
            let end = (offset + MAX_PARITY_CHUNK).min(xor.len());
            out.push(Self {
                manifest,
                cell,
                product,
                second,
                lens: lens.clone(),
                total,
                offset: offset as u32,
                bytes: xor[offset..end].to_vec(),
            });
            offset = end;
            if offset >= xor.len() {
                return Ok(out);
            }
        }
    }
}

impl Check for ParityChunk {
    /// One product, at most `MAX_STRIPES` slice lengths, at most `MAX_PARITY_CHUNK` bytes, and
    /// those bytes inside a whole of at most `MAX_PARITY_LEN`.
    fn check(&self) -> Result<(), WireError> {
        check_one_product(self.product)?;
        let end = u64::from(self.offset) + self.bytes.len() as u64;
        if self.lens.len() > usize::from(MAX_STRIPES)
            || self.bytes.len() > MAX_PARITY_CHUNK
            || self.total > MAX_PARITY_LEN
            || end > u64::from(self.total)
        {
            return Err(WireError::Invalid {
                field: "parity chunk",
                value: end,
            });
        }
        Ok(())
    }
}

impl Fields for ParityChunk {
    fn write(chunk: Checked<'_, Self>, out: &mut Vec<u8>) -> Result<(), WireError> {
        out.extend_from_slice(&chunk.manifest);
        out.extend_from_slice(&chunk.cell.as_u64().to_be_bytes());
        chunk.product.write(out);
        out.extend_from_slice(&chunk.second.to_be_bytes());
        count_u16(out, chunk.lens.len(), usize::from(MAX_STRIPES))?;
        for len in &chunk.lens {
            out.extend_from_slice(&len.to_be_bytes());
        }
        out.extend_from_slice(&chunk.total.to_be_bytes());
        out.extend_from_slice(&chunk.offset.to_be_bytes());
        count_u16(out, chunk.bytes.len(), MAX_PARITY_CHUNK)?;
        out.extend_from_slice(&chunk.bytes);
        Ok(())
    }

    fn read(reader: &mut Body<'_>) -> Result<Unchecked<Self>, WireError> {
        let manifest = reader.array()?;
        let cell = Region::from_u64(reader.u64()?)?;
        let product = Streams::read(reader)?;
        let second = reader.u64()?;
        let count = read_count(reader, usize::from(MAX_STRIPES))?;
        let lens = (0..count)
            .map(|_| reader.u32())
            .collect::<Result<Vec<_>, _>>()?;
        let total = reader.u32()?;
        let offset = reader.u32()?;
        let length = read_count(reader, MAX_PARITY_CHUNK)?;
        Ok(Unchecked::new(Self {
            manifest,
            cell,
            product,
            second,
            lens,
            total,
            offset,
            bytes: reader.bytes(length)?.to_vec(),
        }))
    }
}

/// A bundler's index of one second of a parent cell's product (§2.6): every child of the parent,
/// in the H3 tree's order, with the digest of the origin manifests under it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BundleIndexContent {
    pub parent: Region,
    pub product: Streams,
    pub second: u64,
    pub children: Vec<(Region, Hash)>,
}

impl Check for BundleIndexContent {
    /// One product, and at most `MAX_CHILDREN` children, each a child of the parent one
    /// resolution finer, strictly ascending (the H3 tree's order, so none is named twice).
    fn check(&self) -> Result<(), WireError> {
        check_one_product(self.product)?;
        if self.children.len() > MAX_CHILDREN
            || self
                .children
                .windows(2)
                .any(|pair| pair[0].0.as_u64() >= pair[1].0.as_u64())
        {
            return Err(WireError::Invalid {
                field: "bundle children",
                value: self.children.len() as u64,
            });
        }
        for (child, _) in &self.children {
            if !self.parent.contains(*child) || child.resolution() != self.parent.resolution() + 1 {
                return Err(WireError::Invalid {
                    field: "bundle child",
                    value: child.as_u64(),
                });
            }
        }
        Ok(())
    }
}

impl Fields for BundleIndexContent {
    fn write(index: Checked<'_, Self>, out: &mut Vec<u8>) -> Result<(), WireError> {
        out.extend_from_slice(&index.parent.as_u64().to_be_bytes());
        index.product.write(out);
        out.extend_from_slice(&index.second.to_be_bytes());
        count_u16(out, index.children.len(), MAX_CHILDREN)?;
        for (child, digest) in &index.children {
            out.extend_from_slice(&child.as_u64().to_be_bytes());
            out.extend_from_slice(digest);
        }
        Ok(())
    }

    fn read(reader: &mut Body<'_>) -> Result<Unchecked<Self>, WireError> {
        let parent = Region::from_u64(reader.u64()?)?;
        let product = Streams::read(reader)?;
        let second = reader.u64()?;
        let count = read_count(reader, MAX_CHILDREN)?;
        let children = (0..count)
            .map(|_| Ok((Region::from_u64(reader.u64()?)?, reader.array()?)))
            .collect::<Result<Vec<_>, WireError>>()?;
        Ok(Unchecked::new(Self {
            parent,
            product,
            second,
            children,
        }))
    }
}

signed_record!(
    /// A bundler's signed `BundleIndexContent`.
    BundleIndex,
    BundleIndexContent,
    b"tally bundle index",
    1,
    1 + 32 + 8 + 2 + 8 + 2 + MAX_CHILDREN * 40 + 64
);

#[cfg(test)]
mod network_tests {
    use super::*;
    use crate::directory::tests::cell;
    use crate::key::Identity;

    #[test]
    fn a_long_parity_travels_in_chunks_and_a_bundle_index_names_only_children()
    -> Result<(), WireError> {
        let xor: Vec<u8> = (0..150_000u32).map(|at| at as u8).collect();
        let chunks =
            ParityChunk::chunks([1; 32], cell()?, Streams::RAW, 7, vec![10, 20, 30], &xor)?;
        assert_eq!(chunks.len(), 3);
        let mut whole = Vec::new();
        for chunk in &chunks {
            let back = ParityChunk::from_body(&chunk.to_bytes()?)?;
            assert_eq!(&back, chunk);
            whole.extend_from_slice(&back.bytes);
        }
        assert_eq!(whole, xor);
        let parent = cell()?;
        let children: Vec<(Region, Hash)> = parent_children(parent)?
            .into_iter()
            .map(|child| (child, [2; 32]))
            .collect();
        let index = BundleIndexContent {
            parent,
            product: Streams::POSITIONS,
            second: 9,
            children,
        };
        let relay = Identity::generate()?;
        let signed = BundleIndex::sign(&relay, &index)?;
        signed.verify()?;
        assert_eq!(signed.content()?, index);
        let stray = BundleIndexContent {
            children: vec![(parent, [0; 32])],
            ..index
        };
        assert!(BundleIndex::sign(&relay, &stray).is_err());
        Ok(())
    }

    fn parent_children(parent: Region) -> Result<Vec<Region>, WireError> {
        let cell = h3o::CellIndex::try_from(parent.as_u64()).map_err(|_| WireError::Invalid {
            field: "H3 cell",
            value: 0,
        })?;
        let finer =
            h3o::Resolution::try_from(parent.resolution() + 1).map_err(|_| WireError::Invalid {
                field: "H3 resolution",
                value: 0,
            })?;
        cell.children(finer)
            .map(|child| Region::from_u64(u64::from(child)))
            .collect()
    }
}
