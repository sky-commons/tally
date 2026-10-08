//! Parent bundles over the fixed area tree (RFC-0174 §2.6). The tree is H3's: everyone agrees
//! which cells compose which parent ([`children`], from the wire's own H3). A relay that holds every cell under a parent,
//! each as an area it takes or as a bundle it holds, may offer the parent ([`Bundles::complete`]),
//! so a reader of a state, a country or the world asks one provider instead of hundreds.
//!
//! A bundle adds no trust. Its records are the origins' own, signatures intact, and so are the
//! manifests that list them. What the bundler adds is a [`BundleIndex`] per (parent, product,
//! second): every child of the parent with the digest of the origin manifests under it. A reader
//! checks the index against the fixed tree and the manifests ([`BundleIndex::check`]), so a bundle
//! that leaves out a child, a manifest any origin signed, or a record a manifest lists is caught:
//! omission is detectable, not merely unlikely.

use std::collections::BTreeSet;
use std::sync::RwLock;

use tally_wire::batch::Hash;
use tally_wire::rendezvous::{AREA_RESOLUTION, areas_of};
use tally_wire::sharing::receipt_digest;
use tally_wire::{PieceManifest, Region, Streams};

use super::locks::{read, write};
use super::stripes::domain_block;

const BUNDLE: &[u8] = b"tally sharing bundle child";

/// The cells one resolution finer that compose `parent`, a cell coarser than an area: seven, or
/// six under a pentagon, ascending. Read off the wire's own area tree (`rendezvous::areas_of`, the
/// areas under the parent, each taken up to the child's resolution by `Region::ancestor`), so the
/// relay holds no H3 arithmetic of its own. Empty for an area or anything finer: bundles are
/// offered only above the areas.
pub fn children(parent: Region) -> Vec<Region> {
    if parent.resolution() >= AREA_RESOLUTION {
        return Vec::new();
    }
    let child = parent.resolution() + 1;
    let mut cells: Vec<Region> = areas_of(parent)
        .unwrap_or_default()
        .into_iter()
        .filter_map(|area| area.ancestor(child))
        .collect();
    cells.sort_by_key(|cell| cell.as_u64());
    cells.dedup();
    cells
}

/// What this relay holds of the area tree.
#[derive(Default)]
pub struct Bundles {
    /// Areas (at `AREA_RESOLUTION`) whose groups this relay is in.
    gathered: RwLock<BTreeSet<u64>>,
    /// Coarser cells held whole as bundles from another provider.
    held: RwLock<BTreeSet<u64>>,
}

impl Bundles {
    pub fn new() -> Self {
        Self::default()
    }

    /// The areas this relay holds now (it takes them and is in their groups).
    pub fn set_gathered(&self, areas: &[Region]) {
        *write(&self.gathered) = areas
            .iter()
            .filter(|area| area.resolution() == AREA_RESOLUTION)
            .map(|area| area.as_u64())
            .collect();
    }

    /// A coarser cell held whole as a bundle from a provider (or no longer).
    pub fn set_held(&self, cell: Region, held: bool) {
        let mut set = write(&self.held);
        if held {
            set.insert(cell.as_u64());
        } else {
            set.remove(&cell.as_u64());
        }
    }

    /// Whether every child of `parent` is held, so the parent may be offered.
    pub fn complete(&self, parent: Region) -> bool {
        complete(parent, &read(&self.gathered), &read(&self.held))
    }

    /// Every cell coarser than an area that this relay may offer as a bundle now.
    pub fn offerable(&self) -> Vec<Region> {
        let (gathered, held) = (read(&self.gathered), read(&self.held));
        let mut candidates = BTreeSet::new();
        for area in gathered
            .iter()
            .filter_map(|area| Region::from_u64(*area).ok())
        {
            for resolution in 0..AREA_RESOLUTION {
                if let Some(parent) = area.ancestor(resolution) {
                    candidates.insert(parent.as_u64());
                }
            }
        }
        candidates
            .into_iter()
            .filter_map(|cell| Region::from_u64(cell).ok())
            .filter(|cell| complete(*cell, &gathered, &held))
            .collect()
    }
}

fn complete(cell: Region, gathered: &BTreeSet<u64>, held: &BTreeSet<u64>) -> bool {
    if held.contains(&cell.as_u64()) {
        return true;
    }
    if cell.resolution() >= AREA_RESOLUTION {
        return gathered.contains(&cell.as_u64());
    }
    let children = children(cell);
    !children.is_empty()
        && children
            .into_iter()
            .all(|child| complete(child, gathered, held))
}

/// Why a bundle is not whole.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Omission {
    /// A child of the parent the index does not name.
    MissingChild(Region),
    /// A cell named that is not a child of the parent, or named twice.
    StrayChild(Region),
    /// A child whose digest is not that of the bundled manifests under it.
    Digest(Region),
    /// A manifest an origin signed for a cell under the parent that the bundle left out.
    Manifest(Hash),
    /// A record a bundled manifest lists that the bundle does not carry.
    Record(Hash),
    /// A bundled manifest that does not verify or is for another parent, product or second.
    Forged(Hash),
}

/// A bundler's index of one second of a parent's product: every child, with the digest of the
/// origin manifests under it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BundleIndex {
    pub parent: Region,
    pub product: Streams,
    pub second: u64,
    /// Every child of `parent`, in `children` order, with its digest.
    pub children: Vec<(Region, Hash)>,
}

impl BundleIndex {
    /// The index of the manifests a bundler holds (those under `parent` for the product and
    /// second are taken; the rest are not this bundle's).
    pub fn build(
        parent: Region,
        product: Streams,
        second: u64,
        manifests: &[PieceManifest],
    ) -> Self {
        let under = under(parent, product, second, manifests);
        let children = children(parent)
            .into_iter()
            .map(|child| (child, digest(child, &under)))
            .collect();
        Self {
            parent,
            product,
            second,
            children,
        }
    }

    /// Checks a bundle: the index against the fixed tree, the bundled manifests against the
    /// index, every manifest the reader has seen elsewhere (from the cells' own groups or another
    /// provider) against the bundle, and the bundled records against the manifests.
    pub fn check(
        &self,
        bundled: &[PieceManifest],
        records: &[Hash],
        seen: &[PieceManifest],
    ) -> Result<(), Omission> {
        let expected = children(self.parent);
        let mut named = BTreeSet::new();
        for (child, _) in &self.children {
            if !expected.contains(child) || !named.insert(child.as_u64()) {
                return Err(Omission::StrayChild(*child));
            }
        }
        if let Some(missing) = expected
            .iter()
            .find(|child| !named.contains(&child.as_u64()))
        {
            return Err(Omission::MissingChild(*missing));
        }
        for manifest in bundled {
            let fits = manifest.verify().is_ok()
                && manifest.content().is_ok_and(|content| {
                    content.product == self.product
                        && content.second == self.second
                        && self.parent.contains(content.cell)
                });
            if !fits {
                return Err(Omission::Forged(manifest.hash()));
            }
        }
        let under = under(self.parent, self.product, self.second, bundled);
        for (child, claimed) in &self.children {
            if digest(*child, &under) != *claimed {
                return Err(Omission::Digest(*child));
            }
        }
        let bundled_hashes: BTreeSet<Hash> = under.iter().map(|(_, hash, _)| *hash).collect();
        for (_, hash, _) in under_verified(self.parent, self.product, self.second, seen) {
            if !bundled_hashes.contains(&hash) {
                return Err(Omission::Manifest(hash));
            }
        }
        let carried: BTreeSet<&Hash> = records.iter().collect();
        for (_, _, listed) in &under {
            if let Some(missing) = listed.iter().find(|hash| !carried.contains(hash)) {
                return Err(Omission::Record(*missing));
            }
        }
        Ok(())
    }
}

/// The manifests under `parent` for the product and second: (cell, manifest hash, listed).
fn under(
    parent: Region,
    product: Streams,
    second: u64,
    manifests: &[PieceManifest],
) -> Vec<(Region, Hash, Vec<Hash>)> {
    let mut out: Vec<(Region, Hash, Vec<Hash>)> = manifests
        .iter()
        .filter_map(|manifest| {
            let content = manifest.content().ok()?;
            (content.product == product
                && content.second == second
                && parent.contains(content.cell))
            .then(|| (content.cell, manifest.hash(), content.hashes))
        })
        .collect();
    out.sort_by_key(|(_, hash, _)| *hash);
    out.dedup_by_key(|(_, hash, _)| *hash);
    out
}

fn under_verified(
    parent: Region,
    product: Streams,
    second: u64,
    manifests: &[PieceManifest],
) -> Vec<(Region, Hash, Vec<Hash>)> {
    let verified: Vec<PieceManifest> = manifests
        .iter()
        .filter(|manifest| manifest.verify().is_ok())
        .cloned()
        .collect();
    under(parent, product, second, &verified)
}

/// A child's digest: BLAKE2s over a domain block, the child, and the hashes of the manifests
/// under it, ascending. A child with no manifests has a digest too, so "nothing here" is a claim
/// the bundler signs up to, not a gap.
fn digest(child: Region, under: &[(Region, Hash, Vec<Hash>)]) -> Hash {
    let mut head = [0u8; 32];
    head[..8].copy_from_slice(&child.as_u64().to_be_bytes());
    let mut blocks = vec![domain_block(BUNDLE), head];
    blocks.extend(
        under
            .iter()
            .filter(|(cell, _, _)| child.contains(*cell))
            .map(|(_, hash, _)| *hash),
    );
    receipt_digest(&blocks)
}
