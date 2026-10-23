//! An engine's clock model (RFC-0171 §3.8.1): the clocks of one connected group of receivers over
//! the stretch of a window its solutions use, relative to one reference receiver (the gauge),
//! published as shared evidence, never kept as private state. Content-addressed: a `Positions`
//! solution names the model it used by `ClockModel::id`, and is a deterministic function of that
//! model, its observation set and the solver specification's version. It is never combined with
//! another.
//!
//! **The model bytes are the solver specification's** (`spec_version`; for version 1 the
//! `tally-mlat-solver` crate documentation, § Publishing): its clocks, their fixed-point bins,
//! sites and noise, the gauge, the joint covariance of every offset and rate, and the sync
//! observations it was fitted from. They are carried here as bytes, not re-described, because a
//! solution is a function of exactly what the solver reads: a second description of the model in
//! this crate would be a twin that could drift from it. This crate signs, addresses, splits and
//! frames the model; a reader that does not know `spec_version` keeps it (and its id) intact.
//!
//! **A model of any size** travels as one signed manifest (`ClockModel`, kind 0x0d) and, when it
//! does not fit the manifest, unsigned content-addressed parts (`ClockModelPart`, kind 0x0f). A
//! model is one aircraft's scope over one window and carries no covariance, a few kilobytes, so
//! it normally fits its manifest; parts cost nothing until one does not.
//!
//! ```text
//! manifest = format u8 = 1 | engine key [32] | boot_id u64 | sequence u64
//!          | issued_ms u64 | spec_version u16 | inputs [32]
//!          | model length u32
//!          | part count u16 | count x part hash [32]
//!          | inline length u16 | inline bytes
//!          | signature [64]
//!
//! part     = format u8 = 1 | model id [32] | index u16 | bytes
//! ```
//!
//! With no parts the model is the inline bytes, whose length is the model length: the common case,
//! one record. Otherwise the inline bytes are empty and the model is the parts' bytes in index
//! order: the model's encoding cut into `PART_LEN` pieces, the last the remainder, so the part
//! count and every part's length follow from the model length. A part's hash is BLAKE2s-256 over
//! `"tally clock model part" 0x00` and its bytes; the manifest lists them in index order, and its
//! signature covers them, so a part is checked against its manifest alone and needs no signature
//! of its own. A part names its model's id so it can be held until its manifest arrives.
//!
//! **The inputs** are a hash, computed by the specification, of everything the model is a
//! function of (the aircraft, the window, the scope as its receivers described themselves, and
//! the raw observations cited). Two models with the same inputs and specification version are
//! the same model, byte for byte, from any honest engine; two that differ are a fault anyone can
//! prove with the two manifests alone (`FaultProof::models`).
//!
//! The prefix (format, engine key, boot id, sequence) is the same as a `Positions` record's and
//! fixed across every format, so a relay verifies, deduplicates and windows a manifest it cannot
//! read. Its sequence is its own, separate from the engine's `Positions` sequence. An engine sends
//! a model's parts, then its manifest, then the positions that cite it.
//!
//! **The id** is BLAKE2s-256 over `"tally clock model id" 0x00` and the manifest's signed bytes
//! without the signature, so it covers every part's hash. Ed25519 signatures are deterministic and
//! strictly verified, so a valid manifest has one signature and the id names it exactly; leaving
//! the signature out lets an engine compute the id its parts carry before it signs. Only a verified
//! model is ever looked up by id.

use std::collections::{BTreeMap, HashMap, VecDeque};

use blake2::{Blake2s256, Digest};

use crate::WireError;
use crate::batch::{Hash, domain, split_signature, u64_at};
use crate::key::{KEY_LEN, PublicKey, SIGNATURE_LEN, Signs};
use crate::record::{Body, MAX_BODY, Record};

pub const CLOCK_MODEL_FORMAT: u8 = 1;
pub const CLOCK_MODEL_PART_FORMAT: u8 = 1;
const CLOCK_MODEL_DOMAIN: &[u8] = b"tally clock model";
const CLOCK_MODEL_ID_DOMAIN: &[u8] = b"tally clock model id";
const CLOCK_MODEL_PART_DOMAIN: &[u8] = b"tally clock model part";
const CLOCK_MODEL_CONTENT_DOMAIN: &[u8] = b"tally clock model content";
const PREFIX_LEN: usize = 1 + KEY_LEN + 8 + 8;
/// Every byte of a manifest that is neither a part hash nor inline model, signature included.
const MANIFEST_FIXED_LEN: usize = PREFIX_LEN + 8 + 2 + 32 + 4 + 2 + 2 + SIGNATURE_LEN;
/// A part's bytes before its share of the model: format, model id, index.
const PART_HEADER_LEN: usize = 1 + 32 + 2;
/// The bytes of the model every part but the last carries: 60 KiB, which with its header fits
/// one record.
pub const PART_LEN: usize = 60 * 1024;
const _: () = assert!(PART_HEADER_LEN + PART_LEN <= MAX_BODY);
/// The largest manifest: half of what a `FaultProof` can carry, so any two fit one proof.
pub const MAX_MANIFEST_LEN: usize = (MAX_BODY - crate::fault_proof::FAULT_PROOF_OVERHEAD) / 2;
/// The longest model a manifest carries inline.
pub const MAX_INLINE_LEN: usize = MAX_MANIFEST_LEN - MANIFEST_FIXED_LEN;
/// The most parts a manifest lists.
pub const MAX_PARTS: usize = (MAX_MANIFEST_LEN - MANIFEST_FIXED_LEN) / 32;
/// The longest model of all: about 60 MiB.
pub const MAX_MODEL_LEN: usize = MAX_PARTS * PART_LEN;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClockModelContent {
    /// As a `Positions` record's: a stream per engine boot, its own sequence.
    pub boot_id: u64,
    pub sequence: u64,
    pub issued_ms: u64,
    /// The solver specification the model is encoded under and was fitted by.
    pub spec_version: u16,
    /// What the model is a function of, as the specification hashes it.
    pub inputs: Hash,
    /// The model, in the encoding the specification `spec_version` defines.
    pub model: Vec<u8>,
}

/// What a manifest says, apart from the model's bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Manifest {
    pub boot_id: u64,
    pub sequence: u64,
    pub issued_ms: u64,
    pub spec_version: u16,
    pub inputs: Hash,
    pub length: usize,
    /// Each part's hash (`part_hash`), in index order; empty when the model is inline.
    pub parts: Vec<Hash>,
    pub inline: Vec<u8>,
}

/// A signed manifest, as bytes. Immutable: forwarding never re-encodes it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClockModel {
    bytes: Vec<u8>,
}

/// A model as an engine publishes it: its parts (none for a small model), then its manifest.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedClockModel {
    pub manifest: ClockModel,
    pub parts: Vec<ClockModelPart>,
}

impl SignedClockModel {
    /// The records to send, in the order to send them: every part, then the manifest.
    pub fn records(&self) -> Vec<Record> {
        self.parts
            .iter()
            .cloned()
            .map(Record::ClockModelPart)
            .chain([Record::ClockModel(self.manifest.clone())])
            .collect()
    }
}

/// BLAKE2s-256 over `"tally clock model part" 0x00` and a part's share of the model: what its
/// manifest lists.
pub fn part_hash(data: &[u8]) -> Hash {
    Blake2s256::digest(domain(CLOCK_MODEL_PART_DOMAIN, data)).into()
}

impl ClockModel {
    /// The manifest and parts of `content`: inline when the model fits the manifest, else cut
    /// into `PART_LEN` parts. Refused beyond `MAX_MODEL_LEN`.
    pub fn sign(
        identity: &impl Signs,
        content: &ClockModelContent,
    ) -> Result<SignedClockModel, WireError> {
        let model = &content.model;
        if model.len() > MAX_MODEL_LEN {
            return Err(WireError::Oversize(model.len()));
        }
        let chunks: Vec<&[u8]> = if model.len() <= MAX_INLINE_LEN {
            Vec::new()
        } else {
            model.chunks(PART_LEN).collect()
        };
        let inline: &[u8] = if chunks.is_empty() { model } else { &[] };
        let mut bytes = Vec::with_capacity(MANIFEST_FIXED_LEN + 32 * chunks.len() + inline.len());
        bytes.push(CLOCK_MODEL_FORMAT);
        bytes.extend_from_slice(identity.public().as_bytes());
        bytes.extend_from_slice(&content.boot_id.to_be_bytes());
        bytes.extend_from_slice(&content.sequence.to_be_bytes());
        bytes.extend_from_slice(&content.issued_ms.to_be_bytes());
        bytes.extend_from_slice(&content.spec_version.to_be_bytes());
        bytes.extend_from_slice(&content.inputs);
        // Bounded by `MAX_MODEL_LEN`, `MAX_PARTS` and `MAX_INLINE_LEN`, each within its field.
        bytes.extend_from_slice(&(model.len() as u32).to_be_bytes());
        bytes.extend_from_slice(&(chunks.len() as u16).to_be_bytes());
        for chunk in &chunks {
            bytes.extend_from_slice(&part_hash(chunk));
        }
        bytes.extend_from_slice(&(inline.len() as u16).to_be_bytes());
        bytes.extend_from_slice(inline);
        let id = id_of(&bytes);
        let signature = identity.sign(&domain(CLOCK_MODEL_DOMAIN, &bytes));
        bytes.extend_from_slice(&signature);
        let parts = chunks
            .iter()
            .enumerate()
            .map(|(index, chunk)| ClockModelPart::new(id, index as u16, chunk))
            .collect();
        Ok(SignedClockModel {
            manifest: Self { bytes },
            parts,
        })
    }

    /// Accepts any format whose fixed prefix is well formed. Does not check the signature.
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self, WireError> {
        if bytes.len() < PREFIX_LEN + SIGNATURE_LEN {
            return Err(WireError::Truncated {
                needed: PREFIX_LEN + SIGNATURE_LEN,
                had: bytes.len(),
            });
        }
        PublicKey::from_slice(&bytes[1..1 + KEY_LEN])?;
        Ok(Self { bytes })
    }

    /// What it allocates of its own: its bytes' capacity.
    pub fn allocated(&self) -> usize {
        crate::footprint::vec::<u8>(self.bytes.capacity())
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn format(&self) -> u8 {
        self.bytes[0]
    }

    pub fn engine(&self) -> Result<PublicKey, WireError> {
        PublicKey::from_slice(&self.bytes[1..1 + KEY_LEN])
    }

    pub fn boot_id(&self) -> u64 {
        u64_at(&self.bytes, 1 + KEY_LEN)
    }

    pub fn sequence(&self) -> u64 {
        u64_at(&self.bytes, 1 + KEY_LEN + 8)
    }

    /// Its signed `issued_ms` (`Manifest::issued_ms`), read without its model: what a relay's time
    /// window judges it by.
    pub fn issued_ms(&self) -> Result<u64, WireError> {
        crate::batch::u64_from(&self.bytes, 1 + KEY_LEN + 16)
    }

    /// The content address `Positions` solutions and parts cite: BLAKE2s-256 over
    /// `"tally clock model id" 0x00` and every signed byte but the signature. Defined for any
    /// format.
    pub fn id(&self) -> Hash {
        id_of(&self.bytes[..self.bytes.len().saturating_sub(SIGNATURE_LEN)])
    }

    pub fn verify(&self) -> Result<(), WireError> {
        let (signed, signature) = split_signature(&self.bytes)?;
        self.engine()?
            .verify(&domain(CLOCK_MODEL_DOMAIN, signed), &signature)
    }

    /// What the manifest says. Refuses one whose lengths disagree: a stated length past
    /// `MAX_MODEL_LEN`, inline bytes beside parts, an inline model not the stated length, or a part
    /// count that is not the stated length cut into `PART_LEN` pieces.
    pub fn manifest(&self) -> Result<Manifest, WireError> {
        if self.format() != CLOCK_MODEL_FORMAT {
            return Err(WireError::Invalid {
                field: "clock model format",
                value: u64::from(self.format()),
            });
        }
        let (signed, _) = split_signature(&self.bytes)?;
        let mut reader = Body::new(&signed[1 + KEY_LEN..]);
        let boot_id = reader.u64()?;
        let sequence = reader.u64()?;
        let issued_ms = reader.u64()?;
        let spec_version = reader.u16()?;
        let inputs = reader.array::<32>()?;
        let length = reader.u32()? as usize;
        let parts = (0..reader.u16()?)
            .map(|_| reader.array::<32>())
            .collect::<Result<Vec<Hash>, _>>()?;
        let inline_length = usize::from(reader.u16()?);
        let inline = reader.bytes(inline_length)?.to_vec();
        let consistent = length <= MAX_MODEL_LEN
            && if parts.is_empty() {
                inline.len() == length
            } else {
                inline.is_empty()
                    && length > MAX_INLINE_LEN
                    && parts.len() == length.div_ceil(PART_LEN)
            };
        if !consistent {
            return Err(WireError::Invalid {
                field: "clock model length",
                value: length as u64,
            });
        }
        Ok(Manifest {
            boot_id,
            sequence,
            issued_ms,
            spec_version,
            inputs,
            length,
            parts,
            inline,
        })
    }

    /// The model, from this manifest and its parts given in any order, with repeats, and among
    /// parts of other models. Each index takes the first part offered whose hash the manifest
    /// lists there; it fails when an index has none.
    pub fn content(&self, parts: &[ClockModelPart]) -> Result<ClockModelContent, WireError> {
        let manifest = self.manifest()?;
        let model = if manifest.parts.is_empty() {
            manifest.inline
        } else {
            let id = self.id();
            let mut found: BTreeMap<u16, &[u8]> = BTreeMap::new();
            for part in parts {
                let Ok(index) = part.index() else { continue };
                if !part.model().is_ok_and(|model| model == id) || found.contains_key(&index) {
                    continue;
                }
                let data = part.data();
                if manifest.parts.get(usize::from(index)) == Some(&part_hash(data)) {
                    found.insert(index, data);
                }
            }
            if found.len() != manifest.parts.len() {
                let missing = (0..manifest.parts.len() as u16)
                    .find(|index| !found.contains_key(index))
                    .unwrap_or(0);
                return Err(WireError::Invalid {
                    field: "missing clock model part",
                    value: u64::from(missing),
                });
            }
            let mut model = Vec::with_capacity(manifest.length);
            for data in found.values() {
                model.extend_from_slice(data);
            }
            if model.len() != manifest.length {
                return Err(WireError::Invalid {
                    field: "clock model length",
                    value: model.len() as u64,
                });
            }
            model
        };
        Ok(ClockModelContent {
            boot_id: manifest.boot_id,
            sequence: manifest.sequence,
            issued_ms: manifest.issued_ms,
            spec_version: manifest.spec_version,
            inputs: manifest.inputs,
            model,
        })
    }
}

impl ClockModel {
    /// What the model is, apart from who signed it and when: BLAKE2s-256 over
    /// `"tally clock model content" 0x00`, the specification version, the model's length, its
    /// part hashes and its inline bytes. Two manifests of one model have the same content id.
    pub fn content_id(&self) -> Result<Hash, WireError> {
        let manifest = self.manifest()?;
        let mut hasher = Blake2s256::new();
        hasher.update(CLOCK_MODEL_CONTENT_DOMAIN);
        hasher.update([0]);
        hasher.update(manifest.spec_version.to_be_bytes());
        hasher.update((manifest.length as u32).to_be_bytes());
        for part in &manifest.parts {
            hasher.update(part);
        }
        hasher.update(&manifest.inline);
        Ok(hasher.finalize().into())
    }
}

/// A clock model as a client receives it (wire version 3): the full model (`ClockModel`, its
/// sites, `site_mm` and offsets) is relay-only, since sites and offsets with the aircraft's
/// positions give every receiver's site; a client is sent this summary instead, signed by the same
/// engine under a domain of its own. It names the full model by the id solutions cite, so a client
/// joins a solution to its model's summary, and says nothing of which receivers the model is of:
/// no receiver key, no site reference, no entry per receiver. A tile's members are chosen by
/// their exact sites (a sphere test about the tile's centre, and the farthest-point choice of
/// members), so the tiles a receiver is a member of, over time, narrow its site to a fraction of
/// its public cell; membership is relay-only like the site itself.
///
/// ```text
/// format u8 = 1 | engine key [32] | boot_id u64 | sequence u64 | issued_ms u64
/// | spec_version u16 | model id [32] | inputs [32] | window first i64 | window last i64
/// | signature [64]
/// ```
///
/// Its boot id and sequence are the full model's, so a summary is numbered with the model it
/// summarises. `inputs` is the full model's inputs hash: equal for two models of the same inputs,
/// and a function of the members' site ids, which a client is never sent, so it names no member.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClientClockModelContent {
    pub boot_id: u64,
    pub sequence: u64,
    pub issued_ms: u64,
    pub spec_version: u16,
    /// The full model's `ClockModel::id`: what a solution's `clock_model` names.
    pub model: Hash,
    /// The full model's `Manifest::inputs`.
    pub inputs: Hash,
    /// The window the model is of, as the solver specification numbers windows.
    pub window_first: i64,
    pub window_last: i64,
}

/// A client model's bytes, signature included: it is of one size.
pub const CLIENT_MODEL_LEN: usize = 1 + KEY_LEN + 8 + 8 + 8 + 2 + 32 + 32 + 8 + 8 + SIGNATURE_LEN;

impl crate::signed::Check for ClientClockModelContent {
    /// A window that does not end before it begins.
    fn check(&self) -> Result<(), WireError> {
        if self.window_first > self.window_last {
            return Err(WireError::Invalid {
                field: "client clock model window",
                value: 0,
            });
        }
        Ok(())
    }
}

impl crate::signed::Fields for ClientClockModelContent {
    fn write(model: crate::signed::Checked<'_, Self>, out: &mut Vec<u8>) -> Result<(), WireError> {
        out.extend_from_slice(&model.boot_id.to_be_bytes());
        out.extend_from_slice(&model.sequence.to_be_bytes());
        out.extend_from_slice(&model.issued_ms.to_be_bytes());
        out.extend_from_slice(&model.spec_version.to_be_bytes());
        out.extend_from_slice(&model.model);
        out.extend_from_slice(&model.inputs);
        out.extend_from_slice(&model.window_first.to_be_bytes());
        out.extend_from_slice(&model.window_last.to_be_bytes());
        Ok(())
    }

    fn read(reader: &mut Body<'_>) -> Result<crate::signed::Unchecked<Self>, WireError> {
        let boot_id = reader.u64()?;
        let sequence = reader.u64()?;
        let issued_ms = reader.u64()?;
        let spec_version = reader.u16()?;
        let model = reader.array()?;
        let inputs = reader.array()?;
        let window_first = reader.u64()? as i64;
        let window_last = reader.u64()? as i64;
        Ok(crate::signed::Unchecked::new(Self {
            boot_id,
            sequence,
            issued_ms,
            spec_version,
            model,
            inputs,
            window_first,
            window_last,
        }))
    }
}

crate::signed::signed_record!(
    /// An engine's signed `ClientClockModelContent`: the clock model a client is sent.
    ClientClockModel,
    ClientClockModelContent,
    b"tally client clock model",
    1,
    MAX_BODY
);

fn id_of(signed: &[u8]) -> Hash {
    Blake2s256::digest(domain(CLOCK_MODEL_ID_DOMAIN, signed)).into()
}

/// One part of a model too large for its manifest, as bytes. Unsigned: its manifest's signature
/// covers its hash.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClockModelPart {
    bytes: Vec<u8>,
}

impl ClockModelPart {
    pub fn new(model: Hash, index: u16, data: &[u8]) -> Self {
        let mut bytes = Vec::with_capacity(PART_HEADER_LEN + data.len());
        bytes.push(CLOCK_MODEL_PART_FORMAT);
        bytes.extend_from_slice(&model);
        bytes.extend_from_slice(&index.to_be_bytes());
        bytes.extend_from_slice(data);
        Self { bytes }
    }

    /// Accepts any body with a format byte; `model`, `index` and `data` read only format 1.
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self, WireError> {
        if bytes.is_empty() {
            return Err(WireError::Truncated { needed: 1, had: 0 });
        }
        Ok(Self { bytes })
    }

    /// What it allocates of its own: its bytes' capacity.
    pub fn allocated(&self) -> usize {
        crate::footprint::vec::<u8>(self.bytes.capacity())
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn format(&self) -> u8 {
        self.bytes[0]
    }

    fn header(&self) -> Result<(), WireError> {
        if self.format() != CLOCK_MODEL_PART_FORMAT {
            return Err(WireError::Invalid {
                field: "clock model part format",
                value: u64::from(self.format()),
            });
        }
        if self.bytes.len() < PART_HEADER_LEN {
            return Err(WireError::Truncated {
                needed: PART_HEADER_LEN,
                had: self.bytes.len(),
            });
        }
        Ok(())
    }

    /// The id of the model it is a part of.
    pub fn model(&self) -> Result<Hash, WireError> {
        self.header()?;
        let mut id = [0; 32];
        id.copy_from_slice(&self.bytes[1..33]);
        Ok(id)
    }

    pub fn index(&self) -> Result<u16, WireError> {
        self.header()?;
        Ok(u16::from_be_bytes([self.bytes[33], self.bytes[34]]))
    }

    /// Its share of the model (empty for a format this build does not read).
    pub fn data(&self) -> &[u8] {
        if self.header().is_err() {
            return &[];
        }
        &self.bytes[PART_HEADER_LEN..]
    }

    /// What its manifest lists for it (`part_hash` of its data).
    pub fn hash(&self) -> Hash {
        part_hash(self.data())
    }
}

/// A consumer's reassembly of clock models from what a relay delivers, in whatever order: parts
/// are held by model id until their verified manifest completes them, and a manifest waits for
/// its parts. Bounded: held parts by bytes and waiting manifests by count, the oldest model
/// forgotten first.
pub struct Assembler {
    parts: HashMap<Hash, Vec<ClockModelPart>>,
    manifests: HashMap<Hash, ClockModel>,
    /// Model ids in the order they were first seen, for forgetting.
    order: VecDeque<Hash>,
    bytes: usize,
    max_bytes: usize,
    max_models: usize,
}

impl Assembler {
    pub fn new(max_bytes: usize, max_models: usize) -> Self {
        Self {
            parts: HashMap::new(),
            manifests: HashMap::new(),
            order: VecDeque::new(),
            bytes: 0,
            max_bytes,
            max_models: max_models.max(1),
        }
    }

    /// Takes a part; the model it completes, if it does.
    pub fn part(&mut self, part: ClockModelPart) -> Option<(ClockModel, ClockModelContent)> {
        let id = part.model().ok()?;
        self.seen(id);
        self.bytes += part.as_bytes().len();
        self.parts.entry(id).or_default().push(part);
        let done = self.complete(id);
        self.bound();
        done
    }

    /// Takes a manifest, which must verify; the model it completes, if it does.
    pub fn manifest(
        &mut self,
        model: ClockModel,
    ) -> Result<Option<(ClockModel, ClockModelContent)>, WireError> {
        model.verify()?;
        let id = model.id();
        self.seen(id);
        self.manifests.insert(id, model);
        let done = self.complete(id);
        self.bound();
        Ok(done)
    }

    fn seen(&mut self, id: Hash) {
        if !self.parts.contains_key(&id) && !self.manifests.contains_key(&id) {
            self.order.push_back(id);
        }
    }

    fn complete(&mut self, id: Hash) -> Option<(ClockModel, ClockModelContent)> {
        let manifest = self.manifests.get(&id)?;
        let parts = self.parts.get(&id).map_or(&[][..], Vec::as_slice);
        let content = manifest.content(parts).ok()?;
        let manifest = self.manifests.remove(&id)?;
        self.forget(&id);
        Some((manifest, content))
    }

    fn forget(&mut self, id: &Hash) {
        if let Some(parts) = self.parts.remove(id) {
            self.bytes -= parts
                .iter()
                .map(|part| part.as_bytes().len())
                .sum::<usize>();
        }
        self.manifests.remove(id);
        self.order.retain(|other| other != id);
    }

    fn bound(&mut self) {
        while self.bytes > self.max_bytes || self.order.len() > self.max_models {
            let Some(oldest) = self.order.front().copied() else {
                break;
            };
            self.forget(&oldest);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key::Identity;

    fn content(model: Vec<u8>) -> ClockModelContent {
        ClockModelContent {
            boot_id: 0xb007,
            sequence: 2,
            issued_ms: 1_791_220_000_000,
            spec_version: 1,
            inputs: [9; 32],
            model,
        }
    }

    /// A model of `len` bytes that differ from part to part.
    fn large(len: usize) -> Vec<u8> {
        (0..len as u64)
            .map(|at| (at.wrapping_mul(2_654_435_761) >> 13) as u8)
            .collect()
    }

    #[test]
    fn a_small_model_is_one_record_that_round_trips_and_is_content_addressed()
    -> Result<(), WireError> {
        let engine = Identity::generate()?;
        let content = content(b"the solver's model".to_vec());
        let signed = ClockModel::sign(&engine, &content)?;
        assert!(signed.parts.is_empty());
        assert_eq!(signed.records().len(), 1);
        let back = ClockModel::from_bytes(signed.manifest.as_bytes().to_vec())?;
        back.verify()?;
        assert_eq!(back.content(&[])?, content);
        assert_eq!(back.id(), signed.manifest.id());
        assert_eq!(
            (back.engine()?, back.boot_id(), back.sequence()),
            (engine.public(), 0xb007, 2)
        );
        let mut other = content.clone();
        other.model[0] ^= 1;
        assert_ne!(ClockModel::sign(&engine, &other)?.manifest.id(), back.id());
        Ok(())
    }

    #[test]
    fn the_largest_inline_model_is_one_record_and_one_byte_more_is_parts() -> Result<(), WireError>
    {
        let engine = Identity::generate()?;
        let inline = ClockModel::sign(&engine, &content(large(MAX_INLINE_LEN)))?;
        assert!(inline.parts.is_empty());
        let mut record = Vec::new();
        Record::ClockModel(inline.manifest).encode(&mut record)?;
        assert!(record.len() <= crate::noise::MAX_PLAINTEXT);
        let split = ClockModel::sign(&engine, &content(large(MAX_INLINE_LEN + 1)))?;
        assert_eq!(split.parts.len(), 1);
        // The largest model's manifest is at most half a record, so two fit one fault proof.
        let largest = ClockModel::sign(&engine, &content(large(MAX_PARTS * PART_LEN)))?;
        assert_eq!(largest.parts.len(), MAX_PARTS);
        assert!(largest.manifest.as_bytes().len() <= MAX_MANIFEST_LEN);
        Ok(())
    }

    #[test]
    fn a_large_model_travels_as_parts_that_reassemble_in_any_order_with_repeats()
    -> Result<(), WireError> {
        let engine = Identity::generate()?;
        let content = content(large(3 * PART_LEN + 1234));
        let signed = ClockModel::sign(&engine, &content)?;
        assert_eq!(signed.parts.len(), 4);
        let id = signed.manifest.id();
        for (index, part) in signed.parts.iter().enumerate() {
            assert_eq!(part.model()?, id);
            assert_eq!(usize::from(part.index()?), index);
            let mut record = Vec::new();
            Record::ClockModelPart(part.clone()).encode(&mut record)?;
            assert!(record.len() <= crate::noise::MAX_PLAINTEXT);
        }
        // Parts first, then the manifest.
        let records = signed.records();
        assert!(matches!(records.last(), Some(Record::ClockModel(_))));
        let mut shuffled: Vec<ClockModelPart> = signed.parts.iter().rev().cloned().collect();
        shuffled.extend(signed.parts.iter().cloned());
        assert_eq!(signed.manifest.content(&shuffled)?, content);
        Ok(())
    }

    #[test]
    fn a_missing_forged_or_foreign_part_does_not_make_a_model() -> Result<(), WireError> {
        let engine = Identity::generate()?;
        let signed = ClockModel::sign(&engine, &content(large(2 * PART_LEN + 5)))?;
        let other = ClockModel::sign(&engine, &content(large(2 * PART_LEN + 6)))?;
        let manifest = &signed.manifest;
        // Missing.
        assert!(manifest.content(&signed.parts[..2]).is_err());
        // Forged: right model and index, other bytes.
        let mut forged = signed.parts.clone();
        let mut data = forged[1].data().to_vec();
        data[0] ^= 1;
        forged[1] = ClockModelPart::new(manifest.id(), 1, &data);
        assert!(manifest.content(&forged).is_err());
        // A forged copy beside the real one is passed over.
        let mut both = forged.clone();
        both.push(signed.parts[1].clone());
        assert_eq!(manifest.content(&both)?.model, large(2 * PART_LEN + 5));
        // Another model's part at the same index.
        let mut foreign = signed.parts.clone();
        foreign[0] = other.parts[0].clone();
        assert!(manifest.content(&foreign).is_err());
        // A part moved to another index.
        let mut moved = signed.parts.clone();
        moved[0] = ClockModelPart::new(manifest.id(), 0, signed.parts[1].data());
        assert!(manifest.content(&moved).is_err());
        Ok(())
    }

    #[test]
    fn any_changed_byte_of_a_manifest_fails_verification() -> Result<(), WireError> {
        let signed = ClockModel::sign(&Identity::generate()?, &content(large(PART_LEN * 2)))?;
        let model = signed.manifest;
        for at in 0..model.as_bytes().len() {
            let mut bytes = model.as_bytes().to_vec();
            bytes[at] ^= 1;
            let tampered = ClockModel::from_bytes(bytes);
            assert!(
                tampered.is_err() || tampered.is_ok_and(|model| model.verify().is_err()),
                "byte {at}"
            );
        }
        Ok(())
    }

    #[test]
    fn a_positions_signature_never_passes_as_a_clock_models() -> Result<(), WireError> {
        let engine = Identity::generate()?;
        let model = ClockModel::sign(&engine, &content(vec![7]))?.manifest;
        let positions = crate::Positions::from_bytes(model.as_bytes().to_vec())?;
        assert!(positions.verify().is_err());
        Ok(())
    }

    #[test]
    fn an_assembler_completes_a_model_from_parts_and_manifest_in_either_order()
    -> Result<(), WireError> {
        let engine = Identity::generate()?;
        let content = content(large(2 * PART_LEN + 77));
        let signed = ClockModel::sign(&engine, &content)?;

        let mut assembler = Assembler::new(1 << 20, 16);
        assert!(assembler.part(signed.parts[1].clone()).is_none());
        assert!(assembler.manifest(signed.manifest.clone())?.is_none());
        assert!(assembler.part(signed.parts[1].clone()).is_none());
        assert!(assembler.part(signed.parts[2].clone()).is_none());
        let (manifest, back) =
            assembler
                .part(signed.parts[0].clone())
                .ok_or(WireError::Invalid {
                    field: "not assembled",
                    value: 0,
                })?;
        assert_eq!((manifest.id(), back), (signed.manifest.id(), content));

        // A forged manifest is refused.
        let mut bytes = signed.manifest.as_bytes().to_vec();
        let last = bytes.len() - 1;
        bytes[last] ^= 1;
        assert!(
            Assembler::new(1 << 20, 16)
                .manifest(ClockModel::from_bytes(bytes)?)
                .is_err()
        );

        // Bounded: parts beyond the budget forget the oldest model first.
        let mut small = Assembler::new(PART_LEN + 1000, 16);
        small.part(signed.parts[0].clone());
        small.part(signed.parts[1].clone());
        assert!(small.bytes <= PART_LEN + 1000);
        assert_eq!(small.parts.len(), 0);
        Ok(())
    }

    #[test]
    fn a_client_model_round_trips_and_names_no_receiver() -> Result<(), WireError> {
        let engine = Identity::generate()?;
        let content = ClientClockModelContent {
            boot_id: 1,
            sequence: 2,
            issued_ms: 3,
            spec_version: 6,
            model: [4; 32],
            inputs: [5; 32],
            window_first: -7,
            window_last: 8,
        };
        let signed = ClientClockModel::sign(&engine, &content)?;
        let back = ClientClockModel::from_bytes(signed.as_bytes().to_vec())?;
        back.verify()?;
        assert_eq!(back.content()?, content);
        // One size: no room for a member of any kind.
        assert_eq!(back.as_bytes().len(), CLIENT_MODEL_LEN);
        // Its signature is no full model's.
        assert!(
            ClockModel::from_bytes(signed.as_bytes().to_vec())?
                .verify()
                .is_err()
        );
        // Bytes appended to what was signed (a scope smuggled in) do not verify.
        let mut longer = signed.as_bytes().to_vec();
        longer.splice(
            longer.len() - SIGNATURE_LEN..longer.len() - SIGNATURE_LEN,
            [0u8; 2],
        );
        assert!(
            ClientClockModel::from_bytes(longer)
                .and_then(|model| model.verify())
                .is_err()
        );
        // A window ending before it begins: refused.
        let inverted = ClientClockModelContent {
            window_first: 9,
            ..content
        };
        assert!(ClientClockModel::sign(&engine, &inverted).is_err());
        Ok(())
    }

    /// The id is part of the protocol: it is what every solution and part cites.
    #[test]
    fn the_id_is_a_fixed_known_answer() -> Result<(), WireError> {
        let engine = Identity::from_seed([42; 32]);
        let model = ClockModel::sign(&engine, &content(b"model".to_vec()))?.manifest;
        assert_eq!(crate::observation_set::tests::hex(&model.id()), KNOWN_ID);
        Ok(())
    }

    /// Computed independently (Python `hashlib.blake2s` over the documented layout).
    const KNOWN_ID: &str = "153047fc1ebf5ad8bcdd5332eb5335c243c0eb1b5506288b9ef542b78761450f";
}
