//! The delivery check (RFC-0174 §2.2): a feeder asks members of its area's sharing group, on
//! distinct networks, whether they hold a few of its recent batches, by (boot, sequence). A member
//! that holds one proves it with the keyed hash of the feeder's fresh nonce over the batch's bytes
//! ([`possession_proof`]), which only a holder can compute, and signs its answer; one that does not
//! take the feeder's area says so, which is not the same as "not seen". A majority of networks
//! proving a batch is delivery; one member's word alone convicts no relay.

use blake2::{Blake2s256, Digest};

use crate::WireError;
use crate::batch::{Batch, Hash};
use crate::key::{KEY_LEN, PublicKey};
use crate::record::Body;
use crate::signed::{Check, Checked, Fields, Unchecked, count_u16, read_count, signed_record};

/// The most sequence ranges one query names.
pub const MAX_RANGES: usize = 16;
/// The most batches one query asks about, over all its ranges: a sample, never a stream.
pub const MAX_SEQUENCES: u64 = 64;
const POSSESSION_DOMAIN: &[u8] = b"tally possession";

/// Sequences `first..=last` of one boot.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SequenceRange {
    pub first: u64,
    pub last: u64,
}

impl SequenceRange {
    /// How many sequences it names: `None` for an inverted range (`last < first`) or one of
    /// `2^64` sequences (`{0, u64::MAX}`), which no `u64` counts.
    pub fn len(&self) -> Option<u64> {
        self.last.checked_sub(self.first)?.checked_add(1)
    }

    pub fn is_empty(&self) -> bool {
        self.last < self.first
    }
}

/// A feeder's question (unsigned: the nonce is what binds the answer to it).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeliveryQuery {
    /// Fresh for every query.
    pub nonce: Hash,
    /// The feeder's own key: whose batches.
    pub receiver: PublicKey,
    pub boot_id: u64,
    /// Ascending and disjoint, at most `MAX_RANGES`, at most `MAX_SEQUENCES` in all.
    pub ranges: Vec<SequenceRange>,
}

impl DeliveryQuery {
    /// How many batches it asks about over all its ranges: `None` when a range is inverted or the
    /// sum does not fit a `u64`.
    pub fn sequences(&self) -> Option<u64> {
        self.ranges
            .iter()
            .try_fold(0u64, |total, range| total.checked_add(range.len()?))
    }
}

impl Check for DeliveryQuery {
    /// At most `MAX_RANGES` ranges, each non-empty, ascending and disjoint, naming at most
    /// `MAX_SEQUENCES` batches in all, every count exact (no range or sum wraps).
    fn check(&self) -> Result<(), WireError> {
        let ordered = self
            .ranges
            .windows(2)
            .all(|pair| pair[0].last < pair[1].first);
        let total = self.sequences();
        if self.ranges.len() > MAX_RANGES
            || !ordered
            || total.is_none_or(|total| total > MAX_SEQUENCES)
        {
            return Err(WireError::Invalid {
                field: "delivery query ranges",
                value: total.unwrap_or(u64::MAX),
            });
        }
        Ok(())
    }
}

impl Fields for DeliveryQuery {
    fn write(query: Checked<'_, Self>, out: &mut Vec<u8>) -> Result<(), WireError> {
        out.extend_from_slice(&query.nonce);
        out.extend_from_slice(query.receiver.as_bytes());
        out.extend_from_slice(&query.boot_id.to_be_bytes());
        count_u16(out, query.ranges.len(), MAX_RANGES)?;
        for range in &query.ranges {
            out.extend_from_slice(&range.first.to_be_bytes());
            out.extend_from_slice(&range.last.to_be_bytes());
        }
        Ok(())
    }

    fn read(reader: &mut Body<'_>) -> Result<Unchecked<Self>, WireError> {
        let nonce = reader.array()?;
        let receiver = PublicKey::from_slice(reader.bytes(KEY_LEN)?)?;
        let boot_id = reader.u64()?;
        let count = read_count(reader, MAX_RANGES)?;
        let ranges = (0..count)
            .map(|_| {
                Ok(SequenceRange {
                    first: reader.u64()?,
                    last: reader.u64()?,
                })
            })
            .collect::<Result<Vec<_>, WireError>>()?;
        Ok(Unchecked::new(Self {
            nonce,
            receiver,
            boot_id,
            ranges,
        }))
    }
}

/// What a member says of one batch.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Possession {
    /// It holds the batch: `possession_proof(nonce, batch)`.
    Proved(Hash),
    /// It takes the feeder's area and has not seen the batch.
    NotSeen,
}

/// A member's signed answer to a `DeliveryQuery`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeliveryAnswerContent {
    pub nonce: Hash,
    pub receiver: PublicKey,
    pub boot_id: u64,
    pub issued_ms: u64,
    /// False: the member does not take the feeder's area, so it says nothing of the batches
    /// (`entries` is empty), which is no evidence against anyone.
    pub takes_area: bool,
    /// Per sequence asked, ascending.
    pub entries: Vec<(u64, Possession)>,
}

/// A `Possession`'s tag on the wire. Only these two are defined: any other byte is an error,
/// never read as a proof (RFC-0171 §3.4's `Other` rule does not apply: an answer is evidence, and
/// a tag this build cannot read proves nothing either way).
const TAG_NOT_SEEN: u8 = 0;
const TAG_PROVED: u8 = 1;

impl Check for DeliveryAnswerContent {
    /// At most `MAX_SEQUENCES` entries, strictly ascending by sequence, and none at all from a
    /// member that does not take the area.
    fn check(&self) -> Result<(), WireError> {
        if !self.takes_area && !self.entries.is_empty() {
            return Err(WireError::Invalid {
                field: "delivery entries outside the area",
                value: self.entries.len() as u64,
            });
        }
        let ascending = self.entries.windows(2).all(|pair| pair[0].0 < pair[1].0);
        if self.entries.len() > MAX_SEQUENCES as usize || !ascending {
            return Err(WireError::Invalid {
                field: "delivery entries",
                value: self.entries.len() as u64,
            });
        }
        Ok(())
    }
}

impl Fields for DeliveryAnswerContent {
    fn write(answer: Checked<'_, Self>, out: &mut Vec<u8>) -> Result<(), WireError> {
        out.extend_from_slice(&answer.nonce);
        out.extend_from_slice(answer.receiver.as_bytes());
        out.extend_from_slice(&answer.boot_id.to_be_bytes());
        out.extend_from_slice(&answer.issued_ms.to_be_bytes());
        out.push(u8::from(answer.takes_area));
        count_u16(out, answer.entries.len(), MAX_SEQUENCES as usize)?;
        for (sequence, possession) in &answer.entries {
            out.extend_from_slice(&sequence.to_be_bytes());
            match possession {
                Possession::Proved(proof) => {
                    out.push(TAG_PROVED);
                    out.extend_from_slice(proof);
                }
                Possession::NotSeen => out.push(TAG_NOT_SEEN),
            }
        }
        Ok(())
    }

    fn read(reader: &mut Body<'_>) -> Result<Unchecked<Self>, WireError> {
        let nonce = reader.array()?;
        let receiver = PublicKey::from_slice(reader.bytes(KEY_LEN)?)?;
        let boot_id = reader.u64()?;
        let issued_ms = reader.u64()?;
        let takes_area = match reader.u8()? {
            0 => false,
            1 => true,
            other => {
                return Err(WireError::Invalid {
                    field: "delivery takes-area flag",
                    value: u64::from(other),
                });
            }
        };
        let count = read_count(reader, MAX_SEQUENCES as usize)?;
        let entries = (0..count)
            .map(|_| {
                let sequence = reader.u64()?;
                let possession = match reader.u8()? {
                    TAG_NOT_SEEN => Possession::NotSeen,
                    TAG_PROVED => Possession::Proved(reader.array()?),
                    other => {
                        return Err(WireError::Invalid {
                            field: "possession tag",
                            value: u64::from(other),
                        });
                    }
                };
                Ok((sequence, possession))
            })
            .collect::<Result<Vec<_>, WireError>>()?;
        Ok(Unchecked::new(Self {
            nonce,
            receiver,
            boot_id,
            issued_ms,
            takes_area,
            entries,
        }))
    }
}

signed_record!(
    /// A member's signed `DeliveryAnswerContent`: evidence, carried in an `EvidenceBundle`.
    DeliveryAnswer,
    DeliveryAnswerContent,
    b"tally delivery answer",
    1,
    1 + KEY_LEN + 32 + KEY_LEN + 8 + 8 + 1 + 2 + MAX_SEQUENCES as usize * 41 + 64
);

/// The proof that one holds `batch`: BLAKE2s-256 over `"tally possession" 0x00`, the nonce and
/// the batch's signed bytes. The nonce comes first and is fresh, so the proof is keyed by it and
/// no earlier answer can be replayed.
pub fn possession_proof(nonce: &Hash, batch: &Batch) -> Hash {
    let mut hasher = Blake2s256::new();
    hasher.update(POSSESSION_DOMAIN);
    hasher.update([0]);
    hasher.update(nonce);
    hasher.update(batch.as_bytes());
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::batch::BatchContent;
    use crate::key::Identity;

    #[test]
    fn a_query_and_its_signed_answer_round_trip_and_only_a_holder_proves() -> Result<(), WireError>
    {
        let feeder = Identity::generate()?;
        let batch = Batch::sign(
            &feeder,
            &BatchContent {
                boot_id: 3,
                sequence: 41,
                counter_epoch: 0,
                wall_ms: 1,
                dropped: 0,
                previous: [0; 32],
                observations: Vec::new(),
            },
        )?;
        let query = DeliveryQuery {
            nonce: [9; 32],
            receiver: feeder.public(),
            boot_id: 3,
            ranges: vec![
                SequenceRange {
                    first: 40,
                    last: 41,
                },
                SequenceRange {
                    first: 50,
                    last: 50,
                },
            ],
        };
        assert_eq!(DeliveryQuery::from_body(&query.to_bytes()?)?, query);
        let proof = possession_proof(&query.nonce, &batch);
        assert_ne!(proof, possession_proof(&[8; 32], &batch));
        let member = Identity::generate()?;
        let content = DeliveryAnswerContent {
            nonce: query.nonce,
            receiver: feeder.public(),
            boot_id: 3,
            issued_ms: 5,
            takes_area: true,
            entries: vec![
                (40, Possession::NotSeen),
                (41, Possession::Proved(proof)),
                (50, Possession::NotSeen),
            ],
        };
        let answer = DeliveryAnswer::sign(&member, &content)?;
        let back = DeliveryAnswer::from_bytes(answer.as_bytes().to_vec())?;
        back.verify()?;
        assert_eq!(back.content()?, content);
        // Too many asked, or out of order, is refused.
        let mut greedy = query.clone();
        greedy.ranges = vec![SequenceRange {
            first: 0,
            last: 100,
        }];
        assert!(greedy.to_bytes().is_err());
        let mut backwards = query;
        backwards.ranges.reverse();
        assert!(backwards.to_bytes().is_err());
        // Outside its area a member says nothing of the batches.
        let outside = DeliveryAnswerContent {
            takes_area: false,
            ..content
        };
        assert!(DeliveryAnswer::sign(&member, &outside).is_err());
        Ok(())
    }

    /// A query's body with `ranges` as given, unchecked: what a hostile sender could write.
    fn query_body(ranges: &[(u64, u64)]) -> Result<Vec<u8>, WireError> {
        let mut body = Vec::new();
        body.extend_from_slice(&[9; 32]);
        body.extend_from_slice(Identity::generate()?.public().as_bytes());
        body.extend_from_slice(&3u64.to_be_bytes());
        body.extend_from_slice(&(ranges.len() as u16).to_be_bytes());
        for (first, last) in ranges {
            body.extend_from_slice(&first.to_be_bytes());
            body.extend_from_slice(&last.to_be_bytes());
        }
        Ok(body)
    }

    #[test]
    fn hostile_ranges_are_refused_on_both_sides_and_never_wrap() -> Result<(), WireError> {
        // {0, u64::MAX} names 2^64 sequences: no count, never 0.
        let whole = SequenceRange {
            first: 0,
            last: u64::MAX,
        };
        assert_eq!(whole.len(), None);
        let inverted = SequenceRange { first: 5, last: 4 };
        assert_eq!(inverted.len(), None);
        assert_eq!(SequenceRange { first: 4, last: 4 }.len(), Some(1));
        for ranges in [
            vec![(0, u64::MAX)],
            vec![(5, 4)],
            // Two ranges whose counts sum to 2^64, which wraps to 0 unchecked.
            vec![(0, u64::MAX - 1), (u64::MAX, u64::MAX)],
            vec![(0, 63), (64, 64)],
            vec![(3, 3), (3, 3)],
        ] {
            assert!(
                DeliveryQuery::from_body(&query_body(&ranges)?).is_err(),
                "{ranges:?}"
            );
            let query = DeliveryQuery {
                nonce: [9; 32],
                receiver: Identity::generate()?.public(),
                boot_id: 3,
                ranges: ranges
                    .iter()
                    .map(|(first, last)| SequenceRange {
                        first: *first,
                        last: *last,
                    })
                    .collect(),
            };
            assert!(query.to_bytes().is_err(), "{ranges:?}");
        }
        assert!(DeliveryQuery::from_body(&query_body(&[(0, 63)])?).is_ok());
        Ok(())
    }

    #[test]
    fn an_unknown_possession_tag_is_an_error_not_a_proof() -> Result<(), WireError> {
        let member = Identity::generate()?;
        let content = DeliveryAnswerContent {
            nonce: [1; 32],
            receiver: member.public(),
            boot_id: 2,
            issued_ms: 3,
            takes_area: true,
            entries: vec![(7, Possession::NotSeen)],
        };
        let mut body = Vec::new();
        content.encode(&mut body)?;
        assert_eq!(DeliveryAnswerContent::from_body(&body)?, content);
        // The tag is the last byte of a "not seen" entry: 2 is no tag.
        if let Some(tag) = body.last_mut() {
            *tag = 2;
        }
        assert!(DeliveryAnswerContent::from_body(&body).is_err());
        // Entries out of order, or repeated, are refused.
        for entries in [
            vec![(8, Possession::NotSeen), (7, Possession::NotSeen)],
            vec![(7, Possession::NotSeen), (7, Possession::NotSeen)],
        ] {
            let bad = DeliveryAnswerContent {
                entries,
                ..content.clone()
            };
            assert!(DeliveryAnswer::sign(&member, &bad).is_err());
        }
        Ok(())
    }
}
