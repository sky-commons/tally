//! The delivery check (RFC-0174 §2.2, RFC-0178 §7): a feeder asks members of its area's sharing
//! group, on distinct networks, whether they took in a few of its recent batches, by (boot,
//! sequence). A member answers with the tag it made when the batch arrived, which only a relay
//! that held the batch's bytes and the feeder's key for it could compute, and signs its answer;
//! one that does not take the feeder's area says so, which is not the same as "not seen". A
//! majority of networks proving a batch is delivery; one member's word alone convicts no relay.
//!
//! # Tags made on arrival
//!
//! Every key period (`KEY_PERIOD_MS`) the feeder gives every member it may ask a key of that
//! member's own ([`TagKeys`]): the key in force now and the next one, signed by the feeder and
//! carried in a [`DeliveryQuery`] over a `Probe` session. A member that holds a key for a feeder
//! tags each of that feeder's batches as it arrives, [`delivery_tag`] of the key and the batch's
//! signed bytes, keeps the 16-byte tag with the key's id for `TAG_WINDOW_MS`, and lets the bytes
//! go. An audit later names batches by boot and sequence; the member answers with the tags; the
//! feeder, which still holds the audited batches and every key it gave, recomputes them.
//!
//! - The tag needs the bytes: it is a keyed hash over all of them, so a member that saw only a
//!   batch's hash (a piece manifest lists every hash) cannot make it.
//! - The keys are per feeder and per member, and handed out on a schedule that has nothing to do
//!   with audits, so nothing a member sees says when an audit runs or which batches it covers.
//! - The keys rotate: a tag counts only under a key that was in force when the batch was sent
//!   ([`tag_keys_for`]), so a tag made under an old key (a replay) proves nothing.
//! - `TAG_WINDOW_MS` is the one window both sides use: a member keeps tags that long after
//!   arrival, and a feeder asks only about batches it sent less than that long ago.

use std::ops::RangeInclusive;

use blake2::{Blake2s256, Digest};

use crate::WireError;
use crate::batch::Hash;
use crate::key::{KEY_LEN, PublicKey};
use crate::record::Body;
use crate::signed::{
    Check, Checked, Fields, Unchecked, count_u16, put_blob, read_blob, read_count, signed_record,
};

/// The most sequence ranges one query names.
pub const MAX_RANGES: usize = 16;
/// The most batches one query asks about, over all its ranges: a sample, never a stream.
pub const MAX_SEQUENCES: u64 = 64;
/// How long a member keeps a batch's tag after it arrived, and how long after sending a batch a
/// feeder may still ask about it: one constant, so the two sides cannot drift.
pub const TAG_WINDOW_MS: u64 = 5 * 60 * 1000;
/// How long one tag key is in force. A grant names the key in force and the next, so one grant
/// lost still leaves a member a key for a whole period.
pub const KEY_PERIOD_MS: u64 = TAG_WINDOW_MS;
/// The bytes of a tag: BLAKE2s-256 truncated. A forger guesses one in 2^128.
pub const TAG_LEN: usize = 16;
/// The bytes of a tag key.
pub const TAG_KEY_LEN: usize = 32;
const TAG_DOMAIN: &[u8] = b"tally delivery tag";

/// A batch's tag under one member's key.
pub type Tag = [u8; TAG_LEN];

/// The key period a wall-clock instant falls in: a tag key's id.
pub fn key_period(wall_ms: u64) -> u32 {
    u32::try_from(wall_ms / KEY_PERIOD_MS).unwrap_or(u32::MAX)
}

/// The ids of the keys a tag of a batch sent at `sent_ms` may be under: the period it was sent in,
/// and one either side, for a member whose switch to the next key came a little early or late (it
/// switches by its own clock, `switch_in_ms` after the grant arrived). A tag under any other key
/// proves nothing.
pub fn tag_keys_for(sent_ms: u64) -> RangeInclusive<u32> {
    let period = key_period(sent_ms);
    period.saturating_sub(1)..=period.saturating_add(1)
}

/// The tag of a batch's signed bytes under a member's key: BLAKE2s-256 over `"tally delivery
/// tag" 0x00`, the key and the bytes, its first `TAG_LEN` bytes. Only one holding both the key
/// and every byte of the batch computes it.
pub fn delivery_tag(key: &[u8; TAG_KEY_LEN], batch: &[u8]) -> Tag {
    let mut hasher = Blake2s256::new();
    hasher.update(TAG_DOMAIN);
    hasher.update([0]);
    hasher.update(key);
    hasher.update(batch);
    let digest: Hash = hasher.finalize().into();
    let mut tag = [0; TAG_LEN];
    tag.copy_from_slice(&digest[..TAG_LEN]);
    tag
}

/// One tag key and its id (its key period).
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct TagKey {
    pub id: u32,
    pub key: [u8; TAG_KEY_LEN],
}

impl std::fmt::Debug for TagKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // A secret: never printed.
        write!(f, "TagKey({}, ..)", self.id)
    }
}

/// A feeder's grant of tag keys to one member: the key in force now, the next, and how long until
/// the next takes over.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TagKeysContent {
    /// The member the keys are for: no other member takes them.
    pub member: PublicKey,
    pub current: TagKey,
    /// `current.id + 1`.
    pub next: TagKey,
    /// After this long, by the member's clock from when the grant arrived, `next` is in force; one
    /// period after that, neither.
    pub switch_in_ms: u64,
}

impl Check for TagKeysContent {
    /// The next key is the one after the current, and the switch is at most one period away.
    fn check(&self) -> Result<(), WireError> {
        if self.current.id.checked_add(1) != Some(self.next.id) {
            return Err(WireError::Invalid {
                field: "next tag key id",
                value: u64::from(self.next.id),
            });
        }
        if self.switch_in_ms > KEY_PERIOD_MS {
            return Err(WireError::Invalid {
                field: "tag key switch",
                value: self.switch_in_ms,
            });
        }
        Ok(())
    }
}

impl Fields for TagKeysContent {
    fn write(keys: Checked<'_, Self>, out: &mut Vec<u8>) -> Result<(), WireError> {
        out.extend_from_slice(keys.member.as_bytes());
        for key in [keys.current, keys.next] {
            out.extend_from_slice(&key.id.to_be_bytes());
            out.extend_from_slice(&key.key);
        }
        out.extend_from_slice(&keys.switch_in_ms.to_be_bytes());
        Ok(())
    }

    fn read(reader: &mut Body<'_>) -> Result<Unchecked<Self>, WireError> {
        let member = PublicKey::from_slice(reader.bytes(KEY_LEN)?)?;
        let mut key = || -> Result<TagKey, WireError> {
            Ok(TagKey {
                id: reader.u32()?,
                key: reader.array()?,
            })
        };
        let current = key()?;
        let next = key()?;
        Ok(Unchecked::new(Self {
            member,
            current,
            next,
            switch_in_ms: reader.u64()?,
        }))
    }
}

signed_record!(
    /// A feeder's signed grant of tag keys to one member, carried in a `DeliveryQuery`. Signed, so
    /// no one but the feeder can give a member keys for its batches (which would make every tag
    /// that member made for it fail, and void its audits).
    TagKeys,
    TagKeysContent,
    b"tally delivery tag keys",
    1,
    1 + KEY_LEN + KEY_LEN + 2 * (4 + TAG_KEY_LEN) + 8 + 64
);

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

/// A feeder's word to a member: its tag keys for that member, and, in an audit, the batches it
/// asks about (unsigned itself: the nonce binds the answer to it, and the keys are signed).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeliveryQuery {
    /// Fresh for every query.
    pub nonce: Hash,
    /// The feeder's own key: whose batches.
    pub receiver: PublicKey,
    pub boot_id: u64,
    /// Ascending and disjoint, at most `MAX_RANGES`, at most `MAX_SEQUENCES` in all; none when the
    /// query only carries keys.
    pub ranges: Vec<SequenceRange>,
    /// The feeder's grant of tag keys to the member asked, signed by `receiver`.
    pub keys: Option<TagKeys>,
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
    /// `MAX_SEQUENCES` batches in all, every count exact (no range or sum wraps); keys, if any,
    /// signed by the receiver (whether the signature holds is the member's to verify).
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
        if let Some(keys) = &self.keys
            && keys.signer()? != self.receiver
        {
            return Err(WireError::Key(
                "tag keys signed by another key than the receiver's".to_owned(),
            ));
        }
        Ok(())
    }
}

/// Whether a query carries keys, on the wire.
const NO_KEYS: u8 = 0;
const KEYS: u8 = 1;

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
        match &query.keys {
            Some(keys) => {
                out.push(KEYS);
                put_blob(out, keys.as_bytes())?;
            }
            None => out.push(NO_KEYS),
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
        let keys = match reader.u8()? {
            NO_KEYS => None,
            KEYS => {
                let bytes = read_blob(reader)?;
                if bytes.len() > TagKeys::MAX_LEN {
                    return Err(WireError::Oversize(bytes.len()));
                }
                Some(TagKeys::from_bytes(bytes)?)
            }
            other => {
                return Err(WireError::Invalid {
                    field: "delivery query keys flag",
                    value: u64::from(other),
                });
            }
        };
        Ok(Unchecked::new(Self {
            nonce,
            receiver,
            boot_id,
            ranges,
            keys,
        }))
    }
}

/// What a member says of one batch.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Possession {
    /// It took the batch in while it held the feeder's key `key`: the tag it made then.
    Proved { key: u32, tag: Tag },
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
/// One entry's bytes at most: sequence, possession tag, key id, tag.
const ENTRY_MAX: usize = 8 + 1 + 4 + TAG_LEN;

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
                Possession::Proved { key, tag } => {
                    out.push(TAG_PROVED);
                    out.extend_from_slice(&key.to_be_bytes());
                    out.extend_from_slice(tag);
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
                    TAG_PROVED => Possession::Proved {
                        key: reader.u32()?,
                        tag: reader.array()?,
                    },
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
    1 + KEY_LEN + 32 + KEY_LEN + 8 + 8 + 1 + 2 + MAX_SEQUENCES as usize * ENTRY_MAX + 64
);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::batch::{Batch, BatchContent};
    use crate::key::Identity;

    fn batch(feeder: &Identity, sequence: u64) -> Result<Batch, WireError> {
        Batch::sign(
            feeder,
            &BatchContent {
                boot_id: 3,
                sequence,
                counter_epoch: 0,
                wall_ms: 1,
                dropped: 0,
                previous: [0; 32],
                observations: Vec::new(),
            },
        )
    }

    fn grant(feeder: &Identity, member: PublicKey) -> Result<TagKeys, WireError> {
        TagKeys::sign(
            feeder,
            &TagKeysContent {
                member,
                current: TagKey {
                    id: 7,
                    key: [1; TAG_KEY_LEN],
                },
                next: TagKey {
                    id: 8,
                    key: [2; TAG_KEY_LEN],
                },
                switch_in_ms: 1_000,
            },
        )
    }

    #[test]
    fn a_query_with_keys_and_its_signed_answer_round_trip() -> Result<(), WireError> {
        let feeder = Identity::generate()?;
        let member = Identity::generate()?;
        let batch = batch(&feeder, 41)?;
        let keys = grant(&feeder, member.public())?;
        keys.verify()?;
        assert_eq!(keys.content()?.next.id, 8);
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
            keys: Some(keys.clone()),
        };
        assert_eq!(DeliveryQuery::from_body(&query.to_bytes()?)?, query);
        let keyless = DeliveryQuery {
            keys: None,
            ..query.clone()
        };
        assert_eq!(DeliveryQuery::from_body(&keyless.to_bytes()?)?, keyless);
        let tag = delivery_tag(&[1; TAG_KEY_LEN], batch.as_bytes());
        let content = DeliveryAnswerContent {
            nonce: query.nonce,
            receiver: feeder.public(),
            boot_id: 3,
            issued_ms: 5,
            takes_area: true,
            entries: vec![
                (40, Possession::NotSeen),
                (41, Possession::Proved { key: 7, tag }),
                (50, Possession::NotSeen),
            ],
        };
        let answer = DeliveryAnswer::sign(&member, &content)?;
        let back = DeliveryAnswer::from_bytes(answer.as_bytes().to_vec())?;
        back.verify()?;
        assert_eq!(back.content()?, content);
        // A full answer fits its bound.
        let full = DeliveryAnswerContent {
            entries: (0..MAX_SEQUENCES)
                .map(|sequence| (sequence, Possession::Proved { key: 7, tag }))
                .collect(),
            ..content.clone()
        };
        assert!(DeliveryAnswer::sign(&member, &full).is_ok());
        // Too many asked, or out of order, is refused.
        let mut greedy = query.clone();
        greedy.ranges = vec![SequenceRange {
            first: 0,
            last: 100,
        }];
        assert!(greedy.to_bytes().is_err());
        let mut backwards = query.clone();
        backwards.ranges.reverse();
        assert!(backwards.to_bytes().is_err());
        // Keys signed by anyone but the receiver are refused on both sides.
        let forged = DeliveryQuery {
            keys: Some(grant(&Identity::generate()?, member.public())?),
            ..query
        };
        assert!(forged.to_bytes().is_err());
        // Outside its area a member says nothing of the batches.
        let outside = DeliveryAnswerContent {
            takes_area: false,
            ..content
        };
        assert!(DeliveryAnswer::sign(&member, &outside).is_err());
        Ok(())
    }

    #[test]
    fn a_grants_ids_follow_each_other_and_its_switch_is_within_a_period() -> Result<(), WireError> {
        let feeder = Identity::generate()?;
        let member = Identity::generate()?.public();
        let mut content = grant(&feeder, member)?.content()?;
        content.next.id = 9;
        assert!(TagKeys::sign(&feeder, &content).is_err());
        content.next.id = 8;
        content.switch_in_ms = KEY_PERIOD_MS + 1;
        assert!(TagKeys::sign(&feeder, &content).is_err());
        // Never printed.
        assert!(!format!("{:?}", content.current).contains("[1"));
        Ok(())
    }

    #[test]
    fn a_tag_needs_the_key_and_every_byte_and_rotation_bounds_it() -> Result<(), WireError> {
        let feeder = Identity::generate()?;
        let one = batch(&feeder, 1)?;
        let other = batch(&feeder, 2)?;
        let key = [5; TAG_KEY_LEN];
        let tag = delivery_tag(&key, one.as_bytes());
        assert_eq!(tag, delivery_tag(&key, one.as_bytes()));
        assert_ne!(tag, delivery_tag(&[6; TAG_KEY_LEN], one.as_bytes()));
        assert_ne!(tag, delivery_tag(&key, other.as_bytes()));
        // What a piece manifest lists of the batch is its hash: no tag made from the hash (or any
        // prefix of the bytes) is the batch's.
        assert_ne!(tag, delivery_tag(&key, &one.hash()));
        let bytes = one.as_bytes();
        assert_ne!(tag, delivery_tag(&key, &bytes[..bytes.len() - 1]));
        // Keys in force for a batch: its period and one either side.
        let sent = 10 * KEY_PERIOD_MS + 5;
        assert_eq!(tag_keys_for(sent), 9..=11);
        assert_eq!(tag_keys_for(0), 0..=1);
        assert!(!tag_keys_for(sent + 3 * KEY_PERIOD_MS).contains(&10));
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
        body.push(NO_KEYS);
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
                keys: None,
            };
            assert!(query.to_bytes().is_err(), "{ranges:?}");
        }
        assert!(DeliveryQuery::from_body(&query_body(&[(0, 63)])?).is_ok());
        // A keys flag that is neither is refused.
        let mut body = query_body(&[(0, 0)])?;
        if let Some(flag) = body.last_mut() {
            *flag = 2;
        }
        assert!(DeliveryQuery::from_body(&body).is_err());
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
