//! Which raw observations an MLAT solution used (RFC-0171 §3.8.1). The signed raw observations
//! are the only exactly mergeable object, so a published solution names the exact set it was
//! solved from, and consumers merge solutions of one transmission by comparing sets: the same set
//! is a duplicate, a superset wins, and incomparable sets are never averaged or fused.
//!
//! An observation's identity is its receiver key, counter epoch, raw counter and message (§3.8).
//! Every observation in one set heard the same transmission, so a set holds the message once and
//! each observation as a `Reception` (receiver, epoch, counter). The set is kept in its one
//! canonical order, by (receiver key, epoch, counter), so the same observations are the same
//! bytes and the same hash whatever order an engine gathered them in.

use std::cmp::Ordering;

use blake2::{Blake2s256, Digest};

use crate::WireError;
use crate::batch::{Hash, domain};
use crate::key::PublicKey;

/// What an observation set's hash is computed under, so it can never equal any other hash.
const SET_DOMAIN: &[u8] = b"tally observation set";
/// What a clock model's sync citations are hashed under.
const CITATIONS_DOMAIN: &[u8] = b"tally sync citations";
/// A receiver's counter is 48 bits (BEAST's, and the batch's six bytes).
pub const COUNTER_LIMIT: u64 = 1 << 48;
/// The most observations one set may hold: its count is one byte on the wire.
pub const MAX_OBSERVATIONS: usize = u8::MAX as usize;
/// The longest message a set may name: its length is one byte on the wire.
pub const MAX_MESSAGE_LEN: usize = u8::MAX as usize;

/// One receiver's reception of a transmission: who heard it, and its raw counter at the time.
/// The message it heard is the set's.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Reception {
    pub receiver: PublicKey,
    /// The batch's `counter_epoch`: counters from different epochs never meet.
    pub epoch: u32,
    /// The receiver's 48-bit counter, raw.
    pub counter: u64,
}

impl Reception {
    /// The canonical encoding: key, epoch (four bytes), counter (six bytes), all big-endian.
    fn encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(self.receiver.as_bytes());
        out.extend_from_slice(&self.epoch.to_be_bytes());
        out.extend_from_slice(&self.counter.to_be_bytes()[2..]);
    }
}

/// How two observation sets stand to each other.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Relation {
    /// The same observations: two solutions over it are duplicates (or a fault, if they differ).
    Equal,
    /// Every observation of this set is in the other, which has more: the other's solution wins.
    Subset,
    /// This set holds every observation of the other and more: this solution wins.
    Superset,
    /// Neither holds the other, or they are of different messages. Never averaged or fused;
    /// whoever holds both solves their union.
    Incomparable,
}

/// The observations one solution used: one message, and the receptions of it, canonically sorted
/// and without repeats. Immutable once built, so it is always canonical.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ObservationSet {
    message: Vec<u8>,
    receptions: Vec<Reception>,
}

impl ObservationSet {
    /// Sorts the receptions canonically and drops repeats. Refuses an empty set, a counter that
    /// does not fit 48 bits, and a message or set too long for its one-byte length.
    pub fn new(message: Vec<u8>, mut receptions: Vec<Reception>) -> Result<Self, WireError> {
        if message.len() > MAX_MESSAGE_LEN {
            return Err(WireError::Oversize(message.len()));
        }
        if let Some(bad) = receptions.iter().find(|r| r.counter >= COUNTER_LIMIT) {
            return Err(WireError::Invalid {
                field: "reception counter",
                value: bad.counter,
            });
        }
        receptions.sort_unstable();
        receptions.dedup();
        if receptions.is_empty() {
            return Err(WireError::Invalid {
                field: "observation set size",
                value: 0,
            });
        }
        if receptions.len() > MAX_OBSERVATIONS {
            return Err(WireError::Oversize(receptions.len()));
        }
        Ok(Self {
            message,
            receptions,
        })
    }

    /// The transmission's bytes, as every receiver in the set heard them.
    pub fn message(&self) -> &[u8] {
        &self.message
    }

    /// In canonical order: by receiver key, then epoch, then counter.
    pub fn receptions(&self) -> &[Reception] {
        &self.receptions
    }

    /// The canonical encoding the hash is over: message length (one byte), message, count (one
    /// byte), then each reception as key (32), epoch (4), counter (6), in canonical order.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(2 + self.message.len() + self.receptions.len() * 42);
        // Both lengths were bounded to a byte when the set was built.
        out.push(self.message.len() as u8);
        out.extend_from_slice(&self.message);
        out.push(self.receptions.len() as u8);
        for reception in &self.receptions {
            reception.encode(&mut out);
        }
        out
    }

    /// BLAKE2s-256 over `"tally observation set" 0x00` and the canonical encoding. Stable: it
    /// depends on nothing but the message and the receptions, never on their order.
    pub fn hash(&self) -> Hash {
        Blake2s256::digest(domain(SET_DOMAIN, &self.canonical_bytes())).into()
    }

    /// How this set stands to `other`. Sets of different messages are `Incomparable`.
    pub fn relation(&self, other: &Self) -> Relation {
        if self.message != other.message {
            return Relation::Incomparable;
        }
        let (mine, theirs) = (&self.receptions, &other.receptions);
        let (mut i, mut j) = (0, 0);
        let (mut only_mine, mut only_theirs) = (false, false);
        while i < mine.len() && j < theirs.len() {
            match mine[i].cmp(&theirs[j]) {
                Ordering::Equal => {
                    i += 1;
                    j += 1;
                }
                Ordering::Less => {
                    only_mine = true;
                    i += 1;
                }
                Ordering::Greater => {
                    only_theirs = true;
                    j += 1;
                }
            }
        }
        only_mine |= i < mine.len();
        only_theirs |= j < theirs.len();
        match (only_mine, only_theirs) {
            (false, false) => Relation::Equal,
            (false, true) => Relation::Subset,
            (true, false) => Relation::Superset,
            (true, true) => Relation::Incomparable,
        }
    }

    pub fn is_subset_of(&self, other: &Self) -> bool {
        matches!(self.relation(other), Relation::Equal | Relation::Subset)
    }

    pub fn is_superset_of(&self, other: &Self) -> bool {
        other.is_subset_of(self)
    }

    /// The union of two sets of one message, which whoever holds both solves (§3.8.1); `None` for
    /// sets of different messages. Refused when the union is larger than one set may be.
    pub fn union(&self, other: &Self) -> Option<Result<Self, WireError>> {
        (self.message == other.message).then(|| {
            let mut receptions = self.receptions.clone();
            receptions.extend_from_slice(&other.receptions);
            Self::new(self.message.clone(), receptions)
        })
    }
}

/// One observation's full identity (§3.8), as a clock model cites the observations it was fitted
/// from: its reception and the BLAKE2s-256 of its message.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ObservationIdentity {
    pub reception: Reception,
    pub message: Hash,
}

impl ObservationIdentity {
    pub fn new(reception: Reception, message: &[u8]) -> Self {
        Self {
            reception,
            message: Blake2s256::digest(message).into(),
        }
    }
}

/// The observations a clock model was fitted from, cited by a hash and a count: enough to check a
/// claimed citation list against, without carrying the list in every model.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Citations {
    /// BLAKE2s-256 over `"tally sync citations" 0x00`, then each distinct identity in canonical
    /// order (by reception, then message hash) as key (32), epoch (4), counter (6), message
    /// hash (32).
    pub hash: Hash,
    pub count: u32,
}

impl Citations {
    /// Cites the identities given, in any order; repeats count once.
    pub fn of(identities: &[ObservationIdentity]) -> Result<Self, WireError> {
        let mut sorted = identities.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        let count = u32::try_from(sorted.len()).map_err(|_| WireError::Oversize(sorted.len()))?;
        let mut bytes = Vec::with_capacity(sorted.len() * 74);
        for identity in &sorted {
            identity.reception.encode(&mut bytes);
            bytes.extend_from_slice(&identity.message);
        }
        Ok(Self {
            hash: Blake2s256::digest(domain(CITATIONS_DOMAIN, &bytes)).into(),
            count,
        })
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::key::Identity;

    fn key(seed: u8) -> PublicKey {
        Identity::from_seed([seed; 32]).public()
    }

    fn reception(seed: u8, epoch: u32, counter: u64) -> Reception {
        Reception {
            receiver: key(seed),
            epoch,
            counter,
        }
    }

    fn set(receptions: &[Reception]) -> Result<ObservationSet, WireError> {
        ObservationSet::new(vec![0x8d, 1, 2, 3], receptions.to_vec())
    }

    #[test]
    fn the_order_given_never_changes_the_set_or_its_hash() -> Result<(), WireError> {
        let a = reception(1, 0, 10);
        let b = reception(1, 0, 9);
        let c = reception(1, 1, 0);
        let d = reception(2, 0, 5);
        let sorted = set(&[a, b, c, d])?;
        for order in [[d, c, b, a], [b, d, a, c], [c, a, d, b]] {
            let other = set(&order)?;
            assert_eq!(other, sorted);
            assert_eq!(other.hash(), sorted.hash());
        }
        let mut expected = vec![a, b, c, d];
        expected.sort();
        assert_eq!(sorted.receptions(), expected.as_slice());
        // Repeats count once.
        assert_eq!(set(&[a, a, b, c, d, d])?, sorted);
        Ok(())
    }

    #[test]
    fn the_canonical_order_is_key_then_epoch_then_counter() -> Result<(), WireError> {
        let low = key(1).min(key(2));
        let high = key(1).max(key(2));
        let at = |receiver, epoch, counter| Reception {
            receiver,
            epoch,
            counter,
        };
        let built = set(&[at(high, 0, 0), at(low, 2, 0), at(low, 1, 7), at(low, 1, 3)])?;
        assert_eq!(
            built.receptions(),
            &[at(low, 1, 3), at(low, 1, 7), at(low, 2, 0), at(high, 0, 0)]
        );
        Ok(())
    }

    #[test]
    fn set_relations() -> Result<(), WireError> {
        let (a, b, c) = (reception(1, 0, 1), reception(2, 0, 2), reception(3, 0, 3));
        let ab = set(&[a, b])?;
        let abc = set(&[c, b, a])?;
        let bc = set(&[b, c])?;
        assert_eq!(ab.relation(&set(&[b, a])?), Relation::Equal);
        assert_eq!(ab.relation(&abc), Relation::Subset);
        assert_eq!(abc.relation(&ab), Relation::Superset);
        assert_eq!(ab.relation(&bc), Relation::Incomparable);
        assert!(ab.is_subset_of(&abc) && ab.is_subset_of(&ab) && !abc.is_subset_of(&ab));
        assert!(abc.is_superset_of(&ab) && !ab.is_superset_of(&bc));
        let other_message = ObservationSet::new(vec![0x5d], vec![a, b])?;
        assert_eq!(ab.relation(&other_message), Relation::Incomparable);
        assert_eq!(ab.union(&bc).transpose()?, Some(abc));
        assert!(ab.union(&other_message).is_none());
        Ok(())
    }

    #[test]
    fn a_set_is_refused_empty_overlong_or_with_a_counter_past_48_bits() {
        assert!(set(&[]).is_err());
        assert!(set(&[reception(1, 0, COUNTER_LIMIT)]).is_err());
        assert!(set(&[reception(1, 0, COUNTER_LIMIT - 1)]).is_ok());
        assert!(ObservationSet::new(vec![0; 256], vec![reception(1, 0, 0)]).is_err());
        let many: Vec<Reception> = (0..256).map(|n| reception(1, 0, n)).collect();
        assert!(set(&many).is_err());
        assert!(set(&many[..255]).is_ok());
    }

    /// The hash is part of the protocol: a change to it is a change to every published solution's
    /// identity, so it is pinned to a known answer.
    #[test]
    fn the_hash_is_a_fixed_known_answer() -> Result<(), WireError> {
        let built = ObservationSet::new(
            vec![0x8d, 0x4c, 0xa2, 0x51],
            vec![reception(7, 3, 0x0102_0304_0506), reception(9, 0, 42)],
        )?;
        assert_eq!(hex(&built.hash()), KNOWN_SET_HASH);
        let cited = Citations::of(&[
            ObservationIdentity::new(reception(9, 0, 42), b"two"),
            ObservationIdentity::new(reception(7, 3, 1), b"one"),
        ])?;
        assert_eq!(cited.count, 2);
        assert_eq!(hex(&cited.hash), KNOWN_CITATIONS_HASH);
        Ok(())
    }

    /// Computed independently (Python `hashlib.blake2s` over the documented encoding).
    const KNOWN_SET_HASH: &str = "f91613438be4e90325418f6c0cda7777a536213f36db26dfea784cad146a935e";
    const KNOWN_CITATIONS_HASH: &str =
        "9e8519b5a42d6f391497ccf32615ab54c7a08673534cc915623fa85269de31a2";

    #[test]
    fn citations_ignore_order_and_repeats() -> Result<(), WireError> {
        let one = ObservationIdentity::new(reception(1, 0, 1), b"one");
        let two = ObservationIdentity::new(reception(2, 0, 1), b"two");
        assert_eq!(
            Citations::of(&[one, two])?,
            Citations::of(&[two, one, two])?
        );
        assert_ne!(Citations::of(&[one])?, Citations::of(&[two])?);
        Ok(())
    }

    pub(crate) fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }
}
