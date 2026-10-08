//! Answering delivery checks (RFC-0174 §2.2): the relay keeps the recent batches it forwards, by
//! (receiver, boot, sequence), long enough for a feeder's check (`HELD_FOR_MS`, bounded by
//! `HELD_BYTES`), and answers a `DeliveryQuery` with a signed `DeliveryAnswer`: per batch asked,
//! the proof of possession (`tally_wire::possession_proof`) or "not seen", or, for a feeder of an
//! area it does not take, that it does not take it. Its answers are also evidence for its
//! clients' credit (`credit`).
//!
//! **"Not seen" is said only when it is known.** A batch the relay once held and has since let go
//! (its bytes or its age ran out) can no longer be proved, and it was seen, so it is neither proved
//! nor denied: its sequence is left out of the answer, which a feeder counts as not proved, and
//! which is no signed claim against anyone. Per stream (receiver and boot) the relay keeps the
//! horizon below which it may have let a batch go; below it a sequence not held is left out, at or
//! above it a sequence not held was never seen. A stream silent for `STREAM_MEMORY_MS` is
//! forgotten, so "not seen" for a stream the relay holds nothing of means not seen within that
//! time (the check asks about recent batches); a stream forgotten sooner, to bound memory, makes
//! every unknown stream unanswerable until that time has passed.

use std::collections::{BTreeSet, HashMap, VecDeque};
use std::sync::Mutex;

use tally_wire::{
    Batch, DeliveryAnswer, DeliveryAnswerContent, DeliveryQuery, Identity, Possession, PublicKey,
    Region, possession_proof,
};

use crate::selection::Selection;

/// The most bytes of batches held for proofs. About 3 KB a feeder a second (RFC-0174 §1), so this
/// holds ten minutes of some 35 feeders, or two minutes of 175.
pub const HELD_BYTES: usize = 64 * 1024 * 1024;
/// How long a batch is held for a feeder's check (a few minutes after it is sent, §2.2).
pub const HELD_FOR_MS: u64 = 10 * 60 * 1000;
/// The most streams (receiver and boot) whose horizon is remembered.
pub const STREAMS_REMEMBERED: usize = 100_000;
/// How long a silent stream's horizon is remembered: what "not seen" of an unknown stream means.
pub const STREAM_MEMORY_MS: u64 = 60 * 60 * 1000;

type StreamKey = (PublicKey, u64);

#[derive(Default)]
pub struct Delivery {
    state: Mutex<State>,
}

#[derive(Default)]
struct State {
    batches: HashMap<(StreamKey, u64), Batch>,
    /// Held batches in the order they came, for letting go oldest first.
    arrivals: VecDeque<Arrival>,
    bytes: usize,
    streams: HashMap<StreamKey, Stream>,
    /// Streams by when they last held a batch: the order they are forgotten in.
    recency: BTreeSet<(u64, StreamKey)>,
    /// Until then a stream the relay knows nothing of may be one it forgot early.
    unsure_until_ms: u64,
}

struct Arrival {
    stream: StreamKey,
    sequence: u64,
    held_ms: u64,
}

struct Stream {
    /// Sequences below this may have been held and let go.
    horizon: u64,
    last_ms: u64,
    held: BTreeSet<u64>,
}

/// What the relay can say of one sequence.
enum Said {
    Proved(Batch),
    NotSeen,
    /// Held once and let go, or of a stream it may have forgotten: nothing to say.
    Unknown,
}

impl Delivery {
    pub fn new() -> Self {
        Self::default()
    }

    /// A receiver's batch the relay forwarded: kept for proofs, until `HELD_FOR_MS` or
    /// `HELD_BYTES` lets it go, oldest first.
    pub fn hold(&self, batch: &Batch, now_ms: u64) {
        let Ok(receiver) = batch.receiver() else {
            return;
        };
        let Ok(mut state) = self.state.lock() else {
            return;
        };
        state.hold(receiver, batch, now_ms);
    }

    /// The signed answer to `query` from a feeder whose signed location falls at `point`: per
    /// sequence asked, a proof for a batch held, "not seen" for one known never to have come, and
    /// nothing for one held once and let go; or, outside the areas the relay takes, that it does
    /// not take the area and nothing else.
    pub fn answer_at(
        &self,
        selection: &Selection,
        identity: Option<&Identity>,
        query: &DeliveryQuery,
        point: Option<Region>,
        now_ms: u64,
    ) -> Option<DeliveryAnswer> {
        let identity = identity?;
        let takes_area = selection.takes_receiver(point);
        let entries = if takes_area {
            let state = self.state.lock().ok()?;
            let stream = (query.receiver, query.boot_id);
            query
                .ranges
                .iter()
                .flat_map(|range| range.first..=range.last)
                .filter_map(|sequence| match state.said(stream, sequence, now_ms) {
                    Said::Proved(batch) => Some((
                        sequence,
                        Possession::Proved(possession_proof(&query.nonce, &batch)),
                    )),
                    Said::NotSeen => Some((sequence, Possession::NotSeen)),
                    Said::Unknown => None,
                })
                .collect()
        } else {
            Vec::new()
        };
        let content = DeliveryAnswerContent {
            nonce: query.nonce,
            receiver: query.receiver,
            boot_id: query.boot_id,
            issued_ms: now_ms,
            takes_area,
            entries,
        };
        DeliveryAnswer::sign(identity, &content).ok()
    }

    /// Bytes of batches held now.
    pub fn held_bytes(&self) -> usize {
        self.state.lock().map_or(0, |state| state.bytes)
    }

    /// Streams remembered now.
    pub fn streams(&self) -> usize {
        self.state.lock().map_or(0, |state| state.streams.len())
    }
}

impl State {
    fn hold(&mut self, receiver: PublicKey, batch: &Batch, now_ms: u64) {
        let stream = (receiver, batch.boot_id());
        let sequence = batch.sequence();
        if self.batches.contains_key(&(stream, sequence)) {
            return;
        }
        let entry = self.streams.entry(stream).or_insert(Stream {
            horizon: 0,
            last_ms: now_ms,
            held: BTreeSet::new(),
        });
        let before = entry.last_ms;
        entry.last_ms = entry.last_ms.max(now_ms);
        entry.held.insert(sequence);
        let after = entry.last_ms;
        self.recency.remove(&(before, stream));
        self.recency.insert((after, stream));
        self.bytes += batch.as_bytes().len();
        self.batches.insert((stream, sequence), batch.clone());
        self.arrivals.push_back(Arrival {
            stream,
            sequence,
            held_ms: now_ms,
        });
        self.let_go(now_ms);
    }

    /// Lets go the oldest batches past the age or the bytes, and the streams past their count or
    /// their memory.
    fn let_go(&mut self, now_ms: u64) {
        while let Some(oldest) = self.arrivals.front() {
            let aged = now_ms.saturating_sub(oldest.held_ms) > HELD_FOR_MS;
            if !aged && self.bytes <= HELD_BYTES {
                break;
            }
            if let Some(arrival) = self.arrivals.pop_front() {
                self.drop_batch(arrival.stream, arrival.sequence);
            }
        }
        while self.streams.len() > STREAMS_REMEMBERED {
            let Some((last_ms, stream)) = self.recency.pop_first() else {
                break;
            };
            // Forgotten early: until its memory would have run out, an unknown stream may be it.
            self.unsure_until_ms = self.unsure_until_ms.max(last_ms + STREAM_MEMORY_MS);
            self.forget_stream(stream);
        }
        while let Some((last_ms, stream)) = self.recency.first().copied() {
            if now_ms.saturating_sub(last_ms) <= STREAM_MEMORY_MS {
                break;
            }
            self.recency.pop_first();
            self.forget_stream(stream);
        }
    }

    fn drop_batch(&mut self, stream: StreamKey, sequence: u64) {
        if let Some(batch) = self.batches.remove(&(stream, sequence)) {
            self.bytes -= batch.as_bytes().len();
        }
        if let Some(entry) = self.streams.get_mut(&stream) {
            entry.held.remove(&sequence);
            entry.horizon = entry.horizon.max(sequence.saturating_add(1));
        }
    }

    fn forget_stream(&mut self, stream: StreamKey) {
        if let Some(entry) = self.streams.remove(&stream) {
            for sequence in entry.held {
                if let Some(batch) = self.batches.remove(&(stream, sequence)) {
                    self.bytes -= batch.as_bytes().len();
                }
            }
        }
        // Its arrivals are skipped when they reach the front (`drop_batch` finds nothing).
    }

    fn said(&self, stream: StreamKey, sequence: u64, now_ms: u64) -> Said {
        if let Some(batch) = self.batches.get(&(stream, sequence)) {
            return Said::Proved(batch.clone());
        }
        match self.streams.get(&stream) {
            Some(entry) if sequence >= entry.horizon => Said::NotSeen,
            Some(_) => Said::Unknown,
            None if now_ms < self.unsure_until_ms => Said::Unknown,
            None => Said::NotSeen,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tally_wire::rendezvous::area_of;
    use tally_wire::{BatchContent, Location, SequenceRange};

    type Result = std::result::Result<(), String>;

    fn text(error: impl std::fmt::Display) -> String {
        error.to_string()
    }

    fn here() -> Location {
        Location {
            lat_e7: 337_490_000,
            lon_e7: -843_880_000,
            alt_m: 0,
            precision_m: 0,
        }
    }

    fn batch(feeder: &Identity, boot_id: u64, sequence: u64) -> std::result::Result<Batch, String> {
        Batch::sign(
            feeder,
            &BatchContent {
                boot_id,
                sequence,
                counter_epoch: 0,
                wall_ms: sequence,
                dropped: 0,
                previous: [0; 32],
                observations: Vec::new(),
            },
        )
        .map_err(text)
    }

    /// A batch's bytes, unsigned (the hub verifies before it holds; holding reads only the
    /// prefix), `len` long: for floods, which signing would make slow.
    fn unsigned(
        key: &PublicKey,
        boot_id: u64,
        sequence: u64,
        len: usize,
    ) -> std::result::Result<Batch, String> {
        let mut bytes = vec![1];
        bytes.extend_from_slice(key.as_bytes());
        bytes.extend_from_slice(&boot_id.to_be_bytes());
        bytes.extend_from_slice(&sequence.to_be_bytes());
        bytes.resize(len.max(bytes.len() + 64), 0);
        Batch::from_bytes(bytes).map_err(text)
    }

    fn query(feeder: &Identity, boot_id: u64, first: u64, last: u64) -> DeliveryQuery {
        DeliveryQuery {
            nonce: [first as u8 ^ 0x5a; 32],
            receiver: feeder.public(),
            boot_id,
            ranges: vec![SequenceRange { first, last }],
        }
    }

    fn taking_here() -> std::result::Result<(Selection, Region), String> {
        let selection = Selection::new();
        selection.set_taken(vec![area_of(&here()).map_err(text)?]);
        Ok((selection, Region::point(&here()).map_err(text)?))
    }

    #[test]
    fn proofs_verify_against_the_batch_and_a_batch_never_held_is_not_seen() -> Result {
        let relay = Identity::generate().map_err(text)?;
        let feeder = Identity::generate().map_err(text)?;
        let (selection, point) = taking_here()?;
        let delivery = Delivery::new();
        let held: Vec<Batch> = (10..13)
            .map(|seq| batch(&feeder, 4, seq))
            .collect::<std::result::Result<_, _>>()?;
        for batch in &held {
            delivery.hold(batch, 1_000);
        }
        let asked = query(&feeder, 4, 9, 14);
        let answer = delivery
            .answer_at(&selection, Some(&relay), &asked, Some(point), 2_000)
            .ok_or("no answer")?;
        answer.verify().map_err(text)?;
        assert_eq!(answer.signer().map_err(text)?, relay.public());
        let content = answer.content().map_err(text)?;
        assert!(content.takes_area);
        assert_eq!(content.nonce, asked.nonce);
        let mut expected = vec![(9, Possession::NotSeen)];
        expected.extend(held.iter().map(|batch| {
            (
                batch.sequence(),
                Possession::Proved(possession_proof(&asked.nonce, batch)),
            )
        }));
        expected.extend([(13, Possession::NotSeen), (14, Possession::NotSeen)]);
        assert_eq!(content.entries, expected);
        // A proof is bound to the nonce: an earlier answer is no proof for a fresh query.
        let fresh = DeliveryQuery {
            nonce: [1; 32],
            ..asked.clone()
        };
        let again = delivery
            .answer_at(&selection, Some(&relay), &fresh, Some(point), 2_000)
            .ok_or("no answer")?
            .content()
            .map_err(text)?;
        assert_ne!(again.entries[1], content.entries[1]);
        assert_eq!(
            again.entries[1],
            (
                10,
                Possession::Proved(possession_proof(&fresh.nonce, &held[0]))
            )
        );
        // Another boot of the same feeder, never held: not seen.
        let other_boot = delivery
            .answer_at(
                &selection,
                Some(&relay),
                &query(&feeder, 5, 10, 10),
                Some(point),
                2_000,
            )
            .ok_or("no answer")?
            .content()
            .map_err(text)?;
        assert_eq!(other_boot.entries, vec![(10, Possession::NotSeen)]);
        Ok(())
    }

    #[test]
    fn a_feeder_outside_the_relays_areas_gets_takes_area_false() -> Result {
        let relay = Identity::generate().map_err(text)?;
        let feeder = Identity::generate().map_err(text)?;
        let (selection, _) = taking_here()?;
        let delivery = Delivery::new();
        delivery.hold(&batch(&feeder, 1, 1)?, 1_000);
        let london = Region::point(&Location {
            lat_e7: 515_000_000,
            lon_e7: -1_200_000,
            alt_m: 0,
            precision_m: 0,
        })
        .map_err(text)?;
        for point in [Some(london), None] {
            let content = delivery
                .answer_at(
                    &selection,
                    Some(&relay),
                    &query(&feeder, 1, 1, 1),
                    point,
                    2_000,
                )
                .ok_or("no answer")?
                .content()
                .map_err(text)?;
            assert!(!content.takes_area);
            assert!(content.entries.is_empty(), "nothing said of the batches");
        }
        // With no key to sign with, nothing is said at all.
        assert!(
            delivery
                .answer_at(&selection, None, &query(&feeder, 1, 1, 1), None, 2_000)
                .is_none()
        );
        Ok(())
    }

    #[test]
    fn a_batch_let_go_is_neither_proved_nor_denied() -> Result {
        let relay = Identity::generate().map_err(text)?;
        let feeder = Identity::generate().map_err(text)?;
        let (selection, point) = taking_here()?;
        let delivery = Delivery::new();
        delivery.hold(&batch(&feeder, 1, 1)?, 1_000);
        delivery.hold(&batch(&feeder, 1, 2)?, 1_000 + HELD_FOR_MS);
        // Past its age, sequence 1 is let go when the next batch comes.
        delivery.hold(&batch(&feeder, 1, 3)?, 2_000 + HELD_FOR_MS);
        let content = delivery
            .answer_at(
                &selection,
                Some(&relay),
                &query(&feeder, 1, 0, 4),
                Some(point),
                3_000 + HELD_FOR_MS,
            )
            .ok_or("no answer")?
            .content()
            .map_err(text)?;
        let said: Vec<u64> = content
            .entries
            .iter()
            .map(|(sequence, _)| *sequence)
            .collect();
        // 0 and 1 are below the horizon: nothing said. 2 and 3 proved, 4 not seen.
        assert_eq!(said, vec![2, 3, 4]);
        assert!(matches!(content.entries[0].1, Possession::Proved(_)));
        assert_eq!(content.entries[2], (4, Possession::NotSeen));
        Ok(())
    }

    #[test]
    fn memory_stays_bounded_under_a_flood() -> Result {
        let relay = Identity::generate().map_err(text)?;
        let (selection, point) = taking_here()?;
        let delivery = Delivery::new();
        // A flood of large batches from many keys, all at one instant (age lets nothing go).
        let flooders: Vec<Identity> = (0..8_u8)
            .map(|seed| Identity::from_seed([seed; 32]))
            .collect();
        let one = 64 * 1024;
        let count = HELD_BYTES / one + 200;
        for index in 0..count {
            let feeder = &flooders[index % flooders.len()];
            delivery.hold(&unsigned(&feeder.public(), 0, index as u64, one)?, 5_000);
            assert!(delivery.held_bytes() <= HELD_BYTES);
        }
        assert!(
            delivery.held_bytes() + one > HELD_BYTES,
            "held to the bound"
        );
        // The oldest were let go and are not denied; the newest are proved.
        let early = delivery
            .answer_at(
                &selection,
                Some(&relay),
                &query(&flooders[0], 0, 0, 0),
                Some(point),
                6_000,
            )
            .ok_or("no answer")?
            .content()
            .map_err(text)?;
        assert!(early.entries.is_empty());
        let last = (count - 1) as u64;
        let newest = &flooders[(count - 1) % flooders.len()];
        let late = delivery
            .answer_at(
                &selection,
                Some(&relay),
                &query(newest, 0, last, last),
                Some(point),
                6_000,
            )
            .ok_or("no answer")?
            .content()
            .map_err(text)?;
        assert!(matches!(late.entries[..], [(_, Possession::Proved(_))]));
        Ok(())
    }

    #[test]
    fn streams_are_bounded_and_an_early_forgotten_one_is_not_denied() -> Result {
        let relay = Identity::generate().map_err(text)?;
        let (selection, point) = taking_here()?;
        let delivery = Delivery::new();
        let feeder = Identity::from_seed([3; 32]);
        // One stream per boot, more than are remembered.
        for boot in 0..(STREAMS_REMEMBERED as u64 + 10) {
            delivery.hold(&unsigned(&feeder.public(), boot, 0, 0)?, 1_000 + boot);
        }
        assert!(delivery.streams() <= STREAMS_REMEMBERED);
        // Boot 0 was forgotten early: it is not denied.
        let content = delivery
            .answer_at(
                &selection,
                Some(&relay),
                &query(&feeder, 0, 0, 0),
                Some(point),
                200_000,
            )
            .ok_or("no answer")?
            .content()
            .map_err(text)?;
        assert!(content.entries.is_empty());
        // Once its memory would have run out, an unknown stream is not seen again.
        let later = 1_000 + STREAM_MEMORY_MS + STREAMS_REMEMBERED as u64 + 20;
        let content = delivery
            .answer_at(
                &selection,
                Some(&relay),
                &query(&feeder, 0, 0, 0),
                Some(point),
                later,
            )
            .ok_or("no answer")?
            .content()
            .map_err(text)?;
        assert_eq!(content.entries, vec![(0, Possession::NotSeen)]);
        Ok(())
    }
}
