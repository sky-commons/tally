//! Hands a receiver's receptions to its mlat-client in time with every other receiver's.
//!
//! mlat-server groups the copies of one message by when they reach it: the first copy opens a
//! group and the group is solved 0.9 s later (`MLAT_DELAY` in mlat/config.py, `Cohort` and
//! `receiver_mlat` in mlat/mlattrack.py), so a copy that arrives later is lost to it. mlat-client
//! forwards a reception within a quarter second of hearing it. A Tally receiver's receptions
//! arrive a batch, about a second, at a time, through relays, so sent as they arrive the copies
//! would be up to a second apart. The engine therefore replays each receiver's receptions on one
//! shared timeline: each is released a fixed `delay` after the moment the engine estimates it was
//! heard, so copies of one transmission from every receiver reach the server together.
//!
//! The estimate needs no receiver's wall clock (a batch's `wall_ms` "can be wrong"). For each
//! batch, the engine's own arrival time less the newest counter in it is an offset between the
//! receiver's clock and the engine's; it is never less than the true offset (a batch is sealed
//! after its last reception and then travels), and a busy receiver's batches come close to it, so
//! the smallest offset of the last minute is the estimate. The same offsets give the check
//! mlat-client makes on every counter against its own clock (`timestamp_check` in
//! modes_reader.c): a counter that runs ahead of the engine's clock by more than its 1.25 s
//! tolerance has jumped.

use std::collections::VecDeque;

use tally_wire::Observation;

use crate::protocol::Mode;

/// How long the offsets are remembered. Long enough to include a batch sealed right after its
/// last reception; short enough that clock drift (100 ppm, the worst mlat-server assumes of a
/// dump1090 clock) moves the estimate by under 6 ms.
const OFFSET_WINDOW_SECS: f64 = 60.0;
/// `max_offset` in `timestamp_check`: 1.25 seconds.
const JUMP_SECS: f64 = 1.25;

/// What the receiver's mlat-client is handed, in order.
#[derive(Debug, PartialEq)]
pub enum Item {
    Observation(Observation),
    /// The counter jumped forward by more than mlat-client tolerates.
    ClockJump,
}

pub struct Playout {
    mode: Mode,
    delay_secs: f64,
    /// (arrival, offset) of recent batches, in arrival order.
    offsets: VecDeque<(f64, f64)>,
    queue: VecDeque<(f64, Item)>,
    last_release: f64,
}

impl Playout {
    pub fn new(mode: Mode, delay_secs: f64) -> Self {
        Self {
            mode,
            delay_secs,
            offsets: VecDeque::new(),
            queue: VecDeque::new(),
            last_release: f64::NEG_INFINITY,
        }
    }

    /// The receiver's counter restarted: offsets from before mean nothing now.
    pub fn restart(&mut self) {
        self.offsets.clear();
    }

    /// Drops everything waiting, as a closed input does.
    pub fn clear(&mut self) {
        self.queue.clear();
    }

    /// Queues a batch's receptions that arrived at `arrival` (engine seconds).
    pub fn push(&mut self, arrival: f64, observations: Vec<Observation>) {
        let newest = observations
            .iter()
            .filter(|observation| observation.timestamp != 0)
            .map(|observation| self.mode.seconds(observation.timestamp))
            .fold(f64::NEG_INFINITY, f64::max);
        let mut offset_estimate = None;
        if newest.is_finite() {
            let offset = arrival - newest;
            while self
                .offsets
                .front()
                .is_some_and(|(at, _)| arrival - at > OFFSET_WINDOW_SECS)
            {
                self.offsets.pop_front();
            }
            if self
                .smallest()
                .is_some_and(|smallest| offset < smallest - JUMP_SECS)
            {
                self.offsets.clear();
                self.enqueue(arrival, Item::ClockJump);
            }
            self.offsets.push_back((arrival, offset));
            offset_estimate = self.smallest();
        }
        for observation in observations {
            let release = match offset_estimate {
                Some(offset) if observation.timestamp != 0 => {
                    let heard = self.mode.seconds(observation.timestamp) + offset;
                    // Never before it arrived, never held longer than the delay.
                    (heard + self.delay_secs).clamp(arrival, arrival + self.delay_secs)
                }
                _ => arrival,
            };
            self.enqueue(release, Item::Observation(observation));
        }
    }

    fn smallest(&self) -> Option<f64> {
        self.offsets
            .iter()
            .map(|(_, offset)| *offset)
            .reduce(f64::min)
    }

    /// Releases keep the receiver's own order: mlat-client reads its receiver in order.
    fn enqueue(&mut self, release: f64, item: Item) {
        let release = release.max(self.last_release);
        self.last_release = release;
        self.queue.push_back((release, item));
    }

    /// When the next item is due, if any is waiting.
    pub fn next_release(&self) -> Option<f64> {
        self.queue.front().map(|(release, _)| *release)
    }

    /// The next item if it is due at `now`.
    pub fn pop_due(&mut self, now: f64) -> Option<Item> {
        if self.next_release().is_some_and(|release| release <= now) {
            self.queue.pop_front().map(|(_, item)| item)
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn observation(seconds: f64) -> Observation {
        Observation {
            format: b'3',
            timestamp: (seconds * 12e6) as u64,
            signal: 1,
            data: vec![0; 14],
        }
    }

    fn releases(playout: &mut Playout) -> Vec<f64> {
        let mut out = Vec::new();
        while let Some(release) = playout.next_release() {
            if let Some(Item::Observation(_)) = playout.pop_due(release) {
                out.push(release);
            }
        }
        out
    }

    #[test]
    fn two_receivers_batching_out_of_phase_release_one_transmission_together() {
        // The same transmission heard at engine time 100.2 by both. Receiver A's counter reads
        // 50.2 then and its batch arrives at 100.9; receiver B's reads 7.2 and its batch, sealed
        // later, arrives at 101.6. Both have sent an earlier batch that came promptly.
        let delay = 2.0;
        let mut a = Playout::new(Mode::Beast, delay);
        a.push(100.05, vec![observation(50.0)]);
        a.push(100.9, vec![observation(50.2)]);
        let mut b = Playout::new(Mode::Beast, delay);
        b.push(99.55, vec![observation(6.5)]);
        b.push(101.6, vec![observation(7.2), observation(7.5)]);
        let (a, b) = (releases(&mut a), releases(&mut b));
        assert!((a[1] - b[1]).abs() < 1e-6, "{a:?} {b:?}");
        assert!((b[2] - b[1] - 0.3).abs() < 1e-6, "{b:?}");
    }

    #[test]
    fn nothing_is_held_longer_than_the_delay_or_released_before_it_arrived() {
        let mut playout = Playout::new(Mode::Beast, 1.0);
        playout.push(10.0, vec![observation(5.0)]);
        // Eleven seconds later on the engine, five on the receiver: late, released on arrival.
        playout.push(21.0, vec![observation(10.0)]);
        assert_eq!(releases(&mut playout), vec![11.0, 21.0]);
    }

    #[test]
    fn a_counter_jumping_ahead_is_a_clock_jump() {
        let mut playout = Playout::new(Mode::Beast, 0.0);
        playout.push(10.0, vec![observation(5.0)]);
        playout.push(11.0, vec![observation(600.0)]);
        assert_eq!(playout.pop_due(10.0).map(|_| ()), Some(()));
        assert_eq!(playout.pop_due(11.0), Some(Item::ClockJump));
        assert!(matches!(playout.pop_due(11.0), Some(Item::Observation(_))));
        assert_eq!(playout.pop_due(99.0), None);
    }
}
