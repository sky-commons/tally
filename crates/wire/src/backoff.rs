//! How a feeder or relay waits before trying a peer again (RFC-0166 §3.5): doubling from one
//! second to five minutes, with up to half again of random jitter so a relay restart is not every
//! feeder reconnecting in the same second. A peer can lengthen the wait (`Goodbye`, `Redirect`)
//! and never shorten it.

use std::time::Duration;

pub struct Backoff {
    next: Duration,
}

impl Default for Backoff {
    fn default() -> Self {
        Self::new()
    }
}

impl Backoff {
    pub const FIRST: Duration = Duration::from_secs(1);
    pub const MOST: Duration = Duration::from_secs(300);

    pub fn new() -> Self {
        Self { next: Self::FIRST }
    }

    /// After a session that worked.
    pub fn reset(&mut self) {
        self.next = Self::FIRST;
    }

    /// A peer asked for at least this long.
    pub fn at_least(&mut self, wait: Duration) {
        self.next = self.next.max(wait);
    }

    /// The wait before the next try, and the one after it doubled.
    pub fn wait(&mut self) -> Duration {
        let wait = self.next;
        self.next = (self.next * 2).clamp(Self::FIRST, Self::MOST.max(wait));
        wait + wait.mul_f64(f64::from(random_u16()) / f64::from(u16::MAX) / 2.0)
    }
}

/// Jitter only spreads reconnects; if the system has no randomness to give, there is none.
fn random_u16() -> u16 {
    let mut bytes = [0; 2];
    let _ = getrandom::getrandom(&mut bytes);
    u16::from_be_bytes(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_wait_doubles_to_five_minutes_with_at_most_half_again_of_jitter() {
        let mut backoff = Backoff::new();
        let mut floor = Backoff::FIRST;
        for _ in 0..12 {
            let wait = backoff.wait();
            assert!(
                wait >= floor && wait <= floor.mul_f64(1.5),
                "{wait:?} from {floor:?}"
            );
            floor = (floor * 2).min(Backoff::MOST);
        }
    }

    #[test]
    fn a_peer_can_lengthen_the_wait_and_a_good_session_resets_it() {
        let mut backoff = Backoff::new();
        backoff.at_least(Duration::from_secs(3_600));
        assert!(backoff.wait() >= Duration::from_secs(3_600));
        backoff.reset();
        assert!(backoff.wait() < Duration::from_secs(2));
    }
}
