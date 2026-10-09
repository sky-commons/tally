//! How long a member that said it is full (`Reason::Full`, RFC-0174 §2.5) is routed around: the
//! one rule, read by both ends of the refusal. The relay turned away keeps it for the member that
//! refused it (`peers::Peers::refused_full`), and routes around that member while it holds; the
//! relay that turned it away keeps the same wait for the relay it refused
//! (`member::Member::turned_away`), so it knows exactly when that relay was sending its slice past
//! it and files no shortfall against it for those windows. Both apply this rule to the same
//! refusals and the same asked wait, so the two cannot disagree on when one routed around the
//! other.

use std::time::Duration;

/// The longest a member that said it is full is routed around, however often it says so.
pub const FULL_WAIT_MAX_MS: u64 = 30 * 60 * 1000;
/// The shortest wait a refusal is taken as, whatever it asked.
pub const FULL_WAIT_MIN_MS: u64 = 1_000;

/// One refusal's wait: routed around until `until_ms`, having been given `wait_ms`, which the next
/// refusal within that wait of its end doubles.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Wait {
    pub until_ms: u64,
    pub wait_ms: u64,
}

impl Wait {
    /// The wait a refusal at `now_ms` asking `asked` starts: the asked wait (within
    /// `FULL_WAIT_MIN_MS` and `FULL_WAIT_MAX_MS`), or twice the last one given if this refusal came
    /// within that wait of the last one's end (at most `FULL_WAIT_MAX_MS`), so a full member is
    /// tried less and less often and never in a loop.
    pub fn after(last: Option<Self>, asked: Duration, now_ms: u64) -> Self {
        let asked_ms = u64::try_from(asked.as_millis())
            .unwrap_or(u64::MAX)
            .clamp(FULL_WAIT_MIN_MS, FULL_WAIT_MAX_MS);
        let wait_ms = match last {
            Some(last) if now_ms <= last.until_ms.saturating_add(last.wait_ms) => last
                .wait_ms
                .saturating_mul(2)
                .max(asked_ms)
                .min(FULL_WAIT_MAX_MS),
            _ => asked_ms,
        };
        Self {
            until_ms: now_ms.saturating_add(wait_ms),
            wait_ms,
        }
    }

    /// Whether the member is routed around at `now_ms`.
    pub fn holds(&self, now_ms: u64) -> bool {
        now_ms < self.until_ms
    }

    /// Whether this wait still doubles the next refusal at `now_ms`: once a wait as long again has
    /// passed with no refusal, the next starts afresh, and the wait is forgotten.
    pub fn remembered(&self, now_ms: u64) -> bool {
        now_ms <= self.until_ms.saturating_add(self.wait_ms)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_refusal_within_the_wait_after_the_last_doubles_it_up_to_the_most() {
        let asked = Duration::from_secs(60);
        let first = Wait::after(None, asked, 0);
        assert_eq!(
            first,
            Wait {
                until_ms: 60_000,
                wait_ms: 60_000
            }
        );
        assert!(first.holds(59_999) && !first.holds(60_000));
        // Refused again as soon as it was tried again: twice the wait.
        let second = Wait::after(Some(first), asked, 60_000);
        assert_eq!(second.wait_ms, 120_000);
        // Long after the wait as long again: afresh.
        let afresh = Wait::after(Some(second), asked, 180_000 + 120_001);
        assert_eq!(afresh.wait_ms, 60_000);
        assert!(!second.remembered(180_000 + 120_001));
        let mut wait = first;
        for _ in 0..20 {
            wait = Wait::after(Some(wait), asked, wait.until_ms);
        }
        assert_eq!(wait.wait_ms, FULL_WAIT_MAX_MS);
        assert_eq!(
            Wait::after(None, Duration::ZERO, 0).wait_ms,
            FULL_WAIT_MIN_MS
        );
    }
}
