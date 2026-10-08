//! Delivery latency, to the millisecond up to a minute.

/// The longest latency told apart; anything later counts as this.
const MAX_MS: usize = 60_000;

#[derive(Clone)]
pub struct Histogram {
    counts: Vec<u64>,
    total: u64,
    max: u64,
}

impl Default for Histogram {
    fn default() -> Self {
        Self {
            counts: vec![0; MAX_MS + 1],
            total: 0,
            max: 0,
        }
    }
}

impl Histogram {
    pub fn record(&mut self, ms: u64) {
        let at = usize::try_from(ms).unwrap_or(MAX_MS).min(MAX_MS);
        self.counts[at] += 1;
        self.total += 1;
        self.max = self.max.max(ms);
    }

    pub fn merge(&mut self, other: &Self) {
        for (mine, theirs) in self.counts.iter_mut().zip(&other.counts) {
            *mine += theirs;
        }
        self.total += other.total;
        self.max = self.max.max(other.max);
    }

    pub fn total(&self) -> u64 {
        self.total
    }

    pub fn max(&self) -> u64 {
        self.max
    }

    /// The smallest latency at least `quantile` of the samples are at or under; `None` if empty.
    pub fn quantile(&self, quantile: f64) -> Option<u64> {
        if self.total == 0 {
            return None;
        }
        let wanted = ((quantile * self.total as f64).ceil() as u64).clamp(1, self.total);
        let mut seen = 0;
        for (ms, count) in self.counts.iter().enumerate() {
            seen += count;
            if seen >= wanted {
                return Some(ms as u64);
            }
        }
        Some(self.max)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quantiles_are_the_samples_own() {
        let mut histogram = Histogram::default();
        assert_eq!(histogram.quantile(0.5), None);
        for ms in 1..=100 {
            histogram.record(ms);
        }
        assert_eq!(histogram.quantile(0.5), Some(50));
        assert_eq!(histogram.quantile(0.99), Some(99));
        assert_eq!(histogram.quantile(1.0), Some(100));
        let mut other = Histogram::default();
        other.record(90_000);
        histogram.merge(&other);
        assert_eq!(histogram.total(), 101);
        assert_eq!(histogram.max(), 90_000);
        assert_eq!(histogram.quantile(1.0), Some(MAX_MS as u64));
    }
}
