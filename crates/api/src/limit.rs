//! A token bucket per client: `rate` requests a second, up to `burst` at once. Clients are an IPv4
//! address or an IPv6 /64 (`tally_relay::hub::source_of`, the relay's rule), and their buckets are
//! held to a count: a full bucket is the same as none, so when the table fills those are forgotten
//! first, and a client that cannot be given a bucket is refused rather than let through.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use tally_relay::hub::source_of;

pub const DEFAULT_RATE: f64 = 20.0;
pub const DEFAULT_BURST: f64 = 40.0;
/// The most clients held at once. At about 64 bytes each, 4 MB.
pub const CLIENTS_HELD: usize = 65_536;
/// The table is swept of full buckets at most this often, so a table full of clients being
/// limited costs one sweep a second, not one a request.
const SWEEP_EVERY: Duration = Duration::from_secs(1);

pub struct Limiter {
    rate: f64,
    burst: f64,
    most: usize,
    table: Mutex<Table>,
}

struct Table {
    buckets: HashMap<IpAddr, Bucket>,
    swept: Option<Instant>,
}

#[derive(Clone, Copy)]
struct Bucket {
    tokens: f64,
    at: Instant,
}

impl Bucket {
    fn tokens_at(&self, now: Instant, rate: f64, burst: f64) -> f64 {
        let elapsed = now.saturating_duration_since(self.at).as_secs_f64();
        (self.tokens + elapsed * rate).min(burst)
    }
}

impl Limiter {
    pub fn new(rate: f64, burst: f64) -> Self {
        Self::holding(rate, burst, CLIENTS_HELD)
    }

    pub fn holding(rate: f64, burst: f64, most: usize) -> Self {
        Self {
            rate,
            burst: burst.max(1.0),
            most: most.max(1),
            table: Mutex::new(Table {
                buckets: HashMap::new(),
                swept: None,
            }),
        }
    }

    /// Whether `client` may make a request at `now`, taking a token if so.
    pub fn admit(&self, client: IpAddr, now: Instant) -> bool {
        let client = source_of(client);
        let Ok(mut table) = self.table.lock() else {
            return false;
        };
        let (rate, burst) = (self.rate, self.burst);
        if let Some(bucket) = table.buckets.get_mut(&client) {
            let tokens = bucket.tokens_at(now, rate, burst);
            let admitted = tokens >= 1.0;
            *bucket = Bucket {
                tokens: if admitted { tokens - 1.0 } else { tokens },
                at: now,
            };
            return admitted;
        }
        if table.buckets.len() >= self.most {
            let due = table
                .swept
                .is_none_or(|swept| now.saturating_duration_since(swept) >= SWEEP_EVERY);
            if !due {
                return false;
            }
            table.swept = Some(now);
            table
                .buckets
                .retain(|_, bucket| bucket.tokens_at(now, rate, burst) < burst);
            if table.buckets.len() >= self.most {
                return false;
            }
        }
        table.buckets.insert(
            client,
            Bucket {
                tokens: burst - 1.0,
                at: now,
            },
        );
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn v4(last: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, last))
    }

    #[test]
    fn a_client_gets_its_burst_then_its_rate() {
        let limiter = Limiter::new(20.0, 40.0);
        let start = Instant::now();
        let admitted = (0..100).filter(|_| limiter.admit(v4(1), start)).count();
        assert_eq!(admitted, 40);
        // Another client is not held to the first one's bucket.
        assert!(limiter.admit(v4(2), start));
        // A quarter second refills five.
        let later = start + Duration::from_millis(250);
        let admitted = (0..100).filter(|_| limiter.admit(v4(1), later)).count();
        assert_eq!(admitted, 5);
    }

    #[test]
    fn an_ipv6_64_is_one_client() {
        let limiter = Limiter::new(1.0, 2.0);
        let start = Instant::now();
        let host = |n: u16| IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, n));
        assert!(limiter.admit(host(1), start));
        assert!(limiter.admit(host(2), start));
        assert!(!limiter.admit(host(3), start));
    }

    #[test]
    fn a_full_table_forgets_full_buckets_and_otherwise_refuses_new_clients() {
        let limiter = Limiter::holding(10.0, 10.0, 2);
        let start = Instant::now();
        assert!(limiter.admit(v4(1), start));
        assert!(limiter.admit(v4(2), start));
        // Both are still refilling, so a third has no room.
        assert!(!limiter.admit(v4(3), start));
        // A second later both buckets are full again, the same as none: swept, and room made.
        let later = start + Duration::from_secs(1);
        assert!(limiter.admit(v4(3), later));
        assert!(limiter.admit(v4(4), later));
        // Swept once this second already: refused without another sweep.
        assert!(!limiter.admit(v4(5), later));
    }
}
