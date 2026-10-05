//! Reading the receiver's own decoder and turning its frames into signed batches (RFC-0166 §3.1,
//! §3.5). The decoder's port is read as one more client; nothing about readsb is changed.

use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use tally_wire::backoff::Backoff;
use tally_wire::batch::Hash;
use tally_wire::beast::Decoder;
use tally_wire::{Batch, BatchContent, Frame, Identity, Observation, Record};
use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;
use tokio::sync::broadcast;

/// How often a batch is sealed, at most.
const SEAL_EVERY: Duration = Duration::from_secs(1);
/// A batch is sealed early once its receptions reach this, well inside one Noise message.
const MAX_BATCH_BYTES: usize = 48 * 1024;
/// A counter that runs backwards by more than a second of 12 MHz ticks means the receiver's clock
/// restarted, so later counters must not be compared with earlier ones.
const COUNTER_RESTART: u64 = 12_000_000;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// The feeder's upload ceiling: a token bucket that drops what is over budget and never buffers
/// (§3.5). One second of budget is the most it lets through at once.
pub struct TokenBucket {
    rate: f64,
    tokens: f64,
    filled: Instant,
}

impl TokenBucket {
    pub fn new(bytes_per_sec: u32) -> Self {
        Self {
            rate: f64::from(bytes_per_sec),
            tokens: f64::from(bytes_per_sec),
            filled: Instant::now(),
        }
    }

    pub fn set_rate(&mut self, bytes_per_sec: u32) {
        self.rate = f64::from(bytes_per_sec);
        self.tokens = self.tokens.min(self.rate);
    }

    /// True if `cost` bytes fit, and takes them.
    pub fn take(&mut self, cost: usize) -> bool {
        let now = Instant::now();
        let elapsed = now.duration_since(self.filled).as_secs_f64();
        self.filled = now;
        self.tokens = (self.tokens + elapsed * self.rate).min(self.rate);
        let cost = cost as f64;
        if cost > self.tokens {
            return false;
        }
        self.tokens -= cost;
        true
    }
}

/// Builds one boot's chain of signed batches.
pub struct Batcher {
    identity: Identity,
    boot_id: u64,
    sequence: u64,
    counter_epoch: u32,
    previous: Hash,
    observations: Vec<Observation>,
    bytes: usize,
    dropped: u32,
    last_counter: Option<u64>,
    bucket: TokenBucket,
}

impl Batcher {
    pub fn new(identity: Identity, ceiling: u32) -> Self {
        let mut boot = [0; 8];
        // A boot id only has to differ from this receiver's other boots; failing that, the
        // clock does.
        if getrandom::getrandom(&mut boot).is_err() {
            boot = wall_ms().to_be_bytes();
        }
        Self {
            identity,
            boot_id: u64::from_be_bytes(boot),
            sequence: 0,
            counter_epoch: 0,
            previous: [0; 32],
            observations: Vec::new(),
            bytes: 0,
            dropped: 0,
            last_counter: None,
            bucket: TokenBucket::new(ceiling),
        }
    }

    pub fn observe(&mut self, frame: &Frame) {
        let counter = frame.timestamp();
        if self
            .last_counter
            .is_some_and(|last| last > counter && last - counter > COUNTER_RESTART)
        {
            self.counter_restarted();
        }
        self.last_counter = Some(counter);
        let observation = Observation::from_beast(frame);
        let cost = 1 + 6 + 1 + 2 + observation.data.len();
        if !self.bucket.take(cost) {
            self.dropped = self.dropped.saturating_add(1);
            return;
        }
        self.bytes += cost;
        self.observations.push(observation);
    }

    /// The source went away or its counter jumped: counters after this are a new epoch.
    pub fn counter_restarted(&mut self) {
        self.counter_epoch = self.counter_epoch.wrapping_add(1);
        self.last_counter = None;
    }

    pub fn is_full(&self) -> bool {
        self.bytes >= MAX_BATCH_BYTES
    }

    /// Signs what has gathered, if anything has.
    pub fn seal(&mut self) -> Result<Option<Batch>, String> {
        if self.observations.is_empty() && self.dropped == 0 {
            return Ok(None);
        }
        let content = BatchContent {
            boot_id: self.boot_id,
            sequence: self.sequence,
            counter_epoch: self.counter_epoch,
            wall_ms: wall_ms(),
            dropped: self.dropped,
            previous: self.previous,
            observations: std::mem::take(&mut self.observations),
        };
        let batch = Batch::sign(&self.identity, &content).map_err(|error| error.to_string())?;
        self.sequence += 1;
        self.previous = batch.hash();
        self.bytes = 0;
        self.dropped = 0;
        Ok(Some(batch))
    }
}

pub fn wall_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| {
            u64::try_from(since.as_millis()).unwrap_or(u64::MAX)
        })
}

/// Reads the decoder for as long as the feeder runs and publishes sealed batches to `out`.
pub async fn run(address: String, mut batcher: Batcher, out: broadcast::Sender<Arc<Record>>) {
    let mut backoff = Backoff::new();
    let mut refusing = false;
    loop {
        match read_source(&address, &mut batcher, &out, &mut refusing).await {
            Ok(()) => backoff.reset(),
            Err(error) => eprintln!("tally-feed: source {address}: {error}"),
        }
        batcher.counter_restarted();
        flush(&mut batcher, &out);
        tokio::time::sleep(backoff.wait()).await;
    }
}

async fn read_source(
    address: &str,
    batcher: &mut Batcher,
    out: &broadcast::Sender<Arc<Record>>,
    refusing: &mut bool,
) -> Result<(), String> {
    let mut stream = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(address))
        .await
        .map_err(|_| "connect timed out".to_owned())?
        .map_err(|error| error.to_string())?;
    eprintln!("tally-feed: reading {address}");
    let mut decoder = Decoder::new();
    let mut buffer = vec![0; 16 * 1024];
    let mut seal = tokio::time::interval(SEAL_EVERY);
    loop {
        tokio::select! {
            read = stream.read(&mut buffer) => {
                let length = read.map_err(|error| error.to_string())?;
                if length == 0 {
                    return Err("closed".to_owned());
                }
                decoder.push(&buffer[..length], |frame| {
                    if !*refusing {
                        batcher.observe(&frame);
                    }
                });
                if decoder.is_merged() && !*refusing {
                    *refusing = true;
                    eprintln!(
                        "tally-feed: {address} carries more than one receiver; a feeder \
                         publishes one antenna, so nothing more is published until restart"
                    );
                }
                if batcher.is_full() {
                    flush(batcher, out);
                }
            }
            _ = seal.tick() => flush(batcher, out),
        }
    }
}

fn flush(batcher: &mut Batcher, out: &broadcast::Sender<Arc<Record>>) {
    match batcher.seal() {
        // An error only means no relay session is listening right now; the batch is gone, and
        // its sequence number tells everyone downstream so.
        Ok(Some(batch)) => {
            let _ = out.send(Arc::new(Record::Batch(batch)));
        }
        Ok(None) => {}
        Err(error) => eprintln!("tally-feed: signing a batch: {error}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tally_wire::FrameKind;

    fn frame(counter: u64) -> Result<Frame, String> {
        Frame::new(FrameKind::ModeSLong, counter, 9, &[0x8d; 14]).map_err(|error| error.to_string())
    }

    fn batcher(ceiling: u32) -> Result<Batcher, String> {
        Ok(Batcher::new(
            Identity::generate().map_err(|error| error.to_string())?,
            ceiling,
        ))
    }

    #[test]
    fn batches_chain_and_number_within_a_boot() -> Result<(), String> {
        let mut batcher = batcher(1_000_000)?;
        batcher.observe(&frame(1)?);
        let first = batcher.seal()?.ok_or("no first batch")?;
        batcher.observe(&frame(2)?);
        let second = batcher.seal()?.ok_or("no second batch")?;
        assert!(batcher.seal()?.is_none());
        assert_eq!((first.sequence(), second.sequence()), (0, 1));
        assert_eq!(first.boot_id(), second.boot_id());
        let content = second.content().map_err(|error| error.to_string())?;
        assert_eq!(content.previous, first.hash());
        second.verify().map_err(|error| error.to_string())?;
        Ok(())
    }

    #[test]
    fn a_counter_that_runs_backwards_starts_a_new_epoch() -> Result<(), String> {
        let mut batcher = batcher(1_000_000)?;
        batcher.observe(&frame(500_000_000)?);
        batcher.observe(&frame(499_999_000)?);
        batcher.observe(&frame(1_000)?);
        let content = batcher
            .seal()?
            .ok_or("no batch")?
            .content()
            .map_err(|error| error.to_string())?;
        assert_eq!(content.counter_epoch, 1);
        Ok(())
    }

    #[test]
    fn over_the_ceiling_is_dropped_and_counted_never_buffered() -> Result<(), String> {
        let mut batcher = batcher(100)?;
        for counter in 0..20 {
            batcher.observe(&frame(counter)?);
        }
        let content = batcher
            .seal()?
            .ok_or("no batch")?
            .content()
            .map_err(|error| error.to_string())?;
        assert_eq!(content.observations.len(), 4);
        assert_eq!(content.dropped, 16);
        Ok(())
    }
}
