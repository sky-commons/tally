//! Reading the receiver's own decoders and turning what they heard into signed batches (RFC-0171
//! §3.1, §3.5). Each decoder's port is read as one more client; nothing about readsb or dump978 is
//! changed. Each source has its own reader, and every reader feeds the one batcher that owns the
//! chain.

use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use tally_wire::backoff::Backoff;
use tally_wire::batch::Hash;
use tally_wire::beast::Decoder;
use tally_wire::noise;
use tally_wire::{Batch, BatchContent, Clock, Codec, Frame, Identity, Observation, Record};
use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;
use tokio::sync::{broadcast, mpsc};

use crate::uat::{self, Lines};

/// How often a batch is sealed, at most.
const SEAL_EVERY: Duration = Duration::from_secs(1);
/// A batch is sealed early once its receptions reach this, well inside one Noise message.
const MAX_BATCH_BYTES: usize = 48 * 1024;
/// A signed batch as a record: the record's header (kind and length), the batch's fixed fields
/// (format, key, boot id, sequence, epoch, wall clock, dropped, previous hash, count) and its
/// signature. `a_batch_record_costs_its_overhead` checks it against the wire's own encoding.
pub const BATCH_OVERHEAD: usize = 3 + (1 + 32 + 8 + 8 + 4 + 8 + 4 + 32 + 4) + 64;
/// The most one batch's receptions may come to: what makes the signed batch, as a record, exactly
/// one Noise message. The batcher never seals more, so no batch is ever too big to send.
const MAX_OBSERVATION_BYTES: usize = noise::MAX_PLAINTEXT - BATCH_OVERHEAD;
/// A free-running counter that runs backwards by more than a second of 12 MHz ticks means the
/// receiver's clock restarted, so later counters must not be compared with earlier ones.
const COUNTER_RESTART: u64 = 12_000_000;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// Receptions waiting for the batcher. It only falls this far behind if the box is starved, and
/// then what does not fit is dropped and counted like anything over the ceiling.
const INPUT_BACKLOG: usize = 4096;

/// A token bucket that drops what is over budget and never buffers (§3.5). It starts full.
pub struct TokenBucket {
    rate: f64,
    burst: f64,
    tokens: f64,
    filled: Instant,
}

impl TokenBucket {
    /// The owner's upload ceiling: one second of budget is the most it lets through at once.
    pub fn new(bytes_per_sec: u32) -> Self {
        Self::with_burst(bytes_per_sec, bytes_per_sec)
    }

    /// `bytes_per_sec`, and at most `burst` bytes at once.
    pub fn with_burst(bytes_per_sec: u32, burst: u32) -> Self {
        Self {
            rate: f64::from(bytes_per_sec),
            burst: f64::from(burst),
            tokens: f64::from(burst),
            filled: Instant::now(),
        }
    }

    /// True if `cost` bytes fit, and takes them.
    pub fn take(&mut self, cost: usize) -> bool {
        self.take_at(cost, Instant::now())
    }

    /// As `take`, at `now` (which never runs backwards for one bucket).
    pub fn take_at(&mut self, cost: usize, now: Instant) -> bool {
        let elapsed = now.saturating_duration_since(self.filled).as_secs_f64();
        self.filled = self.filled.max(now);
        self.tokens = (self.tokens + elapsed * self.rate).min(self.burst);
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
    clock: Clock,
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
    /// `clock` is the receiver's, which says whether a counter that runs backwards restarted.
    pub fn new(identity: Identity, ceiling: u32, clock: Clock) -> Self {
        let mut boot = [0; 8];
        // A boot id only has to differ from this receiver's other boots; failing that, the
        // clock does.
        if getrandom::getrandom(&mut boot).is_err() {
            boot = wall_ms().to_be_bytes();
        }
        Self {
            identity,
            clock,
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

    /// Takes what a reader sent. A batch is returned when the input had to seal one first.
    pub fn take(&mut self, input: Input) -> Result<Option<Batch>, String> {
        match input {
            Input::Frame(frame) => self.observe(&frame),
            Input::Observation(observation) => self.push(observation),
            Input::CounterRestarted => self.counter_restarted(),
        }
    }

    /// A 1090 MHz frame. A free-running counter that ran backwards seals what came before it, so
    /// a batch never holds counters from two epochs. A Radarcape's GPS counter is time of day and
    /// runs back every UTC midnight by design, so for it only a reconnect starts an epoch. A frame
    /// with no timestamp (0) says nothing about the counter.
    pub fn observe(&mut self, frame: &Frame) -> Result<Option<Batch>, String> {
        let counter = frame.timestamp();
        let mut sealed = None;
        if counter != 0 {
            if free_running(self.clock)
                && self
                    .last_counter
                    .is_some_and(|last| last > counter && last - counter > COUNTER_RESTART)
            {
                sealed = self.counter_restarted()?;
            }
            self.last_counter = Some(counter);
        }
        // After a restart the batch is empty, so this reception cannot seal a second one.
        let pushed = self.push(Observation::from_beast(frame))?;
        Ok(sealed.or(pushed))
    }

    /// A reception of any format, under the ceiling or dropped and counted. If it would take the
    /// batch past what one message carries, what gathered before it is sealed first and returned.
    pub fn push(&mut self, observation: Observation) -> Result<Option<Batch>, String> {
        let cost = 1 + 6 + 1 + 2 + observation.data.len();
        if cost > MAX_OBSERVATION_BYTES || !self.bucket.take(cost) {
            self.dropped = self.dropped.saturating_add(1);
            return Ok(None);
        }
        let sealed = if self.bytes + cost > MAX_OBSERVATION_BYTES {
            self.seal()?
        } else {
            None
        };
        self.bytes += cost;
        self.observations.push(observation);
        Ok(sealed)
    }

    /// Receptions dropped before they reached the batcher, counted with the ceiling's own.
    pub fn add_dropped(&mut self, count: u32) {
        self.dropped = self.dropped.saturating_add(count);
    }

    /// The BEAST source went away or its counter jumped: counters after this are a new epoch.
    /// What gathered under the old epoch is sealed first and returned.
    pub fn counter_restarted(&mut self) -> Result<Option<Batch>, String> {
        let sealed = self.seal()?;
        self.counter_epoch = self.counter_epoch.wrapping_add(1);
        self.last_counter = None;
        Ok(sealed)
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
        // Compressed: every relay reads it (wire version 2 is the minimum).
        let batch = Batch::sign_with(&self.identity, &content, Codec::Deflate)
            .map_err(|error| error.to_string())?;
        self.sequence += 1;
        self.previous = batch.hash();
        self.bytes = 0;
        self.dropped = 0;
        Ok(Some(batch))
    }
}

/// Whether the counter runs freely from power-on, so that one running backwards means it restarted.
fn free_running(clock: Clock) -> bool {
    matches!(
        clock,
        Clock::Dump1090 | Clock::Beast | Clock::Radarcape12Mhz | Clock::Unknown
    )
}

pub fn wall_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| {
            u64::try_from(since.as_millis()).unwrap_or(u64::MAX)
        })
}

/// What a source reader hands the batcher. Every source feeds one batcher, so a receiver's 1090
/// and 978 MHz receptions are one chain: one boot id, one sequence, one upload ceiling.
#[derive(Debug)]
pub enum Input {
    /// A 1090 MHz frame from the BEAST source.
    Frame(Frame),
    /// A reception from a source with no receiver counter (978 MHz UAT, wall-clock timestamped).
    Observation(Observation),
    /// The BEAST source went away, so its counter may restart: later counters are a new epoch.
    CounterRestarted,
}

/// A source reader's end of the channel to the batcher.
#[derive(Clone)]
pub struct Inputs {
    sender: mpsc::Sender<Input>,
    overflow: Arc<AtomicU32>,
}

/// The batcher's end.
pub struct Intake {
    receiver: mpsc::Receiver<Input>,
    overflow: Arc<AtomicU32>,
}

pub fn channel() -> (Inputs, Intake) {
    let (sender, receiver) = mpsc::channel(INPUT_BACKLOG);
    let overflow = Arc::new(AtomicU32::new(0));
    (
        Inputs {
            sender,
            overflow: Arc::clone(&overflow),
        },
        Intake { receiver, overflow },
    )
}

impl Inputs {
    /// A reception. If the batcher is behind it is dropped and counted, never waited for: a
    /// reader that waited would buffer in the socket instead, which the ceiling forbids. Public
    /// for a source that is not a decoder's port: the load harness (`tally-load`) offers a
    /// simulated receiver's receptions here, so its batches are this batcher's own.
    pub fn offer(&self, input: Input) {
        if let Err(mpsc::error::TrySendError::Full(_)) = self.sender.try_send(input) {
            self.overflow.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// An epoch change is not a reception and is never dropped.
    async fn counter_restarted(&self) {
        let _ = self.sender.send(Input::CounterRestarted).await;
    }
}

/// Owns the batch chain for as long as the feeder runs: seals once a second or when full, and
/// publishes each sealed batch to `out`.
pub async fn batch(mut batcher: Batcher, mut intake: Intake, out: broadcast::Sender<Arc<Record>>) {
    let mut seal = tokio::time::interval(SEAL_EVERY);
    loop {
        tokio::select! {
            input = intake.receiver.recv() => {
                let Some(input) = input else {
                    flush(&mut batcher, &intake.overflow, &out);
                    return;
                };
                match batcher.take(input) {
                    Ok(Some(batch)) => publish(&out, batch),
                    Ok(None) => {}
                    Err(error) => eprintln!("tally-feed: signing a batch: {error}"),
                }
                if batcher.is_full() {
                    flush(&mut batcher, &intake.overflow, &out);
                }
            }
            _ = seal.tick() => flush(&mut batcher, &intake.overflow, &out),
        }
    }
}

/// Reads readsb's BEAST output for as long as the feeder runs.
pub async fn read_beast(address: String, inputs: Inputs) {
    let mut backoff = Backoff::new();
    let mut refusing = false;
    loop {
        if let Err(error) = read_beast_once(&address, &inputs, &mut backoff, &mut refusing).await {
            eprintln!("tally-feed: source {address}: {error}");
        }
        tokio::time::sleep(backoff.wait()).await;
    }
}

async fn read_beast_once(
    address: &str,
    inputs: &Inputs,
    backoff: &mut Backoff,
    refusing: &mut bool,
) -> Result<(), String> {
    let stream = connect(address).await?;
    backoff.reset();
    eprintln!("tally-feed: reading {address}");
    let result = read_beast_stream(stream, address, inputs, refusing).await;
    // The counter may restart with the next connection (readsb restarted, or a different one).
    inputs.counter_restarted().await;
    result
}

async fn read_beast_stream(
    mut stream: TcpStream,
    address: &str,
    inputs: &Inputs,
    refusing: &mut bool,
) -> Result<(), String> {
    let mut decoder = Decoder::new();
    let mut buffer = vec![0; 16 * 1024];
    loop {
        let length = stream
            .read(&mut buffer)
            .await
            .map_err(|error| error.to_string())?;
        if length == 0 {
            return Err("closed".to_owned());
        }
        decoder.push(&buffer[..length], |frame| {
            if !*refusing {
                inputs.offer(Input::Frame(frame));
            }
        });
        if decoder.is_merged() && !*refusing {
            *refusing = true;
            eprintln!(
                "tally-feed: {address} carries more than one receiver; a feeder publishes one \
                 antenna, so nothing more is published until restart"
            );
        }
    }
}

/// Reads dump978-fa's raw output for as long as the feeder runs. Its timestamps are wall clock,
/// so a reconnect starts no new counter epoch.
pub async fn read_uat(address: String, inputs: Inputs) {
    let mut backoff = Backoff::new();
    loop {
        if let Err(error) = read_uat_once(&address, &inputs, &mut backoff).await {
            eprintln!("tally-feed: uat source {address}: {error}");
        }
        tokio::time::sleep(backoff.wait()).await;
    }
}

async fn read_uat_once(
    address: &str,
    inputs: &Inputs,
    backoff: &mut Backoff,
) -> Result<(), String> {
    let mut stream = connect(address).await?;
    backoff.reset();
    eprintln!("tally-feed: reading {address}");
    let mut lines = Lines::new();
    let mut skipped = 0u64;
    let mut buffer = vec![0; 16 * 1024];
    loop {
        let length = stream
            .read(&mut buffer)
            .await
            .map_err(|error| error.to_string())?;
        if length == 0 {
            return Err(format!("closed ({skipped} unreadable lines skipped)"));
        }
        let mut bad = 0;
        let unreadable = lines.push(&buffer[..length], |line| {
            match uat::parse_line(line, uat::now_us()) {
                uat::Line::Reception(observation) => inputs.offer(Input::Observation(observation)),
                uat::Line::Ignored => {}
                uat::Line::Bad => bad += 1,
            }
        });
        if skipped == 0 && bad + unreadable > 0 {
            eprintln!(
                "tally-feed: {address} sent a line that is not a UAT reception; such lines are \
                 skipped"
            );
        }
        skipped += bad + unreadable;
    }
}

async fn connect(address: &str) -> Result<TcpStream, String> {
    tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(address))
        .await
        .map_err(|_| "connect timed out".to_owned())?
        .map_err(|error| error.to_string())
}

fn flush(batcher: &mut Batcher, overflow: &AtomicU32, out: &broadcast::Sender<Arc<Record>>) {
    batcher.add_dropped(overflow.swap(0, Ordering::Relaxed));
    match batcher.seal() {
        Ok(Some(batch)) => publish(out, batch),
        Ok(None) => {}
        Err(error) => eprintln!("tally-feed: signing a batch: {error}"),
    }
}

fn publish(out: &broadcast::Sender<Arc<Record>>, batch: Batch) {
    // An error only means no relay session is listening right now; the batch is gone, and its
    // sequence number tells everyone downstream so.
    let _ = out.send(Arc::new(Record::Batch(batch)));
}

#[cfg(test)]
mod tests {
    use super::*;
    use tally_wire::FrameKind;

    fn frame(counter: u64) -> Result<Frame, String> {
        Frame::new(FrameKind::ModeSLong, counter, 9, &[0x8d; 14]).map_err(|error| error.to_string())
    }

    fn batcher(ceiling: u32) -> Result<Batcher, String> {
        clocked(ceiling, Clock::Dump1090)
    }

    fn clocked(ceiling: u32, clock: Clock) -> Result<Batcher, String> {
        Ok(Batcher::new(
            Identity::generate().map_err(|error| error.to_string())?,
            ceiling,
            clock,
        ))
    }

    fn content(batch: &Batch) -> Result<BatchContent, String> {
        batch.content().map_err(|error| error.to_string())
    }

    #[test]
    fn batches_chain_and_number_within_a_boot() -> Result<(), String> {
        let mut batcher = batcher(1_000_000)?;
        batcher.observe(&frame(1)?)?;
        let first = batcher.seal()?.ok_or("no first batch")?;
        batcher.observe(&frame(2)?)?;
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
        assert!(batcher.observe(&frame(500_000_000)?)?.is_none());
        assert!(batcher.observe(&frame(499_999_000)?)?.is_none());
        let before = batcher
            .observe(&frame(1_000)?)?
            .ok_or("the old epoch was not sealed first")?
            .content()
            .map_err(|error| error.to_string())?;
        let after = batcher
            .seal()?
            .ok_or("no batch")?
            .content()
            .map_err(|error| error.to_string())?;
        assert_eq!((before.counter_epoch, before.observations.len()), (0, 2));
        assert_eq!((after.counter_epoch, after.observations.len()), (1, 1));
        Ok(())
    }

    #[test]
    fn uat_and_1090_share_one_chain_and_only_beast_moves_the_epoch() -> Result<(), String> {
        let mut batcher = batcher(1_000_000)?;
        let uat = Observation {
            format: tally_wire::batch::format::UAT_DOWNLINK,
            timestamp: 5,
            signal: 0,
            data: vec![0; 18],
        };
        batcher.take(Input::Frame(frame(1)?))?;
        batcher.take(Input::Observation(uat.clone()))?;
        let first = batcher.seal()?.ok_or("no first batch")?;
        batcher.take(Input::Observation(uat.clone()))?;
        let restarted = batcher
            .take(Input::CounterRestarted)?
            .ok_or("the restart did not seal")?;
        batcher.take(Input::Observation(uat))?;
        let last = batcher.seal()?.ok_or("no last batch")?;
        let content = |batch: &Batch| batch.content().map_err(|error| error.to_string());
        let (first_content, restarted_content, last_content) =
            (content(&first)?, content(&restarted)?, content(&last)?);
        assert_eq!(first_content.observations.len(), 2);
        assert_eq!(
            [first.sequence(), restarted.sequence(), last.sequence()],
            [0, 1, 2]
        );
        assert_eq!(first.boot_id(), last.boot_id());
        assert_eq!(restarted_content.previous, first.hash());
        let epochs =
            [&first_content, &restarted_content, &last_content].map(|each| each.counter_epoch);
        assert_eq!(epochs, [0, 0, 1]);
        Ok(())
    }

    #[test]
    fn what_never_reached_the_batcher_is_counted() -> Result<(), String> {
        let mut batcher = batcher(1_000_000)?;
        batcher.add_dropped(3);
        let content = batcher
            .seal()?
            .ok_or("no batch")?
            .content()
            .map_err(|error| error.to_string())?;
        assert_eq!((content.dropped, content.observations.len()), (3, 0));
        Ok(())
    }

    #[test]
    fn over_the_ceiling_is_dropped_and_counted_never_buffered() -> Result<(), String> {
        let mut batcher = batcher(100)?;
        for counter in 0..20 {
            batcher.observe(&frame(counter)?)?;
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

    #[test]
    fn a_gps_counter_falling_back_at_midnight_starts_no_epoch() -> Result<(), String> {
        let gps = |seconds: u64, nanos: u64| (seconds << 30) | nanos;
        let mut batcher = clocked(1_000_000, Clock::RadarcapeGps)?;
        assert!(
            batcher
                .observe(&frame(gps(86_399, 999_000_000))?)?
                .is_none()
        );
        assert!(batcher.observe(&frame(gps(0, 1_000))?)?.is_none());
        let only = content(&batcher.seal()?.ok_or("no batch")?)?;
        assert_eq!((only.counter_epoch, only.observations.len()), (0, 2));
        // A reconnect is still a new epoch.
        batcher.observe(&frame(gps(5, 0))?)?;
        let before = batcher.counter_restarted()?.ok_or("no batch")?;
        batcher.observe(&frame(gps(6, 0))?)?;
        let after = batcher.seal()?.ok_or("no batch")?;
        assert_eq!(
            (
                content(&before)?.counter_epoch,
                content(&after)?.counter_epoch
            ),
            (0, 1)
        );
        Ok(())
    }

    #[test]
    fn every_free_running_clock_restarts_when_its_counter_runs_back() -> Result<(), String> {
        for clock in [
            Clock::Dump1090,
            Clock::Beast,
            Clock::Radarcape12Mhz,
            Clock::Unknown,
        ] {
            let mut batcher = clocked(1_000_000, clock)?;
            batcher.observe(&frame(500_000_000)?)?;
            assert!(batcher.observe(&frame(1_000)?)?.is_some(), "{clock:?}");
        }
        Ok(())
    }

    #[test]
    fn a_frame_without_a_timestamp_neither_moves_nor_restarts_the_counter() -> Result<(), String> {
        let mut batcher = batcher(1_000_000)?;
        batcher.observe(&frame(500_000_000)?)?;
        assert!(batcher.observe(&frame(0)?)?.is_none(), "0 started an epoch");
        // Had 0 become the last counter, this would read as a jump forward and the next one as a
        // fall of more than a second; it is neither.
        assert!(batcher.observe(&frame(499_999_000)?)?.is_none());
        let only = content(&batcher.seal()?.ok_or("no batch")?)?;
        assert_eq!((only.counter_epoch, only.observations.len()), (0, 3));
        Ok(())
    }

    #[test]
    fn a_batch_record_costs_its_overhead() -> Result<(), String> {
        let mut batcher = batcher(1_000_000)?;
        batcher.add_dropped(1);
        let empty = batcher.seal()?.ok_or("no batch")?;
        let mut encoded = Vec::new();
        Record::Batch(empty)
            .encode(&mut encoded)
            .map_err(|error| error.to_string())?;
        assert_eq!(encoded.len(), BATCH_OVERHEAD);
        Ok(())
    }

    #[test]
    fn no_sealed_batch_is_too_big_for_one_message() -> Result<(), String> {
        let mut batcher = batcher(u32::MAX)?;
        let big = |size: usize| Observation {
            format: tally_wire::batch::format::UAT_UPLINK,
            timestamp: 1,
            signal: 0,
            data: vec![0; size],
        };
        let mut sealed = Vec::new();
        // Receptions the early seal never sees, since none is offered between them.
        for _ in 0..12 {
            sealed.extend(batcher.push(big(20_000))?);
        }
        assert!(batcher.push(big(noise::MAX_PLAINTEXT))?.is_none());
        sealed.extend(batcher.seal()?);
        assert!(sealed.len() >= 4);
        let (mut total, mut dropped) = (0, 0);
        for batch in &sealed {
            let mut encoded = Vec::new();
            Record::Batch(batch.clone())
                .encode(&mut encoded)
                .map_err(|error| error.to_string())?;
            assert!(encoded.len() <= noise::MAX_PLAINTEXT, "{}", encoded.len());
            let content = content(batch)?;
            total += content.observations.len();
            dropped += content.dropped;
        }
        // The one reception bigger than a message is dropped and counted, never sent.
        assert_eq!((total, dropped), (12, 1));
        Ok(())
    }

    #[test]
    fn a_reception_too_big_for_any_batch_is_dropped_and_counted() -> Result<(), String> {
        let mut batcher = batcher(u32::MAX)?;
        batcher.push(Observation {
            format: tally_wire::batch::format::UAT_UPLINK,
            timestamp: 1,
            signal: 0,
            data: vec![0; MAX_OBSERVATION_BYTES],
        })?;
        let content = content(&batcher.seal()?.ok_or("no batch")?)?;
        assert_eq!((content.dropped, content.observations.len()), (1, 0));
        Ok(())
    }

    #[test]
    fn a_relay_bucket_lets_through_its_burst_then_its_rate() {
        let mut bucket = TokenBucket::with_burst(1_000, 10_000);
        let start = Instant::now();
        assert!(bucket.take_at(10_000, start));
        assert!(!bucket.take_at(1, start));
        assert!(!bucket.take_at(5_000, start + Duration::from_secs(4)));
        assert!(bucket.take_at(5_000, start + Duration::from_secs(5)));
    }
}
