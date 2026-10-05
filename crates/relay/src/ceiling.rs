//! How much one connection may send a relay (RFC-0166 §3.6: taking data in costs a relay only its
//! server, so the relay sets what that is). Every byte read off a connection is counted at the
//! socket, before decryption or decoding, and held to a rate with a burst.

use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context, Poll};
use std::time::Instant;

use tally_wire::noise;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// What one message costs on the socket beyond the records' own bytes as a feeder counts them (a
/// batch's signed bytes): the frame's two-byte length, the Noise tag, and the record's header
/// (kind and length). A feeder sends one batch to a message.
pub const FRAMING_PER_MESSAGE: u64 = 2 + (noise::MAX_MESSAGE - noise::MAX_PLAINTEXT) as u64 + 3;

/// The messages a second the advertised rate leaves framing room for. A feeder seals once a second
/// and early only at 48 KiB, so a few a second at most, plus a heartbeat every thirty seconds.
pub const MESSAGES_A_SECOND: u64 = 64;

/// Room in the burst for the Noise handshake and `Hello`, which no feeder counts.
pub const HANDSHAKE_ALLOWANCE: u64 = 1024;

/// One whole message on the socket: the largest a description, which a feeder sends outside its
/// pacing, can be.
const FRAMED_MESSAGE: u64 = 2 + noise::MAX_MESSAGE as u64;

/// The least burst a connection is allowed, whatever its rate: a feeder's first second carries the
/// handshake, its description (up to a whole message) and a burst of batches of at least a whole
/// message (the least burst a feeder keeps to), and a message is spare.
pub const MIN_BURST: u64 = 3 * 64 * 1024;

/// The burst a connection held to `rate` is allowed.
pub fn burst(rate: u64) -> u64 {
    rate.max(MIN_BURST)
}

/// What a feeder is told as its `RateLimit` under the ingest ceiling `rate`: a rate and burst of
/// batch bytes such that a feeder keeping to them, with its framing, handshake and description
/// beside them, never trips the ceiling.
pub fn advertised(rate: u64) -> (u32, u32) {
    let framing = FRAMING_PER_MESSAGE * MESSAGES_A_SECOND;
    let bytes_per_sec = rate.saturating_sub(framing);
    let burst = burst(rate).saturating_sub(HANDSHAKE_ALLOWANCE + FRAMED_MESSAGE + framing);
    (
        u32::try_from(bytes_per_sec).unwrap_or(u32::MAX),
        u32::try_from(burst).unwrap_or(u32::MAX),
    )
}

/// A stream that counts the bytes read from it.
pub struct Metered<S> {
    inner: S,
    read: Arc<AtomicU64>,
}

impl<S> Metered<S> {
    /// The stream, and the count of bytes read from it so far.
    pub fn new(inner: S) -> (Self, Arc<AtomicU64>) {
        let read = Arc::new(AtomicU64::new(0));
        (
            Self {
                inner,
                read: Arc::clone(&read),
            },
            read,
        )
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for Metered<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let before = buf.filled().len();
        let polled = Pin::new(&mut self.inner).poll_read(cx, buf);
        if let Poll::Ready(Ok(())) = polled {
            let read = buf.filled().len().saturating_sub(before);
            self.read
                .fetch_add(u64::try_from(read).unwrap_or(u64::MAX), Ordering::Relaxed);
        }
        polled
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Metered<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }
}

/// A token bucket over a connection's byte count: `rate` bytes a second, up to `burst` saved.
pub struct Ceiling {
    rate: u64,
    burst: u64,
    /// Bytes still allowed now.
    allowance: f64,
    refilled: Instant,
    read: Arc<AtomicU64>,
    counted: u64,
}

impl Ceiling {
    /// Holds the count `read` to `rate` bytes a second, with a burst of the larger of the rate and
    /// `MIN_BURST`. The connection starts with its whole burst.
    pub fn new(rate: u64, read: Arc<AtomicU64>) -> Self {
        let burst = burst(rate);
        Self {
            rate,
            burst,
            allowance: burst as f64,
            refilled: Instant::now(),
            read,
            counted: 0,
        }
    }

    /// False once the connection has sent more than its rate and burst allow.
    pub fn within(&mut self) -> bool {
        self.within_at(Instant::now())
    }

    fn within_at(&mut self, now: Instant) -> bool {
        let elapsed = now.saturating_duration_since(self.refilled).as_secs_f64();
        self.refilled = now;
        self.allowance = (self.allowance + elapsed * self.rate as f64).min(self.burst as f64);
        let read = self.read.load(Ordering::Relaxed);
        self.allowance -= read.saturating_sub(self.counted) as f64;
        self.counted = read;
        self.allowance >= 0.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn a_burst_is_allowed_and_a_sustained_excess_is_not() {
        let read = Arc::new(AtomicU64::new(0));
        let mut ceiling = Ceiling::new(1_000, Arc::clone(&read));
        let start = ceiling.refilled;
        // The whole burst at once is within the ceiling.
        read.store(MIN_BURST, Ordering::Relaxed);
        assert!(ceiling.within_at(start));
        // A second later, one second's rate more is too.
        read.fetch_add(1_000, Ordering::Relaxed);
        assert!(ceiling.within_at(start + Duration::from_secs(1)));
        // Twice the rate in the next second is not.
        read.fetch_add(2_000, Ordering::Relaxed);
        assert!(!ceiling.within_at(start + Duration::from_secs(2)));
    }

    #[test]
    fn a_feeder_keeping_to_what_it_is_told_stays_within_the_ceiling() {
        let rate = 262_144;
        let (bytes_per_sec, told_burst) = advertised(rate);
        // A feeder keeps at least one whole message of burst, whatever it is told.
        let floor = noise::MAX_PLAINTEXT as u64;
        let feeder_burst = u64::from(told_burst).max(floor);
        let read = Arc::new(AtomicU64::new(0));
        let mut ceiling = Ceiling::new(rate, Arc::clone(&read));
        let start = ceiling.refilled;
        // The worst first moment: handshake, the largest description, the whole burst of batches
        // in as many small messages as a second's framing allows.
        read.store(
            HANDSHAKE_ALLOWANCE
                + FRAMED_MESSAGE
                + feeder_burst
                + MESSAGES_A_SECOND * FRAMING_PER_MESSAGE,
            Ordering::Relaxed,
        );
        assert!(ceiling.within_at(start));
        // Then its rate, framed, for a minute.
        for second in 1..=60 {
            read.fetch_add(
                u64::from(bytes_per_sec) + MESSAGES_A_SECOND * FRAMING_PER_MESSAGE,
                Ordering::Relaxed,
            );
            assert!(ceiling.within_at(start + Duration::from_secs(second)));
        }
    }
}
