//! Every hop is Noise IK over a byte stream (RFC-0171 §3.3).
//!
//! A connection opens with a 16-byte plaintext preamble: `TALY`, the preamble version, the
//! handshake pattern, two reserved bytes, and a hint naming which of the responder's keys the
//! initiator is dialling. The preamble is the Noise prologue, so tampering with it fails the
//! handshake, and it is what lets the handshake itself change later, and a relay hold several keys
//! while it rotates, without a feeder update.
//!
//! The initiator's first handshake message carries its Ed25519 identity, which the responder
//! checks against the X25519 key the handshake authenticated. Then the initiator sends `Hello`
//! with the versions it speaks, and the responder answers `Welcome` with the one both will speak,
//! or `Goodbye`. Every step has a deadline.
//!
//! # Buffers
//!
//! A session holds no message buffer of its own between messages (RFC-0181 §11). Each message's
//! ciphertext, plaintext and the records packed into it are written in buffers taken from one
//! process-wide pool ([`Buffer`]) for as long as that message is in hand, and given back after:
//! at most `POOL_IDLE` are kept idle, so the pool holds what the busiest moment needed, not two
//! zeroed 64 KiB buffers for every connection, idle or not. A buffer given back is zeroed over
//! every byte any holder wrote before the pool keeps it, so no session's plaintext outlives its
//! message in memory, and a holder reads zeros wherever it has not written.

use std::borrow::Borrow;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use snow::StatelessTransportState;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadHalf, WriteHalf};

use crate::WireError;
use crate::key::{Identity, KEY_HINT_LEN, KEY_LEN, PublicKey, hint_of};
use crate::record::{MAX_VERSION, MIN_VERSION, Reason, Record, Role};

pub const PATTERN: &str = "Noise_IK_25519_ChaChaPoly_BLAKE2s";

/// How long a connection may take from the first byte to `Welcome`.
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);

/// How long one `Writer::send` may wait on a peer that is not reading. A peer that takes longer is
/// treated as gone, so a stalled reader can never hold a writer, and with it a session, forever.
pub const WRITE_TIMEOUT: Duration = Duration::from_secs(30);

/// The largest Noise message, ciphertext and tag together.
pub const MAX_MESSAGE: usize = 65_535;
const TAG_LEN: usize = 16;
/// The most plaintext one message carries.
pub const MAX_PLAINTEXT: usize = MAX_MESSAGE - TAG_LEN;

const MAGIC: &[u8; 4] = b"TALY";
const PREAMBLE_VERSION: u8 = 1;
const PATTERN_IK_25519_CHACHAPOLY_BLAKE2S: u8 = 1;
const PREAMBLE_LEN: usize = 4 + 1 + 1 + 2 + KEY_HINT_LEN;

/// The most message buffers the pool keeps idle; past it a buffer given back is freed.
pub const POOL_IDLE: usize = 256;

static POOL: Pool = Pool::new(POOL_IDLE);

/// Message buffers kept idle for the next message, at most `keep` of them, each `MAX_MESSAGE`
/// bytes and zero in every byte it holds. One per process (`POOL`); a test makes its own, so what
/// it counts is only its own.
pub(crate) struct Pool {
    idle: Mutex<Vec<Vec<u8>>>,
    keep: usize,
    /// Buffers allocated because none was idle, ever.
    made: AtomicUsize,
    /// Buffers taken and not yet given back.
    out: AtomicUsize,
}

impl Pool {
    pub(crate) const fn new(keep: usize) -> Self {
        Self {
            idle: Mutex::new(Vec::new()),
            keep,
            made: AtomicUsize::new(0),
            out: AtomicUsize::new(0),
        }
    }

    #[cfg(test)]
    /// Buffers idle now.
    fn idle(&self) -> usize {
        self.idle.lock().map_or(0, |idle| idle.len())
    }
}

/// A buffer of `MAX_MESSAGE` bytes from a pool, given back when dropped. Its bytes are reached only
/// through `space` (to write) and `written` (to read), and the plaintext a writer packs through
/// `append`, so the buffer knows the most bytes any holder may have written (`dirty`), and zeroes
/// exactly those when it goes back: the cost of a message is the bytes it used, never 64 KiB.
pub struct Buffer {
    bytes: Vec<u8>,
    /// No byte at or past this has been written since the buffer was last zeroed; the bytes
    /// before it may hold a holder's plaintext. Only ever rises while the buffer is held.
    dirty: usize,
    pool: &'static Pool,
}

impl Buffer {
    /// One from the process's pool, or a new one when the pool is empty.
    pub fn take() -> Self {
        Self::take_from(&POOL)
    }

    fn take_from(pool: &'static Pool) -> Self {
        let pooled = pool.idle.lock().ok().and_then(|mut idle| idle.pop());
        pool.out.fetch_add(1, Ordering::Relaxed);
        let bytes = pooled.unwrap_or_else(|| {
            pool.made.fetch_add(1, Ordering::Relaxed);
            Vec::with_capacity(MAX_MESSAGE)
        });
        // A pooled buffer is zero in every byte it holds: nothing in it is anyone's yet.
        Self {
            bytes,
            dirty: 0,
            pool,
        }
    }

    /// The first `len` bytes, at most `MAX_MESSAGE`, to be written: zero where this holder has not
    /// written.
    fn space(&mut self, len: usize) -> &mut [u8] {
        let len = len.min(MAX_MESSAGE);
        if self.bytes.len() < len {
            self.bytes.resize(len, 0);
        }
        self.dirty = self.dirty.max(len);
        &mut self.bytes[..len]
    }

    /// The first `len` bytes, as written: never past what this holder made room for (`space`) or
    /// packed (`append`), and zero wherever it made room and did not write.
    fn written(&self, len: usize) -> &[u8] {
        &self.bytes[..len.min(self.dirty).min(self.bytes.len())]
    }

    /// The plaintext packed so far (a writer's), as bytes.
    fn packed(&self) -> &[u8] {
        &self.bytes
    }

    /// Appends what `write` writes to the plaintext packed so far. `write` only appends (it is a
    /// record's `encode`), so the length after it bounds every byte it touched.
    fn append<T>(&mut self, write: impl FnOnce(&mut Vec<u8>) -> T) -> T {
        let result = write(&mut self.bytes);
        self.dirty = self.dirty.max(self.bytes.len());
        result
    }

    /// Cuts the packed plaintext back to `len` bytes: the cut bytes stay counted as written, and
    /// are zeroed when the buffer goes back.
    fn truncate(&mut self, len: usize) {
        self.bytes.truncate(len);
    }
}

impl Drop for Buffer {
    fn drop(&mut self) {
        let mut bytes = std::mem::take(&mut self.bytes);
        // Every byte written, zero: those still in the buffer's length and those past it a holder
        // wrote and cut back (a resize writes zeros over the stretch it regrows).
        bytes.clear();
        bytes.resize(self.dirty, 0);
        self.pool.out.fetch_sub(1, Ordering::Relaxed);
        let Some(buffer) = poolable(bytes) else {
            return;
        };
        if let Ok(mut idle) = self.pool.idle.lock()
            && idle.len() < self.pool.keep
        {
            idle.push(buffer);
        }
    }
}

/// What of a buffer given back the pool keeps: one of `MAX_MESSAGE` bytes' capacity, never more.
/// A writer packs no more than a message's plaintext (`send_now` measures a record before it
/// writes it), so a buffer never grows past a message; one that did is cut back here, so the pool
/// holds at most `POOL_IDLE` messages' worth whatever passed through it.
fn poolable(mut buffer: Vec<u8>) -> Option<Vec<u8>> {
    if buffer.capacity() < MAX_MESSAGE {
        return None;
    }
    buffer.truncate(MAX_MESSAGE);
    buffer.shrink_to(MAX_MESSAGE);
    Some(buffer)
}

fn preamble(hint: [u8; KEY_HINT_LEN]) -> [u8; PREAMBLE_LEN] {
    let mut bytes = [0; PREAMBLE_LEN];
    bytes[..4].copy_from_slice(MAGIC);
    bytes[4] = PREAMBLE_VERSION;
    bytes[5] = PATTERN_IK_25519_CHACHAPOLY_BLAKE2S;
    bytes[8..].copy_from_slice(&hint);
    bytes
}

/// One side of an open session.
pub struct Session<S> {
    pub reader: Reader<S>,
    pub writer: Writer<S>,
    /// The wire version both sides agreed.
    pub version: u16,
}

/// What a responder learns about who connected.
pub struct Accepted<S> {
    pub session: Session<S>,
    pub peer: PublicKey,
    pub role: Role,
    /// Records the initiator sent in the same message as its `Hello` (a subscriber's `Subscribe`),
    /// to act on before anything is sent its way.
    pub first: Vec<Record>,
}

/// Dials a responder whose key is known, says who we are and what we speak.
pub async fn connect<S>(
    stream: S,
    local: &Identity,
    remote: &PublicKey,
    role: Role,
) -> Result<Session<S>, WireError>
where
    S: AsyncRead + AsyncWrite + Send,
{
    connect_with(stream, local, remote, role, &[]).await
}

/// As `connect`, also sending `first` in the same message as `Hello`, so the responder has it
/// before it sends anything: a subscriber's `Subscribe`, so it is never sent what it did not ask
/// for.
pub async fn connect_with<S>(
    stream: S,
    local: &Identity,
    remote: &PublicKey,
    role: Role,
    first: &[Record],
) -> Result<Session<S>, WireError>
where
    S: AsyncRead + AsyncWrite + Send,
{
    tokio::time::timeout(
        HANDSHAKE_TIMEOUT,
        initiate(
            stream,
            local,
            remote,
            (role, first),
            (MIN_VERSION, MAX_VERSION),
            &POOL,
        ),
    )
    .await
    .map_err(|_| WireError::Timeout)?
}

/// Dials and says `Hello` with the versions `speaking` (this build's own range, except in a
/// test of how an older initiator is answered), its messages in buffers from `pool` (the
/// process's, except in a test that counts them).
async fn initiate<S>(
    stream: S,
    local: &Identity,
    remote: &PublicKey,
    (role, first): (Role, &[Record]),
    (min_version, max_version): (u16, u16),
    pool: &'static Pool,
) -> Result<Session<S>, WireError>
where
    S: AsyncRead + AsyncWrite + Send,
{
    let (mut read, mut write) = tokio::io::split(stream);
    let remote_noise = remote.noise_key()?;
    let prologue = preamble(hint_of(&remote_noise));
    write.write_all(&prologue).await?;
    let local_noise = local.noise_private();
    let mut handshake = snow::Builder::new(PATTERN.parse()?)
        .prologue(&prologue)?
        .local_private_key(&local_noise)?
        .remote_public_key(&remote_noise)?
        .build_initiator()?;
    let mut buffer = Buffer::take_from(pool);
    let length = handshake.write_message(local.public().as_bytes(), buffer.space(MAX_MESSAGE))?;
    write_frame(&mut write, buffer.written(length)).await?;
    let mut reply = Buffer::take_from(pool);
    let reply_len = read_frame(&mut read, &mut reply).await?;
    handshake.read_message(reply.written(reply_len), buffer.space(MAX_MESSAGE))?;
    drop((buffer, reply));
    let transport = Arc::new(handshake.into_stateless_transport_mode()?);
    let mut reader = Reader::new(read, Arc::clone(&transport), pool);
    let mut writer = Writer::new(write, transport, pool);
    let mut opening = vec![Record::Hello {
        min_version,
        max_version,
        role,
    }];
    opening.extend_from_slice(first);
    writer.send(&opening).await?;
    let mut records = Vec::new();
    reader.recv(&mut records).await?;
    match records.first() {
        Some(Record::Welcome { version }) if (MIN_VERSION..=MAX_VERSION).contains(version) => {
            Ok(Session {
                reader,
                writer,
                version: *version,
            })
        }
        Some(Record::Goodbye {
            reason,
            retry_after_secs,
        }) => Err(WireError::Refused {
            reason: *reason,
            retry_after_secs: *retry_after_secs,
        }),
        _ => Err(WireError::Invalid {
            field: "answer to Hello",
            value: records.len() as u64,
        }),
    }
}

/// Answers an initiator dialling any of `identities` (more than one while a relay rotates its
/// key). Returns who it is and what it is; whether to serve that key is the caller's decision.
pub async fn accept<S>(stream: S, identities: &[Identity]) -> Result<Accepted<S>, WireError>
where
    S: AsyncRead + AsyncWrite + Send,
{
    tokio::time::timeout(HANDSHAKE_TIMEOUT, respond(stream, identities, &POOL))
        .await
        .map_err(|_| WireError::Timeout)?
}

async fn respond<S>(
    stream: S,
    identities: &[Identity],
    pool: &'static Pool,
) -> Result<Accepted<S>, WireError>
where
    S: AsyncRead + AsyncWrite + Send,
{
    let (mut read, mut write) = tokio::io::split(stream);
    let mut prologue = [0; PREAMBLE_LEN];
    read.read_exact(&mut prologue).await?;
    if &prologue[..4] != MAGIC {
        return Err(WireError::Preamble("not a Tally connection"));
    }
    if prologue[4] != PREAMBLE_VERSION || prologue[5] != PATTERN_IK_25519_CHACHAPOLY_BLAKE2S {
        return Err(WireError::Preamble("unsupported preamble or handshake"));
    }
    let hint = &prologue[8..];
    let local = identities
        .iter()
        .find(|identity| {
            identity
                .public()
                .hint()
                .is_ok_and(|candidate| candidate == hint)
        })
        .ok_or(WireError::Preamble("no key of ours matches the hint"))?;
    let local_noise = local.noise_private();
    let mut handshake = snow::Builder::new(PATTERN.parse()?)
        .prologue(&prologue)?
        .local_private_key(&local_noise)?
        .build_responder()?;
    let mut buffer = Buffer::take_from(pool);
    let mut first = Buffer::take_from(pool);
    let first_len = read_frame(&mut read, &mut first).await?;
    let length = handshake.read_message(first.written(first_len), buffer.space(MAX_MESSAGE))?;
    if length != KEY_LEN {
        return Err(WireError::Truncated {
            needed: KEY_LEN,
            had: length,
        });
    }
    let peer = PublicKey::from_slice(buffer.written(KEY_LEN))?;
    let authenticated = handshake
        .get_remote_static()
        .ok_or(WireError::Preamble("the initiator sent no static key"))?;
    if peer.noise_key()?.as_slice() != authenticated {
        return Err(WireError::Key(
            "the claimed identity does not own the handshake key".to_owned(),
        ));
    }
    let length = handshake.write_message(&[], buffer.space(MAX_MESSAGE))?;
    write_frame(&mut write, buffer.written(length)).await?;
    drop((buffer, first));
    let transport = Arc::new(handshake.into_stateless_transport_mode()?);
    let mut reader = Reader::new(read, Arc::clone(&transport), pool);
    let mut writer = Writer::new(write, transport, pool);
    let mut records = Vec::new();
    reader.recv(&mut records).await?;
    let Some(Record::Hello {
        min_version,
        max_version,
        role,
    }) = records.first().cloned()
    else {
        return Err(WireError::Invalid {
            field: "first record (expected Hello)",
            value: records.len() as u64,
        });
    };
    let version = max_version.min(MAX_VERSION);
    if version < min_version.max(MIN_VERSION) {
        writer
            .send(&[Record::Goodbye {
                reason: Reason::Version,
                retry_after_secs: 86_400,
            }])
            .await?;
        return Err(WireError::Invalid {
            field: "initiator's highest version",
            value: u64::from(max_version),
        });
    }
    writer.send(&[Record::Welcome { version }]).await?;
    Ok(Accepted {
        session: Session {
            reader,
            writer,
            version,
        },
        peer,
        role,
        first: records.split_off(1),
    })
}

/// The receiving half of a session. It holds no buffer between messages: one is taken from the
/// pool once a message's length has arrived, and another to decrypt into, and both go back once
/// its records are decoded.
pub struct Reader<S> {
    read: ReadHalf<S>,
    transport: Arc<StatelessTransportState>,
    nonce: u64,
    pool: &'static Pool,
}

impl<S: AsyncRead> Reader<S> {
    fn new(
        read: ReadHalf<S>,
        transport: Arc<StatelessTransportState>,
        pool: &'static Pool,
    ) -> Self {
        Self {
            read,
            transport,
            nonce: 0,
            pool,
        }
    }

    /// Reads one message and appends the records this build knows to `out`. An end of stream is
    /// an `Io` error of kind `UnexpectedEof`. The caller bounds the wait.
    pub async fn recv(&mut self, out: &mut Vec<Record>) -> Result<(), WireError> {
        let mut length = [0; 2];
        self.read.read_exact(&mut length).await?;
        let length = usize::from(u16::from_be_bytes(length));
        let mut message = Buffer::take_from(self.pool);
        self.read.read_exact(message.space(length)).await?;
        // The plaintext is shorter than its frame: room for the frame's length is room enough,
        // and is all a message makes the buffer zero again.
        let mut plaintext = Buffer::take_from(self.pool);
        let length = self.transport.read_message(
            self.nonce,
            message.written(length),
            plaintext.space(length),
        )?;
        self.nonce += 1;
        Record::decode_message(plaintext.written(length), out)?;
        Ok(())
    }

    /// Reads and drops whatever the peer still sends, undecrypted, until it closes or the read
    /// fails. Ending a session closes over nothing unread this way: a socket closed with bytes
    /// unread is reset, and a reset discards what had not yet been sent of the last word. The
    /// caller bounds the wait.
    pub async fn discard(&mut self) {
        let mut sink = [0u8; 4096];
        while matches!(self.read.read(&mut sink).await, Ok(read) if read > 0) {}
    }
}

/// The sending half of a session. Records are packed into as few messages as fit, in buffers
/// taken from the pool for the send and given back after it: it holds none between sends.
pub struct Writer<S> {
    write: WriteHalf<S>,
    transport: Arc<StatelessTransportState>,
    nonce: u64,
    pool: &'static Pool,
}

impl<S: AsyncWrite> Writer<S> {
    fn new(
        write: WriteHalf<S>,
        transport: Arc<StatelessTransportState>,
        pool: &'static Pool,
    ) -> Self {
        Self {
            write,
            transport,
            nonce: 0,
            pool,
        }
    }

    /// Sends the records, in order, in one or more messages, and flushes.
    /// `R` is `Record` or anything that lends one (an `Arc<Record>` shared by many subscribers).
    ///
    /// Fails with `Timeout` after `WRITE_TIMEOUT`; the writer is then mid-frame and the session must
    /// end.
    pub async fn send<R>(&mut self, records: &[R]) -> Result<(), WireError>
    where
        R: Borrow<Record> + Sync,
    {
        tokio::time::timeout(WRITE_TIMEOUT, self.send_now(records))
            .await
            .map_err(|_| WireError::Timeout)?
    }

    /// Ends the sending direction once everything sent is on its way: the peer reads the end of
    /// stream after the last message. Fails with `Timeout` after `WRITE_TIMEOUT`.
    pub async fn shutdown(&mut self) -> Result<(), WireError> {
        tokio::time::timeout(WRITE_TIMEOUT, self.write.shutdown())
            .await
            .map_err(|_| WireError::Timeout)?
            .map_err(WireError::from)
    }

    async fn send_now<R>(&mut self, records: &[R]) -> Result<(), WireError>
    where
        R: Borrow<Record> + Sync,
    {
        let mut plaintext = Buffer::take_from(self.pool);
        let mut ciphertext = Buffer::take_from(self.pool);
        plaintext.truncate(0);
        for record in records {
            let record = record.borrow();
            // Measured before it is written, and the message sealed first when it would not fit
            // after what is there: a message's plaintext never passes `MAX_PLAINTEXT`, so the
            // buffer never grows past a message and nothing is moved.
            let len = record.encoded_len();
            if len > MAX_PLAINTEXT {
                return Err(WireError::Oversize(len));
            }
            if plaintext.packed().len() + len > MAX_PLAINTEXT {
                self.seal(plaintext.packed(), &mut ciphertext).await?;
                plaintext.truncate(0);
            }
            plaintext.append(|out| record.encode(out))?;
            // `encoded_len` is the one measure of a record (`Record::encoded_len`); were it ever
            // short, the message is refused rather than sent over-long.
            if plaintext.packed().len() > MAX_PLAINTEXT {
                return Err(WireError::Oversize(plaintext.packed().len()));
            }
        }
        if !plaintext.packed().is_empty() {
            self.seal(plaintext.packed(), &mut ciphertext).await?;
        }
        drop((plaintext, ciphertext));
        self.write.flush().await?;
        Ok(())
    }

    async fn seal(&mut self, plaintext: &[u8], ciphertext: &mut Buffer) -> Result<(), WireError> {
        let space = ciphertext.space(plaintext.len() + TAG_LEN);
        let length = self.transport.write_message(self.nonce, plaintext, space)?;
        self.nonce += 1;
        write_frame(&mut self.write, ciphertext.written(length)).await
    }
}

async fn write_frame<W: AsyncWrite + Unpin>(write: &mut W, bytes: &[u8]) -> Result<(), WireError> {
    let length = u16::try_from(bytes.len()).map_err(|_| WireError::Oversize(bytes.len()))?;
    write.write_all(&length.to_be_bytes()).await?;
    write.write_all(bytes).await?;
    Ok(())
}

/// Reads one frame into `into`; its length.
async fn read_frame<R: AsyncRead + Unpin>(
    read: &mut R,
    into: &mut Buffer,
) -> Result<usize, WireError> {
    let mut length = [0; 2];
    read.read_exact(&mut length).await?;
    let length = usize::from(u16::from_be_bytes(length));
    read.read_exact(into.space(length)).await?;
    Ok(length)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::batch::{Batch, BatchContent};
    use crate::record::RelayAddress;

    fn join<T>(result: Result<T, tokio::task::JoinError>) -> Result<T, WireError> {
        result.map_err(|error| WireError::Key(error.to_string()))
    }

    #[tokio::test]
    async fn a_session_names_the_initiator_and_carries_records_both_ways() -> Result<(), WireError>
    {
        let relay = Identity::generate()?;
        let feeder = Identity::generate()?;
        let (near, far) = tokio::io::duplex(1 << 16);
        let relay_key = relay.public();
        let dial = tokio::spawn({
            let feeder = feeder.clone();
            async move { connect(near, &feeder, &relay_key, Role::Feeder).await }
        });
        let accepted = accept(far, &[relay]).await?;
        let mut theirs = join(dial.await)??;
        assert_eq!(accepted.peer, feeder.public());
        assert_eq!(accepted.role, Role::Feeder);
        assert_eq!(
            (accepted.session.version, theirs.version),
            (MAX_VERSION, MAX_VERSION)
        );

        let batches: Vec<Record> = (0..200)
            .map(|sequence| {
                Batch::sign(
                    &feeder,
                    &BatchContent {
                        boot_id: 1,
                        sequence,
                        counter_epoch: 0,
                        wall_ms: 0,
                        dropped: 0,
                        previous: [0; 32],
                        observations: Vec::new(),
                    },
                )
                .map(Record::Batch)
            })
            .collect::<Result<_, _>>()?;
        // The send runs beside the read: the pipe holds 64 KiB, less than these batches.
        let sending = tokio::spawn({
            let batches = batches.clone();
            let mut writer = theirs.writer;
            async move {
                writer.send(&batches).await?;
                Ok::<_, WireError>(writer)
            }
        });
        let mut ours = accepted.session;
        let mut got = Vec::new();
        while got.len() < batches.len() {
            ours.reader.recv(&mut got).await?;
        }
        assert_eq!(got, batches);
        join(sending.await)??;

        ours.writer.send(&[Record::Heartbeat]).await?;
        let mut back = Vec::new();
        theirs.reader.recv(&mut back).await?;
        assert_eq!(back, vec![Record::Heartbeat]);
        Ok(())
    }

    #[tokio::test]
    async fn records_sent_with_hello_reach_the_responder_before_anything_else()
    -> Result<(), WireError> {
        let relay = Identity::generate()?;
        let subscriber = Identity::generate()?;
        let (near, far) = tokio::io::duplex(1 << 16);
        let relay_key = relay.public();
        let dial = tokio::spawn(async move {
            connect_with(
                near,
                &subscriber,
                &relay_key,
                Role::Subscriber,
                &[Record::Heartbeat],
            )
            .await
        });
        let accepted = accept(far, &[relay]).await?;
        join(dial.await)??;
        assert_eq!(accepted.first, vec![Record::Heartbeat]);
        Ok(())
    }

    #[tokio::test]
    async fn a_version_1_initiator_is_refused_with_a_goodbye() -> Result<(), WireError> {
        let relay = Identity::generate()?;
        let feeder = Identity::generate()?;
        let (near, far) = tokio::io::duplex(1 << 16);
        let relay_key = relay.public();
        let dial = tokio::spawn(async move {
            initiate(
                near,
                &feeder,
                &relay_key,
                (Role::Feeder, &[]),
                (1, 1),
                &POOL,
            )
            .await
        });
        assert!(accept(far, &[relay]).await.is_err());
        assert!(matches!(
            join(dial.await)?,
            Err(WireError::Refused {
                reason: Reason::Version,
                ..
            })
        ));
        // An initiator that also speaks 2 is welcomed at 2.
        let relay = Identity::generate()?;
        let feeder = Identity::generate()?;
        let (near, far) = tokio::io::duplex(1 << 16);
        let relay_key = relay.public();
        let dial = tokio::spawn(async move {
            initiate(near, &feeder, &relay_key, (Role::Probe, &[]), (1, 2), &POOL).await
        });
        let accepted = accept(far, &[relay]).await?;
        assert_eq!((accepted.session.version, accepted.role), (2, Role::Probe));
        assert_eq!(join(dial.await)??.version, 2);
        Ok(())
    }

    #[tokio::test]
    async fn a_relay_answers_on_whichever_of_its_keys_was_dialled() -> Result<(), WireError> {
        let old = Identity::generate()?;
        let new = Identity::generate()?;
        let feeder = Identity::generate()?;
        let (near, far) = tokio::io::duplex(1 << 16);
        let dialled = new.public();
        let dial =
            tokio::spawn(async move { connect(near, &feeder, &dialled, Role::Feeder).await });
        accept(far, &[old, new]).await?;
        join(dial.await)??;
        Ok(())
    }

    #[tokio::test]
    async fn dialling_a_key_the_relay_does_not_hold_fails() -> Result<(), WireError> {
        let relay = Identity::generate()?;
        let impostor = Identity::generate()?;
        let feeder = Identity::generate()?;
        let (near, far) = tokio::io::duplex(1 << 16);
        let wrong = impostor.public();
        let dial =
            tokio::spawn(
                async move { connect(near, &feeder, &wrong, Role::Feeder).await.is_err() },
            );
        assert!(accept(far, &[relay]).await.is_err());
        assert!(join(dial.await)?);
        Ok(())
    }

    #[tokio::test]
    async fn a_send_to_a_peer_that_never_reads_times_out() -> Result<(), WireError> {
        let relay = Identity::generate()?;
        let feeder = Identity::generate()?;
        let (near, far) = tokio::io::duplex(1 << 12);
        let relay_key = relay.public();
        let dial =
            tokio::spawn(async move { connect(near, &feeder, &relay_key, Role::Feeder).await });
        let accepted = accept(far, &[relay]).await?;
        let mut theirs = join(dial.await)??;
        tokio::time::pause();
        // The relay never reads again; the pipe fills, and the send gives up instead of waiting.
        let big = Record::RelayList(Vec::new());
        let many: Vec<Record> = std::iter::repeat_n(big, 20_000).collect();
        assert!(matches!(
            theirs.writer.send(&many).await,
            Err(WireError::Timeout)
        ));
        drop(accepted);
        Ok(())
    }

    #[tokio::test]
    async fn a_stranger_that_never_speaks_times_out() -> Result<(), WireError> {
        tokio::time::pause();
        let relay = Identity::generate()?;
        let (_near, far) = tokio::io::duplex(1 << 16);
        assert!(matches!(
            accept(far, &[relay]).await,
            Err(WireError::Timeout)
        ));
        Ok(())
    }

    #[test]
    fn the_pool_keeps_a_message_a_buffer_never_more() {
        let grown = Vec::<u8>::with_capacity(3 * MAX_MESSAGE);
        assert_eq!(
            poolable(grown).map(|kept| kept.capacity()),
            Some(MAX_MESSAGE)
        );
        let mut full = vec![0u8; MAX_MESSAGE + 100];
        full.reserve(MAX_MESSAGE);
        assert_eq!(
            poolable(full).map(|kept| kept.capacity()),
            Some(MAX_MESSAGE)
        );
        assert!(poolable(Vec::with_capacity(MAX_MESSAGE / 2)).is_none());
    }

    /// A pool of the test's own, so what it counts is only what the test did: the process's pool
    /// is shared by every test running beside it.
    fn own_pool(keep: usize) -> &'static Pool {
        Box::leak(Box::new(Pool::new(keep)))
    }

    #[tokio::test]
    async fn a_session_holds_no_message_buffer_between_messages() -> Result<(), WireError> {
        // What a connection costs while idle is its two halves and the shared transport: no
        // 64 KiB buffer of its own, zeroed or not (they were three, some 192 KiB).
        type Half = tokio::io::DuplexStream;
        let halves = std::mem::size_of::<Reader<Half>>() + std::mem::size_of::<Writer<Half>>();
        assert!(halves < 1024, "{halves} bytes");
        let pool = own_pool(16);
        let relay = Identity::generate()?;
        let feeder = Identity::generate()?;
        let mut sessions = Vec::new();
        for _ in 0..8 {
            let (near, far) = tokio::io::duplex(1 << 17);
            let relay_key = relay.public();
            let dial = tokio::spawn({
                let feeder = feeder.clone();
                async move {
                    initiate(
                        near,
                        &feeder,
                        &relay_key,
                        (Role::Feeder, &[]),
                        (MIN_VERSION, MAX_VERSION),
                        pool,
                    )
                    .await
                }
            });
            let mut accepted = respond(far, std::slice::from_ref(&relay), pool).await?;
            let mut theirs = join(dial.await)??;
            // Two messages' worth, so a send packs and splits.
            let records: Vec<Record> = (0..7_000)
                .map(|nonce| Record::Echo(crate::probe::Echo { nonce }))
                .chain(std::iter::once(Record::RelayList(Vec::new())))
                .collect();
            theirs.writer.send(&records).await?;
            let mut got = Vec::new();
            while got.len() < records.len() {
                accepted.session.reader.recv(&mut got).await?;
            }
            assert_eq!(got, records);
            sessions.push((accepted, theirs));
        }
        // Eight open sessions, every one idle between messages, hold no buffer at all.
        assert_eq!(pool.out.load(Ordering::Relaxed), 0);
        // And every message, handshakes included, was written in buffers given back by the one
        // before: never more allocated than one moment had in hand (a handshake's two sides, two
        // each), whatever the sessions and messages.
        let made = pool.made.load(Ordering::Relaxed);
        assert!(made <= 4, "{made} buffers allocated for 8 sessions");
        assert_eq!(pool.idle(), made);
        drop(sessions);
        Ok(())
    }

    #[test]
    fn a_buffer_given_back_is_zero_in_every_byte_any_holder_wrote() {
        let pool = own_pool(4);
        let mut buffer = Buffer::take_from(pool);
        buffer.space(100).fill(0xab);
        // A writer's plaintext packed past that, then cut back: the cut bytes were written too.
        buffer.truncate(0);
        buffer.append(|out| out.extend_from_slice(&[0xcd; 300]));
        buffer.truncate(10);
        let at = buffer.packed().as_ptr();
        drop(buffer);
        assert_eq!(pool.idle(), 1);
        let again = Buffer::take_from(pool);
        // The same allocation, not a new one...
        assert_eq!(again.bytes.as_ptr(), at);
        assert_eq!(pool.made.load(Ordering::Relaxed), 1);
        // ...and nothing of the last holder's in it: every byte written, zero.
        assert_eq!(again.bytes.len(), 300);
        assert!(again.bytes.iter().all(|byte| *byte == 0));
        assert!(again.written(MAX_MESSAGE).is_empty());
    }

    #[test]
    fn the_pool_keeps_at_most_its_idle_bound() {
        let pool = own_pool(2);
        let held: Vec<Buffer> = (0..5).map(|_| Buffer::take_from(pool)).collect();
        assert_eq!(pool.out.load(Ordering::Relaxed), 5);
        assert_eq!(pool.made.load(Ordering::Relaxed), 5);
        drop(held);
        assert_eq!(pool.out.load(Ordering::Relaxed), 0);
        assert_eq!(pool.idle(), 2);
        let mut taken = Buffer::take_from(pool);
        assert!(taken.bytes.capacity() >= MAX_MESSAGE);
        assert_eq!(taken.space(MAX_MESSAGE + 1).len(), MAX_MESSAGE);
        assert_eq!(pool.made.load(Ordering::Relaxed), 5);
    }

    #[tokio::test]
    async fn a_send_seals_a_message_before_the_record_that_would_overflow_it()
    -> Result<(), WireError> {
        let relay = Identity::generate()?;
        let feeder = Identity::generate()?;
        let (near, far) = tokio::io::duplex(1 << 20);
        let relay_key = relay.public();
        let dial =
            tokio::spawn(async move { connect(near, &feeder, &relay_key, Role::Feeder).await });
        let mut accepted = accept(far, std::slice::from_ref(&relay)).await?;
        let mut theirs = join(dial.await)??;
        // Records of which three fit a message and four do not.
        let list: Vec<RelayAddress> = (0..70)
            .map(|index| RelayAddress {
                key: relay.public(),
                address: format!("{index:0>255}"),
            })
            .collect();
        let record = Record::RelayList(list);
        let len = record.encoded_len();
        assert!(3 * len <= MAX_PLAINTEXT && 4 * len > MAX_PLAINTEXT, "{len}");
        let records: Vec<Record> = std::iter::repeat_n(record, 12).collect();
        theirs.writer.send(&records).await?;
        let mut got = Vec::new();
        let mut messages = 0;
        while got.len() < records.len() {
            accepted.session.reader.recv(&mut got).await?;
            messages += 1;
        }
        assert_eq!(got, records);
        assert_eq!(messages, 4);
        // One record larger than a message is refused before a byte of it is written.
        let huge = Record::RelayList(vec![
            RelayAddress {
                key: relay.public(),
                address: "x".repeat(255),
            };
            255
        ]);
        assert!(huge.encoded_len() > MAX_PLAINTEXT);
        assert!(matches!(
            theirs.writer.send(&[huge]).await,
            Err(WireError::Oversize(_))
        ));
        Ok(())
    }
}
