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

use std::borrow::Borrow;
use std::sync::Arc;
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
        ),
    )
    .await
    .map_err(|_| WireError::Timeout)?
}

/// Dials and says `Hello` with the versions `speaking` (this build's own range, except in a
/// test of how an older initiator is answered).
async fn initiate<S>(
    stream: S,
    local: &Identity,
    remote: &PublicKey,
    (role, first): (Role, &[Record]),
    (min_version, max_version): (u16, u16),
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
    let mut buffer = vec![0; MAX_MESSAGE];
    let length = handshake.write_message(local.public().as_bytes(), &mut buffer)?;
    write_frame(&mut write, &buffer[..length]).await?;
    let reply = read_frame(&mut read).await?;
    handshake.read_message(&reply, &mut buffer)?;
    let transport = Arc::new(handshake.into_stateless_transport_mode()?);
    let mut reader = Reader::new(read, Arc::clone(&transport));
    let mut writer = Writer::new(write, transport);
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
    tokio::time::timeout(HANDSHAKE_TIMEOUT, respond(stream, identities))
        .await
        .map_err(|_| WireError::Timeout)?
}

async fn respond<S>(stream: S, identities: &[Identity]) -> Result<Accepted<S>, WireError>
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
    let mut buffer = vec![0; MAX_MESSAGE];
    let first = read_frame(&mut read).await?;
    let length = handshake.read_message(&first, &mut buffer)?;
    if length != KEY_LEN {
        return Err(WireError::Truncated {
            needed: KEY_LEN,
            had: length,
        });
    }
    let peer = PublicKey::from_slice(&buffer[..KEY_LEN])?;
    let authenticated = handshake
        .get_remote_static()
        .ok_or(WireError::Preamble("the initiator sent no static key"))?;
    if peer.noise_key()?.as_slice() != authenticated {
        return Err(WireError::Key(
            "the claimed identity does not own the handshake key".to_owned(),
        ));
    }
    let length = handshake.write_message(&[], &mut buffer)?;
    write_frame(&mut write, &buffer[..length]).await?;
    let transport = Arc::new(handshake.into_stateless_transport_mode()?);
    let mut reader = Reader::new(read, Arc::clone(&transport));
    let mut writer = Writer::new(write, transport);
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

/// The receiving half of a session.
pub struct Reader<S> {
    read: ReadHalf<S>,
    transport: Arc<StatelessTransportState>,
    nonce: u64,
    plaintext: Vec<u8>,
}

impl<S: AsyncRead> Reader<S> {
    fn new(read: ReadHalf<S>, transport: Arc<StatelessTransportState>) -> Self {
        Self {
            read,
            transport,
            nonce: 0,
            plaintext: vec![0; MAX_MESSAGE],
        }
    }

    /// Reads one message and appends the records this build knows to `out`. An end of stream is
    /// an `Io` error of kind `UnexpectedEof`. The caller bounds the wait.
    pub async fn recv(&mut self, out: &mut Vec<Record>) -> Result<(), WireError> {
        let message = read_frame(&mut self.read).await?;
        let length = self
            .transport
            .read_message(self.nonce, &message, &mut self.plaintext)?;
        self.nonce += 1;
        Record::decode_message(&self.plaintext[..length], out)?;
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

/// The sending half of a session. Records are packed into as few messages as fit.
pub struct Writer<S> {
    write: WriteHalf<S>,
    transport: Arc<StatelessTransportState>,
    nonce: u64,
    plaintext: Vec<u8>,
    ciphertext: Vec<u8>,
}

impl<S: AsyncWrite> Writer<S> {
    fn new(write: WriteHalf<S>, transport: Arc<StatelessTransportState>) -> Self {
        Self {
            write,
            transport,
            nonce: 0,
            plaintext: Vec::with_capacity(MAX_PLAINTEXT),
            ciphertext: vec![0; MAX_MESSAGE],
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
        let mut encoded = Vec::new();
        for record in records {
            encoded.clear();
            record.borrow().encode(&mut encoded)?;
            if encoded.len() > MAX_PLAINTEXT {
                return Err(WireError::Oversize(encoded.len()));
            }
            if self.plaintext.len() + encoded.len() > MAX_PLAINTEXT {
                self.seal().await?;
            }
            self.plaintext.extend_from_slice(&encoded);
        }
        if !self.plaintext.is_empty() {
            self.seal().await?;
        }
        self.write.flush().await?;
        Ok(())
    }

    async fn seal(&mut self) -> Result<(), WireError> {
        let length =
            self.transport
                .write_message(self.nonce, &self.plaintext, &mut self.ciphertext)?;
        self.nonce += 1;
        self.plaintext.clear();
        write_frame(&mut self.write, &self.ciphertext[..length]).await
    }
}

async fn write_frame<W: AsyncWrite + Unpin>(write: &mut W, bytes: &[u8]) -> Result<(), WireError> {
    let length = u16::try_from(bytes.len()).map_err(|_| WireError::Oversize(bytes.len()))?;
    write.write_all(&length.to_be_bytes()).await?;
    write.write_all(bytes).await?;
    Ok(())
}

async fn read_frame<R: AsyncRead + Unpin>(read: &mut R) -> Result<Vec<u8>, WireError> {
    let mut length = [0; 2];
    read.read_exact(&mut length).await?;
    let mut bytes = vec![0; usize::from(u16::from_be_bytes(length))];
    read.read_exact(&mut bytes).await?;
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::batch::{Batch, BatchContent};

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
            initiate(near, &feeder, &relay_key, (Role::Feeder, &[]), (1, 1)).await
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
            initiate(near, &feeder, &relay_key, (Role::Probe, &[]), (1, 2)).await
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
}
