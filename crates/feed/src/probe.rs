//! Round-trip probing (RFC-0174 §2.2): every few minutes the feeder sends an `Echo` (with its
//! Hello) to candidate relays (its cache, the seeds, its owner's `--relay`, the relays that offer
//! its own area first, and a few random ones every round) and keeps the median of several probes of
//! each, with the signed `EchoReply` (headroom, network) that came back. A round-trip time cannot be
//! faked downward; a location can.
//!
//! One probe is one session: the TCP connect is the first sample, the `Echo` sent with Hello is
//! answered before admission (so a full relay still says how near it is, and that it is full), and
//! the rest of `PROBES_PER_ROUND` are echoes inside the session, each timed from send to signed
//! reply. A relay that gives no signed reply is not measured. The probe dials as `Role::Probe`
//! (RFC-0171 §3.3), which takes none of the relay's feeder slots: a relay at capacity says so by
//! declaring no spare slot in its signed reply, and one that still turns the probe away
//! (`Redirect`, or `Goodbye` full) is measured as full.
//!
//! The address the session's socket reached is kept (`Measured::observed`): it is what tells two
//! relays' networks apart beside what each declares (`tally_wire::rendezvous::distinct_networks`).

use std::net::IpAddr;
use std::time::Duration;

use tally_wire::noise;
use tally_wire::rendezvous::Placement;
use tally_wire::{
    Echo, EchoReply, EchoReplyContent, Identity, Record, RelayAddress, Role, WireError,
};
use tokio::net::TcpStream;
use tokio::time::Instant;

/// One relay as measured.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Measured {
    pub relay: RelayAddress,
    /// The median of the round's probes.
    pub rtt: Duration,
    /// The newest signed reply's content, checked against `relay.key`.
    pub reply: EchoReplyContent,
    /// The address the probe's connection reached: observed, not declared. None when the socket
    /// could not say.
    pub observed: Option<IpAddr>,
    /// The relay turned the probe away after its reply (`Redirect`, or `Goodbye` full): whatever
    /// its reply declared, it takes no feeder now.
    pub full: bool,
}

impl Measured {
    /// The spare feeder capacity the ranking weighs it by (RFC-0174 §2.2): its signed
    /// `feeder_slots`, zero when it turned the probe away.
    pub fn weight(&self) -> u64 {
        if self.full {
            return 0;
        }
        u64::from(self.reply.headroom.feeder_slots)
    }

    /// The autonomous system its signed reply names; 0 when it does not say.
    pub fn network(&self) -> u32 {
        self.reply.network
    }

    /// What it declares and where it was seen, for `rendezvous::distinct_networks`.
    pub fn placement(&self) -> Placement {
        Placement {
            network: self.network(),
            host: self.observed,
        }
    }
}

/// A probe's measurement, and the relays it hinted at while the session was open.
#[derive(Clone, Debug)]
pub struct Probed {
    pub measured: Measured,
    pub hints: Vec<RelayAddress>,
}

/// Probes to send per relay per round, whose median is its time.
pub const PROBES_PER_ROUND: usize = 5;
/// How often a round runs.
pub const ROUND_EVERY: Duration = Duration::from_secs(5 * 60);
/// Relays picked at random each round beside the nearest by location.
pub const RANDOM_PER_ROUND: usize = 3;
/// The most relays probed in one round, the random ones included.
pub const MOST_PER_ROUND: usize = 16;
/// The least the band reaches past the closest time.
pub const BAND_FLOOR: Duration = Duration::from_millis(10);
/// The longest one probe (connect, handshake and every echo) may take.
pub const PROBE_TIMEOUT: Duration = Duration::from_secs(20);
/// The longest one echo inside a session is waited for.
const ECHO_TIMEOUT: Duration = Duration::from_secs(5);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// The band (§2.2): the measured relays that can take a feeder (weight above zero) within the
/// closest such time plus half again, or plus `BAND_FLOOR`, whichever is larger.
pub fn band(measured: &[Measured]) -> Vec<Measured> {
    let eligible = || measured.iter().filter(|each| each.weight() > 0);
    let Some(closest) = eligible().map(|each| each.rtt).min() else {
        return Vec::new();
    };
    let limit = closest + (closest / 2).max(BAND_FLOOR);
    eligible()
        .filter(|each| each.rtt <= limit)
        .cloned()
        .collect()
}

/// The median of `samples` (the lower of the middle two of an even count).
pub fn median(samples: &mut [Duration]) -> Option<Duration> {
    samples.sort_unstable();
    let middle = samples.len().checked_sub(1)? / 2;
    samples.get(middle).copied()
}

/// How the publisher measures one relay. The feeder's is `measure`; a test over loopback relays,
/// which are all equally near, pins the time it reads so the ranking decides and not the test host's
/// scheduling.
pub type Prober =
    fn(
        RelayAddress,
        Identity,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Probed, String>> + Send>>;

/// The feeder's `Prober`: `probe`.
pub fn measure(
    relay: RelayAddress,
    me: Identity,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Probed, String>> + Send>> {
    Box::pin(async move { probe(&relay, &me).await })
}

/// Probes `relay`: its round-trip time (the median of `PROBES_PER_ROUND` samples), its signed
/// reply, and whether it is full.
pub async fn probe(relay: &RelayAddress, me: &Identity) -> Result<Probed, String> {
    tokio::time::timeout(PROBE_TIMEOUT, probe_once(relay, me))
        .await
        .map_err(|_| "probe timed out".to_owned())?
}

async fn probe_once(relay: &RelayAddress, me: &Identity) -> Result<Probed, String> {
    let started = Instant::now();
    let stream = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(&relay.address))
        .await
        .map_err(|_| "connect timed out".to_owned())?
        .map_err(|error| error.to_string())?;
    let mut samples = vec![started.elapsed()];
    let observed = stream.peer_addr().ok().map(|address| address.ip());
    let first = Echo { nonce: nonce() };
    let session = noise::connect_with(stream, me, &relay.key, Role::Probe, &[Record::Echo(first)])
        .await
        .map_err(|error| error.to_string())?;
    let (mut reader, mut writer) = (session.reader, session.writer);
    let mut heard = Heard::default();
    // Every relay answers an Echo; one whose answer never came, or did not verify as its key's,
    // is not measured.
    let mut reply = heard
        .reply(&mut reader, relay, first.nonce)
        .await
        .ok_or("no signed echo reply")?;
    while !heard.ended && samples.len() < PROBES_PER_ROUND {
        let echo = Echo { nonce: nonce() };
        let sent = Instant::now();
        if writer.send(&[Record::Echo(echo)]).await.is_err() {
            break;
        }
        match heard.reply(&mut reader, relay, echo.nonce).await {
            Some(newer) => {
                samples.push(sent.elapsed());
                reply = newer;
            }
            None => break,
        }
    }
    let rtt = median(&mut samples).unwrap_or_default();
    Ok(Probed {
        measured: Measured {
            relay: relay.clone(),
            rtt,
            reply,
            observed,
            full: heard.full,
        },
        hints: heard.hints,
    })
}

/// What a probe session said besides its replies.
#[derive(Default)]
struct Heard {
    hints: Vec<RelayAddress>,
    full: bool,
    ended: bool,
}

impl Heard {
    /// Reads until the signed reply to `nonce`, checked against `relay`'s key; none if the session
    /// ends, the wait runs out, or the reply does not verify.
    async fn reply<S: tokio::io::AsyncRead>(
        &mut self,
        reader: &mut noise::Reader<S>,
        relay: &RelayAddress,
        nonce: u64,
    ) -> Option<EchoReplyContent> {
        let deadline = Instant::now() + ECHO_TIMEOUT;
        loop {
            if self.ended {
                return None;
            }
            let mut got = Vec::new();
            match tokio::time::timeout_at(deadline, reader.recv(&mut got)).await {
                Ok(Ok(())) => {}
                Ok(Err(_)) | Err(_) => {
                    self.ended = true;
                    return None;
                }
            }
            let mut answer = None;
            for record in got {
                match record {
                    Record::EchoReply(signed) => {
                        if let Ok(content) = checked(&signed, relay)
                            && content.nonce == nonce
                        {
                            answer = Some(content);
                        }
                    }
                    Record::RelayList(relays) => self.hints.extend(relays),
                    Record::Redirect { hints, .. } => {
                        self.hints.extend(hints);
                        self.full = true;
                        self.ended = true;
                    }
                    Record::Goodbye { reason, .. } => {
                        self.full = matches!(reason, tally_wire::Reason::Full);
                        self.ended = true;
                    }
                    _ => {}
                }
            }
            if answer.is_some() {
                return answer;
            }
        }
    }
}

/// The reply's content, if `relay`'s key signed it.
fn checked(reply: &EchoReply, relay: &RelayAddress) -> Result<EchoReplyContent, WireError> {
    if reply.signer()? != relay.key {
        return Err(WireError::Key(
            "an echo reply signed by another key".to_owned(),
        ));
    }
    reply.verify()?;
    reply.content()
}

fn nonce() -> u64 {
    let mut bytes = [0; 8];
    let _ = getrandom::getrandom(&mut bytes);
    u64::from_be_bytes(bytes)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use tally_wire::{EchoReplyContent, Headroom, PublicKey};

    pub(crate) fn measured(key: PublicKey, rtt_ms: u64, slots: u32, network: u32) -> Measured {
        Measured {
            relay: RelayAddress {
                key,
                address: format!("relay-{network}-{rtt_ms}.example:10900"),
            },
            rtt: Duration::from_millis(rtt_ms),
            reply: EchoReplyContent {
                nonce: 1,
                issued_ms: 1,
                network,
                headroom: Headroom {
                    feeder_slots: slots,
                    pace_headroom_bytes_per_sec: 1 << 20,
                    mlat_cores: 0,
                },
            },
            // Its own /24, by its key: two test relays share a prefix only when a test says so.
            observed: Some(IpAddr::V4(std::net::Ipv4Addr::new(
                10,
                key.as_bytes()[0],
                key.as_bytes()[1],
                1,
            ))),
            full: false,
        }
    }

    fn key() -> Result<PublicKey, String> {
        Ok(Identity::generate()
            .map_err(|error| error.to_string())?
            .public())
    }

    fn rtts(band: &[Measured]) -> Vec<u64> {
        let mut rtts: Vec<u64> = band
            .iter()
            .map(|each| u64::try_from(each.rtt.as_millis()).unwrap_or(u64::MAX))
            .collect();
        rtts.sort_unstable();
        rtts
    }

    #[test]
    fn the_band_is_the_closest_plus_half_or_plus_ten_ms() -> Result<(), String> {
        // Far: closest 40 ms, so half again (60 ms) is wider than plus 10.
        let far: Vec<Measured> = [40, 55, 60, 61, 90]
            .into_iter()
            .map(|rtt| Ok(measured(key()?, rtt, 10, 1)))
            .collect::<Result<_, String>>()?;
        assert_eq!(rtts(&band(&far)), vec![40, 55, 60]);
        // Near: closest 4 ms, so plus 10 (14 ms) is wider than half again.
        let near: Vec<Measured> = [4, 6, 14, 15]
            .into_iter()
            .map(|rtt| Ok(measured(key()?, rtt, 10, 1)))
            .collect::<Result<_, String>>()?;
        assert_eq!(rtts(&band(&near)), vec![4, 6, 14]);
        Ok(())
    }

    #[test]
    fn a_full_relay_neither_joins_the_band_nor_sets_it() -> Result<(), String> {
        let mut closest_full = measured(key()?, 2, 10, 1);
        closest_full.full = true;
        let no_slots = measured(key()?, 3, 0, 2);
        let measured = vec![
            closest_full,
            no_slots,
            measured(key()?, 30, 10, 3),
            measured(key()?, 44, 10, 4),
        ];
        assert_eq!(rtts(&band(&measured)), vec![30, 44]);
        Ok(())
    }

    #[test]
    fn the_median_is_the_middle_sample() {
        let ms = Duration::from_millis;
        assert_eq!(
            median(&mut [ms(9), ms(1), ms(200), ms(2), ms(3)]),
            Some(ms(3))
        );
        assert_eq!(median(&mut [ms(4), ms(2)]), Some(ms(2)));
        assert_eq!(median(&mut []), None);
    }

    /// What a fake relay does once a probe or a feeder is in.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(crate) enum Mode {
        /// Answers every echo and takes every batch.
        Serve,
        /// Answers the first echo, then redirects: full.
        Full,
        /// Answers echoes, and redirects at the first batch.
        RedirectOnBatch,
    }

    /// A fake relay on loopback.
    pub(crate) struct Fake {
        pub identity: Identity,
        /// Who signs its echo replies (another key than `identity` to forge them).
        pub signer: Identity,
        /// The loopback address it listens on (`127.0.0.N`).
        pub ip: &'static str,
        pub network: u32,
        pub slots: u32,
        pub mode: Mode,
        /// Where the batches it takes are told, with its key.
        pub batches: Option<tokio::sync::mpsc::UnboundedSender<(PublicKey, tally_wire::Batch)>>,
        /// Where the role each session dialled as is told.
        pub roles: Option<tokio::sync::mpsc::UnboundedSender<Role>>,
        /// The area's sharing group as this relay passes on to it: the batches it takes go there.
        pub forwards_to: Option<Group>,
        /// As a member of the area's sharing group: a `DeliveryQuery` is answered from what the
        /// group holds (a tag of each batch it holds, under the key the feeder last gave it, "not
        /// seen" of the rest).
        pub answers_from: Option<Group>,
        /// The tag key in force each feeder gave it, from the keys its queries carried.
        pub keys: std::sync::Mutex<std::collections::HashMap<PublicKey, tally_wire::TagKey>>,
    }

    /// What an area's sharing group holds, in a test.
    pub(crate) type Group = std::sync::Arc<std::sync::Mutex<Vec<tally_wire::Batch>>>;

    impl Fake {
        pub(crate) fn new(identity: Identity, network: u32, slots: u32, mode: Mode) -> Self {
            Self {
                signer: identity.clone(),
                identity,
                ip: "127.0.0.1",
                network,
                slots,
                mode,
                batches: None,
                roles: None,
                forwards_to: None,
                answers_from: None,
                keys: std::sync::Mutex::default(),
            }
        }
    }

    /// Starts `fake`: it answers every `Echo` with a reply signed by its signer, declaring its
    /// slots and network, and behaves as its mode says.
    pub(crate) async fn echo_relay(fake: Fake) -> Result<RelayAddress, String> {
        let listener = tokio::net::TcpListener::bind((fake.ip, 0))
            .await
            .map_err(|error| error.to_string())?;
        let address = listener
            .local_addr()
            .map_err(|error| error.to_string())?
            .to_string();
        let key = fake.identity.public();
        let fake = std::sync::Arc::new(fake);
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let fake = std::sync::Arc::clone(&fake);
                tokio::spawn(async move {
                    let _ = serve(&fake, stream).await;
                });
            }
        });
        Ok(RelayAddress { key, address })
    }

    async fn serve(fake: &Fake, stream: TcpStream) -> Result<(), WireError> {
        let accepted = noise::accept(stream, std::slice::from_ref(&fake.identity)).await?;
        if let Some(roles) = &fake.roles {
            let _ = roles.send(accepted.role);
        }
        let (mut reader, mut writer) = (accepted.session.reader, accepted.session.writer);
        let key = fake.identity.public();
        let answer = |echo: &Echo| {
            EchoReply::sign(
                &fake.signer,
                &EchoReplyContent {
                    nonce: echo.nonce,
                    issued_ms: 1,
                    network: fake.network,
                    headroom: Headroom {
                        feeder_slots: fake.slots,
                        pace_headroom_bytes_per_sec: 0,
                        mlat_cores: 0,
                    },
                },
            )
            .map(Record::EchoReply)
        };
        let redirect = Record::Redirect {
            retry_after_secs: 600,
            hints: Vec::new(),
        };
        let mut pending = accepted.first;
        loop {
            let mut out = Vec::new();
            let mut leave = false;
            for record in &pending {
                match record {
                    Record::Echo(echo) => out.push(answer(echo)?),
                    Record::Batch(_) if fake.mode == Mode::RedirectOnBatch => leave = true,
                    Record::Batch(batch) => {
                        if let Some(batches) = &fake.batches {
                            let _ = batches.send((key, batch.clone()));
                        }
                        if let Some(group) = &fake.forwards_to
                            && let Ok(mut group) = group.lock()
                        {
                            group.push(batch.clone());
                        }
                    }
                    Record::DeliveryQuery(query) => {
                        if let Some(keys) = &query.keys
                            && keys.verify().is_ok()
                            && let Ok(content) = keys.content()
                            && content.member == key
                            && let Ok(mut held) = fake.keys.lock()
                        {
                            held.insert(query.receiver, content.current);
                        }
                        if let Some(group) = &fake.answers_from {
                            let keyed = fake
                                .keys
                                .lock()
                                .ok()
                                .and_then(|held| held.get(&query.receiver).copied());
                            out.push(delivery_answer(&fake.identity, query, group, keyed)?);
                        }
                    }
                    _ => {}
                }
            }
            leave |= fake.mode == Mode::Full && !out.is_empty();
            if leave {
                out.push(redirect.clone());
            }
            if !out.is_empty() {
                writer.send(&out).await?;
            }
            if leave {
                // Closing over bytes not yet read resets the connection, and a reset discards
                // whatever of the farewell the kernel had not sent yet. So the peer closes first:
                // what it sends is read and dropped until it hangs up on reading the farewell. The
                // timeout only bounds a peer that never does.
                let _ = tokio::time::timeout(PROBE_TIMEOUT, async {
                    let mut rest = Vec::new();
                    while reader.recv(&mut rest).await.is_ok() {
                        rest.clear();
                    }
                })
                .await;
                return Ok(());
            }
            pending = Vec::new();
            reader.recv(&mut pending).await?;
        }
    }

    /// A member's signed answer to `query` from what `group` holds: a tag under `keyed` of each
    /// batch held (none, and no word, without a key), "not seen" of the rest.
    fn delivery_answer(
        member: &Identity,
        query: &tally_wire::DeliveryQuery,
        group: &Group,
        keyed: Option<tally_wire::TagKey>,
    ) -> Result<Record, WireError> {
        let held: Vec<tally_wire::Batch> =
            group.lock().map(|held| held.clone()).unwrap_or_default();
        let entries = query
            .ranges
            .iter()
            .flat_map(|range| range.first..=range.last)
            .filter_map(|sequence| {
                let found = held.iter().find(|batch| {
                    batch.sequence() == sequence
                        && batch.boot_id() == query.boot_id
                        && batch
                            .receiver()
                            .is_ok_and(|receiver| receiver == query.receiver)
                });
                let possession = match (found, keyed) {
                    (Some(batch), Some(key)) => tally_wire::Possession::Proved {
                        key: key.id,
                        tag: tally_wire::delivery_tag(&key.key, batch.as_bytes()),
                    },
                    (Some(_), None) => return None,
                    (None, _) => tally_wire::Possession::NotSeen,
                };
                Some((sequence, possession))
            })
            .collect();
        tally_wire::DeliveryAnswer::sign(
            member,
            &tally_wire::DeliveryAnswerContent {
                nonce: query.nonce,
                receiver: query.receiver,
                boot_id: query.boot_id,
                issued_ms: 1,
                takes_area: true,
                entries,
            },
        )
        .map(Record::DeliveryAnswer)
    }

    #[tokio::test]
    async fn a_probe_dials_as_a_probe_and_takes_no_feeder_slot() -> Result<(), String> {
        let (roles, mut dialled) = tokio::sync::mpsc::unbounded_channel();
        let relay_identity = Identity::generate().map_err(|error| error.to_string())?;
        let relay = echo_relay(Fake {
            roles: Some(roles),
            ..Fake::new(relay_identity, 64_512, 42, Mode::Serve)
        })
        .await?;
        let me = Identity::generate().map_err(|error| error.to_string())?;
        probe(&relay, &me).await?;
        assert_eq!(dialled.recv().await, Some(Role::Probe));
        Ok(())
    }

    #[tokio::test]
    async fn a_probe_takes_the_median_of_its_echoes_and_the_signed_headroom() -> Result<(), String>
    {
        let relay_identity = Identity::generate().map_err(|error| error.to_string())?;
        let relay = echo_relay(Fake::new(relay_identity, 64_512, 42, Mode::Serve)).await?;
        let me = Identity::generate().map_err(|error| error.to_string())?;
        let probed = probe(&relay, &me).await?;
        // Where the connection reached is observed, beside what the relay declares.
        assert_eq!(probed.measured.observed, "127.0.0.1".parse().ok());
        assert_eq!(probed.measured.weight(), 42);
        assert_eq!(probed.measured.network(), 64_512);
        assert!(!probed.measured.full);
        assert!(probed.measured.rtt < Duration::from_secs(1));
        Ok(())
    }

    #[tokio::test]
    async fn a_full_relay_is_measured_and_weighs_nothing_whatever_it_declared() -> Result<(), String>
    {
        let relay_identity = Identity::generate().map_err(|error| error.to_string())?;
        let relay = echo_relay(Fake::new(relay_identity, 64_512, 500, Mode::Full)).await?;
        let me = Identity::generate().map_err(|error| error.to_string())?;
        let probed = probe(&relay, &me).await?;
        assert!(probed.measured.full);
        assert_eq!(probed.measured.weight(), 0);
        assert!(band(&[probed.measured]).is_empty());
        Ok(())
    }

    #[tokio::test]
    async fn a_reply_signed_by_another_key_is_no_measurement() -> Result<(), String> {
        let relay_identity = Identity::generate().map_err(|error| error.to_string())?;
        let impostor = Identity::generate().map_err(|error| error.to_string())?;
        let relay = echo_relay(Fake {
            signer: impostor,
            ..Fake::new(relay_identity, 64_512, 42, Mode::Serve)
        })
        .await?;
        let me = Identity::generate().map_err(|error| error.to_string())?;
        assert!(probe(&relay, &me).await.is_err());
        Ok(())
    }
}
