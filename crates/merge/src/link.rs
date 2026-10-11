//! A consumer's sessions with Tally relays: it dials each as a `Subscriber`, asks in the same
//! message as its Hello for the whole world's positions and clock models (and raw, when it merges
//! from raw), and hands every record it is sent that the merge reads to `inbound`. The relays are
//! the operator's to name and may overlap: the merge holds a record once however many deliver it.
//! A relay that says "leave me" is only left for as long as it asks.
//!
//! Firehose access (RFC-0174 §2.1) is earned by a linked relay: the relay whose operator vouches
//! for this consumer's key signs it a short-lived credential and its evidence on the consumer's
//! session to it. The consumer holds the newest pair ([`Vouching`]) and presents it on every
//! session, before its `Subscribe`, so every relay it reads serves it in proportion to that
//! evidence; without one it is served the free tier.

use std::sync::Arc;
use std::time::Duration;

use tally_wire::backoff::Backoff;
use tally_wire::noise;
use tally_wire::{
    EvidenceBundle, FirehoseCredential, Identity, PublicKey, Record, RelayAddress, Role, Streams,
    WireError,
};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, watch};
use tokio::time::Instant;

const HEARTBEAT: Duration = Duration::from_secs(30);
const READ_TIMEOUT: Duration = Duration::from_secs(120);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// A session that stayed up this long worked: the wait after it starts from the shortest again.
const HEALTHY_SESSION: Duration = Duration::from_secs(60);

/// The streams a consumer merging MLAT asks for: final and provisional positions (a provisional
/// is served only while it is later than every final one, `Track::served`), and clock models.
pub fn streams(raw: bool) -> Streams {
    let streams = Streams::POSITIONS
        .with(Streams::PROVISIONAL)
        .with(Streams::CLOCK_MODELS);
    if raw {
        streams.with(Streams::RAW)
    } else {
        streams
    }
}

/// Whether the merge reads `record`.
pub fn wanted(record: &Record) -> bool {
    matches!(
        record,
        Record::Positions(_)
            | Record::Provisional(_)
            | Record::ClockModel(_)
            | Record::ClockModelPart(_)
            | Record::FaultProof(_)
            | Record::Batch(_)
            // Raw mode places receivers by their signed descriptions (the merge's sites).
            | Record::ReceiverInfo(_)
            | Record::WorldPositions(_)
            | Record::WorldPrecise(_)
    )
}

/// A credential a linked relay signed this consumer, with that relay's evidence.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Vouched {
    pub credential: FirehoseCredential,
    pub evidence: EvidenceBundle,
}

/// The firehose credential this consumer holds, shared by all its sessions: only a pair signed
/// by the relay it is linked to (`linked`), bound to its own key, is taken, so a relay it merely
/// reads cannot replace its credit with a worthless one.
#[derive(Clone)]
pub struct Vouching {
    linked: Option<PublicKey>,
    held: Arc<watch::Sender<Option<Vouched>>>,
}

impl Vouching {
    /// Linked to no relay: the free tier everywhere.
    pub fn none() -> Self {
        Self {
            linked: None,
            held: Arc::new(watch::channel(None).0),
        }
    }

    /// Linked to the relay whose key is `relay`: what it signs this consumer is presented to every
    /// relay the consumer reads.
    pub fn linked_to(relay: PublicKey) -> Self {
        Self {
            linked: Some(relay),
            ..Self::none()
        }
    }

    /// The pair held now, if any.
    pub fn held(&self) -> Option<Vouched> {
        self.held.borrow().clone()
    }

    /// Takes `credential` and `evidence` from the session with `from`, if `from` is the linked
    /// relay and both are its, signed for `client`, and the credential is good.
    fn offered(
        &self,
        from: &PublicKey,
        client: &PublicKey,
        credential: FirehoseCredential,
        evidence: EvidenceBundle,
    ) -> bool {
        let ours = self.linked.as_ref() == Some(from)
            && credential.verify().is_ok()
            && credential.signer().ok().as_ref() == Some(from)
            && evidence.signer().ok().as_ref() == Some(from)
            && credential
                .content()
                .is_ok_and(|content| content.client == *client);
        if ours {
            self.held.send_replace(Some(Vouched {
                credential,
                evidence,
            }));
        }
        ours
    }

    /// What a session presents before its `Subscribe`: the held pair, if any.
    fn presented(&self) -> Vec<Record> {
        self.held().map_or_else(Vec::new, |vouched| {
            vec![
                Record::FirehoseCredential(vouched.credential),
                Record::EvidenceBundle(vouched.evidence),
            ]
        })
    }
}

/// Keeps a session with one relay up for as long as the consumer runs, linked to no relay (the
/// free tier). Returns when `inbound` closes.
pub async fn subscribe(
    relay: RelayAddress,
    identity: Identity,
    streams: Streams,
    inbound: mpsc::Sender<Record>,
) {
    subscribe_vouched(relay, identity, streams, inbound, Vouching::none()).await;
}

/// As [`subscribe`], presenting what `vouching` holds on every session (and again whenever it
/// changes), and taking a fresh pair when the relay is the one `vouching` is linked to.
pub async fn subscribe_vouched(
    relay: RelayAddress,
    identity: Identity,
    streams: Streams,
    inbound: mpsc::Sender<Record>,
    vouching: Vouching,
) {
    let mut backoff = Backoff::new();
    while !inbound.is_closed() {
        let started = Instant::now();
        let outcome = session(&relay, &identity, streams, &inbound, &vouching).await;
        if started.elapsed() >= HEALTHY_SESSION {
            backoff.reset();
        }
        match outcome {
            Ok(wait) => {
                backoff.reset();
                backoff.at_least(wait);
            }
            Err(error) => eprintln!("tally-merge: relay {}: {error}", relay.address),
        }
        tokio::time::sleep(backoff.wait()).await;
    }
}

/// One session; `Ok` with the wait the relay asked for when it ended the session itself.
async fn session(
    relay: &RelayAddress,
    identity: &Identity,
    streams: Streams,
    inbound: &mpsc::Sender<Record>,
    vouching: &Vouching,
) -> Result<Duration, String> {
    let stream = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(&relay.address))
        .await
        .map_err(|_| "connect timed out".to_owned())?
        .map_err(|error| error.to_string())?;
    let subscribe = Record::Subscribe {
        streams,
        regions: Vec::new(),
    };
    // The credential goes first, so the relay weighs it before it admits the `Subscribe`.
    let mut changes = vouching.held.subscribe();
    changes.borrow_and_update();
    let mut opening = vouching.presented();
    opening.push(subscribe.clone());
    let session =
        match noise::connect_with(stream, identity, &relay.key, Role::Subscriber, &opening).await {
            Ok(session) => session,
            Err(WireError::Refused {
                retry_after_secs, ..
            }) => return Ok(Duration::from_secs(retry_after_secs.into())),
            Err(error) => return Err(error.to_string()),
        };
    let (mut reader, mut writer) = (session.reader, session.writer);
    // The reader runs on its own: a read cut short by a select would lose its bytes.
    let (ended_in, mut ended) = mpsc::channel::<Result<Duration, String>>(1);
    let inbound = inbound.clone();
    let (from, client, held) = (relay.key, identity.public(), vouching.clone());
    let reading = tokio::spawn(async move {
        // A credential waits for the evidence the relay sends with it.
        let mut credential = None;
        let outcome = loop {
            let mut got = Vec::new();
            match tokio::time::timeout(READ_TIMEOUT, reader.recv(&mut got)).await {
                Ok(Ok(())) => {}
                Ok(Err(error)) => break Err(error.to_string()),
                Err(_) => break Err("silent too long".to_owned()),
            }
            let mut leave = None;
            for record in got {
                match record {
                    Record::Goodbye {
                        retry_after_secs, ..
                    }
                    | Record::Redirect {
                        retry_after_secs, ..
                    } => leave = Some(Ok(Duration::from_secs(retry_after_secs.into()))),
                    Record::FirehoseCredential(signed) => credential = Some(signed),
                    Record::EvidenceBundle(evidence) => {
                        if let Some(signed) = credential.take() {
                            held.offered(&from, &client, signed, evidence);
                        }
                    }
                    record if wanted(&record) => {
                        if inbound.send(record).await.is_err() {
                            leave = Some(Err("the consumer ended".to_owned()));
                            break;
                        }
                    }
                    _ => {}
                }
            }
            if let Some(outcome) = leave {
                break outcome;
            }
        };
        let _ = ended_in.send(outcome).await;
    });
    let mut heartbeat = tokio::time::interval(HEARTBEAT);
    let result = loop {
        tokio::select! {
            _ = heartbeat.tick() => {
                if let Err(error) = writer.send(&[Record::Heartbeat]).await {
                    break Err(error.to_string());
                }
            }
            outcome = ended.recv() => break outcome.unwrap_or_else(|| Err("reader ended".to_owned())),
            // A fresh credential is presented at once, and the subscription asked again under it.
            Ok(()) = changes.changed() => {
                let mut renewed = vouching.presented();
                renewed.push(subscribe.clone());
                if let Err(error) = writer.send(&renewed).await {
                    break Err(error.to_string());
                }
            }
        }
    };
    reading.abort();
    result
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    use tally_relay::credit::Allowance;
    use tally_relay::egress::Cap;
    use tally_relay::hub::Hub;
    use tally_wire::batch::{Clock, ReceiverInfoContent};
    use tally_wire::{Identity, ReceiverInfo, RelayAddress, Streams};
    use tokio::net::TcpListener;
    use tokio::sync::mpsc;

    use super::{Vouching, subscribe, subscribe_vouched};

    fn text(error: impl std::fmt::Display) -> String {
        error.to_string()
    }

    fn now_ms() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |since| since.as_millis() as u64)
    }

    async fn relay(identity: &Identity, hub: Arc<Hub>) -> Result<RelayAddress, String> {
        let listener = TcpListener::bind("127.0.0.1:0").await.map_err(text)?;
        let address = listener.local_addr().map_err(text)?.to_string();
        tokio::spawn(tally_relay::serve(listener, vec![identity.clone()], hub));
        Ok(RelayAddress {
            key: identity.public(),
            address,
        })
    }

    /// Polls `done` every 20 ms until it holds, failing only on a hang (120 s), never on how fast
    /// the machine running the test is.
    async fn until(what: &str, done: impl Fn() -> bool) -> Result<(), String> {
        tokio::time::timeout(Duration::from_secs(120), async {
            while !done() {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .map_err(|_| format!("never: {what}"))
    }

    #[tokio::test]
    async fn a_client_its_relay_vouches_for_reads_on_that_relays_credit_and_others_read_free()
    -> Result<(), String> {
        let (linked, serving) = (
            Identity::generate().map_err(text)?,
            Identity::generate().map_err(text)?,
        );
        let (client, stranger) = (
            Identity::generate().map_err(text)?,
            Identity::generate().map_err(text)?,
        );
        // The linked relay hosts ten feeders and vouches for the client; the serving relay has
        // corroborated those feeders first-hand, and rations its clients.
        let linked_hub = Arc::new(
            Hub::new(8)
                .max_upload(Cap::bytes_per_sec(1 << 30))
                .vouching_for([client.public(), stranger.public()]),
        );
        let serving_hub = Arc::new(Hub::new(8).max_upload(Cap::bytes_per_sec(1 << 30)));
        serving_hub.network().credit.set_upload_cap(1 << 30);
        linked_hub.network().credit.adopt_identity(linked.public());
        for _ in 0..10 {
            let feeder = Identity::generate().map_err(text)?;
            let now = now_ms();
            let info = ReceiverInfo::sign(
                &feeder,
                &ReceiverInfoContent {
                    issued_ms: now,
                    location: None,
                    clock: Clock::Beast,
                    software: "tally-feed".to_owned(),
                    relays: vec![linked.public()],
                },
            )
            .map_err(text)?;
            linked_hub.network().credit.described(info, now);
            serving_hub
                .network()
                .credit
                .corroborate_receiver(feeder.public(), now);
        }
        let linked_at = relay(&linked, Arc::clone(&linked_hub)).await?;
        let serving_at = relay(&serving, Arc::clone(&serving_hub)).await?;
        let (inbound, mut records) = mpsc::channel(1_024);
        tokio::spawn(async move { while records.recv().await.is_some() {} });
        let streams = Streams::POSITIONS;
        // The client reads both relays, linked to the one that vouches for it.
        let vouching = Vouching::linked_to(linked.public());
        for at in [&linked_at, &serving_at] {
            tokio::spawn(subscribe_vouched(
                at.clone(),
                client.clone(),
                streams,
                inbound.clone(),
                vouching.clone(),
            ));
        }
        until("the linked relay vouched", || vouching.held().is_some()).await?;
        let credit = &serving_hub.network().credit;
        until("the serving relay lifted the client", || {
            credit.allowance(&client.public(), now_ms()).bytes_per_sec
                > Allowance::FREE.bytes_per_sec
        })
        .await?;
        let lifted = credit.allowance(&client.public(), now_ms());
        assert_eq!(
            lifted.bytes_per_sec,
            credit.earned(&linked.public(), now_ms())
        );
        assert!(lifted.world && lifted.regions > Allowance::FREE.regions);
        // A client with no linked relay, and one linked to a relay other than the one that signs
        // for it, read the free tier.
        tokio::spawn(subscribe(
            serving_at.clone(),
            Identity::generate().map_err(text)?,
            streams,
            inbound.clone(),
        ));
        let elsewhere = Vouching::linked_to(serving.public());
        tokio::spawn(subscribe_vouched(
            linked_at,
            stranger.clone(),
            streams,
            inbound.clone(),
            elsewhere.clone(),
        ));
        tokio::spawn(subscribe_vouched(
            serving_at,
            stranger.clone(),
            streams,
            inbound,
            elsewhere.clone(),
        ));
        until("the stranger reached the serving relay", || {
            serving_hub.subscribers() >= 3
        })
        .await?;
        tokio::time::sleep(Duration::from_millis(500)).await;
        assert!(elsewhere.held().is_none());
        assert_eq!(
            credit.allowance(&stranger.public(), now_ms()),
            Allowance::FREE
        );
        Ok(())
    }
}
