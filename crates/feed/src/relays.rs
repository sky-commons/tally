//! Which relays a feeder publishes to, and each session with one (RFC-0174 §2.2, RFC-0171 §3.5,
//! §3.7).
//!
//! The rules are fixed here and no relay can change them. Every round (`probe::ROUND_EVERY`; while
//! it holds no relay at all, at the reconnect backoff's pace) the feeder measures candidate relays by round-trip time (`probe`), and chooses two from the band by
//! the shared per-area pick, on two networks, with hysteresis (`selection`). It publishes every
//! batch to both. The owner's `--relay` and the seeds are candidates, measured and ranked like any
//! other: nothing is pinned. A relay that fails, refuses or redirects is replaced by the next in
//! the ranking, dialled after a jitter; with no other to take its place it is retried at the
//! backoff's pace. A relay that says "leave me" is not dialled again until its `retry_after_secs`
//! has passed; what it suggests instead is only a hint, added to what the feeder knows. Every few
//! minutes a delivery check (`delivery_check`) asks the area's sharing group whether a relay's
//! batches arrived, and a relay found swallowing them is left for days.
//!
//! The receiver's site is relay-only (RFC-0171 §8.3). The feeder publishes only to a relay that
//! negotiated `tally_wire::SITES_VERSION`, and so keeps sites off client links: an older relay is
//! sent nothing at all and left (`OLD_RELAY_WAIT`). A relay is sent the receiver's site
//! (`ReceiverSite`) and its public description (a format 2 `ReceiverInfo`: its public cell, never
//! its site). The area the feeder chooses relays by, and so the relays its description names, is
//! the public cell's (`Directory::area`), so nothing it publishes says more than the public cell.
//!
//! A session ends when the relay stops reading (a send waits at most `noise::WRITE_TIMEOUT`) and
//! when the reader fails (closed, or silent for `READ_TIMEOUT`), even while a send is pending.

use std::collections::{HashMap, HashSet, VecDeque};
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tally_wire::backoff::Backoff;
use tally_wire::noise;
use tally_wire::{
    Batch, Clock, DeliveryAnswer, DeliveryQuery, Identity, Location, ProviderOffer, ProviderQuery,
    PublicInfoContent, PublicKey, Reason, ReceiverInfo, ReceiverSite, ReceiverSiteContent, Record,
    Region, RelayAddress, Role, Streams, carries_sites,
};
use tokio::net::TcpStream;
use tokio::sync::{broadcast, mpsc, watch};
use tokio::task::JoinSet;

use crate::delivery_check::{self, Checking, DeliveryChecker, SAMPLED, Sent, Verdict};
use crate::health::Health;
use crate::probe::{self, MOST_PER_ROUND, Measured, Probed, Prober, RANDOM_PER_ROUND, ROUND_EVERY};
use crate::selection::{BandRendezvous, Choice, RelaySelection, failover_jitter};
use crate::source::{Stating, TokenBucket, WantedCeilings, wall_ms};

const HEARTBEAT: Duration = Duration::from_secs(30);
const READ_TIMEOUT: Duration = Duration::from_secs(120);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// How long a session must stay up to count as having worked: one that fails sooner is a failed
/// relay, and its place goes to the next; one that worked is dialled again.
const HEALTHY_SESSION: Duration = Duration::from_secs(60);
/// The most relays kept from any one source's hints. A relay's own list weighs no more than this,
/// however long it is.
const HINTS_PER_SOURCE: usize = 32;
/// The most learned relays kept in all; past it the oldest learned is forgotten first.
const HINTS_IN_ALL: usize = 512;
/// The most offers of the feeder's area kept, the newest of each relay.
const OFFERS_KEPT: usize = 64;
/// The state file of learned relays is written at most this often.
const SAVE_EVERY: Duration = Duration::from_secs(60);
/// How often a session says how many batches it did not send.
const REPORT_EVERY: Duration = Duration::from_secs(600);
/// How often a session re-signs and re-sends the receiver's description, so a relay that forgot it
/// (a restart, memory pressure) has it back within this long, not at the next change of relays.
/// The session asks for its area's offers as often.
const INFO_EVERY: Duration = Duration::from_secs(600);
/// How long a relay that negotiated a wire version older than `tally_wire::SITES_VERSION` is left
/// before it is dialled again: it may have been upgraded by then.
const OLD_RELAY_WAIT: Duration = Duration::from_secs(3_600);
/// The least burst a relay's rate limit is given: the largest record one message carries, so a
/// batch always fits, however small a burst the relay asked for.
const BURST_FLOOR: u32 = noise::MAX_PLAINTEXT as u32;
/// The most batches remembered with the relays they were written to, for the delivery check: the
/// window (`ASK_WITHIN_MS`) at one a second, with room for a feeder that seals faster. Each is a
/// few dozen bytes; only the audited batches keep their bytes.
const SENT_KEPT: usize = 1_024;
/// The most relays the remembered batches name: a feeder writes to two, and a few more over the
/// window as it fails over.
const RELAY_SLOTS: usize = 15;
/// The bit of a remembered batch's relays that says one of them could not be named (more than
/// `RELAY_SLOTS` in the window): such a batch is never taken as the audited relay's alone.
const UNNAMED: u16 = 1 << RELAY_SLOTS;

/// Where the feeder heard of a relay. Kept so that one relay's hints never outweigh the owner's
/// list, the seeds, or another relay's hints in what is remembered.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Source {
    /// The owner named it (`--relay`).
    Configured,
    /// Shipped in the binary.
    Seed,
    /// Hinted by this relay (`RelayList`, `Redirect`, a `ProviderOffer` it passed on).
    Learned(PublicKey),
    /// Read from a state file written before sources were kept: learned, from whom unknown.
    Cached,
}

impl Source {
    fn is_learned(self) -> bool {
        matches!(self, Self::Learned(_) | Self::Cached)
    }
}

struct Known {
    /// The address dialled: the one it was heard of at, or the newest its own signed offer named.
    relay: RelayAddress,
    source: Source,
    /// `issued_ms` of the relay's own signed offer that set `relay.address`; none while the
    /// address is only what it was heard of at.
    offered_ms: Option<u64>,
    /// The owner's or the seed's address for a relay its own offer has moved: still probed, so a
    /// move to an address that does not answer leaves the feeder where it was.
    fallback: Option<String>,
}

impl Known {
    /// The addresses to probe for this relay: the one in use, then the owner's or the seed's.
    fn addresses(&self) -> impl Iterator<Item = RelayAddress> + '_ {
        std::iter::once(self.relay.clone()).chain(self.fallback.iter().map(|address| {
            RelayAddress {
                key: self.relay.key,
                address: address.clone(),
            }
        }))
    }
}

/// What the feeder knows of relays, oldest first, and which it is using.
struct Relays {
    known: Vec<Known>,
    held: Vec<PublicKey>,
    /// Relays that said "leave me", and until when none is dialled.
    avoided: HashMap<PublicKey, tokio::time::Instant>,
    /// The newest offer of the feeder's area from each relay, verified: the area's sharing group,
    /// whom the delivery check asks, and the relays probed first.
    offers: Vec<ProviderOffer>,
    /// Learned relays changed since the state file was last written.
    changed: bool,
}

impl Relays {
    /// Adds a relay not yet known, then forgets the oldest learned ones past the caps. False if
    /// its key was already known.
    fn add(&mut self, relay: RelayAddress, source: Source) -> bool {
        if self.known.iter().any(|known| known.relay.key == relay.key) {
            return false;
        }
        self.known.push(Known {
            relay,
            source,
            offered_ms: None,
            fallback: None,
        });
        if source.is_learned() {
            if self.count(|each| each == source) > HINTS_PER_SOURCE {
                self.forget_oldest(|each| each == source);
            }
            if self.count(Source::is_learned) > HINTS_IN_ALL {
                self.forget_oldest(Source::is_learned);
            }
        }
        true
    }

    /// Moves a known relay to the address its own signed offer, issued at `issued_ms`, names
    /// (RFC-0180 §5.1). Only an offer newer than the last one applied moves it, so a replayed old
    /// offer cannot move it back. A hint is never this: a hint is another relay's word, an offer
    /// is the relay's own, signed by the key the feeder will make it prove when it dials. The
    /// owner's or the seed's address is kept as the fallback. False if nothing changed.
    fn supersede(&mut self, key: &PublicKey, address: &str, issued_ms: u64) -> bool {
        let Some(known) = self.known.iter_mut().find(|known| known.relay.key == *key) else {
            return false;
        };
        if known.offered_ms.is_some_and(|applied| applied >= issued_ms) {
            return false;
        }
        known.offered_ms = Some(issued_ms);
        if known.relay.address == address {
            return false;
        }
        let old = std::mem::replace(&mut known.relay.address, address.to_owned());
        if matches!(known.source, Source::Configured | Source::Seed) && known.fallback.is_none() {
            known.fallback = Some(old);
        }
        if known.fallback.as_deref() == Some(address) {
            known.fallback = None;
        }
        self.changed = true;
        true
    }

    fn count(&self, which: impl Fn(Source) -> bool) -> usize {
        self.known
            .iter()
            .filter(|known| which(known.source))
            .count()
    }

    fn forget_oldest(&mut self, which: impl Fn(Source) -> bool) {
        if let Some(at) = self.known.iter().position(|known| which(known.source)) {
            self.known.remove(at);
        }
    }

    fn is_avoided(&self, key: &PublicKey, now: tokio::time::Instant) -> bool {
        self.avoided.get(key).is_some_and(|until| *until > now)
    }

    /// The learned relays as the state file keeps them, oldest first: `HOST:PORT=KEY from KEY`, or
    /// the bare `HOST:PORT=KEY` of a relay learned from a relay not recorded; either ends
    /// ` offered MS` when the relay's own offer issued at `MS` set the address. The owner's and
    /// the seeds' relays come from the command line and the binary each run, so they are kept
    /// only once their own offer has moved them, and then as that address.
    fn state(&self) -> String {
        let mut text = String::new();
        for known in &self.known {
            let mut line = format!("{}={}", known.relay.address, known.relay.key);
            match known.source {
                Source::Learned(from) => line.push_str(&format!(" from {from}")),
                Source::Cached => {}
                Source::Configured | Source::Seed if known.offered_ms.is_some() => {}
                Source::Configured | Source::Seed => continue,
            }
            if let Some(issued_ms) = known.offered_ms {
                line.push_str(&format!(" offered {issued_ms}"));
            }
            text.push_str(&line);
            text.push('\n');
        }
        text
    }
}

/// One measurement a relay, its fastest: a relay its own offer moved is probed at its new address
/// and at the owner's or the seed's, and is chosen, and dialled, at whichever answered sooner.
fn fastest_per_relay(mut measured: Vec<Measured>) -> Vec<Measured> {
    let mut fastest: HashMap<PublicKey, Duration> = HashMap::new();
    for each in &measured {
        fastest
            .entry(each.relay.key)
            .and_modify(|rtt| *rtt = (*rtt).min(each.rtt))
            .or_insert(each.rtt);
    }
    let mut kept = HashSet::new();
    measured.retain(|each| {
        fastest.get(&each.relay.key) == Some(&each.rtt) && kept.insert(each.relay.key)
    });
    measured
}

/// A number below `n`, for choosing among relays.
fn random_below(n: usize) -> usize {
    let mut bytes = [0; 8];
    let _ = getrandom::getrandom(&mut bytes);
    let n = u64::try_from(n).unwrap_or(u64::MAX).max(1);
    usize::try_from(u64::from_be_bytes(bytes) % n).unwrap_or(0)
}

/// What the feeder says about itself, signed together under one `issued_ms`: its public
/// description and its site. Only a relay that keeps sites off client links is sent either
/// (`refuse_old_relay`).
#[derive(Debug)]
pub struct Announcement {
    /// A format 2 `ReceiverInfo`: the public cell, the clock, the software and the relays held.
    info: Arc<Record>,
    /// A `ReceiverSite`: the snapped location. None without a location.
    site: Option<Arc<Record>>,
}

impl Announcement {
    /// The records a relay session sends: the site, if any, ahead of the description, so the
    /// relay can pair them as the description arrives.
    pub fn records(&self) -> Vec<Arc<Record>> {
        let mut out = Vec::with_capacity(2);
        out.extend(self.site.clone());
        out.push(Arc::clone(&self.info));
        out
    }
}

/// What the feeder knows of relays, which it is using, and what it says about itself.
pub struct Directory {
    state_dir: PathBuf,
    relays: Mutex<Relays>,
    identity: Identity,
    location: Option<Location>,
    clock: Clock,
    info: watch::Sender<Arc<Announcement>>,
    /// The relays already said (in the log) to be too old to publish to, so each is said once.
    too_old: Mutex<HashSet<PublicKey>>,
}

impl Directory {
    /// `configured` are the owner's (`--relay`), `seeds` the binary's: both candidates, never
    /// pinned. `location` is the antenna's as the owner gave it; the directory holds and signs it
    /// snapped to its precision (`precision::snap`), and never keeps the exact one.
    pub fn new(
        state_dir: PathBuf,
        configured: Vec<RelayAddress>,
        seeds: Vec<RelayAddress>,
        identity: Identity,
        location: Option<Location>,
        clock: Clock,
    ) -> Result<Arc<Self>, String> {
        let location = location.map(crate::precision::snap);
        let mut relays = Relays {
            known: Vec::new(),
            held: Vec::new(),
            avoided: HashMap::new(),
            offers: Vec::new(),
            changed: false,
        };
        for relay in configured {
            relays.add(relay, Source::Configured);
        }
        for relay in seeds {
            relays.add(relay, Source::Seed);
        }
        for (relay, source, offered_ms) in read_relays(&state_dir.join("relays")) {
            relays.add(relay.clone(), source);
            if let Some(issued_ms) = offered_ms {
                relays.supersede(&relay.key, &relay.address, issued_ms);
            }
        }
        relays.changed = false;
        let info = sign_announcement(&identity, location, clock, &[])?;
        Ok(Arc::new(Self {
            state_dir,
            relays: Mutex::new(relays),
            identity,
            location,
            clock,
            info: watch::channel(Arc::new(info)).0,
            too_old: Mutex::new(HashSet::new()),
        }))
    }

    pub fn info(&self) -> watch::Receiver<Arc<Announcement>> {
        self.info.subscribe()
    }

    /// The feeder's public cell (`Region::public_cell` of its signed location), what its public
    /// description names; none without a location.
    pub fn public_cell(&self) -> Option<Region> {
        self.location
            .as_ref()
            .and_then(|location| Region::public_cell(location).ok())
    }

    /// The feeder's area: the area its public cell lies in (`rendezvous::area_of_public`), as every
    /// relay reckons it from the description. The relays it chooses by it, which its description
    /// names, so tell nothing finer than the public cell. None without a location.
    pub fn area(&self) -> Option<Region> {
        self.public_cell()
            .and_then(tally_wire::rendezvous::area_of_public)
    }

    /// `None` when a relay that negotiated `version` may be published to: it keeps sites off client
    /// links (`carries_sites`). An older relay is sent nothing and left for `OLD_RELAY_WAIT`, which
    /// is said once per relay for as long as the feeder runs.
    fn refuse_old_relay(&self, relay: &RelayAddress, version: u16) -> Option<Outcome> {
        if carries_sites(version, Role::Relay) {
            return None;
        }
        let first = self
            .too_old
            .lock()
            .is_ok_and(|mut told| told.insert(relay.key));
        if first {
            eprintln!(
                "tally-feed: relay {} speaks wire version {version}, older than {}, which keeps \
                 receiver sites off client links: nothing is sent to it, and it is left",
                relay.address,
                tally_wire::SITES_VERSION
            );
        }
        Some(Outcome::Leave(OLD_RELAY_WAIT))
    }

    /// Adds relays that relay `from` offered. They are hints: they only widen what is probed, and
    /// at most `HINTS_PER_SOURCE` of them count, its newest.
    pub fn learn(&self, from: PublicKey, offered: &[RelayAddress]) {
        let Ok(mut relays) = self.relays.lock() else {
            return;
        };
        let mut added = 0;
        for relay in offered {
            if added == HINTS_PER_SOURCE {
                break;
            }
            if relay.address.rsplit_once(':').is_some()
                && relays.add(relay.clone(), Source::Learned(from))
            {
                added += 1;
            }
        }
        if added > 0 {
            relays.changed = true;
        }
    }

    /// An offer relay `from` passed on. If it verifies and is alive, a known relay it is newer for
    /// moves to the address it names (`Relays::supersede`), whatever its cell. It is kept if it
    /// is for the feeder's area or a cell above it; its relay is learned, and probed first.
    pub fn offered(&self, from: PublicKey, offer: ProviderOffer) {
        let (Ok(signer), Ok(())) = (offer.signer(), offer.verify()) else {
            return;
        };
        let Ok(content) = offer.content() else {
            return;
        };
        if content.expires_ms <= wall_ms() {
            return;
        }
        if let Ok(mut relays) = self.relays.lock() {
            relays.supersede(&signer, &content.address, content.issued_ms);
        }
        let Some(area) = self.area() else {
            return;
        };
        if !content.cell.contains(area) {
            return;
        }
        self.learn(
            from,
            &[RelayAddress {
                key: signer,
                address: content.address.clone(),
            }],
        );
        let Ok(mut relays) = self.relays.lock() else {
            return;
        };
        // A relay this offer made known now carries its issue time, so an older one cannot move
        // it.
        relays.supersede(&signer, &content.address, content.issued_ms);
        relays
            .offers
            .retain(|kept| kept.signer().is_ok_and(|kept| kept != signer));
        relays.offers.push(offer);
        if relays.offers.len() > OFFERS_KEPT {
            relays.offers.remove(0);
        }
    }

    /// The offers of the feeder's area held now.
    pub fn offers(&self) -> Vec<ProviderOffer> {
        let now = wall_ms();
        self.relays.lock().map_or_else(
            |_| Vec::new(),
            |relays| {
                relays
                    .offers
                    .iter()
                    .filter(|offer| {
                        offer
                            .content()
                            .is_ok_and(|content| content.expires_ms > now)
                    })
                    .cloned()
                    .collect()
            },
        )
    }

    /// The relays to probe this round, at most `MOST_PER_ROUND`: those held, those that offer the
    /// feeder's area (the one use of where a relay says it is: whom to probe first), the owner's,
    /// the seeds, and last round's band, in that order, at most `MOST_PER_ROUND - RANDOM_PER_ROUND`
    /// of them; then the rest of the round at random among the others known, so a relay whose
    /// offer lies about where it is still gets measured. Relays that
    /// asked to be left are not probed until their wait has passed.
    pub fn probe_set(&self, last_band: &[PublicKey]) -> Vec<RelayAddress> {
        let Ok(relays) = self.relays.lock() else {
            return Vec::new();
        };
        let now = tokio::time::Instant::now();
        let offering: Vec<PublicKey> = relays
            .offers
            .iter()
            .filter_map(|offer| offer.signer().ok())
            .collect();
        let find = |key: &PublicKey| {
            relays
                .known
                .iter()
                .filter(|known| known.relay.key == *key)
                .flat_map(Known::addresses)
                .collect::<Vec<_>>()
        };
        let mut first: Vec<RelayAddress> = Vec::new();
        let push = |relay: RelayAddress, into: &mut Vec<RelayAddress>| {
            if !relays.is_avoided(&relay.key, now) && !into.contains(&relay) {
                into.push(relay);
            }
        };
        let ordered = relays
            .held
            .iter()
            .chain(&offering)
            .flat_map(find)
            .chain(
                relays
                    .known
                    .iter()
                    .filter(|known| matches!(known.source, Source::Configured))
                    .flat_map(Known::addresses),
            )
            .chain(
                relays
                    .known
                    .iter()
                    .filter(|known| matches!(known.source, Source::Seed))
                    .flat_map(Known::addresses),
            )
            .chain(last_band.iter().flat_map(find));
        for relay in ordered {
            push(relay, &mut first);
        }
        first.truncate(MOST_PER_ROUND - RANDOM_PER_ROUND);
        // The rest of the round, at least `RANDOM_PER_ROUND`, at random among the others known.
        let mut rest: Vec<RelayAddress> = relays
            .known
            .iter()
            .flat_map(Known::addresses)
            .filter(|relay| !first.iter().any(|each| each.key == relay.key))
            .filter(|relay| !relays.is_avoided(&relay.key, now))
            .collect();
        while first.len() < MOST_PER_ROUND && !rest.is_empty() {
            let picked = rest.swap_remove(random_below(rest.len()));
            first.push(picked);
        }
        first
    }

    /// Writes the learned relays if they changed since the last write.
    pub fn save(&self) {
        let text = {
            let Ok(mut relays) = self.relays.lock() else {
                return;
            };
            if !relays.changed {
                return;
            }
            relays.changed = false;
            relays.state()
        };
        self.write_state("relays", &text);
    }

    /// Records which relays the feeder publishes to, and re-signs the receiver's description to
    /// say so.
    pub fn hold(&self, held: &[PublicKey]) {
        let Ok(mut relays) = self.relays.lock() else {
            return;
        };
        if relays.held == held {
            return;
        }
        relays.held = held.to_vec();
        self.announce(&relays, true);
    }

    /// Keeps the feeder off `relay` for `wait`, or the backoff's first wait if that is longer; a
    /// longer wait already asked for stays.
    pub fn avoid(&self, relay: &PublicKey, wait: Duration) {
        let Ok(mut relays) = self.relays.lock() else {
            return;
        };
        let until = tokio::time::Instant::now() + wait.max(Backoff::FIRST);
        let entry = relays.avoided.entry(*relay).or_insert(until);
        *entry = (*entry).max(until);
    }

    /// The relays that asked to be left and whose wait has not passed.
    pub fn avoided(&self) -> Vec<PublicKey> {
        let Ok(mut relays) = self.relays.lock() else {
            return Vec::new();
        };
        let now = tokio::time::Instant::now();
        relays.avoided.retain(|_, until| *until > now);
        relays.avoided.keys().copied().collect()
    }

    /// How long until `relay` may be dialled again; zero if it never asked to be left.
    pub fn avoided_for(&self, relay: &PublicKey) -> Duration {
        let now = tokio::time::Instant::now();
        self.relays
            .lock()
            .ok()
            .and_then(|relays| relays.avoided.get(relay).copied())
            .map_or(Duration::ZERO, |until| until.saturating_duration_since(now))
    }

    /// The receiver's description and site signed afresh, with a new `issued_ms` and the relays
    /// held now. They are kept as the latest without waking the sessions, each of which re-sends on
    /// its own schedule.
    pub fn resign(&self) -> Option<Arc<Announcement>> {
        let relays = self.relays.lock().ok()?;
        self.announce(&relays, false)
    }

    /// Signs the receiver's description and site for the relays held now and makes them the
    /// latest. It runs under the relays lock, so the latest is always the newest signed and names
    /// what is held.
    fn announce(&self, relays: &Relays, wake: bool) -> Option<Arc<Announcement>> {
        match sign_announcement(&self.identity, self.location, self.clock, &relays.held) {
            Ok(info) => {
                let record = Arc::new(info);
                let latest = Arc::clone(&record);
                self.info.send_if_modified(move |info| {
                    *info = latest;
                    wake
                });
                Some(record)
            }
            Err(error) => {
                eprintln!("tally-feed: signing receiver info: {error}");
                None
            }
        }
    }

    fn write_state(&self, name: &str, text: &str) {
        let path = self.state_dir.join(name);
        let written = std::fs::create_dir_all(&self.state_dir)
            .and_then(|()| std::fs::write(path.with_extension("new"), text))
            .and_then(|()| std::fs::rename(path.with_extension("new"), &path));
        if let Err(error) = written {
            eprintln!("tally-feed: saving {}: {error}", path.display());
        }
    }

    #[cfg(test)]
    fn known(&self) -> Vec<(RelayAddress, Source)> {
        self.relays.lock().map_or_else(
            |_| Vec::new(),
            |relays| {
                relays
                    .known
                    .iter()
                    .map(|known| (known.relay.clone(), known.source))
                    .collect()
            },
        )
    }
}

/// Saves what the feeder learns, at most once a minute, for as long as it runs.
pub async fn keep_saved(directory: Arc<Directory>) {
    let mut every = tokio::time::interval(SAVE_EVERY);
    loop {
        every.tick().await;
        directory.save();
    }
}

fn read_relays(path: &std::path::Path) -> Vec<(RelayAddress, Source, Option<u64>)> {
    std::fs::read_to_string(path)
        .map(|text| text.lines().filter_map(read_relay).collect())
        .unwrap_or_default()
}

fn read_relay(line: &str) -> Option<(RelayAddress, Source, Option<u64>)> {
    let line = line.trim();
    let (line, offered_ms) = match line.rsplit_once(" offered ") {
        Some((line, issued_ms)) => (line.trim(), Some(issued_ms.trim().parse().ok()?)),
        None => (line, None),
    };
    match line.split_once(" from ") {
        Some((relay, from)) => Some((
            crate::config::parse_relay(relay.trim()).ok()?,
            Source::Learned(PublicKey::from_base64(from.trim()).ok()?),
            offered_ms,
        )),
        None => Some((
            crate::config::parse_relay(line).ok()?,
            Source::Cached,
            offered_ms,
        )),
    }
}

/// The public description (format 2: the location's public cell, never the location) and the
/// site (`ReceiverSite`: the location as given, already snapped), under one `issued_ms` so a relay
/// pairs them.
fn sign_announcement(
    identity: &Identity,
    location: Option<Location>,
    clock: Clock,
    relays: &[PublicKey],
) -> Result<Announcement, String> {
    let error = |error: tally_wire::WireError| error.to_string();
    let issued_ms = wall_ms();
    let cell = location
        .as_ref()
        .map(Region::public_cell)
        .transpose()
        .map_err(error)?;
    let info = ReceiverInfo::sign_public(
        identity,
        &PublicInfoContent {
            issued_ms,
            cell,
            clock,
            software: concat!("tally-feed ", env!("CARGO_PKG_VERSION")).to_owned(),
            relays: relays.to_vec(),
        },
    )
    .map_err(error)?;
    let site = location
        .map(|location| {
            ReceiverSite::sign(
                identity,
                &ReceiverSiteContent {
                    issued_ms,
                    location,
                    clock,
                },
            )
        })
        .transpose()
        .map_err(error)?;
    Ok(Announcement {
        info: Arc::new(Record::ReceiverInfo(info)),
        site: site.map(|site| Arc::new(Record::ReceiverSite(site))),
    })
}

/// An audit: the batches of sequences `first..=last` go to `relay` alone (`delivery_check`).
#[derive(Clone, Copy, Debug)]
struct Audit {
    relay: PublicKey,
    first: u64,
    last: u64,
    /// The audited relay's session ended during the audit: what it was written may not have
    /// reached it.
    broken: bool,
}

/// A batch an audit held back, and the relays it was held back from.
struct Withheld {
    batch: Batch,
    from: Vec<PublicKey>,
}

/// One of the feeder's batches as remembered: its name, when it was first written, and to which
/// relays (bits over `LedgerState::slots`). Not its bytes.
#[derive(Clone, Copy, Debug)]
struct Mark {
    boot_id: u64,
    sequence: u64,
    first_at: tokio::time::Instant,
    sent_ms: u64,
    relays: u16,
}

#[derive(Default)]
struct LedgerState {
    /// The feeder's batches written within the window, oldest first.
    sent: VecDeque<Mark>,
    /// The relays the marks name, by bit.
    slots: Vec<PublicKey>,
    /// The sequences the latest audit covers (kept after it ends, until the next), and the
    /// batches of them written: the only bytes the ledger keeps.
    audited_range: Option<(u64, u64)>,
    audited: Vec<Batch>,
    /// The newest sequence any session has seen.
    newest: Option<u64>,
    audit: Option<Audit>,
    /// What the audit in force has held back.
    withheld: Vec<Withheld>,
    /// Batches each relay's session is to send after all: an ended audit's, that the audited
    /// relay did not carry.
    owed: HashMap<PublicKey, Vec<Batch>>,
    /// Relays with a session up.
    live: HashSet<PublicKey>,
}

/// Which batch went to which relay, and the audit in force: what the sessions write and the
/// delivery check reads.
pub struct Ledger {
    state: Mutex<LedgerState>,
    /// Bumped when batches are owed to some session (`take_owed`).
    owed: watch::Sender<u64>,
}

impl Default for Ledger {
    fn default() -> Self {
        Self {
            state: Mutex::default(),
            owed: watch::channel(0).0,
        }
    }
}

impl Ledger {
    /// Whether the session to `relay` sends `batch`: every batch, except one being audited to
    /// another relay whose session is up, which is held back (`end_audit`).
    pub fn routes(&self, relay: &PublicKey, batch: &Batch) -> bool {
        let Ok(mut state) = self.state.lock() else {
            return true;
        };
        let sequence = batch.sequence();
        state.newest = Some(state.newest.map_or(sequence, |newest| newest.max(sequence)));
        let held_back = match state.audit {
            Some(audit) if (audit.first..=audit.last).contains(&sequence) => {
                audit.relay != *relay && state.live.contains(&audit.relay)
            }
            _ => false,
        };
        if held_back {
            let same = |kept: &&mut Withheld| {
                kept.batch.sequence() == sequence && kept.batch.boot_id() == batch.boot_id()
            };
            match state.withheld.iter_mut().find(same) {
                Some(kept) => {
                    if !kept.from.contains(relay) {
                        kept.from.push(*relay);
                    }
                }
                None => state.withheld.push(Withheld {
                    batch: batch.clone(),
                    from: vec![*relay],
                }),
            }
        }
        !held_back
    }

    /// The session to `relay` wrote `batch`.
    pub fn record(&self, relay: PublicKey, batch: &Batch) {
        let Ok(mut state) = self.state.lock() else {
            return;
        };
        let (boot_id, sequence) = (batch.boot_id(), batch.sequence());
        let bit = state.bit(relay);
        let now = tokio::time::Instant::now();
        let window = Duration::from_millis(delivery_check::ASK_WITHIN_MS);
        while state
            .sent
            .front()
            .is_some_and(|mark| now.saturating_duration_since(mark.first_at) > window)
        {
            state.sent.pop_front();
        }
        let found = state
            .sent
            .iter_mut()
            .rev()
            .find(|mark| mark.sequence == sequence && mark.boot_id == boot_id);
        match found {
            Some(mark) => mark.relays |= bit,
            None => {
                state.sent.push_back(Mark {
                    boot_id,
                    sequence,
                    first_at: now,
                    sent_ms: wall_ms(),
                    relays: bit,
                });
                if state.sent.len() > SENT_KEPT {
                    state.sent.pop_front();
                }
            }
        }
        let audited = state
            .audited_range
            .is_some_and(|(first, last)| (first..=last).contains(&sequence));
        if audited
            && !state
                .audited
                .iter()
                .any(|kept| kept.sequence() == sequence && kept.boot_id() == boot_id)
            && state.audited.len() < 2 * SAMPLED
        {
            state.audited.push(batch.clone());
        }
    }

    /// Audits `relay`: the next `SAMPLED` batches go to it alone, until `end_audit`. An audit
    /// still in force is ended first.
    pub fn audit(&self, relay: PublicKey) {
        self.end_audit();
        if let Ok(mut state) = self.state.lock() {
            let first = state.newest.map_or(0, |newest| newest + 2);
            let last = first + SAMPLED as u64 - 1;
            state.audit = Some(Audit {
                relay,
                first,
                last,
                broken: false,
            });
            state.audited_range = Some((first, last));
            state.audited.clear();
        }
    }

    /// Ends the audit in force: every batch it held back that the audited relay's session did not
    /// write, or every one if that session ended during the audit, is owed to the relays it was
    /// held back from, so the network has it either way. How many batches are owed.
    pub fn end_audit(&self) -> usize {
        let owed = {
            let Ok(mut state) = self.state.lock() else {
                return 0;
            };
            let Some(audit) = state.audit.take() else {
                return 0;
            };
            let withheld = std::mem::take(&mut state.withheld);
            let mut owed = 0;
            let audited_bit = state.slot(&audit.relay).map_or(0, |slot| 1 << slot);
            for kept in withheld {
                let carried = !audit.broken
                    && state.sent.iter().any(|mark| {
                        mark.sequence == kept.batch.sequence()
                            && mark.boot_id == kept.batch.boot_id()
                            && mark.relays & audited_bit != 0
                    });
                if carried {
                    continue;
                }
                for relay in kept.from {
                    state
                        .owed
                        .entry(relay)
                        .or_default()
                        .push(kept.batch.clone());
                    owed += 1;
                }
            }
            owed
        };
        if owed > 0 {
            self.owed
                .send_modify(|count| *count = count.wrapping_add(1));
        }
        owed
    }

    /// Bumped whenever batches are owed to some session.
    pub fn owed_changes(&self) -> watch::Receiver<u64> {
        self.owed.subscribe()
    }

    /// The batches owed to `relay`'s session, oldest first; they are its to send now.
    pub fn take_owed(&self, relay: &PublicKey) -> Vec<Batch> {
        self.state
            .lock()
            .ok()
            .and_then(|mut state| state.owed.remove(relay))
            .unwrap_or_default()
    }

    fn live(&self, relay: PublicKey, up: bool) {
        if let Ok(mut state) = self.state.lock() {
            if up {
                state.live.insert(relay);
            } else {
                state.live.remove(&relay);
                if let Some(audit) = &mut state.audit
                    && audit.relay == relay
                {
                    audit.broken = true;
                }
            }
        }
    }

    /// The relays with a session up, in key order.
    fn live_relays(&self) -> Vec<PublicKey> {
        let mut live: Vec<PublicKey> = self
            .state
            .lock()
            .map(|state| state.live.iter().copied().collect())
            .unwrap_or_default();
        live.sort_unstable_by(|one, other| one.as_bytes().cmp(other.as_bytes()));
        live
    }

    /// The latest audit's batches first written at least `settle` ago, oldest first, each with the
    /// relays it was written to and when: what a check samples. A batch one of whose relays could
    /// not be named is left out (it could look like the audited relay's alone).
    pub fn audited(&self, settle: Duration) -> Vec<Sent> {
        let now = tokio::time::Instant::now();
        let Ok(state) = self.state.lock() else {
            return Vec::new();
        };
        let mut out: Vec<Sent> = state
            .audited
            .iter()
            .filter_map(|batch| {
                let mark = state.sent.iter().rev().find(|mark| {
                    mark.sequence == batch.sequence() && mark.boot_id == batch.boot_id()
                })?;
                if now.saturating_duration_since(mark.first_at) < settle
                    || mark.relays & UNNAMED != 0
                {
                    return None;
                }
                Some(Sent {
                    batch: batch.clone(),
                    relays: state.named(mark.relays),
                    sent_ms: mark.sent_ms,
                })
            })
            .collect();
        out.sort_by_key(|sent| (sent.batch.boot_id(), sent.batch.sequence()));
        out
    }

    /// Batches remembered now, and the bytes the ledger holds of batches (the audited and the
    /// withheld): what it costs a feeder.
    pub fn held(&self) -> (usize, usize) {
        self.state.lock().map_or((0, 0), |state| {
            let bytes = state
                .audited
                .iter()
                .chain(state.withheld.iter().map(|kept| &kept.batch))
                .chain(state.owed.values().flatten())
                .map(|batch| batch.as_bytes().len())
                .sum();
            (state.sent.len(), bytes)
        })
    }
}

impl LedgerState {
    fn slot(&self, relay: &PublicKey) -> Option<usize> {
        self.slots.iter().position(|slot| slot == relay)
    }

    /// `relay`'s bit: its slot, a new one, or one no remembered batch names any more; `UNNAMED`
    /// when every slot is in use.
    fn bit(&mut self, relay: PublicKey) -> u16 {
        if let Some(slot) = self.slot(&relay) {
            return 1 << slot;
        }
        if self.slots.len() < RELAY_SLOTS {
            self.slots.push(relay);
            return 1 << (self.slots.len() - 1);
        }
        let used = self.sent.iter().fold(0u16, |used, mark| used | mark.relays);
        match (0..RELAY_SLOTS).find(|slot| used & (1 << slot) == 0) {
            Some(slot) => {
                self.slots[slot] = relay;
                1 << slot
            }
            None => UNNAMED,
        }
    }

    fn named(&self, relays: u16) -> Vec<PublicKey> {
        self.slots
            .iter()
            .enumerate()
            .filter(|(slot, _)| relays & (1 << slot) != 0)
            .map(|(_, relay)| *relay)
            .collect()
    }
}

/// How a session ended.
#[derive(Debug)]
pub enum Outcome {
    /// Try the same relay again, after at least this long.
    Retry(Duration),
    /// The relay asked to be left (a redirect, or a goodbye because it is full, leaving, or
    /// refusing): a declaration, never swallowing.
    Leave(Duration),
}

/// What a running session and the background work tell the publisher.
enum Event {
    Probed(Vec<Probed>),
    Up {
        relay: PublicKey,
        generation: u64,
    },
    Ended {
        relay: PublicKey,
        generation: u64,
        ended: Result<Outcome, String>,
        up_for: Option<Duration>,
    },
    Answers {
        query: DeliveryQuery,
        answers: Vec<(u32, DeliveryAnswer)>,
    },
}

/// Everything the publisher works from.
pub struct Publishing {
    pub directory: Arc<Directory>,
    pub identity: Identity,
    pub batches: broadcast::Sender<Arc<Record>>,
    /// The owner's ceiling, bytes a second.
    pub ceiling: u32,
    /// The wanted receptions a second the relays state, which the batcher sheds to: each session
    /// states its relay's (`source::WantedCeilings`).
    pub wanted: Arc<WantedCeilings>,
    pub checker: DeliveryChecker,
    /// When the delivery checks run: `Checking::default()`.
    pub checking: Checking,
    /// How each candidate is measured each round: `probe::measure`.
    pub prober: Prober,
    /// The local address its sessions connect from, when one is chosen (`None`: the system's
    /// choice, as a feeder always runs). A load harness gives each simulated feeder its own, so a
    /// relay sees the many networks real feeders come from.
    pub source_address: Option<IpAddr>,
    /// Told how many relay sessions are up whenever that changes (`health`).
    pub health: Arc<Health>,
}

/// One session the publisher keeps.
struct Running {
    relay: RelayAddress,
    generation: u64,
    task: tokio::task::AbortHandle,
    backoff: Backoff,
}

/// The publisher's state between events.
struct Publisher {
    directory: Arc<Directory>,
    identity: Identity,
    batches: broadcast::Sender<Arc<Record>>,
    ceiling: u32,
    wanted: Arc<WantedCeilings>,
    checker: DeliveryChecker,
    checking: Checking,
    prober: Prober,
    source_address: Option<IpAddr>,
    health: Arc<Health>,
    area: Option<Region>,
    ledger: Arc<Ledger>,
    selection: BandRendezvous,
    sessions: HashMap<PublicKey, Running>,
    /// Where each relay's last probe reached it: the observed half of telling networks apart
    /// (`rendezvous::distinct_networks`) for the members a delivery check asks.
    observed: HashMap<PublicKey, IpAddr>,
    last_band: Vec<PublicKey>,
    generation: u64,
    events: mpsc::Sender<Event>,
    tasks: JoinSet<()>,
}

/// Publishes the feeder's batches for as long as it runs: probes every round, chooses, keeps a
/// session with each relay chosen, fails over, and checks delivery.
pub async fn run(publishing: Publishing) {
    let (events, mut inbox) = mpsc::channel(64);
    let area = publishing.directory.area();
    let mut publisher = Publisher {
        directory: publishing.directory,
        identity: publishing.identity,
        batches: publishing.batches,
        ceiling: publishing.ceiling,
        wanted: publishing.wanted,
        checker: publishing.checker,
        checking: publishing.checking,
        prober: publishing.prober,
        source_address: publishing.source_address,
        health: publishing.health,
        area,
        ledger: Arc::new(Ledger::default()),
        selection: BandRendezvous::new(),
        sessions: HashMap::new(),
        observed: HashMap::new(),
        last_band: Vec::new(),
        generation: 0,
        events,
        tasks: JoinSet::new(),
    };
    // Rounds come every `ROUND_EVERY`, except while the feeder holds no relay at all: then the
    // next round is the reconnect backoff's (one second, doubling to the round), so a feeder
    // that started before its relay was listening (a host booting both at once) publishes once
    // the relay is up, not a whole round later.
    let mut next_round = tokio::time::Instant::now();
    let mut round_began = next_round;
    let mut unplaced = Backoff::new();
    let mut probing = false;
    let every = publisher.checking.every;
    let mut check = tokio::time::interval_at(tokio::time::Instant::now() + jittered(every), every);
    check.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    // Keys go to the members on their own schedule, never an audit's (`delivery_check`).
    let mut grant = tokio::time::interval(publisher.checking.grant_every);
    grant.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    // The check in progress: the stage it is in, and when that stage is over.
    let mut stage: Option<(Stage, tokio::time::Instant)> = None;
    loop {
        let due = stage.map(|(_, due)| due);
        tokio::select! {
            _ = tokio::time::sleep_until(next_round), if !probing => {
                probing = true;
                round_began = tokio::time::Instant::now();
                publisher.probe_round();
            }
            _ = grant.tick(), if publisher.area.is_some() => publisher.grant_keys(),
            // One check at a time: the next begins once the last is judged or dropped.
            _ = check.tick(), if publisher.area.is_some() && stage.is_none()
                && !publisher.checker.in_progress() => {
                if publisher.begin_check() {
                    let over = tokio::time::Instant::now() + publisher.checking.audit_for;
                    stage = Some((Stage::Auditing, over));
                }
            }
            _ = sleep_until(due), if due.is_some() => {
                stage = match stage {
                    Some((Stage::Auditing, _)) => {
                        publisher.ledger.end_audit();
                        let asked = tokio::time::Instant::now() + publisher.checking.settle;
                        Some((Stage::Settling, asked))
                    }
                    _ => {
                        publisher.ask_members();
                        None
                    }
                };
            }
            Some(event) = inbox.recv() => {
                let probed = matches!(event, Event::Probed(_));
                publisher.handle(event);
                if probed {
                    probing = false;
                    next_round = if publisher.sessions.is_empty() {
                        tokio::time::Instant::now() + unplaced.wait().min(ROUND_EVERY)
                    } else {
                        unplaced.reset();
                        round_began + ROUND_EVERY
                    };
                }
            }
            Some(_) = publisher.tasks.join_next(), if !publisher.tasks.is_empty() => {}
        }
    }
}

/// A delivery check's stages: the audit holds batches back from the other relay; then the group
/// is given time to carry them; then its members are asked.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Stage {
    Auditing,
    Settling,
}

async fn sleep_until(due: Option<tokio::time::Instant>) {
    match due {
        Some(due) => tokio::time::sleep_until(due).await,
        None => std::future::pending().await,
    }
}

impl Publisher {
    /// Probes this round's candidates at once, and reports what came back.
    fn probe_round(&mut self) {
        let candidates = self.directory.probe_set(&self.last_band);
        let identity = self.identity.clone();
        let events = self.events.clone();
        let prober = self.prober;
        self.tasks.spawn(async move {
            let mut probes = JoinSet::new();
            for relay in candidates {
                probes.spawn(prober(relay, identity.clone()));
            }
            let mut probed = Vec::new();
            while let Some(done) = probes.join_next().await {
                if let Ok(Ok(result)) = done {
                    probed.push(result);
                }
            }
            let _ = events.send(Event::Probed(probed)).await;
        });
    }

    /// The members of the feeder's area to ask about batches sent to `checked`: those given the
    /// key in force now.
    fn members(&self, checked: &[PublicKey]) -> Vec<delivery_check::Member> {
        let Some(area) = self.area else {
            return Vec::new();
        };
        let now = wall_ms();
        delivery_check::members(
            &self.directory.offers(),
            area,
            checked,
            &self.observed,
            |member| self.checker.keyring.keyed(member, now),
            now,
        )
    }

    /// Gives every member of the area drawn for this period (`DeliveryChecker::draw`, from every
    /// member the feeder may ask) its tag keys for this period and the next, if it has not been
    /// given this period's: a query that carries keys alone, over a `Probe` session, whose answer
    /// says nothing the feeder needs.
    fn grant_keys(&mut self) {
        let Some(area) = self.area else {
            return;
        };
        let now = wall_ms();
        let candidates =
            delivery_check::keyable(&self.directory.offers(), area, &self.observed, now);
        let members = self.checker.draw(candidates, now);
        let receiver = self.identity.public();
        for member in members {
            if self.checker.keyring.keyed(&member.relay.key, now) {
                continue;
            }
            let Some(keys) = self
                .checker
                .keyring
                .grant(&self.identity, member.relay.key, now)
            else {
                continue;
            };
            let query = DeliveryQuery {
                nonce: delivery_check::fresh_nonce(),
                receiver,
                boot_id: 0,
                ranges: Vec::new(),
                keys: Some(keys),
            };
            let identity = self.identity.clone();
            self.tasks.spawn(async move {
                let _ = delivery_check::ask(&member.relay, &identity, &query).await;
            });
        }
    }

    /// Begins a check: audits the next relay with a session up that the area has members to ask
    /// about. False when there is none, and nothing is held back.
    fn begin_check(&mut self) -> bool {
        let live = self.ledger.live_relays();
        let held: Vec<PublicKey> = live
            .into_iter()
            .filter(|relay| self.sessions.contains_key(relay))
            .collect();
        let offers = self.directory.offers();
        let Some(area) = self.area else {
            return false;
        };
        let now = wall_ms();
        let observed = &self.observed;
        let keyring = &self.checker.keyring;
        let askable: Vec<PublicKey> = held
            .iter()
            .filter(|relay| {
                !delivery_check::members(
                    &offers,
                    area,
                    &[**relay],
                    observed,
                    |member| keyring.keyed(member, now),
                    now,
                )
                .is_empty()
            })
            .copied()
            .collect();
        let audited = self.checker.audit(&held, |relay| askable.contains(relay));
        match audited {
            Some(relay) => {
                self.ledger.audit(relay);
                true
            }
            None => false,
        }
    }

    /// Asks the area's members about the audited batches, once they have settled.
    fn ask_members(&mut self) {
        let recent = self.ledger.audited(self.checking.settle);
        let Some(query) = self.checker.sample(&recent) else {
            self.checker.abandon();
            return;
        };
        let members = self.members(&self.checker.checked_relays());
        if members.is_empty() {
            self.checker.abandon();
            return;
        }
        // Each member's query carries its keys again: an ask looks like a grant.
        let now = wall_ms();
        let asks: Vec<(delivery_check::Member, DeliveryQuery)> = members
            .into_iter()
            .map(|member| {
                let keys = self
                    .checker
                    .keyring
                    .grant(&self.identity, member.relay.key, now);
                let query = DeliveryQuery {
                    keys,
                    ..query.clone()
                };
                (member, query)
            })
            .collect();
        let identity = self.identity.clone();
        let events = self.events.clone();
        self.tasks.spawn(async move {
            let mut asking = JoinSet::new();
            for (member, query) in asks {
                let identity = identity.clone();
                asking.spawn(async move {
                    delivery_check::ask(&member.relay, &identity, &query)
                        .await
                        .map(|answer| (member.network, answer))
                });
            }
            let mut answers = Vec::new();
            while let Some(done) = asking.join_next().await {
                if let Ok(Some(answer)) = done {
                    answers.push(answer);
                }
            }
            let _ = events.send(Event::Answers { query, answers }).await;
        });
    }

    fn handle(&mut self, event: Event) {
        match event {
            Event::Probed(probed) => {
                let mut measured: Vec<Measured> = Vec::new();
                for each in probed {
                    self.directory.learn(each.measured.relay.key, &each.hints);
                    measured.push(each.measured);
                }
                let measured = fastest_per_relay(measured);
                for each in &measured {
                    if let Some(host) = each.observed {
                        self.observed.insert(each.relay.key, host);
                    }
                }
                self.last_band = probe::band(&measured)
                    .iter()
                    .map(|each| each.relay.key)
                    .collect();
                let avoid = self.avoid();
                let choice = self.selection.choose(self.area, &measured, &avoid);
                self.apply(&choice, false);
            }
            Event::Up { relay, generation } => {
                if let Some(running) = self.sessions.get(&relay)
                    && running.generation == generation
                {
                    self.live(relay, true);
                }
            }
            Event::Ended {
                relay,
                generation,
                ended,
                up_for,
            } => self.ended(relay, generation, ended, up_for),
            Event::Answers { query, answers } => {
                if let Verdict::Swallowed(swallowers) = self.checker.judge(&query, &answers) {
                    for swallower in swallowers {
                        eprintln!(
                            "tally-feed: relay {swallower} did not deliver this feeder's batches \
                             to its area; leaving it for {} days",
                            delivery_check::AVOID_FOR.as_secs() / 86_400
                        );
                        let choice = self.selection.left(&swallower);
                        self.apply(&choice, true);
                    }
                }
            }
        }
    }

    /// Relays not to choose: those remembered as swallowing, and those that asked to be left.
    fn avoid(&self) -> Vec<PublicKey> {
        let mut avoid = self.checker.avoided();
        avoid.extend(self.directory.avoided());
        avoid
    }

    fn ended(
        &mut self,
        relay: PublicKey,
        generation: u64,
        ended: Result<Outcome, String>,
        up_for: Option<Duration>,
    ) {
        let Some(mut running) = self
            .sessions
            .remove(&relay)
            .filter(|running| running.generation == generation)
        else {
            return;
        };
        self.live(relay, false);
        // Whatever ended it, an audit of it in progress says nothing.
        self.checker.session_ended(relay);
        let healthy = up_for.is_some_and(|up| up >= HEALTHY_SESSION);
        if healthy {
            running.backoff.reset();
        }
        let choice = match ended {
            Ok(Outcome::Leave(wait)) => {
                self.directory.avoid(&relay, wait);
                self.selection.failed(&relay)
            }
            Ok(Outcome::Retry(wait)) if healthy => {
                running.backoff.at_least(wait);
                self.redial(running);
                return;
            }
            Ok(Outcome::Retry(wait)) => {
                running.backoff.at_least(wait);
                self.selection.failed(&relay)
            }
            Err(error) => {
                eprintln!("tally-feed: relay {}: {error}", running.relay.address);
                if healthy {
                    self.redial(running);
                    return;
                }
                self.selection.failed(&relay)
            }
        };
        if choice.keys().contains(&relay) {
            // No other relay can take its place: the same one again, at the backoff's pace.
            self.redial(running);
        }
        self.apply(&choice, true);
    }

    /// Whether `relay`'s session is up, for the delivery checks' ledger and the feeder's health.
    fn live(&self, relay: PublicKey, up: bool) {
        self.ledger.live(relay, up);
        self.health.relays_up(self.ledger.live_relays().len());
    }

    /// Dials `running`'s relay again after its backoff's wait.
    fn redial(&mut self, mut running: Running) {
        let wait = running
            .backoff
            .wait()
            .max(self.directory.avoided_for(&running.relay.key));
        let backoff = std::mem::take(&mut running.backoff);
        self.start(running.relay, wait, backoff);
    }

    /// Makes the sessions follow `choice`: those no longer chosen end, those newly chosen start
    /// (after a jitter when they take a failed relay's place).
    fn apply(&mut self, choice: &Choice, failover: bool) {
        let wanted = choice.keys();
        let gone: Vec<PublicKey> = self
            .sessions
            .keys()
            .filter(|key| !wanted.contains(key))
            .copied()
            .collect();
        for key in gone {
            if let Some(running) = self.sessions.remove(&key) {
                running.task.abort();
                self.live(key, false);
            }
        }
        for relay in choice.relays() {
            if self.sessions.contains_key(&relay.key) {
                continue;
            }
            let jitter = if failover {
                failover_jitter()
            } else {
                Duration::ZERO
            };
            let wait = jitter.max(self.directory.avoided_for(&relay.key));
            self.start(relay, wait, Backoff::new());
        }
        self.directory.hold(&wanted);
    }

    fn start(&mut self, relay: RelayAddress, wait: Duration, backoff: Backoff) {
        self.generation += 1;
        let generation = self.generation;
        let context = Context {
            relay: relay.clone(),
            directory: Arc::clone(&self.directory),
            ledger: Arc::clone(&self.ledger),
            ceiling: self.ceiling,
            area: self.area,
            wanted: Arc::clone(&self.wanted),
            source_address: self.source_address,
        };
        let identity = self.identity.clone();
        let batches = self.batches.subscribe();
        let events = self.events.clone();
        let task = self.tasks.spawn(async move {
            tokio::time::sleep(wait).await;
            let key = context.relay.key;
            let (ended, up_for) = session(&context, &identity, batches, || {
                let _ = events.try_send(Event::Up {
                    relay: key,
                    generation,
                });
            })
            .await;
            let _ = events
                .send(Event::Ended {
                    relay: key,
                    generation,
                    ended,
                    up_for,
                })
                .await;
        });
        self.sessions.insert(
            relay.key,
            Running {
                relay,
                generation,
                task,
                backoff,
            },
        );
    }
}

/// What one session works with.
struct Context {
    relay: RelayAddress,
    directory: Arc<Directory>,
    ledger: Arc<Ledger>,
    ceiling: u32,
    area: Option<Region>,
    /// The relays' wanted ceilings the batcher sheds to: this session's statement is one.
    wanted: Arc<WantedCeilings>,
    /// The local address to connect from (`Publishing::source_address`).
    source_address: Option<IpAddr>,
}

/// Connects to `address` from `from` when one is chosen, else as the system chooses.
async fn dial(address: &str, from: Option<IpAddr>) -> std::io::Result<TcpStream> {
    let Some(from) = from else {
        return TcpStream::connect(address).await;
    };
    let mut last = None;
    for target in tokio::net::lookup_host(address).await? {
        let socket = match target {
            std::net::SocketAddr::V4(_) => tokio::net::TcpSocket::new_v4()?,
            std::net::SocketAddr::V6(_) => tokio::net::TcpSocket::new_v6()?,
        };
        socket.bind(std::net::SocketAddr::new(from, 0))?;
        match socket.connect(target).await {
            Ok(stream) => return Ok(stream),
            Err(error) => last = Some(error),
        }
    }
    Err(last.unwrap_or_else(|| std::io::Error::other("no address")))
}

/// One session with a relay: how it ended, and how long it was up (none if it never was).
async fn session(
    context: &Context,
    identity: &Identity,
    batches: broadcast::Receiver<Arc<Record>>,
    up: impl FnOnce(),
) -> (Result<Outcome, String>, Option<Duration>) {
    let relay = &context.relay;
    let stream = match tokio::time::timeout(
        CONNECT_TIMEOUT,
        dial(&relay.address, context.source_address),
    )
    .await
    {
        Ok(Ok(stream)) => stream,
        Ok(Err(error)) => return (Err(error.to_string()), None),
        Err(_) => return (Err("connect timed out".to_owned()), None),
    };
    let session = match noise::connect(stream, identity, &relay.key, Role::Feeder).await {
        Ok(session) => session,
        Err(tally_wire::WireError::Refused {
            reason,
            retry_after_secs,
        }) => return (Ok(goodbye(reason, retry_after_secs)), None),
        Err(error) => return (Err(error.to_string()), None),
    };
    // Refused before it counts as up: an older relay is no session.
    if let Some(outcome) = context.directory.refuse_old_relay(relay, session.version) {
        return (Ok(outcome), None);
    }
    let began = tokio::time::Instant::now();
    up();
    eprintln!(
        "tally-feed: publishing to {} (version {})",
        relay.address, session.version
    );
    let (mut reader, mut writer) = (session.reader, session.writer);
    // The reader runs on its own: a read cut short by a select would lose its bytes.
    let (records_in, mut records) = mpsc::channel(16);
    let reading = tokio::spawn(async move {
        loop {
            let mut got = Vec::new();
            let message = match tokio::time::timeout(READ_TIMEOUT, reader.recv(&mut got)).await {
                Ok(Ok(())) => Ok(got),
                Ok(Err(error)) => Err(error.to_string()),
                Err(_) => Err("silent too long".to_owned()),
            };
            let failed = message.is_err();
            if records_in.send(message).await.is_err() || failed {
                return;
            }
        }
    });
    let ended = publish(context, session.version, &mut writer, &mut records, batches).await;
    reading.abort();
    (ended, Some(began.elapsed()))
}

/// How much one relay session sends of what the batcher sealed. The owner's ceiling is kept once,
/// by the batcher, so a relay that asked nothing gets every batch. A relay that asked for less than
/// the ceiling gets a bucket at its rate, deep enough that a whole batch always fits; the batches
/// over it are skipped for that relay alone, and their sequence numbers say so.
///
/// The wanted receptions a second the relay states with it are the batcher's to keep to
/// (`source::WantedCeilings`): a batch is signed once for every relay, so what is past them is shed
/// before it is signed, never skipped here. What this session stated goes when it ends.
struct Pace {
    ceiling: u32,
    bucket: Option<TokenBucket>,
    skipped: u64,
    wanted: Stating,
}

impl Pace {
    fn new(ceiling: u32, wanted: Stating) -> Self {
        Self {
            ceiling,
            bucket: None,
            skipped: 0,
            wanted,
        }
    }

    /// A relay's `RateLimit`. One at or over the owner's ceiling asks for nothing the batcher
    /// does not already keep to.
    fn limit(&mut self, bytes_per_sec: u32, burst: u32, wanted_per_sec: Option<u32>) {
        self.bucket = (bytes_per_sec < self.ceiling)
            .then(|| TokenBucket::with_burst(bytes_per_sec, burst.max(BURST_FLOOR)));
        self.wanted.state(wanted_per_sec);
    }

    /// True if a batch of `bytes` goes to this relay now; counted as skipped if not.
    fn admit(&mut self, bytes: usize, now: Instant) -> bool {
        let admitted = self
            .bucket
            .as_mut()
            .is_none_or(|bucket| bucket.take_at(bytes, now));
        if !admitted {
            self.skipped += 1;
        }
        admitted
    }
}

type Inbound = mpsc::Receiver<Result<Vec<Record>, String>>;

/// One session's sending half, with what the relay says while it sends. Every send is raced against
/// the reader, so a reader that fails (closed, silent too long) or a relay that says goodbye ends
/// the session at once, even while a send waits on a relay that stopped reading. A send cut short
/// leaves the writer mid-frame, which is why the session then ends.
struct Link<'a, S> {
    context: &'a Context,
    writer: &'a mut noise::Writer<S>,
    records: &'a mut Inbound,
    pace: Pace,
}

impl<S: tokio::io::AsyncWrite> Link<'_, S> {
    /// Sends the records; `Some` if the relay ended the session before the send was done.
    async fn send<R>(&mut self, out: &[R]) -> Result<Option<Outcome>, String>
    where
        R: tally_wire::Outgoing + Sync,
    {
        let sent = {
            let sending = self.writer.send(out);
            tokio::pin!(sending);
            loop {
                tokio::select! {
                    sent = &mut sending => break sent,
                    got = self.records.recv() => {
                        if let Some(outcome) = heard(self.context, &mut self.pace, got)? {
                            return Ok(Some(outcome));
                        }
                    }
                }
            }
        };
        match sent {
            Ok(()) => Ok(None),
            Err(tally_wire::WireError::Io(error)) => self.farewell_or(error.to_string()).await,
            Err(error) => Err(error.to_string()),
        }
    }

    /// Sends what an ended audit owes this relay (`Ledger::end_audit`): batches the audited relay
    /// did not carry, which this session held back. Few, so they go whatever the relay's pace.
    async fn send_owed(&mut self) -> Result<Option<Outcome>, String> {
        let relay = self.context.relay.key;
        for batch in self.context.ledger.take_owed(&relay) {
            let record = Arc::new(Record::Batch(batch.clone()));
            if let Some(outcome) = self.send(&[record]).await? {
                return Ok(Some(outcome));
            }
            self.context.ledger.record(relay, &batch);
        }
        Ok(None)
    }

    /// The socket failed under a send. A relay that says goodbye closes at once, and closing over
    /// batches it has not read resets the connection, so the reset can reach the writer before the
    /// reader has passed the goodbye on. The goodbye is in order ahead of the reset on the read
    /// side, which a dead socket ends promptly, so the reader is drained: the relay's farewell is
    /// the outcome if it said one, and the send's `error` only if it did not.
    async fn farewell_or(&mut self, error: String) -> Result<Option<Outcome>, String> {
        loop {
            match heard(self.context, &mut self.pace, self.records.recv().await) {
                Ok(Some(outcome)) => return Ok(Some(outcome)),
                Ok(None) => {}
                Err(_) => return Err(error),
            }
        }
    }
}

/// Acts on what the reader passed on; `Some` if the relay ended the session, an error if the
/// reader failed or ended.
fn heard(
    context: &Context,
    pace: &mut Pace,
    got: Option<Result<Vec<Record>, String>>,
) -> Result<Option<Outcome>, String> {
    let got = got.ok_or_else(|| "reader ended".to_owned())??;
    let relay = &context.relay;
    for record in got {
        match record {
            Record::RelayList(relays) => context.directory.learn(relay.key, &relays),
            Record::ProviderOffer(offer) => context.directory.offered(relay.key, offer),
            Record::RateLimit {
                bytes_per_sec,
                burst,
                wanted_per_sec,
            } => pace.limit(bytes_per_sec, burst, wanted_per_sec),
            Record::Redirect {
                retry_after_secs,
                hints,
            } => {
                context.directory.learn(relay.key, &hints);
                return Ok(Some(Outcome::Leave(Duration::from_secs(
                    retry_after_secs.into(),
                ))));
            }
            Record::Goodbye {
                reason,
                retry_after_secs,
            } => return Ok(Some(goodbye(reason, retry_after_secs))),
            _ => {}
        }
    }
    Ok(None)
}

/// "Who offers my area?": the relay's answer is the area's sharing group.
fn ask_offers(context: &Context) -> Option<Record> {
    let cell = context.area?;
    Some(Record::ProviderQuery(ProviderQuery {
        cell,
        products: Streams::RAW,
    }))
}

/// The session's sending loop. `version` is what the relay negotiated: a relay older than
/// `SITES_VERSION` is sent nothing (`Directory::refuse_old_relay`).
async fn publish<S: tokio::io::AsyncWrite>(
    context: &Context,
    version: u16,
    writer: &mut noise::Writer<S>,
    records: &mut Inbound,
    mut batches: broadcast::Receiver<Arc<Record>>,
) -> Result<Outcome, String> {
    let relay = &context.relay;
    let directory = &context.directory;
    if let Some(outcome) = directory.refuse_old_relay(relay, version) {
        return Ok(outcome);
    }
    let mut link = Link {
        context,
        writer,
        records,
        pace: Pace::new(context.ceiling, context.wanted.session()),
    };
    let mut info = directory.info();
    let mut owed = context.ledger.owed_changes();
    let mut first = info.borrow_and_update().records();
    first.extend(ask_offers(context).map(Arc::new));
    if let Some(outcome) = link.send(&first).await? {
        return Ok(outcome);
    }
    if let Some(outcome) = link.send_owed().await? {
        return Ok(outcome);
    }
    let mut lagged = 0u64;
    let mut heartbeat = tokio::time::interval(HEARTBEAT);
    let mut report =
        tokio::time::interval_at(tokio::time::Instant::now() + REPORT_EVERY, REPORT_EVERY);
    let mut refresh =
        tokio::time::interval_at(tokio::time::Instant::now() + INFO_EVERY, INFO_EVERY);
    loop {
        let ended = tokio::select! {
            batch = batches.recv() => match batch {
                Ok(batch) => {
                    let Record::Batch(signed) = &*batch else { continue };
                    if !context.ledger.routes(&relay.key, signed) {
                        None
                    } else if link.pace.admit(signed.as_bytes().len(), Instant::now()) {
                        let ended = link.send(&[Arc::clone(&batch)]).await?;
                        if ended.is_none() {
                            context.ledger.record(relay.key, signed);
                        }
                        ended
                    } else {
                        None
                    }
                }
                // Batches this session could not keep up with are gone; gaps say so.
                Err(broadcast::error::RecvError::Lagged(count)) => {
                    lagged += count;
                    None
                }
                Err(broadcast::error::RecvError::Closed) => return Err("source ended".to_owned()),
            },
            changed = info.changed() => {
                if changed.is_ok() {
                    let latest = Arc::clone(&info.borrow_and_update());
                    link.send(&latest.records()).await?
                } else {
                    None
                }
            }
            changed = owed.changed() => {
                if changed.is_ok() { link.send_owed().await? } else { None }
            }
            _ = heartbeat.tick() => link.send(&[Record::Heartbeat]).await?,
            _ = refresh.tick() => {
                let mut out: Vec<Arc<Record>> = directory
                    .resign()
                    .map(|latest| latest.records())
                    .unwrap_or_default();
                out.extend(ask_offers(context).map(Arc::new));
                if out.is_empty() { None } else { link.send(&out).await? }
            }
            _ = report.tick() => {
                if link.pace.skipped > 0 || lagged > 0 {
                    eprintln!(
                        "tally-feed: relay {}: {} batches over its rate limit and {lagged} it was \
                         too slow for were not sent to it",
                        relay.address, link.pace.skipped
                    );
                    link.pace.skipped = 0;
                    lagged = 0;
                }
                None
            }
            got = link.records.recv() => heard(context, &mut link.pace, got)?,
        };
        if let Some(outcome) = ended {
            return Ok(outcome);
        }
    }
}

/// `wait` with the backoff's jitter, so feeders started together do not check together.
fn jittered(wait: Duration) -> Duration {
    let mut backoff = Backoff::new();
    backoff.at_least(wait);
    backoff.wait()
}

/// A relay closing a session or refusing one. Full, leaving or refusing is "leave me": the relay
/// declared it will not carry this feeder now. Anything else is retried.
fn goodbye(reason: Reason, retry_after_secs: u32) -> Outcome {
    let wait = Duration::from_secs(retry_after_secs.into());
    match reason {
        Reason::Full | Reason::Leaving | Reason::Refused => Outcome::Leave(wait),
        _ => Outcome::Retry(wait),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::source::Batcher;

    /// How long a test waits for the event it asserts before calling it a hang: a guard on a
    /// feeder that never gets there, never a verdict on how fast the machine running the test is.
    const HANG: Duration = Duration::from_secs(120);

    fn key() -> Result<PublicKey, String> {
        Ok(Identity::generate()
            .map_err(|error| error.to_string())?
            .public())
    }

    fn relay(address: &str) -> Result<RelayAddress, String> {
        Ok(RelayAddress {
            key: key()?,
            address: address.to_owned(),
        })
    }

    fn relays(prefix: &str, count: usize) -> Result<Vec<RelayAddress>, String> {
        (0..count)
            .map(|at| relay(&format!("{prefix}-{at}.example:10900")))
            .collect()
    }

    fn scratch() -> PathBuf {
        let base = std::env::var_os("TEST_TMPDIR").map_or_else(std::env::temp_dir, PathBuf::from);
        base.join(format!("tally-feed-{:016x}", random_below(usize::MAX)))
    }

    #[test]
    fn the_signed_location_is_the_snapped_one() -> Result<(), String> {
        let exact = Location {
            lat_e7: 339_425_361,
            lon_e7: -1_184_080_749,
            alt_m: 34,
            precision_m: 1_000,
        };
        let directory = Directory::new(
            scratch(),
            Vec::new(),
            Vec::new(),
            Identity::generate().map_err(|error| error.to_string())?,
            Some(exact),
            Clock::Dump1090,
        )?;
        let announced = directory.info().borrow().clone();
        let Some(site) = announced.site.as_deref() else {
            return Err("no site".to_owned());
        };
        let Record::ReceiverSite(site) = site else {
            return Err("not a receiver site".to_owned());
        };
        let signed = site.content().map_err(|error| error.to_string())?.location;
        assert_eq!(signed, crate::precision::snap(exact));
        assert_ne!(signed, exact);
        Ok(())
    }

    fn at_location(location: Option<Location>) -> Result<Arc<Directory>, String> {
        Directory::new(
            scratch(),
            Vec::new(),
            Vec::new(),
            Identity::generate().map_err(|error| error.to_string())?,
            location,
            Clock::Dump1090,
        )
    }

    const SITE: Location = Location {
        lat_e7: 339_425_361,
        lon_e7: -1_184_080_749,
        alt_m: 34,
        precision_m: 0,
    };

    /// The public description is format 2: no site in it, in any form, only the site's public
    /// cell, which holds the site. The site is its own record, signed at the same moment.
    #[test]
    fn the_public_description_never_carries_the_site() -> Result<(), String> {
        let error = |error: tally_wire::WireError| error.to_string();
        for precision_m in [0, 20] {
            let given = Location {
                precision_m,
                ..SITE
            };
            let directory = at_location(Some(given))?;
            let announced = directory.info().borrow().clone();
            let Record::ReceiverInfo(info) = announced.info.as_ref() else {
                return Err("not a receiver info".to_owned());
            };
            info.verify().map_err(error)?;
            assert_eq!(
                info.format(),
                tally_wire::batch::RECEIVER_INFO_FORMAT_PUBLIC
            );
            assert!(!info.carries_site());
            assert!(!announced.info.carries_site());
            let snapped = crate::precision::snap(given);
            let public = info.public().map_err(error)?;
            assert_eq!(
                public.cell,
                Some(Region::public_cell(&snapped).map_err(error)?)
            );
            assert!(public.holds(&snapped));
            // Not a coordinate of the site, the given one or the snapped one, is in its bytes.
            let bytes = info.as_bytes();
            for location in [given, snapped] {
                for field in [location.lat_e7, location.lon_e7] {
                    let needle = field.to_be_bytes();
                    assert!(
                        !bytes.windows(needle.len()).any(|window| window == needle),
                        "{field} in the public description"
                    );
                }
            }
            let Some(Record::ReceiverSite(site)) = announced.site.as_deref() else {
                return Err("no receiver site".to_owned());
            };
            site.verify().map_err(error)?;
            let content = site.content().map_err(error)?;
            assert_eq!(content.location, snapped);
            assert_eq!(content.issued_ms, public.issued_ms);
            assert_eq!(
                site.receiver().map_err(error)?,
                info.receiver().map_err(error)?
            );
            // The area the feeder chooses by is its public cell's, as every relay reckons it.
            assert_eq!(
                directory.area(),
                public.cell.and_then(tally_wire::rendezvous::area_of_public)
            );
        }
        // No location: a description with no cell, and no site at all.
        let directory = at_location(None)?;
        let announced = directory.info().borrow().clone();
        let Record::ReceiverInfo(info) = announced.info.as_ref() else {
            return Err("not a receiver info".to_owned());
        };
        assert_eq!(info.public().map_err(error)?.cell, None);
        assert!(announced.site.is_none());
        assert_eq!(directory.area(), None);
        Ok(())
    }

    /// What a session sends of the receiver's description and site, over its first three
    /// re-sends, at the version the relay negotiated.
    async fn announced_at(
        location: Option<Location>,
        version: Option<u16>,
    ) -> Result<Vec<Record>, String> {
        let error = |error: tally_wire::WireError| error.to_string();
        let (running, mut reader, _out, _records_in) =
            publishing_as(at_location(location)?, version).await?;
        let mut sent = Vec::new();
        let infos = |sent: &[Record]| {
            sent.iter()
                .filter(|record| matches!(record, Record::ReceiverInfo(_)))
                .count()
        };
        while infos(&sent) < 3 {
            let mut got = Vec::new();
            tokio::time::timeout(Duration::from_secs(700), reader.recv(&mut got))
                .await
                .map_err(|_| format!("only {} receiver infos arrived", infos(&sent)))?
                .map_err(error)?;
            sent.extend(got.into_iter().filter(|record| {
                matches!(record, Record::ReceiverInfo(_) | Record::ReceiverSite(_))
            }));
        }
        running.abort();
        Ok(sent)
    }

    /// A relay that negotiated version 3 keeps sites off client links, so it is sent the site,
    /// ahead of each description and signed with it.
    #[tokio::test(start_paused = true)]
    async fn a_version_3_relay_is_sent_the_site_with_each_description() -> Result<(), String> {
        let error = |error: tally_wire::WireError| error.to_string();
        let sent = announced_at(Some(SITE), Some(tally_wire::SITES_VERSION)).await?;
        assert_eq!(sent.len(), 6, "{sent:?}");
        for pair in sent.chunks(2) {
            let [Record::ReceiverSite(site), Record::ReceiverInfo(info)] = pair else {
                return Err(format!("not a site then a description: {pair:?}"));
            };
            site.verify().map_err(error)?;
            info.verify().map_err(error)?;
            assert!(!info.carries_site());
            let site = site.content().map_err(error)?;
            assert_eq!(site.location, SITE);
            assert_eq!(site.issued_ms, info.issued_ms().map_err(error)?);
            assert!(info.public().map_err(error)?.holds(&site.location));
        }
        // The default session (this build's newest) is a version 3 one.
        let sent = announced_at(Some(SITE), None).await?;
        assert!(
            sent.iter()
                .any(|record| matches!(record, Record::ReceiverSite(_)))
        );
        Ok(())
    }

    /// A relay older than version 3 may pass what it is sent to clients, so it is sent nothing at
    /// all, not even the public description, and the session ends with the relay left.
    #[tokio::test]
    async fn a_version_2_relay_is_sent_nothing_and_left() -> Result<(), String> {
        for location in [Some(SITE), None] {
            let (running, mut reader, out, _records_in) =
                publishing_as(at_location(location)?, Some(2)).await?;
            let feeder = Identity::generate().map_err(|error| error.to_string())?;
            let _ = out.send(Arc::new(Record::Batch(batch(&feeder, 0)?)));
            let ended = tokio::time::timeout(HANG, running)
                .await
                .map_err(|_| "the session did not end".to_owned())?
                .map_err(|error| error.to_string())?;
            assert!(
                matches!(ended, Ok(Outcome::Leave(wait)) if wait == OLD_RELAY_WAIT),
                "{ended:?}"
            );
            // The feeder's end is gone, and nothing came before it.
            let mut got = Vec::new();
            let read = tokio::time::timeout(HANG, reader.recv(&mut got))
                .await
                .map_err(|_| "the pipe stayed open".to_owned())?;
            assert!(read.is_err() && got.is_empty(), "{read:?} {got:?}");
        }
        // Every version from SITES_VERSION up is published to.
        let directory = at_location(Some(SITE))?;
        let relay = relay("relay.example:10900")?;
        assert!(directory.refuse_old_relay(&relay, 2).is_some());
        assert!(directory.refuse_old_relay(&relay, 2).is_some());
        assert!(
            directory
                .refuse_old_relay(&relay, tally_wire::SITES_VERSION)
                .is_none()
        );
        Ok(())
    }

    fn directory_at(
        state_dir: PathBuf,
        configured: Vec<RelayAddress>,
    ) -> Result<Arc<Directory>, String> {
        let identity = Identity::generate().map_err(|error| error.to_string())?;
        Directory::new(
            state_dir,
            configured,
            Vec::new(),
            identity,
            None,
            Clock::Dump1090,
        )
    }

    fn from(directory: &Directory, source: Source) -> Vec<RelayAddress> {
        directory
            .known()
            .into_iter()
            .filter(|(_, each)| *each == source)
            .map(|(relay, _)| relay)
            .collect()
    }

    #[test]
    fn one_relays_hints_are_capped_and_all_hints_are_capped() -> Result<(), String> {
        let directory = directory_at(scratch(), relays("owner", 2)?)?;
        let flooder = key()?;
        let flood = relays("flood", 1_000)?;
        directory.learn(flooder, &flood);
        directory.learn(flooder, &flood[500..]);
        let kept = from(&directory, Source::Learned(flooder));
        assert_eq!(kept.len(), HINTS_PER_SOURCE);
        // A second list from the same relay replaces its oldest, never adds to its share.
        assert_eq!(kept.first(), flood.get(500));
        let mut first = None;
        for _ in 0..40 {
            let hinter = key()?;
            first.get_or_insert(hinter);
            directory.learn(hinter, &relays("many", HINTS_PER_SOURCE)?);
        }
        let known = directory.known();
        let learned = known.iter().filter(|(_, source)| source.is_learned());
        assert_eq!(learned.count(), HINTS_IN_ALL);
        assert_eq!(from(&directory, Source::Configured).len(), 2);
        // The oldest learned went first: the flooder's, then the first hinter's.
        assert!(from(&directory, Source::Learned(flooder)).is_empty());
        let first = first.ok_or("no hinter")?;
        assert!(from(&directory, Source::Learned(first)).is_empty());
        Ok(())
    }

    #[test]
    fn learned_relays_are_saved_with_their_source() -> Result<(), String> {
        let state = scratch();
        let hinter = key()?;
        let hinted = relays("hinted", 3)?;
        let old = relay("old.example:10900")?;
        std::fs::create_dir_all(&state).map_err(|error| error.to_string())?;
        // The one-line format of an earlier build still reads, as learned from someone.
        std::fs::write(
            state.join("relays"),
            format!("{}={}\n", old.address, old.key),
        )
        .map_err(|error| error.to_string())?;
        let first = directory_at(state.clone(), relays("owner", 1)?)?;
        first.learn(hinter, &hinted);
        first.save();
        let again = directory_at(state.clone(), Vec::new())?;
        assert_eq!(from(&again, Source::Learned(hinter)), hinted);
        assert_eq!(from(&again, Source::Cached), vec![old]);
        // The owner's relays come from the command line each run, never from the file.
        assert!(from(&again, Source::Configured).is_empty());
        std::fs::remove_dir_all(&state).map_err(|error| error.to_string())
    }

    /// A relay's own offer, signed by `identity`, naming `address`, issued at `issued_ms`.
    fn own_offer(
        identity: &Identity,
        address: &str,
        issued_ms: u64,
    ) -> Result<ProviderOffer, String> {
        ProviderOffer::sign(
            identity,
            &tally_wire::directory::ProviderOfferContent {
                address: address.to_owned(),
                cell: Region::containing(
                    &Location {
                        lat_e7: 0,
                        lon_e7: 0,
                        alt_m: 0,
                        precision_m: 0,
                    },
                    0,
                )
                .map_err(|error| error.to_string())?,
                products: Streams::RAW,
                stripes_of: 1,
                stripes: 1,
                mlat_cores: 0,
                feeder_slots: 1,
                network: 0,
                issued_ms,
                expires_ms: wall_ms() + 600_000,
            },
        )
        .map_err(|error| error.to_string())
    }

    fn address_of(directory: &Directory, key: &PublicKey) -> Option<String> {
        directory
            .known()
            .into_iter()
            .find(|(relay, _)| relay.key == *key)
            .map(|(relay, _)| relay.address)
    }

    /// RFC-0180 §5.1: a relay renamed under feeders already running reaches them. Its own newer
    /// signed offer moves it, whoever passed the offer on; an older offer, and another relay's
    /// hint, never do; and the owner's address stays probed beside the new one.
    #[test]
    fn a_relays_own_newer_offer_moves_it_and_nothing_else_does() -> Result<(), String> {
        let moving = Identity::generate().map_err(|error| error.to_string())?;
        let owner = RelayAddress {
            key: moving.public(),
            address: "relay.old.example:10900".to_owned(),
        };
        let directory = directory_at(scratch(), vec![owner.clone()])?;
        let passer = key()?;
        let now = wall_ms();
        directory.offered(passer, own_offer(&moving, "relay.new.example:10900", now)?);
        assert_eq!(
            address_of(&directory, &owner.key).as_deref(),
            Some("relay.new.example:10900")
        );
        // An older offer, replayed, does not move it back.
        directory.offered(
            passer,
            own_offer(&moving, "relay.older.example:10900", now - 1)?,
        );
        // Another relay's hint names it elsewhere: a hint is not the relay's word.
        directory.learn(
            passer,
            &[RelayAddress {
                key: owner.key,
                address: "relay.hinted.example:10900".to_owned(),
            }],
        );
        assert_eq!(
            address_of(&directory, &owner.key).as_deref(),
            Some("relay.new.example:10900")
        );
        // Both the new address and the owner's are probed; the new first.
        let probed: Vec<String> = directory
            .probe_set(&[])
            .into_iter()
            .filter(|relay| relay.key == owner.key)
            .map(|relay| relay.address)
            .collect();
        assert_eq!(
            probed,
            vec!["relay.new.example:10900".to_owned(), owner.address.clone()]
        );
        // An offer that does not verify moves nothing.
        let mut forged = own_offer(&moving, "relay.forged.example:10900", now + 1)?
            .as_bytes()
            .to_vec();
        if let Some(last) = forged.last_mut() {
            *last ^= 1;
        }
        let forged = ProviderOffer::from_bytes(forged).map_err(|error| error.to_string())?;
        directory.offered(passer, forged);
        assert_eq!(
            address_of(&directory, &owner.key).as_deref(),
            Some("relay.new.example:10900")
        );
        // A newer offer naming the owner's address again moves it back, with no fallback left.
        directory.offered(passer, own_offer(&moving, &owner.address, now + 2)?);
        let probed: Vec<RelayAddress> = directory
            .probe_set(&[])
            .into_iter()
            .filter(|relay| relay.key == owner.key)
            .collect();
        assert_eq!(probed, vec![owner]);
        Ok(())
    }

    /// The move outlives a restart: the owner's relay comes from the command line again, and the
    /// state file moves it to where its own offer said, keeping the owner's as the fallback.
    #[test]
    fn a_move_is_remembered_across_restarts() -> Result<(), String> {
        let state = scratch();
        let moving = Identity::generate().map_err(|error| error.to_string())?;
        let seed = Identity::generate().map_err(|error| error.to_string())?;
        let owner = RelayAddress {
            key: moving.public(),
            address: "relay.old.example:10900".to_owned(),
        };
        let now = wall_ms();
        let first = directory_at(state.clone(), vec![owner.clone()])?;
        let learned = relay("learned.example:10900")?;
        first.learn(seed.public(), std::slice::from_ref(&learned));
        first.offered(
            seed.public(),
            own_offer(&moving, "relay.new.example:10900", now)?,
        );
        first.save();
        let again = directory_at(state.clone(), vec![owner.clone()])?;
        assert_eq!(
            address_of(&again, &owner.key).as_deref(),
            Some("relay.new.example:10900")
        );
        assert_eq!(from(&again, Source::Learned(seed.public())), vec![learned]);
        let probed: Vec<String> = again
            .probe_set(&[])
            .into_iter()
            .filter(|relay| relay.key == owner.key)
            .map(|relay| relay.address)
            .collect();
        assert_eq!(
            probed,
            vec!["relay.new.example:10900".to_owned(), owner.address.clone()]
        );
        // What was applied is remembered too: an offer older than the saved one moves nothing.
        again.offered(
            seed.public(),
            own_offer(&moving, "relay.older.example:10900", now - 1)?,
        );
        assert_eq!(
            address_of(&again, &owner.key).as_deref(),
            Some("relay.new.example:10900")
        );
        std::fs::remove_dir_all(&state).map_err(|error| error.to_string())
    }

    /// A relay probed at two addresses is one candidate, at the faster, in the order probed.
    #[test]
    fn a_relay_probed_twice_is_chosen_at_its_faster_address() -> Result<(), String> {
        use crate::probe::tests::measured;
        let moved = key()?;
        let other = key()?;
        let mut slow = measured(moved, 40, 1, 1);
        slow.relay.address = "relay.old.example:10900".to_owned();
        let mut fast = measured(moved, 10, 1, 1);
        fast.relay.address = "relay.new.example:10900".to_owned();
        let kept = fastest_per_relay(vec![measured(other, 20, 1, 2), slow, fast.clone()]);
        let kept: Vec<(PublicKey, String)> = kept
            .into_iter()
            .map(|each| (each.relay.key, each.relay.address))
            .collect();
        assert_eq!(
            kept,
            vec![
                (other, "relay-2-20.example:10900".to_owned()),
                (moved, fast.relay.address)
            ]
        );
        Ok(())
    }

    #[test]
    fn the_owners_relay_and_the_seeds_are_probed_first_never_pinned() -> Result<(), String> {
        let owner = relays("owner", 2)?;
        let directory = directory_at(scratch(), owner.clone())?;
        directory.learn(key()?, &relays("learned", 30)?);
        let set = directory.probe_set(&[]);
        assert_eq!(set.len(), MOST_PER_ROUND);
        assert_eq!(set[..2], owner[..]);
        // Asked to leave, the owner's relay is not probed until its wait has passed.
        directory.avoid(&owner[0].key, Duration::from_secs(600));
        assert!(
            !directory
                .probe_set(&[])
                .iter()
                .any(|relay| relay.key == owner[0].key)
        );
        Ok(())
    }

    #[test]
    fn a_relay_hiding_behind_a_lying_location_is_still_probed() -> Result<(), String> {
        // Many relays outrank it for the first places (the owner's, last round's band), and it
        // offers no cell near the feeder: the random places still find it within a few rounds.
        let directory = directory_at(scratch(), relays("owner", 3)?)?;
        let band: Vec<RelayAddress> = relays("band", 20)?;
        directory.learn(key()?, &band[..10]);
        directory.learn(key()?, &band[10..]);
        let hidden = relay("close-but-says-far.example:10900")?;
        directory.learn(key()?, std::slice::from_ref(&hidden));
        let band_keys: Vec<PublicKey> = band.iter().map(|relay| relay.key).collect();
        // Every round has its first places (the owner's, then last round's band) and its random
        // ones; the hidden relay can win only a random place. Drawn uniformly, each round finds it
        // with the chance of the random places among the relays not already first.
        let first = MOST_PER_ROUND - RANDOM_PER_ROUND;
        let others = 3 + band.len() + 1 - first;
        let chance = RANDOM_PER_ROUND as f64 / others as f64;
        const ROUNDS: usize = 3_000;
        let mut found = 0;
        for _ in 0..ROUNDS {
            let set = directory.probe_set(&band_keys);
            assert_eq!(set.len(), MOST_PER_ROUND);
            assert!(
                set[..first].iter().all(|relay| relay.key != hidden.key),
                "a lying location never wins a first place"
            );
            found += usize::from(set.iter().any(|relay| relay.key == hidden.key));
        }
        // Expected `chance * ROUNDS` (some 200); within a factor of two either way is more than
        // seven standard deviations, so this fails only when the draw is not uniform.
        let expected = chance * ROUNDS as f64;
        let found = found as f64;
        assert!(
            found >= expected / 2.0 && found <= expected * 2.0,
            "probed in {found} of {ROUNDS} rounds, expected about {expected:.0}"
        );
        Ok(())
    }

    fn pace(ceiling: u32) -> Pace {
        Pace::new(ceiling, Arc::new(WantedCeilings::default()).session())
    }

    #[test]
    fn a_relay_that_asked_nothing_is_not_paced() {
        let mut pace = pace(64_000);
        let now = Instant::now();
        assert!((0..100).all(|_| pace.admit(noise::MAX_PLAINTEXT, now)));
        // A relay asking for the ceiling or more asks for nothing.
        pace.limit(64_000, 0, None);
        assert!((0..100).all(|_| pace.admit(noise::MAX_PLAINTEXT, now)));
    }

    /// What a relay states of its wanted receptions a second is the batcher's to
    /// shed to, the least any live session stated: a session's statement holds while the session
    /// does and goes when it ends, so a relay that is gone holds the feeder to nothing.
    #[test]
    fn each_sessions_wanted_ceiling_holds_the_batcher_while_it_lives() {
        let ceilings = Arc::new(WantedCeilings::default());
        let mut first = Pace::new(64_000, ceilings.session());
        let mut second = Pace::new(64_000, ceilings.session());
        assert_eq!(ceilings.least(), None);
        first.limit(64_000, 64_000, Some(1_800));
        second.limit(64_000, 64_000, Some(1_200));
        assert_eq!(ceilings.least(), Some(1_200));
        // A relay that states none in a later `RateLimit` (or predates the field) holds nothing.
        second.limit(64_000, 64_000, None);
        assert_eq!(ceilings.least(), Some(1_800));
        drop(first);
        assert_eq!(ceilings.least(), None);
        drop(second);
    }

    #[test]
    fn a_relay_that_asked_for_less_gets_fewer_batches_never_none() {
        let mut pace = pace(64_000);
        pace.limit(16_000, 1_000, None);
        let start = Instant::now();
        let batch = 48 * 1024 + 4_000;
        let mut sent = Vec::new();
        for second in 0..600 {
            if pace.admit(batch, start + Duration::from_secs(second)) {
                sent.push(second);
            }
        }
        // About a third of a batch a second, and never a long silence.
        assert!((150..=250).contains(&sent.len()), "{} sent", sent.len());
        assert_eq!(pace.skipped, 600 - sent.len() as u64);
        assert!(sent.windows(2).all(|pair| pair[1] - pair[0] <= 5));
        assert_eq!(sent.first(), Some(&0));
    }

    fn batch(feeder: &Identity, sequence: u64) -> Result<Batch, String> {
        Batch::sign(
            feeder,
            &tally_wire::BatchContent {
                boot_id: 1,
                sequence,
                counter_epoch: 0,
                wall_ms: 1,
                dropped: 0,
                previous: [0; 32],
                observations: Vec::new(),
            },
        )
        .map_err(|error| error.to_string())
    }

    #[test]
    fn an_audit_sends_its_batches_to_one_relay_alone_and_only_while_it_is_up() -> Result<(), String>
    {
        let feeder = Identity::generate().map_err(|error| error.to_string())?;
        let (audited, other) = (key()?, key()?);
        let ledger = Ledger::default();
        ledger.live(audited, true);
        ledger.live(other, true);
        for sequence in 0..3 {
            let batch = batch(&feeder, sequence)?;
            for relay in [audited, other] {
                assert!(ledger.routes(&relay, &batch));
                ledger.record(relay, &batch);
            }
        }
        ledger.audit(audited);
        let mut solo = Vec::new();
        for sequence in 3..12 {
            let batch = batch(&feeder, sequence)?;
            for relay in [audited, other] {
                if ledger.routes(&relay, &batch) {
                    ledger.record(relay, &batch);
                }
            }
            if !ledger.routes(&other, &batch) {
                solo.push(sequence);
            }
        }
        assert_eq!(solo, vec![4, 5, 6, 7]);
        let sent = ledger.audited(Duration::ZERO);
        let audited_alone: Vec<u64> = sent
            .iter()
            .filter(|sent| sent.relays == vec![audited])
            .map(|sent| sent.batch.sequence())
            .collect();
        assert_eq!(audited_alone, solo);
        // The audited relay's session is down: nothing is withheld from the other.
        ledger.audit(audited);
        ledger.live(audited, false);
        let next = batch(&feeder, 13)?;
        assert!(ledger.routes(&other, &next));
        Ok(())
    }

    #[test]
    fn the_ledger_keeps_names_for_the_window_and_bytes_only_of_audited_batches()
    -> Result<(), String> {
        // RFC-0181's feeder: a batch of about 8 KB a second, to two relays, audited now and then.
        // Before, the ledger kept 512 whole batches (some 4 MiB); now it keeps each batch's name
        // and relays, and the bytes of the audited ones alone.
        let feeder = Identity::generate().map_err(|error| error.to_string())?;
        let (audited, other) = (key()?, key()?);
        let ledger = Ledger::default();
        ledger.live(audited, true);
        ledger.live(other, true);
        let large = |sequence: u64| -> Result<Batch, String> {
            let mut bytes = vec![1];
            bytes.extend_from_slice(feeder.public().as_bytes());
            bytes.extend_from_slice(&1u64.to_be_bytes());
            bytes.extend_from_slice(&sequence.to_be_bytes());
            bytes.resize(8 * 1024, 0);
            Batch::from_bytes(bytes).map_err(|error| error.to_string())
        };
        for sequence in 0..3_000 {
            if sequence % 300 == 0 {
                ledger.audit(audited);
            }
            if sequence % 300 == 10 {
                ledger.end_audit();
            }
            let batch = large(sequence)?;
            for relay in [audited, other] {
                if ledger.routes(&relay, &batch) {
                    ledger.record(relay, &batch);
                }
            }
            let _ = ledger.take_owed(&other);
        }
        let (names, bytes) = ledger.held();
        assert!(names <= SENT_KEPT, "{names} names");
        assert!(bytes <= 2 * SAMPLED * 8 * 1024, "{bytes} bytes of batches");
        let resident = names * std::mem::size_of::<Mark>() + bytes;
        assert!(resident < 128 * 1024, "{resident} bytes in all");
        assert!(resident * 32 < 512 * 8 * 1024, "{resident} bytes in all");
        // The audited batches are still there to check.
        let sent = ledger.audited(Duration::ZERO);
        assert_eq!(sent.len(), SAMPLED);
        assert!(sent.iter().all(|sent| sent.relays == vec![audited]));
        Ok(())
    }

    #[test]
    fn an_audited_batch_the_audited_relay_did_not_carry_reaches_the_other_relay()
    -> Result<(), String> {
        let feeder = Identity::generate().map_err(|error| error.to_string())?;
        let (audited, other) = (key()?, key()?);
        let ledger = Ledger::default();
        ledger.live(audited, true);
        ledger.live(other, true);
        let changes = ledger.owed_changes();
        let first = batch(&feeder, 0)?;
        ledger.routes(&audited, &first);
        ledger.routes(&other, &first);
        ledger.audit(audited);
        // The audited session skips the first audited batch (its pace, or it lagged) and writes
        // the rest; the other relay is held back from all of them.
        for sequence in 2..6 {
            let batch = batch(&feeder, sequence)?;
            assert!(!ledger.routes(&other, &batch));
            if ledger.routes(&audited, &batch) && sequence != 2 {
                ledger.record(audited, &batch);
            }
        }
        assert!(!changes.has_changed().map_err(|error| error.to_string())?);
        assert_eq!(ledger.end_audit(), 1);
        assert!(changes.has_changed().map_err(|error| error.to_string())?);
        let owed: Vec<u64> = ledger
            .take_owed(&other)
            .iter()
            .map(Batch::sequence)
            .collect();
        assert_eq!(owed, vec![2]);
        assert!(ledger.take_owed(&audited).is_empty());
        // Ended, the audit holds nothing back.
        assert!(ledger.routes(&other, &batch(&feeder, 6)?));

        // The audited relay's session ends mid-audit: what it was written may not have reached
        // it, so every batch held back goes to the other relay.
        ledger.audit(audited);
        for sequence in 8..12 {
            let batch = batch(&feeder, sequence)?;
            assert!(!ledger.routes(&other, &batch));
            if ledger.routes(&audited, &batch) {
                ledger.record(audited, &batch);
            }
        }
        ledger.live(audited, false);
        assert_eq!(ledger.end_audit(), 4);
        let owed: Vec<u64> = ledger
            .take_owed(&other)
            .iter()
            .map(Batch::sequence)
            .collect();
        assert_eq!(owed, vec![8, 9, 10, 11]);
        Ok(())
    }

    /// The feeder's delivery checks, live over loopback relays: it audits each relay it holds in
    /// turn, asks the area's members (two, on two networks) about the audited batches, convicts the
    /// relay that took its batches and passed none on, remembers it across restarts, and moves to
    /// the next in the ranking. The honest relay, audited too, is never convicted.
    #[tokio::test]
    async fn the_live_audit_loop_catches_a_swallower_and_spares_an_honest_relay()
    -> Result<(), String> {
        use crate::probe::tests::{Fake, Group, Mode, echo_relay};
        use tally_wire::directory::ProviderOfferContent;
        const LOOPBACK: Duration = Duration::from_millis(1);
        let error = |error: tally_wire::WireError| error.to_string();
        let location = Location {
            lat_e7: 339_400_000,
            lon_e7: -1_184_000_000,
            alt_m: 30,
            precision_m: 0,
        };
        let group: Group = Arc::default();
        let (taken, mut arrivals) = mpsc::unbounded_channel();
        // Each on its own /24 and network, so the networks are known distinct.
        let relay = |ip, network, slots, honest: bool| -> Result<Fake, String> {
            Ok(Fake {
                ip,
                batches: Some(taken.clone()),
                forwards_to: honest.then(|| Arc::clone(&group)),
                ..Fake::new(
                    Identity::generate().map_err(error)?,
                    network,
                    slots,
                    Mode::Serve,
                )
            })
        };
        let swallower = echo_relay(relay("127.0.1.1", 1, 1_000_000, false)?).await?;
        let honest = echo_relay(relay("127.0.2.1", 2, 1_000_000, true)?).await?;
        let reserve = echo_relay(relay("127.0.3.1", 3, 1, true)?).await?;
        let feeder = Identity::generate().map_err(error)?;
        let dir = scratch();
        let directory = Directory::new(
            dir.clone(),
            vec![swallower.clone(), honest.clone(), reserve.clone()],
            Vec::new(),
            feeder.clone(),
            Some(location),
            Clock::Dump1090,
        )?;
        let area = directory.area().ok_or("no area")?;
        // Two members of the area's sharing group, which take no feeder.
        for (ip, network) in [("127.0.11.1", 11), ("127.0.12.1", 12)] {
            let identity = Identity::generate().map_err(error)?;
            let member = echo_relay(Fake {
                ip,
                answers_from: Some(Arc::clone(&group)),
                ..Fake::new(identity.clone(), network, 0, Mode::Serve)
            })
            .await?;
            let now = wall_ms();
            let offer = ProviderOffer::sign(
                &identity,
                &ProviderOfferContent {
                    address: member.address.clone(),
                    cell: area,
                    products: Streams::RAW,
                    stripes_of: 1,
                    stripes: 1,
                    mlat_cores: 0,
                    feeder_slots: 0,
                    network,
                    issued_ms: now,
                    expires_ms: now + 600_000,
                },
            )
            .map_err(error)?;
            directory.offered(member.key, offer);
        }
        assert_eq!(directory.offers().len(), 2);
        let (batches, _) = broadcast::channel(64);
        let publisher = tokio::spawn(run(Publishing {
            directory: Arc::clone(&directory),
            identity: feeder.clone(),
            batches: batches.clone(),
            ceiling: 64_000,
            wanted: Arc::default(),
            checker: DeliveryChecker::load(&dir),
            checking: Checking {
                every: Duration::from_secs(1),
                audit_for: Duration::from_secs(1),
                settle: Duration::from_millis(500),
                grant_every: Duration::from_millis(200),
            },
            prober: |relay, me| {
                Box::pin(async move {
                    let mut probed = probe::probe(&relay, &me).await?;
                    probed.measured.rtt = LOOPBACK;
                    Ok(probed)
                })
            },
            source_address: None,
            health: Arc::default(),
        }));
        let sending = tokio::spawn(async move {
            for sequence in 0.. {
                if let Ok(batch) = batch(&feeder, sequence) {
                    let _ = batches.send(Arc::new(Record::Batch(batch)));
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        });
        let convicted = || {
            std::fs::read_to_string(dir.join("swallowers"))
                .unwrap_or_default()
                .lines()
                .filter_map(|line| line.split_once(' '))
                .filter_map(|(key, _)| PublicKey::from_base64(key).ok())
                .collect::<Vec<PublicKey>>()
        };
        // Until the reserve takes the swallower's place.
        let waited = tokio::time::timeout(HANG, async {
            while let Some((relay, _)) = arrivals.recv().await {
                if relay == reserve.key {
                    return;
                }
            }
        })
        .await;
        sending.abort();
        publisher.abort();
        waited.map_err(|_| {
            format!(
                "the swallower was not replaced; convicted {:?}",
                convicted()
            )
        })?;
        assert_eq!(convicted(), vec![swallower.key]);
        let _ = std::fs::remove_dir_all(dir);
        Ok(())
    }

    type Pipe = tokio::io::DuplexStream;
    type Outbound = mpsc::Sender<Result<Vec<Record>, String>>;

    /// A session over an in-memory pipe that buffers `buffer` bytes each way: the feeder's end, the
    /// relay's end, and the relay's key.
    async fn pipe(
        buffer: usize,
    ) -> Result<(noise::Session<Pipe>, noise::Session<Pipe>, PublicKey), String> {
        let error = |error: tally_wire::WireError| error.to_string();
        let feeder = Identity::generate().map_err(error)?;
        let relay_identity = Identity::generate().map_err(error)?;
        let relay_key = relay_identity.public();
        let (near, far) = tokio::io::duplex(buffer);
        let dial =
            tokio::spawn(
                async move { noise::connect(near, &feeder, &relay_key, Role::Feeder).await },
            );
        let accepted = noise::accept(far, &[relay_identity]).await.map_err(error)?;
        let session = dial
            .await
            .map_err(|error| error.to_string())?
            .map_err(error)?;
        Ok((session, accepted.session, relay_key))
    }

    fn context(directory: Arc<Directory>, key: PublicKey, address: &str) -> Context {
        Context {
            relay: RelayAddress {
                key,
                address: address.to_owned(),
            },
            directory,
            ledger: Arc::new(Ledger::default()),
            ceiling: 64_000,
            area: None,
            wanted: Arc::default(),
            source_address: None,
        }
    }

    /// A publishing session over an in-memory pipe, and the relay's end of it.
    async fn publishing(
        directory: Arc<Directory>,
    ) -> Result<
        (
            tokio::task::JoinHandle<Result<Outcome, String>>,
            noise::Reader<Pipe>,
            broadcast::Sender<Arc<Record>>,
            mpsc::Sender<Result<Vec<Record>, String>>,
        ),
        String,
    > {
        publishing_as(directory, None).await
    }

    /// `publishing`, with the session run as though the relay had negotiated `version` (the
    /// handshake itself always agrees this build's newest), so an older relay can be stood for.
    async fn publishing_as(
        directory: Arc<Directory>,
        version: Option<u16>,
    ) -> Result<
        (
            tokio::task::JoinHandle<Result<Outcome, String>>,
            noise::Reader<Pipe>,
            broadcast::Sender<Arc<Record>>,
            mpsc::Sender<Result<Vec<Record>, String>>,
        ),
        String,
    > {
        let (session, relay_end, relay_key) = pipe(1 << 20).await?;
        let (out, batches) = broadcast::channel(64);
        let (records_in, mut records) = mpsc::channel(16);
        let context = context(directory, relay_key, "relay.example:10900");
        let version = version.unwrap_or(session.version);
        let mut writer = session.writer;
        let running = tokio::spawn(async move {
            publish(&context, version, &mut writer, &mut records, batches).await
        });
        Ok((running, relay_end.reader, out, records_in))
    }

    #[tokio::test(start_paused = true)]
    async fn a_session_re_sends_a_freshly_signed_receiver_info_every_ten_minutes()
    -> Result<(), String> {
        let error = |error: tally_wire::WireError| error.to_string();
        let directory = directory_at(scratch(), Vec::new())?;
        let (running, mut reader, _out, _records_in) = publishing(directory).await?;
        let began = tokio::time::Instant::now();
        let mut infos = Vec::new();
        while infos.len() < 3 {
            let mut got = Vec::new();
            tokio::time::timeout(Duration::from_secs(700), reader.recv(&mut got))
                .await
                .map_err(|_| format!("only {} receiver infos arrived", infos.len()))?
                .map_err(error)?;
            for record in got {
                if let Record::ReceiverInfo(info) = record {
                    info.verify().map_err(error)?;
                    infos.push((began.elapsed(), info.issued_ms().map_err(error)?));
                }
            }
        }
        running.abort();
        let at: Vec<u64> = infos.iter().map(|(at, _)| at.as_secs()).collect();
        assert_eq!(at, vec![0, 600, 1_200]);
        let issued: Vec<u64> = infos.iter().map(|(_, issued_ms)| *issued_ms).collect();
        assert!(
            issued.windows(2).all(|pair| pair[0] <= pair[1]),
            "{issued:?}"
        );
        Ok(())
    }

    #[tokio::test]
    async fn a_compressed_batch_reaches_a_relay_whole() -> Result<(), String> {
        let error = |error: tally_wire::WireError| error.to_string();
        let directory = directory_at(scratch(), Vec::new())?;
        let (running, mut reader, out, _records_in) = publishing(directory).await?;
        let feeder = Identity::generate().map_err(error)?;
        let mut batcher = Batcher::new(feeder, u32::MAX, Clock::Dump1090);
        for counter in 1..200u64 {
            let frame = tally_wire::Frame::new(
                tally_wire::FrameKind::ModeSLong,
                counter * 1_000,
                9,
                &[0x8d, 0xa0, 0x00, 0x01, 0x58, 0x1f, 0, 0, 0, 0, 0, 0, 0, 0],
            )
            .map_err(error)?;
            batcher.observe(&frame)?;
        }
        let sealed = batcher.seal()?.ok_or("no batch")?;
        let _ = out.send(Arc::new(Record::Batch(sealed.clone())));
        loop {
            let mut got = Vec::new();
            tokio::time::timeout(Duration::from_secs(10), reader.recv(&mut got))
                .await
                .map_err(|_| "no batch arrived".to_owned())?
                .map_err(error)?;
            if let Some(Record::Batch(arrived)) = got
                .into_iter()
                .find(|record| matches!(record, Record::Batch(_)))
            {
                running.abort();
                assert_eq!(arrived, sealed);
                assert_eq!(arrived.format(), tally_wire::batch::BATCH_FORMAT_DEFLATE);
                arrived.verify().map_err(error)?;
                assert_eq!(arrived.content().map_err(error)?.observations.len(), 199);
                return Ok(());
            }
        }
    }

    #[tokio::test]
    async fn a_feeder_at_its_ceiling_delivers_every_batch_to_a_relay_that_asked_nothing()
    -> Result<(), String> {
        let error = |error: tally_wire::WireError| error.to_string();
        let feeder = Identity::generate().map_err(error)?;
        let relay_identity = Identity::generate().map_err(error)?;
        let relay_key = relay_identity.public();
        let (near, far) = tokio::io::duplex(1 << 20);
        let dialler = feeder.clone();
        let dial =
            tokio::spawn(
                async move { noise::connect(near, &dialler, &relay_key, Role::Feeder).await },
            );
        let accepted = noise::accept(far, &[relay_identity]).await.map_err(error)?;
        let session = dial
            .await
            .map_err(|error| error.to_string())?
            .map_err(error)?;
        let directory = directory_at(scratch(), Vec::new())?;
        let (out, batches) = broadcast::channel(64);
        let (_records_in, mut records) = mpsc::channel(16);
        let context = context(directory, relay_key, "relay.example:10900");
        let version = session.version;
        let mut writer = session.writer;
        let publishing = tokio::spawn(async move {
            publish(&context, version, &mut writer, &mut records, batches).await
        });
        // Batches as big as the batcher seals them, each a large part of the second's ceiling even
        // compressed: each message is noise (splitmix64 of its counter), which DEFLATE barely
        // shrinks.
        let mut batcher = Batcher::new(feeder, u32::MAX, Clock::Dump1090);
        let frame = |counter: u64| {
            let mix = |x: u64| {
                let x = (x ^ (x >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
                let x = (x ^ (x >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
                x ^ (x >> 31)
            };
            let mut message = [0u8; 14];
            message[..8].copy_from_slice(&mix(counter).to_be_bytes());
            message[8..].copy_from_slice(&mix(!counter).to_be_bytes()[..6]);
            tally_wire::Frame::new(tally_wire::FrameKind::ModeSLong, counter, 9, &message)
                .map_err(|error| error.to_string())
        };
        let mut sent = 0;
        let mut counter = 1;
        while sent < 8 {
            batcher.observe(&frame(counter)?)?;
            counter += 1;
            if batcher.is_full() {
                let batch = batcher.seal()?.ok_or("no batch")?;
                assert!(
                    batch.as_bytes().len() > 32 * 1024,
                    "{}",
                    batch.as_bytes().len()
                );
                let _ = out.send(Arc::new(Record::Batch(batch)));
                sent += 1;
            }
        }
        let mut reader = accepted.session.reader;
        let mut sequences = Vec::new();
        while sequences.len() < 8 {
            let mut got = Vec::new();
            tokio::time::timeout(Duration::from_secs(10), reader.recv(&mut got))
                .await
                .map_err(|_| format!("only {} batches arrived", sequences.len()))?
                .map_err(error)?;
            for record in got {
                if let Record::Batch(batch) = record {
                    sequences.push(batch.sequence());
                }
            }
        }
        publishing.abort();
        assert_eq!(sequences, (0..8).collect::<Vec<u64>>());
        Ok(())
    }

    /// A publishing session to a relay that completed the handshake and then stopped reading, over
    /// a pipe too small for even the first receiver info. The relay's end and the reader's sender
    /// are held for as long as the session runs.
    async fn stalled(
        directory: Arc<Directory>,
        records: Option<(Outbound, Inbound)>,
    ) -> Result<Outcome, String> {
        let (session, _relay_end, relay_key) = pipe(64).await?;
        let (_out, batches) = broadcast::channel(64);
        let (_records_in, mut records) = records.unwrap_or_else(|| mpsc::channel(16));
        let context = context(directory, relay_key, "stalled.example:10900");
        let version = session.version;
        let mut writer = session.writer;
        publish(&context, version, &mut writer, &mut records, batches).await
    }

    #[tokio::test(start_paused = true)]
    async fn a_relay_that_stops_reading_ends_the_session_by_the_deadline() -> Result<(), String> {
        let directory = directory_at(scratch(), Vec::new())?;
        let began = tokio::time::Instant::now();
        let ended = stalled(directory, None).await;
        assert!(ended.is_err(), "{ended:?}");
        let lasted = began.elapsed();
        assert!(
            lasted >= noise::WRITE_TIMEOUT
                && lasted <= noise::WRITE_TIMEOUT + Duration::from_secs(1),
            "{lasted:?}"
        );
        Ok(())
    }

    /// A relay that redirects and closes over unread batches resets the connection, and the reset
    /// can fail the next send before the reader has passed the redirect on. The redirect, not the
    /// reset, is how the session ended.
    #[tokio::test]
    async fn a_redirect_the_reader_passes_on_after_a_send_failed_still_ends_the_session()
    -> Result<(), String> {
        let directory = directory_at(scratch(), Vec::new())?;
        let (session, relay_end, relay_key) = pipe(64 * 1024).await?;
        drop(relay_end);
        let (_out, batches) = broadcast::channel(64);
        let (records_in, mut records) = mpsc::channel(16);
        // On this one thread the reader's records arrive only once the session waits on them,
        // which is after its first send has already failed against the closed pipe.
        let reader = tokio::spawn(async move {
            let redirect = Record::Redirect {
                retry_after_secs: 600,
                hints: Vec::new(),
            };
            let _ = records_in.send(Ok(vec![redirect])).await;
            let _ = records_in
                .send(Err("i/o: connection reset by peer".to_owned()))
                .await;
        });
        let context = context(directory, relay_key, "redirecting.example:10900");
        let version = session.version;
        let mut writer = session.writer;
        let ended = publish(&context, version, &mut writer, &mut records, batches).await;
        reader.abort();
        assert!(
            matches!(ended, Ok(Outcome::Leave(wait)) if wait == Duration::from_secs(600)),
            "{ended:?}"
        );
        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn a_failed_reader_ends_the_session_while_a_send_waits() -> Result<(), String> {
        let directory = directory_at(scratch(), Vec::new())?;
        let (records_in, records) = mpsc::channel(16);
        let reader = records_in.clone();
        let running = tokio::spawn(stalled(directory, Some((records_in, records))));
        tokio::time::sleep(Duration::from_secs(5)).await;
        assert!(!running.is_finished(), "ended before the reader failed");
        let failed_at = tokio::time::Instant::now();
        reader
            .send(Err("silent too long".to_owned()))
            .await
            .map_err(|error| error.to_string())?;
        let ended = tokio::time::timeout(Duration::from_secs(1), running)
            .await
            .map_err(|_| "the session waited on its send".to_owned())?
            .map_err(|error| error.to_string())?;
        assert_eq!(ended.err().as_deref(), Some("silent too long"));
        assert!(failed_at.elapsed() < Duration::from_secs(1));
        Ok(())
    }

    /// The whole publisher over loopback relays: it probes, chooses two on distinct networks,
    /// publishes compressed to both, and when one redirects at its
    /// first batch, the next in the ranking takes its place after the failover jitter.
    #[tokio::test]
    async fn the_publisher_sends_to_two_networks_and_fails_over_from_a_redirect()
    -> Result<(), String> {
        use crate::probe::tests::{Fake, Mode, echo_relay};
        // The three relays are equally near. What a probe times between them on loopback is this
        // host's scheduling (one test thread runs the feeder and all three relays), which under
        // load spreads past the band and leaves out whichever relay it happens to slow. So every
        // relay is probed for real (signed reply, headroom, network) and read at one time.
        const LOOPBACK: Duration = Duration::from_millis(1);
        let error = |error: tally_wire::WireError| error.to_string();
        let (taken, mut arrivals) = mpsc::unbounded_channel();
        // The redirecting relay declares overwhelming capacity, so the ranking puts it first.
        let mut fakes = Vec::new();
        for (ip, network, slots, mode) in [
            ("127.0.0.1", 1, 1, Mode::Serve),
            ("127.0.0.2", 2, 1_000_000, Mode::RedirectOnBatch),
            ("127.0.0.3", 3, 1, Mode::Serve),
        ] {
            let fake = Fake {
                ip,
                batches: Some(taken.clone()),
                ..Fake::new(Identity::generate().map_err(error)?, network, slots, mode)
            };
            fakes.push(echo_relay(fake).await?);
        }
        let feeder = Identity::generate().map_err(error)?;
        let directory = Directory::new(
            scratch(),
            fakes.clone(),
            Vec::new(),
            feeder.clone(),
            Some(Location {
                lat_e7: 339_400_000,
                lon_e7: -1_184_000_000,
                alt_m: 30,
                precision_m: 0,
            }),
            Clock::Dump1090,
        )?;
        let (batches, _) = broadcast::channel(64);
        let publisher = tokio::spawn(run(Publishing {
            directory: Arc::clone(&directory),
            identity: feeder.clone(),
            batches: batches.clone(),
            ceiling: 64_000,
            wanted: Arc::default(),
            checker: DeliveryChecker::default(),
            checking: Checking::default(),
            prober: |relay, me| {
                Box::pin(async move {
                    let mut probed = probe::probe(&relay, &me).await?;
                    probed.measured.rtt = LOOPBACK;
                    Ok(probed)
                })
            },
            source_address: None,
            health: Arc::default(),
        }));
        let sending = tokio::spawn(async move {
            for sequence in 0.. {
                if let Ok(batch) = batch(&feeder, sequence) {
                    let _ = batches.send(Arc::new(Record::Batch(batch)));
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        });
        let mut heard: HashSet<PublicKey> = HashSet::new();
        let serving: HashSet<PublicKey> = [fakes[0].key, fakes[2].key].into_iter().collect();
        let waited = tokio::time::timeout(HANG, async {
            while heard != serving {
                match arrivals.recv().await {
                    Some((relay, _)) => {
                        heard.insert(relay);
                    }
                    None => return,
                }
            }
        })
        .await;
        sending.abort();
        publisher.abort();
        waited.map_err(|_| {
            format!(
                "only {} of the two serving relays took batches",
                heard.len()
            )
        })?;
        // The redirecting relay is left for as long as it asked, and the feeder says so.
        assert!(directory.avoided().contains(&fakes[1].key));
        Ok(())
    }

    #[tokio::test]
    async fn a_feeder_that_started_before_its_relay_publishes_once_the_relay_is_up()
    -> Result<(), String> {
        use crate::probe::tests::{Fake, Mode, echo_relay};
        use std::sync::atomic::{AtomicUsize, Ordering};
        // A host booting its relay and its feeder at once: the feeder's first probes find nothing
        // listening. It must not then wait a whole round (`ROUND_EVERY`, five minutes) to look
        // again; with no relay held it looks again at the reconnect backoff's pace.
        static NOT_YET: AtomicUsize = AtomicUsize::new(2);
        let error = |error: tally_wire::WireError| error.to_string();
        let (taken, mut arrivals) = mpsc::unbounded_channel();
        let fake = Fake {
            batches: Some(taken),
            ..Fake::new(Identity::generate().map_err(error)?, 1, 1, Mode::Serve)
        };
        let relay = echo_relay(fake).await?;
        let feeder = Identity::generate().map_err(error)?;
        let directory = Directory::new(
            scratch(),
            vec![relay.clone()],
            Vec::new(),
            feeder.clone(),
            None,
            Clock::Dump1090,
        )?;
        let (batches, _) = broadcast::channel(64);
        let publisher = tokio::spawn(run(Publishing {
            directory,
            identity: feeder.clone(),
            batches: batches.clone(),
            ceiling: 64_000,
            wanted: Arc::default(),
            checker: DeliveryChecker::default(),
            checking: Checking::default(),
            prober: |relay, me| {
                Box::pin(async move {
                    let unanswered = NOT_YET
                        .fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| n.checked_sub(1))
                        .is_ok();
                    if unanswered {
                        return Err("connection refused".to_owned());
                    }
                    probe::probe(&relay, &me).await
                })
            },
            source_address: None,
            health: Arc::default(),
        }));
        let sending = tokio::spawn(async move {
            for sequence in 0.. {
                if let Ok(batch) = batch(&feeder, sequence) {
                    let _ = batches.send(Arc::new(Record::Batch(batch)));
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        });
        // A feeder that waited a whole round would wait `ROUND_EVERY`; one looking again at the
        // backoff's pace arrives in seconds. Waited for well short of a round, and long enough
        // that a loaded machine's seconds are never the verdict.
        const { assert!(HANG.as_secs() < ROUND_EVERY.as_secs()) };
        let arrived = tokio::time::timeout(HANG, arrivals.recv()).await;
        sending.abort();
        publisher.abort();
        match arrived {
            Ok(Some((key, _))) if key == relay.key => Ok(()),
            _ => Err(format!(
                "the relay took no batch within {HANG:?} of coming up"
            )),
        }
    }

    #[test]
    fn full_leaving_and_refused_are_leave_me_and_the_rest_retry() {
        for reason in [Reason::Full, Reason::Leaving, Reason::Refused] {
            assert!(matches!(goodbye(reason, 60), Outcome::Leave(_)));
        }
        for reason in [Reason::Protocol, Reason::Version, Reason::Other(9)] {
            assert!(matches!(goodbye(reason, 60), Outcome::Retry(_)));
        }
    }
}
