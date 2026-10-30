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
use crate::source::{RelayClocks, Stating, Telling, TokenBucket, WantedCeilings};

const HEARTBEAT: Duration = Duration::from_secs(30);
const READ_TIMEOUT: Duration = Duration::from_secs(120);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// How long a session must stay up to count as having worked: one that fails sooner is a failed
/// relay, and its place goes to the next; one that worked is dialled again.
const HEALTHY_SESSION: Duration = Duration::from_secs(60);
/// How soon a configured relay with no live clock sample is probed for its clock when the clocks
/// ask for it (`RelayClocks::probing`), at first: each poll it does not answer doubles it, up to
/// `ROUND_EVERY` (`ClockPolls`), as NTP's poll interval grows for a server that does not answer.
const CLOCK_POLL_FIRST: Duration = Duration::from_secs(30);

const _: () = assert!(CLOCK_POLL_FIRST.as_secs() < ROUND_EVERY.as_secs());

/// Each configured relay's clock poll while it has no live clock sample (RFC 5905 §7.3, the poll
/// interval): when it is next probed for its clock, and how long until the one after. A poll probes
/// only the configured relays due one, never discovery's round: before, a clock that asked for
/// probes brought the whole round forward to every 30 s, so one seed that never answered had every
/// feeder probe sixteen relays twice a minute for ever.
#[derive(Default)]
struct ClockPolls {
    polls: HashMap<PublicKey, (tokio::time::Instant, Duration)>,
}

impl ClockPolls {
    /// Of `unheard` (each configured relay's addresses with no live sample,
    /// `Directory::clock_set`), those due a poll at `now`: each due is due again its interval
    /// later, and that interval doubles, up to `ROUND_EVERY`. A relay no longer unheard is
    /// forgotten, so if it falls silent again it is polled from `CLOCK_POLL_FIRST`.
    fn due(&mut self, unheard: Vec<RelayAddress>, now: tokio::time::Instant) -> Vec<RelayAddress> {
        self.polls
            .retain(|key, _| unheard.iter().any(|relay| relay.key == *key));
        let mut due: Vec<PublicKey> = Vec::new();
        for relay in &unheard {
            let (at, _) = *self
                .polls
                .entry(relay.key)
                .or_insert((now, CLOCK_POLL_FIRST));
            if at <= now && !due.contains(&relay.key) {
                due.push(relay.key);
            }
        }
        for key in &due {
            if let Some((at, every)) = self.polls.get_mut(key) {
                *at = now + *every;
                *every = (*every * 2).min(ROUND_EVERY);
            }
        }
        unheard
            .into_iter()
            .filter(|relay| due.contains(&relay.key))
            .collect()
    }

    /// Relays a probe's answer made live samples of (`heard`, `RelayClocks::heard` once the answer
    /// is handled): each is polled from `CLOCK_POLL_FIRST` again if it is unheard later, its
    /// interval no longer grown by the polls it missed before (as NTP resets a server's poll on a
    /// reply it can use). An answer that made no live sample (no clock, or one too uncertain to
    /// use: a seed whose ClockBound is down) resets nothing, so its poll keeps doubling; before,
    /// any answer reset it, and such a seed was probed some 3,600 times an hour by every feeder.
    fn answered(&mut self, heard: &[PublicKey]) {
        self.polls.retain(|key, _| !heard.contains(key));
    }

    /// When the next poll is due, if any relay is polled.
    fn next(&self) -> Option<tokio::time::Instant> {
        self.polls.values().map(|(at, _)| *at).min()
    }
}
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

    /// Every configured relay (the owner's, then the seeds) with no live clock sample (not in
    /// `heard`) and not avoided at `now`, each of its addresses: the clock's sources unheard.
    fn clock_part(&self, heard: &[PublicKey], now: tokio::time::Instant) -> Vec<RelayAddress> {
        let mut out: Vec<RelayAddress> = Vec::new();
        let configured = self
            .known
            .iter()
            .filter(|known| matches!(known.source, Source::Configured))
            .chain(
                self.known
                    .iter()
                    .filter(|known| matches!(known.source, Source::Seed)),
            )
            .flat_map(Known::addresses);
        for relay in configured {
            if !heard.contains(&relay.key)
                && !self.is_avoided(&relay.key, now)
                && !out.contains(&relay)
            {
                out.push(relay);
            }
        }
        out
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
    identity: Arc<Identity>,
    location: Option<Location>,
    clock: Clock,
    /// The clock the feeder signs by (`RelayClocks::now_ms`): what its description and site are
    /// issued at and what an offer's expiry is judged against, as a relay judges them.
    signing: Arc<RelayClocks>,
    info: watch::Sender<Arc<Announcement>>,
    /// The relays already said (in the log) to be too old to publish to, so each is said once.
    too_old: Mutex<HashSet<PublicKey>>,
}

impl Directory {
    /// `configured` are the owner's (`--relay`), `seeds` the binary's: both candidates, never
    /// pinned. `location` is the antenna's as the owner gave it; the directory holds and signs it
    /// snapped to its precision (`precision::snap`), and never keeps the exact one. `signing` is
    /// the clock the feeder signs by, its batches' (`RelayClocks::now_ms`).
    pub fn new(
        state_dir: PathBuf,
        configured: Vec<RelayAddress>,
        seeds: Vec<RelayAddress>,
        identity: impl Into<Arc<Identity>>,
        location: Option<Location>,
        (clock, signing): (Clock, Arc<RelayClocks>),
    ) -> Result<Arc<Self>, String> {
        let identity = identity.into();
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
        let info = sign_announcement(&identity, location, clock, &[], signing.now_ms())?;
        Ok(Arc::new(Self {
            state_dir,
            relays: Mutex::new(relays),
            identity,
            location,
            clock,
            signing,
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
        if content.expires_ms <= self.signing.now_ms() {
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
        let now = self.signing.now_ms();
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

    /// The relays to probe this round. First, apart from discovery, every configured relay (the
    /// owner's and the seeds) with no live clock sample (not in `heard`, `RelayClocks::heard`):
    /// they are the feeder's clock sources, as NTP's configured servers are, so they are polled
    /// whatever the round holds and no number of offers or hints can crowd them out. Then
    /// discovery's round, at most `MOST_PER_ROUND`: those held, those that offer the feeder's area
    /// (the one use of where a relay says it is: whom to probe first), the owner's, the seeds, and
    /// last round's band, in that order, at most `MOST_PER_ROUND - RANDOM_PER_ROUND` of them; then
    /// the rest of it at random among the others known, so a relay whose offer lies about where it
    /// is still gets measured. Relays that asked to be left are not probed until their wait has
    /// passed. Before, the configured relays were in discovery's cut, after every relay held or
    /// offering, so minted offers left them unprobed and the clock unselected.
    pub fn probe_set(&self, last_band: &[PublicKey], heard: &[PublicKey]) -> Vec<RelayAddress> {
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
        let push = |relay: RelayAddress, into: &mut Vec<RelayAddress>| {
            if !relays.is_avoided(&relay.key, now) && !into.contains(&relay) {
                into.push(relay);
            }
        };
        let configured = || {
            relays
                .known
                .iter()
                .filter(|known| matches!(known.source, Source::Configured))
                .chain(
                    relays
                        .known
                        .iter()
                        .filter(|known| matches!(known.source, Source::Seed)),
                )
                .flat_map(Known::addresses)
        };
        // The clock's sources unheard, outside discovery's cut.
        let mut clock = relays.clock_part(heard, now);
        let probed = |relay: &RelayAddress, first: &[RelayAddress]| {
            first.iter().chain(&clock).any(|each| each.key == relay.key)
        };
        let ordered = relays
            .held
            .iter()
            .chain(&offering)
            .flat_map(find)
            .chain(configured())
            .chain(last_band.iter().flat_map(find));
        let mut first: Vec<RelayAddress> = Vec::new();
        for relay in ordered {
            if !probed(&relay, &[]) {
                push(relay, &mut first);
            }
        }
        first.truncate(MOST_PER_ROUND - RANDOM_PER_ROUND);
        // The rest of the round, at least `RANDOM_PER_ROUND`, at random among the others known.
        let mut rest: Vec<RelayAddress> = relays
            .known
            .iter()
            .flat_map(Known::addresses)
            .filter(|relay| !probed(relay, &first))
            .filter(|relay| !relays.is_avoided(&relay.key, now))
            .collect();
        while first.len() < MOST_PER_ROUND && !rest.is_empty() {
            let picked = rest.swap_remove(random_below(rest.len()));
            first.push(picked);
        }
        clock.extend(first);
        clock
    }

    /// The configured relays with no live clock sample (not in `heard`), not avoided: what a
    /// clock poll probes between rounds (`ClockPolls`), and nothing of discovery's.
    pub fn clock_set(&self, heard: &[PublicKey]) -> Vec<RelayAddress> {
        self.relays
            .lock()
            .map(|relays| relays.clock_part(heard, tokio::time::Instant::now()))
            .unwrap_or_default()
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
        let issued_ms = self.signing.now_ms();
        match sign_announcement(
            &self.identity,
            self.location,
            self.clock,
            &relays.held,
            issued_ms,
        ) {
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
/// site (`ReceiverSite`: the location as given, already snapped), under one `issued_ms`, read off
/// the clock the feeder signs by, so a relay pairs them and judges them as it judges its batches.
fn sign_announcement(
    identity: &Identity,
    location: Option<Location>,
    clock: Clock,
    relays: &[PublicKey],
    issued_ms: u64,
) -> Result<Announcement, String> {
    let error = |error: tally_wire::WireError| error.to_string();
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

    /// The session to `relay` wrote `batch` at `sent_ms`, by the clock the feeder signs by
    /// (`RelayClocks::now_ms`), which the delivery check's windows and tag keys are judged on.
    pub fn record(&self, relay: PublicKey, batch: &Batch, sent_ms: u64) {
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
                    sent_ms,
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
                    state.owe(relay, vec![kept.batch.clone()], false);
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

    /// The batches owed to `relay`'s session, oldest first; they are its to send now. What it
    /// does not send it gives back (`owe_again`).
    pub fn take_owed(&self, relay: &PublicKey) -> Vec<Batch> {
        self.state
            .lock()
            .ok()
            .and_then(|mut state| state.owed.remove(relay))
            .unwrap_or_default()
    }

    /// `rest`, taken from what was owed to `relay` (`take_owed`) and not sent (its session ended
    /// first), is owed to it again, ahead of anything owed to it since: its next session sends it,
    /// or the relay that takes its place does (`hand_owed`).
    pub fn owe_again(&self, relay: PublicKey, rest: Vec<Batch>) {
        if let Ok(mut state) = self.state.lock() {
            state.owe(relay, rest, true);
        }
    }

    /// `relay` was replaced (its session ended and it is not chosen again): what was owed to it
    /// is owed to each of `successors` instead, so no batch an audit held back is dropped with the
    /// relay it was owed to. A relay that already holds one takes it as a duplicate. With no
    /// successor it stays owed to `relay`, within its bound (`OWED_KEPT`).
    pub fn hand_owed(&self, relay: &PublicKey, successors: &[PublicKey]) {
        let handed = {
            let Ok(mut state) = self.state.lock() else {
                return;
            };
            let Some(owed) = state.owed.remove(relay) else {
                return;
            };
            let mut handed = false;
            for successor in successors.iter().filter(|successor| *successor != relay) {
                state.owe(*successor, owed.clone(), false);
                handed = true;
            }
            if !handed {
                state.owe(*relay, owed, true);
            }
            handed
        };
        if handed {
            self.owed
                .send_modify(|count| *count = count.wrapping_add(1));
        }
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

/// The most batches owed to any one relay: four audits' worth. Past it the oldest go first (the
/// network has had the longest to carry them some other way), so what a relay that keeps failing
/// is owed, or what it hands on, never grows without bound.
const OWED_KEPT: usize = 4 * SAMPLED;

impl LedgerState {
    /// `batches` owed to `relay`: ahead of what it is owed already when `first` (given back,
    /// oldest), else after; then the oldest past [`OWED_KEPT`] let go. Every owed list is made
    /// here, so none passes its bound.
    fn owe(&mut self, relay: PublicKey, mut batches: Vec<Batch>, first: bool) {
        if batches.is_empty() {
            return;
        }
        let owed = self.owed.entry(relay).or_default();
        if first {
            batches.append(owed);
            *owed = batches;
        } else {
            owed.append(&mut batches);
        }
        let over = owed.len().saturating_sub(OWED_KEPT);
        owed.drain(..over);
    }

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
#[derive(Debug, PartialEq, Eq)]
pub enum Outcome {
    /// Try the same relay again, after at least this long.
    Retry(Duration),
    /// The relay asked to be left (a redirect, or a goodbye because it is full, leaving, or
    /// refusing): a declaration, never swallowing.
    Leave(Duration),
}

/// What the publisher does at once when a session ends ([`after`]).
#[derive(Debug, PartialEq, Eq)]
enum Next {
    /// The same relay again, waiting at least `wait`.
    Redial { wait: Duration },
    /// The relay asked to be left: avoided for `avoid`, another in its place if one can take it.
    Leave { avoid: Duration },
}

/// The least a feeder waits before dialling again a relay of an older version that refused it for
/// its clock: the protocol's (`tally_wire::batch::CLOCK_RETRY_SECS`), never less, so a relay that
/// says to come back at once (`retry_after_secs` 0) is not redialled about once a second for ever.
pub const CLOCK_RETRY: Duration = Duration::from_secs(tally_wire::batch::CLOCK_RETRY_SECS as u64);

/// How long after a session ends the publisher waits to see whether the feeder's other sessions
/// stayed up before it holds the end against its relay: a heartbeat and a dial's timeout, about how
/// far apart a flap of the feeder's own network ends every session it holds (each notices at its
/// next heartbeat or read).
const ENDED_TOGETHER: Duration =
    Duration::from_secs(HEARTBEAT.as_secs() + CONNECT_TIMEOUT.as_secs());
/// How long the publisher waits on a relay's ends: the protocol's waits
/// (`Pacing::default()`), and a test's shorter ones over loopback relays.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Pacing {
    /// The least wait before a relay that ended a session for its clock is dialled again
    /// ([`CLOCK_RETRY`]).
    pub clock_retry: Duration,
    /// How long an end waits to be judged against its relay ([`ENDED_TOGETHER`], [`Ends`]).
    pub ended_together: Duration,
}

impl Default for Pacing {
    fn default() -> Self {
        Self {
            clock_retry: CLOCK_RETRY,
            ended_together: ENDED_TOGETHER,
        }
    }
}

/// Sessions in a row held against a relay ([`Ends`]) that replace it.
const SHORT_IN_A_ROW: u32 = 2;
// An end is judged before a healthy session after it can end, so "in a row" is in order.
const _: () = assert!(ENDED_TOGETHER.as_secs() < HEALTHY_SESSION.as_secs());

/// How far a session got: whether it reached its relay (a connection was made; a dial that
/// failed or timed out did not), and how long it was up (none if it never was).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Span {
    reached: bool,
    up_for: Option<Duration>,
}

impl Span {
    /// A session that reached its relay and ended before it was up `HEALTHY_SESSION`: a refused
    /// handshake, a goodbye, a cut, whatever the reason.
    fn short(self) -> bool {
        self.reached && self.up_for.is_none_or(|up| up < HEALTHY_SESSION)
    }
}

/// Whether a session up for `up_for` counts as healthy (its backoff reset, and the relay's run of
/// ends held against it cleared): up long enough to have had its batches taken
/// (`HEALTHY_SESSION`), and its relay neither found swallowing them nor ending it while it was
/// audited (`failed`), however long it stayed.
fn healthy(up_for: Option<Duration>, failed: bool) -> bool {
    !failed && up_for.is_some_and(|up| up >= HEALTHY_SESSION)
}

/// What follows a session's end at once: a relay that asked to be left is avoided and replaced;
/// any other end is dialled again, after at least what it asked. Whether an end counts against
/// its relay is judged later, by [`Ends`], once the feeder's other sessions show whether it was
/// the relay's or the feeder's own network.
fn after(ended: &Result<Outcome, String>) -> Next {
    match ended {
        Ok(Outcome::Leave(wait)) => Next::Leave { avoid: *wait },
        Ok(Outcome::Retry(wait)) => Next::Redial { wait: *wait },
        Err(_) => Next::Redial {
            wait: Duration::ZERO,
        },
    }
}

/// The ends the publisher holds against relays (RFC-0171 §3.6). A session that reached its relay
/// and ended short ([`Span::short`]), or ended while its relay was audited (it dodged the audit),
/// waits `ENDED_TOGETHER`, then counts against its relay only if a session to another relay that
/// was up when it ended is up still, the same session: then the feeder's network was fine and the
/// end was the relay's. When every live session ends together (the feeder's own network flapped),
/// or the feeder held no other, nobody is blamed. `SHORT_IN_A_ROW` held in a row replace the
/// relay; a healthy session clears its run. A dial that never reached the relay (an honest relay
/// restarting refuses connections) counts against nobody: a relay that stops answering is
/// replaced by the rounds, which count it silent (`selection::FAILED_ROUNDS`). As the rounds'
/// "a round that heard nothing blames no one", one network's failure is never a relay's.
#[derive(Debug)]
struct Ends {
    in_a_row: HashMap<PublicKey, u32>,
    pending: Vec<Pending>,
    /// How long an end waits to be judged (`Pacing::ended_together`).
    together: Duration,
}

impl Default for Ends {
    fn default() -> Self {
        Self::new(ENDED_TOGETHER)
    }
}

/// An end waiting to be judged: its relay, when it ended, and the sessions (relay, generation) up
/// to other relays then.
#[derive(Debug)]
struct Pending {
    relay: PublicKey,
    at: tokio::time::Instant,
    others: Vec<(PublicKey, u64)>,
}

impl Ends {
    fn new(together: Duration) -> Self {
        Self {
            in_a_row: HashMap::new(),
            pending: Vec::new(),
            together,
        }
    }

    /// `relay`'s session ended at `at`: `held` when it is an end to judge (short, or dodging an
    /// audit), `healthy` when it clears the relay's run; `others` the sessions up then to other
    /// relays.
    fn ended(
        &mut self,
        relay: PublicKey,
        at: tokio::time::Instant,
        (held, healthy): (bool, bool),
        others: Vec<(PublicKey, u64)>,
    ) {
        if healthy {
            self.in_a_row.remove(&relay);
        }
        if held {
            self.pending.push(Pending { relay, at, others });
        }
    }

    /// When the next end is due to be judged.
    fn next_due(&self) -> Option<tokio::time::Instant> {
        self.pending
            .iter()
            .map(|pending| pending.at + self.together)
            .min()
    }

    /// Judges the ends due by `now`, oldest first, given which sessions are up now (`up`, by
    /// relay and generation): the relays whose run reached `SHORT_IN_A_ROW`, to replace.
    fn judge(
        &mut self,
        now: tokio::time::Instant,
        up: impl Fn(&(PublicKey, u64)) -> bool,
    ) -> Vec<PublicKey> {
        self.pending.sort_by_key(|pending| pending.at);
        let due = self
            .pending
            .iter()
            .take_while(|pending| pending.at + self.together <= now)
            .count();
        let mut replace = Vec::new();
        for pending in self.pending.drain(..due) {
            // Nobody stayed up: the feeder's own network, which blames no one.
            if !pending.others.iter().any(&up) {
                continue;
            }
            let run = self.in_a_row.entry(pending.relay).or_insert(0);
            *run += 1;
            if *run >= SHORT_IN_A_ROW {
                self.in_a_row.remove(&pending.relay);
                replace.push(pending.relay);
            }
        }
        replace
    }
}

/// What a running session and the background work tell the publisher.
enum Event {
    Probed(Vec<Probed>),
    /// A clock poll's answers (`Publisher::clock_poll`): clock samples, and the relays they
    /// name, but no round's measure to choose by.
    ClockPolled(Vec<Probed>),
    Up {
        relay: PublicKey,
        generation: u64,
    },
    Ended {
        relay: PublicKey,
        generation: u64,
        ended: Result<Outcome, String>,
        span: Span,
    },
    Answers {
        query: DeliveryQuery,
        answers: Vec<(u32, DeliveryAnswer)>,
    },
}

/// Everything the publisher works from.
pub struct Publishing {
    pub directory: Arc<Directory>,
    pub identity: Arc<Identity>,
    pub batches: broadcast::Sender<Arc<Record>>,
    /// The owner's ceiling, bytes a second.
    pub ceiling: u32,
    /// The wanted receptions a second the relays state, which the batcher sheds to: each session
    /// states its relay's (`source::WantedCeilings`).
    pub wanted: Arc<WantedCeilings>,
    /// The clocks the relays state, which the batcher signs by: each session states its relay's
    /// (`source::RelayClocks`).
    pub clocks: Arc<RelayClocks>,
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
    /// How long it waits on a relay's ends: `Pacing::default()`.
    pub pacing: Pacing,
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
    identity: Arc<Identity>,
    batches: broadcast::Sender<Arc<Record>>,
    ceiling: u32,
    wanted: Arc<WantedCeilings>,
    clocks: Arc<RelayClocks>,
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
    /// The ends held against relays, waiting to be judged ([`Ends`]).
    ends: Ends,
    pacing: Pacing,
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
        clocks: publishing.clocks,
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
        ends: Ends::new(publishing.pacing.ended_together),
        pacing: publishing.pacing,
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
    // The clocks asked for a probe of their unheard configured relays (`RelayClocks::probing`),
    // and none is out: a clock poll runs once one is due (`ClockPolls`).
    let mut clock_wanted = false;
    let mut clock_polling = false;
    let mut polls = ClockPolls::default();
    let clocks = Arc::clone(&publisher.clocks);
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
            // The clocks make no majority while a configured relay is unheard: that relay is
            // polled for its clock on its own interval, and nothing of discovery's round is.
            () = clocks.probing() => clock_wanted = true,
            _ = sleep_until(polls.next().or(Some(tokio::time::Instant::now()))),
                if clock_wanted && !clock_polling => {
                let heard = publisher.clocks.heard();
                let unheard = publisher.directory.clock_set(&heard);
                if unheard.is_empty() {
                    clock_wanted = false;
                }
                let due = polls.due(unheard, tokio::time::Instant::now());
                if !due.is_empty() {
                    clock_wanted = false;
                    clock_polling = true;
                    publisher.clock_poll(due);
                }
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
                let answered = matches!(event, Event::Probed(_) | Event::ClockPolled(_));
                let probed = matches!(event, Event::Probed(_));
                if matches!(event, Event::ClockPolled(_)) {
                    clock_polling = false;
                }
                publisher.handle(event);
                if answered {
                    polls.answered(&publisher.clocks.heard());
                }
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
            // An end held against a relay is judged once the feeder's other sessions have had
            // time to show whether the feeder's own network failed (`Ends`).
            _ = sleep_until(publisher.ends.next_due()), if publisher.ends.next_due().is_some() => {
                publisher.judge_ends();
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
        let candidates = self
            .directory
            .probe_set(&self.last_band, &self.clocks.heard());
        let identity = self.identity.clone();
        let clocks = Arc::clone(&self.clocks);
        let events = self.events.clone();
        let prober = self.prober;
        self.tasks.spawn(async move {
            let mut probes = JoinSet::new();
            for relay in candidates {
                probes.spawn(prober(relay, identity.clone(), Arc::clone(&clocks)));
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

    /// Probes `due` (configured relays with no live clock sample, `ClockPolls::due`) for their
    /// clocks alone, and reports what came back: no round of discovery's, and no choice made by
    /// what so few answered.
    fn clock_poll(&mut self, due: Vec<RelayAddress>) {
        let identity = self.identity.clone();
        let clocks = Arc::clone(&self.clocks);
        let events = self.events.clone();
        let prober = self.prober;
        self.tasks.spawn(async move {
            let mut probes = JoinSet::new();
            for relay in due {
                probes.spawn(prober(relay, identity.clone(), Arc::clone(&clocks)));
            }
            let mut probed = Vec::new();
            while let Some(done) = probes.join_next().await {
                if let Ok(Ok(result)) = done {
                    probed.push(result);
                }
            }
            let _ = events.send(Event::ClockPolled(probed)).await;
        });
    }

    /// Each probe answer's clock told to the clocks (a configured relay's is a source,
    /// `RelayClocks::probed`), and the relays it named learned.
    fn heard_probes(&mut self, probed: &[Probed]) {
        for each in probed {
            self.directory.learn(each.measured.relay.key, &each.hints);
            if let Some(clock) = &each.clock {
                self.clocks.probed(
                    each.measured.relay.key,
                    (clock.asked_ms, clock.took_ms, clock.sent_ms),
                    clock.error_ms,
                    clock.heard_ms,
                );
            }
        }
    }

    /// The members of the feeder's area to ask about batches sent to `checked`: those given the
    /// key in force now.
    fn members(&self, checked: &[PublicKey]) -> Vec<delivery_check::Member> {
        let Some(area) = self.area else {
            return Vec::new();
        };
        let now = self.clocks.now_ms();
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
        let now = self.clocks.now_ms();
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
        let now = self.clocks.now_ms();
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
        let Some(query) = self.checker.sample_at(&recent, self.clocks.now_ms()) else {
            self.checker.abandon();
            return;
        };
        let members = self.members(&self.checker.checked_relays());
        if members.is_empty() {
            self.checker.abandon();
            return;
        }
        // Each member's query carries its keys again: an ask looks like a grant.
        let now = self.clocks.now_ms();
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
            Event::ClockPolled(probed) => self.heard_probes(&probed),
            Event::Probed(probed) => {
                self.heard_probes(&probed);
                let mut measured: Vec<Measured> = Vec::new();
                for each in probed {
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
                self.apply(&choice, false, None);
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
                span,
            } => self.ended(relay, generation, ended, span),
            Event::Answers { query, answers } => {
                if let Verdict::Swallowed(swallowers) =
                    self.checker
                        .judge_at(&query, &answers, self.clocks.now_ms())
                {
                    for swallower in swallowers {
                        eprintln!(
                            "tally-feed: relay {swallower} did not deliver this feeder's batches \
                             to its area; leaving it for {} days",
                            delivery_check::AVOID_FOR.as_secs() / 86_400
                        );
                        let choice = self.selection.left(&swallower);
                        self.apply(&choice, true, None);
                    }
                }
            }
        }
    }

    /// Relays not to choose: those remembered as swallowing, and those that asked to be left.
    fn avoid(&self) -> Vec<PublicKey> {
        let mut avoid = self.checker.avoided_at(self.clocks.now_ms());
        avoid.extend(self.directory.avoided());
        avoid
    }

    fn ended(
        &mut self,
        relay: PublicKey,
        generation: u64,
        ended: Result<Outcome, String>,
        span: Span,
    ) {
        let Some(mut running) = self
            .sessions
            .remove(&relay)
            .filter(|running| running.generation == generation)
        else {
            return;
        };
        self.live(relay, false);
        // An audit of the relay in progress says nothing of it now, and the end dodged it.
        let dodged = self.checker.session_ended(relay);
        let healthy = healthy(
            span.up_for,
            dodged
                || self
                    .checker
                    .avoided_at(self.clocks.now_ms())
                    .contains(&relay),
        );
        let others = self
            .ledger
            .live_relays()
            .into_iter()
            .filter(|other| *other != relay)
            .filter_map(|other| {
                self.sessions
                    .get(&other)
                    .map(|running| (other, running.generation))
            })
            .collect();
        self.ends.ended(
            relay,
            tokio::time::Instant::now(),
            (span.short() || dodged, healthy),
            others,
        );
        if healthy {
            running.backoff.reset();
        }
        if let Err(error) = &ended {
            eprintln!("tally-feed: relay {}: {error}", running.relay.address);
        }
        let choice = match after(&ended) {
            Next::Redial { wait } => {
                running.backoff.at_least(wait);
                self.redial(running);
                return;
            }
            Next::Leave { avoid } => {
                self.directory.avoid(&relay, avoid);
                self.selection.failed(&relay)
            }
        };
        self.replaced(relay, Some(running), &choice);
    }

    /// Judges the ends due ([`Ends::judge`]): a relay whose run of ends held against it is long
    /// enough is replaced, if another can take its place.
    fn judge_ends(&mut self) {
        let live = self.ledger.live_relays();
        let sessions = &self.sessions;
        let replace = self
            .ends
            .judge(tokio::time::Instant::now(), |(relay, generation)| {
                live.contains(relay)
                    && sessions
                        .get(relay)
                        .is_some_and(|running| running.generation == *generation)
            });
        for relay in replace {
            eprintln!(
                "tally-feed: relay {relay} ended {SHORT_IN_A_ROW} sessions in a row short while \
                 others stayed up; replacing it"
            );
            let choice = self.selection.failed(&relay);
            self.replaced(relay, None, &choice);
        }
    }

    /// Follows `choice` after `relay` was replaced: its place to another and what it was owed with
    /// it, or, with no other to take it, the same relay again (`running`, if its session ended, at
    /// the backoff's pace).
    fn replaced(&mut self, relay: PublicKey, running: Option<Running>, choice: &Choice) {
        if choice.keys().contains(&relay) {
            // No other relay can take its place: the same one again, at the backoff's pace (its
            // session, if one is running, goes on).
            if let Some(running) = running {
                self.redial(running);
            }
            self.apply(choice, true, None);
        } else {
            self.apply(choice, true, Some(relay));
        }
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
    /// (after a jitter when they take a failed relay's place). What was owed to a relay whose
    /// session ends here, or to `replaced` (one whose session already ended and is not chosen
    /// again), goes to the relays started in their place, or, if none is, to every relay chosen
    /// (`Ledger::hand_owed`): no batch an audit owed is dropped with the relay it was owed to.
    fn apply(&mut self, choice: &Choice, failover: bool, replaced: Option<PublicKey>) {
        let wanted = choice.keys();
        let mut gone: Vec<PublicKey> = self
            .sessions
            .keys()
            .filter(|key| !wanted.contains(key))
            .copied()
            .collect();
        for key in &gone {
            if let Some(running) = self.sessions.remove(key) {
                running.task.abort();
                self.live(*key, false);
            }
        }
        gone.extend(replaced.filter(|relay| !wanted.contains(relay)));
        let mut started = Vec::new();
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
            started.push(relay.key);
            self.start(relay, wait, Backoff::new());
        }
        let successors = if started.is_empty() {
            &wanted
        } else {
            &started
        };
        for relay in gone {
            self.ledger.hand_owed(&relay, successors);
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
            clocks: Arc::clone(&self.clocks),
            source_address: self.source_address,
            clock_retry: self.pacing.clock_retry,
            health: Arc::clone(&self.health),
        };
        let identity = self.identity.clone();
        let batches = self.batches.subscribe();
        let events = self.events.clone();
        let task = self.tasks.spawn(async move {
            tokio::time::sleep(wait).await;
            let key = context.relay.key;
            let (ended, span) = session(&context, &identity, batches, || {
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
                    span,
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
    /// The relays' clocks the batcher signs by: this session's statement is one.
    clocks: Arc<RelayClocks>,
    /// The local address to connect from (`Publishing::source_address`).
    source_address: Option<IpAddr>,
    /// The least wait after a clock goodbye (`Pacing::clock_retry`).
    clock_retry: Duration,
    /// Told of the batches this session was too slow for (`Health::lagged`).
    health: Arc<Health>,
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

/// One session with a relay: how it ended, and how far it got ([`Span`]).
async fn session(
    context: &Context,
    identity: &Identity,
    batches: broadcast::Receiver<Arc<Record>>,
    up: impl FnOnce(),
) -> (Result<Outcome, String>, Span) {
    let relay = &context.relay;
    let stream = match tokio::time::timeout(
        CONNECT_TIMEOUT,
        dial(&relay.address, context.source_address),
    )
    .await
    {
        Ok(Ok(stream)) => stream,
        Ok(Err(error)) => return (Err(error.to_string()), Span::default()),
        Err(_) => return (Err("connect timed out".to_owned()), Span::default()),
    };
    // Connected: whatever ends the session from here reached the relay.
    let reached = Span {
        reached: true,
        up_for: None,
    };
    // The relay states its clock in its greeting, once the handshake is done: how long that took
    // from the Hello is the uncertainty of the statement (`Telling::stated`), stamped on the
    // anchored clock (the raw monotonic one), never `Instant`, which a daemon slews.
    let hello = context.clocks.stamp_ms();
    let session = match noise::connect(stream, identity, &relay.key, Role::Feeder).await {
        Ok(session) => session,
        Err(tally_wire::WireError::Refused {
            reason,
            retry_after_secs,
        }) => {
            return (
                Ok(goodbye(reason, retry_after_secs, context.clock_retry)),
                reached,
            );
        }
        Err(error) => return (Err(error.to_string()), reached),
    };
    // Refused before it counts as up: an older relay is no session.
    if let Some(outcome) = context.directory.refuse_old_relay(relay, session.version) {
        return (Ok(outcome), reached);
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
    let ended = publish(
        context,
        session.version,
        hello,
        &mut writer,
        &mut records,
        batches,
    )
    .await;
    reading.abort();
    (
        ended,
        Span {
            reached: true,
            up_for: Some(began.elapsed()),
        },
    )
}

/// How fast one relay session sends what the batcher sealed: every batch, in order, never one
/// skipped, each waiting for its bytes' turn. The pace is the owner's ceiling, as the batcher
/// signs at it (`source::signed_most`: its receptions and each batch's own bytes), so a backlog an
/// anchor's return releases at once goes out at the ceiling, never over it, and a session sends at
/// least as fast as the batcher signs, so the backlog drains within its budget
/// (`tally_wire::budget::BACKLOG_DRAIN`). A relay that asked for less gets a pace at its rate,
/// deep enough that a whole batch always fits: its batches wait longer, and what it cannot keep up
/// with lags behind in the sessions' channel (`RecvError::Lagged`, counted and reported).
///
/// The wanted receptions a second the relay states with it are the batcher's to keep to
/// (`source::WantedCeilings`): a batch is signed once for every relay, so what is past them is shed
/// before it is signed, never skipped here. What this session stated goes when it ends.
pub(crate) struct Pace {
    ceiling: u32,
    bucket: TokenBucket,
    /// The rate and burst the relay last stated, which `bucket` holds to.
    told: Option<(u32, u32)>,
    wanted: Stating,
    /// The relay's clock as this session measures it (`source::Telling`): a source the batcher
    /// signs by when the relay is configured, and what the health reports this feeder's clock
    /// against. Never what decides a send, and never what decides the relay's fate.
    clock: Option<Telling>,
    /// When the session sent its Hello, which a statement's uncertainty runs from: the anchored
    /// clock (`RelayClocks::stamp_ms`).
    hello: u64,
    /// The relay restated its clock (`Telling::stated`): the session asks it for an echo at once,
    /// which measures it by its own round trip.
    asking: bool,
}

/// The pace of a session whose relay asks no less than the owner's `ceiling`: what the batcher
/// signs a second at it (`source::signed_most`), a second of it at once, and never less than a
/// whole batch.
fn at_ceiling(ceiling: u32) -> TokenBucket {
    let rate = crate::source::signed_most(ceiling);
    TokenBucket::with_burst(rate, rate.max(BURST_FLOOR))
}

impl Pace {
    pub(crate) fn new(ceiling: u32, wanted: Stating) -> Self {
        Self {
            ceiling,
            bucket: at_ceiling(ceiling),
            told: None,
            wanted,
            clock: None,
            hello: 0,
            asking: false,
        }
    }

    /// The same pace, its relay's clock measured into `clock`, the session's Hello sent at
    /// `hello`.
    fn telling(self, clock: Telling, hello: u64) -> Self {
        Self {
            clock: Some(clock),
            hello,
            ..self
        }
    }

    /// A relay's `RateLimit`. One at or over what the batcher signs a second at the owner's
    /// ceiling asks for nothing the ceiling's pace does not already keep to. One stating the rate
    /// it already holds (a relay states it again with its clock, `clock`) keeps the bucket as it
    /// is, its tokens spent. A rate of 0 is taken as the least there is, so a batch still goes.
    fn limit(&mut self, bytes_per_sec: u32, burst: u32, wanted_per_sec: Option<u32>) {
        if self.told != Some((bytes_per_sec, burst)) {
            self.told = Some((bytes_per_sec, burst));
            self.bucket = if bytes_per_sec < crate::source::signed_most(self.ceiling) {
                TokenBucket::with_burst(bytes_per_sec.max(1), burst.max(BURST_FLOOR))
            } else {
                at_ceiling(self.ceiling)
            };
        }
        self.wanted.state(wanted_per_sec);
    }

    /// A relay's stated clock and its error (`RateLimit`'s `clock_ms` and `error_ms`), heard now.
    /// A restatement (any after the first) is no sample of its own, its one-way time unbounded:
    /// the session asks for an echo at once (`asking`).
    fn clock(&mut self, clock_ms: Option<u64>, error_ms: Option<u64>) {
        if let Some(telling) = &self.clock
            && telling.stated(clock_ms, error_ms, self.hello)
        {
            self.asking = true;
        }
    }

    /// A relay's freshness anchor (RFC-0171 §3.6): this session's newest, for the batcher to sign
    /// into its batches (`source::Telling::anchored`).
    fn anchored(&self, anchor: tally_wire::Anchor) {
        if let Some(telling) = &self.clock {
            telling.anchored(anchor);
        }
    }

    /// A relay's answer to a timed heartbeat (`times`): measured, when it echoes one.
    fn echoed(&self, times: tally_wire::HeartbeatTimes) {
        if let (Some(telling), Some((asked, took))) = (&self.clock, times.echo) {
            telling.echoed(asked, took, times.sent_ms, times.error_ms);
        }
    }

    /// The timed heartbeat this session sends now: its own clock for the relay to echo.
    fn heartbeat(&self) -> Record {
        match &self.clock {
            Some(telling) => {
                Record::TimedHeartbeat(tally_wire::HeartbeatTimes::asking(telling.asking_ms()))
            }
            None => Record::Heartbeat,
        }
    }

    /// How long a batch of `bytes` waits from `now` before it goes to this relay: none when it
    /// may go now, its bytes then taken from the pace. Asked again once the wait is over.
    pub(crate) fn wait(&mut self, bytes: usize, now: Instant) -> Duration {
        self.bucket.wait_at(bytes, now)
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

    /// Waits for a batch of `bytes` to have its turn at the session's pace (`Pace::wait`), hearing
    /// the relay meanwhile; `Some` if the relay ended the session while it waited.
    async fn paced(&mut self, bytes: usize) -> Result<Option<Outcome>, String> {
        loop {
            let wait = self.pace.wait(bytes, Instant::now());
            if wait.is_zero() {
                return Ok(None);
            }
            tokio::select! {
                () = tokio::time::sleep(wait) => {}
                got = self.records.recv() => {
                    if let Some(outcome) = heard(self.context, &mut self.pace, got)? {
                        return Ok(Some(outcome));
                    }
                }
            }
        }
    }

    /// Sends what an ended audit owes this relay (`Ledger::end_audit`): batches the audited relay
    /// did not carry, which this session held back. Few, so they go whatever the relay's pace.
    /// Held back for the audit's length on top of any wait, and sent all the same: the relay
    /// judges whether it can still use each, and holds it either way. If the session ends before
    /// they are all sent, the rest, the one cut short among them, are owed to the relay still
    /// (`Ledger::owe_again`): its next session sends them, or the relay that takes its place does.
    async fn send_owed(&mut self) -> Result<Option<Outcome>, String> {
        let relay = self.context.relay.key;
        let mut owed = self.context.ledger.take_owed(&relay).into_iter();
        while let Some(batch) = owed.next() {
            let record = Arc::new(Record::Batch(batch.clone()));
            let sent = self.send(&[record]).await;
            if !matches!(sent, Ok(None)) {
                self.context
                    .ledger
                    .owe_again(relay, std::iter::once(batch).chain(owed).collect());
                return sent;
            }
            self.context
                .ledger
                .record(relay, &batch, self.context.clocks.now_ms());
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
                clock_ms,
                error_ms,
            } => {
                pace.limit(bytes_per_sec, burst, wanted_per_sec);
                pace.clock(clock_ms, error_ms);
            }
            Record::TimedHeartbeat(times) => pace.echoed(times),
            Record::Anchor(anchor) => pace.anchored(anchor),
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
            } => return Ok(Some(goodbye(reason, retry_after_secs, context.clock_retry))),
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
    hello: u64,
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
        pace: Pace::new(context.ceiling, context.wanted.session())
            .telling(context.clocks.session(relay.key), hello),
    };
    let mut info = directory.info();
    let mut owed = context.ledger.owed_changes();
    let mut first = info.borrow_and_update().records();
    first.extend(ask_offers(context).map(Arc::new));
    if let Some(outcome) = link.send(&first).await? {
        return Ok(outcome);
    }
    // A relay speaks first to a feeder: the rate it takes and the clock it judges a batch by
    // (`RateLimit`), perhaps heard already while the first records went. No batch goes before
    // that is heard, so the first goes at the rate the relay takes, and is signed by the clock it
    // stated if the relay is a configured source. A timed heartbeat then asks for the
    // relay's clock by echo, so it is measured at once rather than a heartbeat later.
    if let Some(outcome) = link.send(&[link.pace.heartbeat()]).await? {
        return Ok(outcome);
    }
    while link.pace.told.is_none() {
        if let Some(outcome) = heard(context, &mut link.pace, link.records.recv().await)? {
            return Ok(outcome);
        }
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
                    // Not this relay's to take: not sent. Whatever its clock, one that is goes,
                    // at its turn.
                    if !context.ledger.routes(&relay.key, signed) {
                        None
                    } else if let Some(outcome) = link.paced(signed.as_bytes().len()).await? {
                        Some(outcome)
                    } else {
                        let ended = link.send(&[Arc::clone(&batch)]).await?;
                        if ended.is_none() {
                            context.ledger.record(relay.key, signed, context.clocks.now_ms());
                        }
                        ended
                    }
                }
                // Batches this session could not keep up with are gone; gaps say so, and the
                // health counts them.
                Err(broadcast::error::RecvError::Lagged(count)) => {
                    lagged += count;
                    context.health.lagged(count);
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
            _ = heartbeat.tick() => {
                let beat = link.pace.heartbeat();
                link.send(&[beat]).await?
            }
            _ = refresh.tick() => {
                let mut out: Vec<Arc<Record>> = directory
                    .resign()
                    .map(|latest| latest.records())
                    .unwrap_or_default();
                out.extend(ask_offers(context).map(Arc::new));
                if out.is_empty() { None } else { link.send(&out).await? }
            }
            _ = report.tick() => {
                if lagged > 0 {
                    eprintln!(
                        "tally-feed: relay {}: {lagged} batches it was too slow for were not sent \
                         to it",
                        relay.address
                    );
                    lagged = 0;
                }
                if let Some(off) = link.pace.clock.as_ref().and_then(Telling::disagreement_ms) {
                    eprintln!("tally-feed: {}", disagreeing(&relay.address, off));
                }
                None
            }
            got = link.records.recv() => heard(context, &mut link.pace, got)?,
        };
        if let Some(outcome) = ended {
            return Ok(outcome);
        }
        // A restated clock is measured by an echo of its own round trip, asked at once.
        if std::mem::take(&mut link.pace.asking) {
            let beat = link.pace.heartbeat();
            if let Some(outcome) = link.send(&[beat]).await? {
                return Ok(outcome);
            }
        }
    }
}

/// What the feeder says when its clock is `off_ms` outside the clock of the relay at `relay`
/// (`Telling::disagreement_ms`): positive ahead of it.
pub fn disagreeing(relay: &str, off_ms: i64) -> String {
    let secs = off_ms.unsigned_abs().div_ceil(1_000);
    let way = if off_ms > 0 { "ahead of" } else { "behind" };
    format!(
        "your clock disagrees with relay {relay} by {secs} s ({way} it); every batch is still \
         sent, and the relay judges whether it can use it"
    )
}

/// What the health says of a relay `relay` whose freshness anchor was `off_ms` outside the
/// feeder's trusted reference as it heard it (positive below it, negative above it), more than an
/// honest relay's can be (RFC-0171 §3.6, `tally_wire::budget::anchor_outside`).
pub fn anchor_disagreeing(relay: &str, off_ms: i64) -> String {
    let secs = off_ms.unsigned_abs().div_ceil(1_000);
    let way = if off_ms > 0 { "behind" } else { "ahead of" };
    format!(
        "relay {relay}'s anchor disagrees with your reference (your configured relays, or this \
         host synced) by {secs} s ({way} it); its anchors are left out of your batches"
    )
}

/// What the health says while the feeder has carried no anchor for `secs` seconds and has signed
/// `unanchored` batches with none since it started: no relay can use them (RFC-0171 §3.6).
pub fn anchorless(secs: u64, unanchored: u64) -> String {
    format!(
        "carrying no anchor for {secs}s, data unusable at every relay ({unanchored} batches \
         signed unanchored); a relay states one while its clock is synced"
    )
}

/// `wait` with the backoff's jitter, so feeders started together do not check together.
fn jittered(wait: Duration) -> Duration {
    let mut backoff = Backoff::new();
    backoff.at_least(wait);
    backoff.wait()
}

/// A relay closing a session or refusing one. Full, leaving or refusing is "leave me": the relay
/// declared it will not carry this feeder now. Anything else is retried, an older relay's clock
/// refusal among it.
fn goodbye(reason: Reason, retry_after_secs: u32, clock_retry: Duration) -> Outcome {
    let wait = Duration::from_secs(retry_after_secs.into());
    match reason {
        Reason::Full | Reason::Leaving | Reason::Refused => Outcome::Leave(wait),
        // No relay of this version sends it (RFC-0171 §3.6): an older one's, or one minted to
        // say it, is retried like any other end, after at least the protocol's minute; a short
        // session ended so is held against its relay like any short session (`Ends`).
        Reason::Clock => Outcome::Retry(wait.max(clock_retry)),
        _ => Outcome::Retry(wait),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::source::{Batcher, wall_ms};

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
            (Clock::Dump1090, Arc::default()),
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
            (Clock::Dump1090, Arc::default()),
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
            (Clock::Dump1090, Arc::default()),
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

    /// Everything the feeder signs or judges against a relay's clock but its batches goes by the
    /// clock its batches are signed by (`RelayClocks::now_ms`): a host an hour ahead whose one
    /// seed is heard at true time issues its description and site at true time, so no relay's
    /// credit refuses them as an hour ahead, and judges an offer's expiry by true time, so it
    /// keeps one alive for ten minutes more. Before, both read the host's own clock: the
    /// description was issued an hour ahead and the offer taken for expired.
    #[test]
    fn a_host_an_hour_ahead_signs_and_judges_by_the_selected_clock() -> Result<(), String> {
        const HOUR: u64 = 3_600_000;
        let error = |error: tally_wire::WireError| error.to_string();
        let real = wall_ms();
        let wall = Arc::new(std::sync::atomic::AtomicU64::new(real + HOUR));
        let monotonic = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let seed = Identity::from_seed([61; 32]).public();
        let clocks = Arc::new(
            RelayClocks::on(crate::source::HostClock::set_by(&wall, &monotonic)).configured([seed]),
        );
        let directory = Directory::new(
            scratch(),
            Vec::new(),
            Vec::new(),
            Identity::generate().map_err(|error| error.to_string())?,
            Some(SITE),
            (Clock::Dump1090, Arc::clone(&clocks)),
        )?;
        let issued = |announcement: &Announcement| -> Result<u64, String> {
            let Record::ReceiverInfo(info) = &*announcement.info else {
                return Err("no description".into());
            };
            info.issued_ms().map_err(error)
        };
        // Nothing heard: the host's clock as read is all there is.
        assert_eq!(issued(&directory.info().borrow())?, real + HOUR);
        let heard = clocks.session(seed);
        let asked = heard.asking_ms();
        heard.echoed(asked, real, real, Some(0));
        let latest = directory.resign().ok_or("not signed")?;
        let at = issued(&latest)?;
        assert!(
            at <= real && at + 1_000 >= real,
            "issued at {at}, true time {real}"
        );
        let Some(Record::ReceiverSite(site)) = latest.site.as_deref() else {
            return Err("no site".into());
        };
        assert_eq!(site.content().map_err(error)?.issued_ms, at);
        // An offer alive for ten minutes by true time, expired by the host's clock: kept.
        let provider = Identity::from_seed([62; 32]);
        let offer = ProviderOffer::sign(
            &provider,
            &tally_wire::directory::ProviderOfferContent {
                address: "provider.example:10900".to_owned(),
                cell: Region::containing(&SITE, 0).map_err(error)?,
                products: Streams::RAW,
                stripes_of: 1,
                stripes: 1,
                mlat_cores: 0,
                feeder_slots: 1,
                network: 0,
                issued_ms: real,
                expires_ms: real + 600_000,
            },
        )
        .map_err(error)?;
        directory.offered(seed, offer);
        assert_eq!(directory.offers().len(), 1);
        drop(heard);
        Ok(())
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
            .probe_set(&[], &[])
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
            .probe_set(&[], &[])
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
            .probe_set(&[], &[])
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
        // Unheard, the owner's relays are the clock's sources, probed beside discovery's round.
        let set = directory.probe_set(&[], &[]);
        assert_eq!(set.len(), 2 + MOST_PER_ROUND);
        assert_eq!(set[..2], owner[..]);
        // Heard, they take discovery's first places, within its round.
        let heard: Vec<PublicKey> = owner.iter().map(|relay| relay.key).collect();
        let set = directory.probe_set(&[], &heard);
        assert_eq!(set.len(), MOST_PER_ROUND);
        assert_eq!(set[..2], owner[..]);
        // Asked to leave, the owner's relay is not probed until its wait has passed.
        directory.avoid(&owner[0].key, Duration::from_secs(600));
        assert!(
            !directory
                .probe_set(&[], &[])
                .iter()
                .any(|relay| relay.key == owner[0].key)
        );
        Ok(())
    }

    /// The round 13 sweep's probe, over the number of offers: every configured relay unheard (the
    /// owner's) is probed in every round however many relays offer the feeder's area, each a key
    /// minted for it. They are the clock's sources, probed outside discovery's cut. Before, they
    /// came after every relay held or offering in that cut, and twenty minted offers left them out
    /// of most rounds.
    #[test]
    fn no_number_of_offers_lowers_how_often_configured_relays_are_probed() -> Result<(), String> {
        let owner = relays("owner", 2)?;
        let mut rates = Vec::new();
        for offers in [0usize, 1, 5, 13, 20, 40, 100] {
            let directory = Directory::new(
                scratch(),
                owner.clone(),
                Vec::new(),
                Identity::generate().map_err(|error| error.to_string())?,
                Some(Location {
                    lat_e7: 0,
                    lon_e7: 0,
                    alt_m: 0,
                    precision_m: 1_000,
                }),
                (Clock::Dump1090, Arc::default()),
            )?;
            let hinter = key()?;
            let now = wall_ms();
            for at in 0..offers {
                let minted = Identity::generate().map_err(|error| error.to_string())?;
                directory.offered(
                    hinter,
                    own_offer(&minted, &format!("minted-{at}.example:10900"), now)?,
                );
            }
            let rounds = 100;
            let probed = (0..rounds)
                .filter(|_| {
                    let set = directory.probe_set(&[], &[]);
                    owner
                        .iter()
                        .all(|configured| set.iter().any(|relay| relay.key == configured.key))
                })
                .count();
            rates.push((offers, probed));
        }
        assert!(
            rates.iter().all(|(_, probed)| *probed == 100),
            "rounds probing every configured relay, by offers: {rates:?}"
        );
        Ok(())
    }

    #[test]
    fn a_relay_hiding_behind_a_lying_location_is_still_probed() -> Result<(), String> {
        // Many relays outrank it for the first places (the owner's, last round's band), and it
        // offers no cell near the feeder: the random places still find it within a few rounds.
        let owner = relays("owner", 3)?;
        // The owner's relays heard, so every place is discovery's.
        let heard: Vec<PublicKey> = owner.iter().map(|relay| relay.key).collect();
        let directory = directory_at(scratch(), owner)?;
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
            let set = directory.probe_set(&band_keys, &heard);
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

    /// The seconds from `start` at which `pace` lets each of `count` batches of `bytes` go, each
    /// waiting its turn after the one before, as a session sends them.
    fn turns(pace: &mut Pace, count: usize, bytes: usize, start: Instant) -> Vec<f64> {
        let mut at = start;
        (0..count)
            .map(|_| {
                loop {
                    let wait = pace.wait(bytes, at);
                    if wait.is_zero() {
                        break;
                    }
                    at += wait;
                }
                at.duration_since(start).as_secs_f64()
            })
            .collect()
    }

    /// A relay that asks nothing, or as much as the batcher signs at the owner's ceiling or more,
    /// is paced at the ceiling as the batcher signs at it (`source::signed_most`): a burst of batches goes out at that rate, a
    /// second of it at once, never all at once. Before, it was not paced at all, and a backlog an
    /// anchor's return released went out over the ceiling in one go.
    #[test]
    fn a_relay_that_asked_nothing_is_paced_at_the_ceiling() {
        const CEILING: u32 = 64_000;
        let signed = crate::source::signed_most(CEILING);
        let most = f64::from(signed);
        for asked in [None, Some(signed), Some(u32::MAX)] {
            let mut pace = pace(CEILING);
            if let Some(rate) = asked {
                pace.limit(rate, 0, None);
            }
            let start = Instant::now();
            let bytes = noise::MAX_PLAINTEXT;
            let sent = turns(&mut pace, 100, bytes, start);
            let last = sent.last().copied().unwrap_or_default();
            // A hundred whole batches at the rate, the first second's at once.
            let expected = (100.0 * bytes as f64 - most.max(bytes as f64)) / most;
            assert!(
                (last - expected).abs() < 0.1,
                "{asked:?}: the last went at {last} s, not {expected} s"
            );
        }
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

    /// A relay's stated clock (`RateLimit`'s `clock_ms` and `error_ms`) is its session's source
    /// for the batcher's clocks (`source::RelayClocks`), uncertain by the time since the
    /// session's Hello on the anchored (raw monotonic) clock; a relay that states none is no
    /// source. The test's scripted slew: 300 ms pass on the raw clock while the slewed one
    /// (`Instant`, tokio's paused clock here) runs 2 s, and the statement is uncertain by the raw
    /// clock's 300 ms. Before, the Hello was an `Instant`, so a daemon's slew moved the
    /// uncertainty; and before that, the statement was an offset with no uncertainty and no error.
    #[tokio::test(start_paused = true)]
    async fn a_sessions_relay_clock_is_told_to_the_batcher() {
        let wall = Arc::new(std::sync::atomic::AtomicU64::new(1_000_000));
        let monotonic = Arc::new(std::sync::atomic::AtomicU64::new(0));
        // A relay the owner configured (`--relay`): a configured clock source.
        let relay = Identity::from_seed([3; 32]).public();
        let clocks = Arc::new(
            RelayClocks::on(crate::source::HostClock::set_by(&wall, &monotonic))
                .configured([relay]),
        );
        let hello = clocks.stamp_ms();
        let mut pace = Pace::new(64_000, Arc::new(WantedCeilings::default()).session())
            .telling(clocks.session(relay), hello);
        monotonic.store(300, std::sync::atomic::Ordering::Relaxed);
        tokio::time::advance(Duration::from_secs(2)).await;
        // The relay alone is a source (this host, unsynced, is none): the batches are signed at
        // the low end of its interval, its statement less the handshake and its error.
        pace.clock(Some(1_005_000), Some(100));
        let signed = clocks.now_ms();
        assert_eq!(signed, 1_005_000 - 100 - 300);
        drop(pace);
        // Gone with its session: this host alone, unsynced, is held over by the clock last taken.
        assert_eq!(clocks.now_ms(), signed);
        let mut quiet = Pace::new(64_000, Arc::new(WantedCeilings::default()).session())
            .telling(clocks.session(relay), hello);
        quiet.clock(None, None);
        assert_eq!(clocks.now_ms(), signed);
    }

    /// A relay that asked for less than the ceiling gets every batch, each waiting its turn at
    /// the rate it asked for, none skipped. Before, a batch over its rate was skipped and counted,
    /// and a backlog an anchor's return released was skipped but for one burst.
    #[test]
    fn a_relay_that_asked_for_less_gets_every_batch_at_its_rate() {
        let mut pace = pace(64_000);
        pace.limit(16_000, 1_000, None);
        let start = Instant::now();
        let batch = 48 * 1024 + 4_000;
        let sent = turns(&mut pace, 60, batch, start);
        assert_eq!(sent.len(), 60);
        assert_eq!(sent.first().copied(), Some(0.0));
        // Past the burst (a whole batch at least), one batch a little over three seconds, each
        // after the one before, never sooner.
        let each = batch as f64 / 16_000.0;
        assert!(sent[1] < each, "{sent:?}");
        assert!(
            sent[1..]
                .windows(2)
                .all(|pair| (pair[1] - pair[0] - each).abs() < 0.01),
            "{sent:?}"
        );
    }

    /// A batch signed now, as a live feeder signs one: the publisher sends it before it outlives
    /// the backlog a relay takes (`outlived`).
    fn batch(feeder: &Identity, sequence: u64) -> Result<Batch, String> {
        batch_at(feeder, sequence, wall_ms())
    }

    fn batch_at(feeder: &Identity, sequence: u64, wall_ms: u64) -> Result<Batch, String> {
        Batch::sign(
            feeder,
            &tally_wire::BatchContent {
                boot_id: 1,
                sequence,
                counter_epoch: 0,
                wall_ms,
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
                ledger.record(relay, &batch, wall_ms());
            }
        }
        ledger.audit(audited);
        let mut solo = Vec::new();
        for sequence in 3..12 {
            let batch = batch(&feeder, sequence)?;
            for relay in [audited, other] {
                if ledger.routes(&relay, &batch) {
                    ledger.record(relay, &batch, wall_ms());
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
                    ledger.record(relay, &batch, wall_ms());
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
                ledger.record(audited, &batch, wall_ms());
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
                ledger.record(audited, &batch, wall_ms());
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

    /// A configured relay's clock poll is reset once a probe's answer made it a live sample (a
    /// round's or a poll's): unheard again later, it is polled from `CLOCK_POLL_FIRST`, not at the
    /// interval the polls it missed before had grown to. An answer with no live sample keeps it
    /// doubling. Before, any answer reset it, so a seed answering with no usable clock was polled
    /// every few seconds for ever.
    #[test]
    fn an_answer_with_no_live_sample_keeps_doubling() -> Result<(), String> {
        let seed = relay("seed.example:10900")?;
        let mut polls = ClockPolls::default();
        let mut at = tokio::time::Instant::now();
        for _ in 0..6 {
            let due = polls.due(vec![seed.clone()], at);
            assert_eq!(due.len(), 1);
            at = polls.next().ok_or("no poll next")?;
        }
        assert_eq!(polls.polls[&seed.key].1, ROUND_EVERY);
        // It answered, and is still no live sample: its poll is as it was.
        polls.answered(&[]);
        assert_eq!(polls.polls[&seed.key].1, ROUND_EVERY);
        assert_eq!(polls.due(vec![seed.clone()], at).len(), 1);
        assert_eq!(polls.next(), Some(at + ROUND_EVERY));
        // Its answer made a live sample: unheard again, it is due at once, and again
        // `CLOCK_POLL_FIRST` after.
        polls.answered(&[seed.key]);
        assert_eq!(polls.due(vec![seed.clone()], at).len(), 1);
        assert_eq!(polls.next(), Some(at + CLOCK_POLL_FIRST));
        Ok(())
    }

    /// What an ended audit owes a relay is never dropped with a session or a relay: a session
    /// that ends before it has sent them all owes the rest to its relay again, the one cut short
    /// among them, oldest first and ahead of anything owed since (`Ledger::owe_again`); and a
    /// relay replaced hands what it was owed to the relays in its place (`Ledger::hand_owed`).
    /// Before, `take_owed` took them all and a session that ended early dropped the rest, and a
    /// replaced relay's were never sent.
    #[test]
    fn owed_batches_outlive_their_session_and_their_relay() -> Result<(), String> {
        let feeder = Identity::generate().map_err(|error| error.to_string())?;
        let (audited, other, successor, another) = (key()?, key()?, key()?, key()?);
        let ledger = Ledger::default();
        ledger.live(audited, true);
        ledger.live(other, true);
        assert!(ledger.routes(&other, &batch(&feeder, 0)?));
        ledger.audit(audited);
        for sequence in 2..6 {
            let batch = batch(&feeder, sequence)?;
            assert!(!ledger.routes(&other, &batch));
        }
        assert_eq!(ledger.end_audit(), 4);
        let sequences =
            |batches: Vec<Batch>| -> Vec<u64> { batches.iter().map(Batch::sequence).collect() };
        // A session took them and sent one before it ended; the rest are owed again, before one
        // owed since.
        let mut taken = ledger.take_owed(&other);
        assert!(ledger.take_owed(&other).is_empty());
        let rest = taken.split_off(1);
        ledger.audit(audited);
        assert!(!ledger.routes(&other, &batch(&feeder, 9)?));
        ledger.live(audited, false);
        assert_eq!(ledger.end_audit(), 1);
        ledger.owe_again(other, rest);
        assert_eq!(sequences(ledger.take_owed(&other)), vec![3, 4, 5, 9]);
        // Replaced: what it was owed goes to each relay in its place, and only to them.
        ledger.owe_again(other, vec![batch(&feeder, 10)?]);
        let changes = ledger.owed_changes();
        ledger.hand_owed(&other, &[successor, another]);
        assert!(changes.has_changed().map_err(|error| error.to_string())?);
        assert!(ledger.take_owed(&other).is_empty());
        assert_eq!(sequences(ledger.take_owed(&successor)), vec![10]);
        assert_eq!(sequences(ledger.take_owed(&another)), vec![10]);
        Ok(())
    }

    /// RFC-0171 §3.6: what a relay that keeps failing is owed stays bounded. The feeder audits
    /// another relay through it again and again, and each session of it ends: what it is owed
    /// stays within `OWED_KEPT` however many audits end, whether it is replaced with no successor
    /// (the list is kept, bounded) or hands the list on (the publisher's replacement of it is
    /// `a_relay_saying_goodbye_for_its_clock_every_session_is_replaced`). Before, its owed list grew
    /// by every audit.
    #[test]
    fn what_a_relay_that_keeps_failing_is_owed_stays_bounded() -> Result<(), String> {
        let feeder = Identity::generate().map_err(|error| error.to_string())?;
        let (audited, minted, successor) = (key()?, key()?, key()?);
        let ledger = Ledger::default();
        ledger.live(audited, true);
        ledger.live(minted, true);
        let mut sequence = 0;
        for round in 0..200 {
            ledger.audit(audited);
            // The audit holds back the `SAMPLED` sequences from the newest seen plus two.
            let held_last = if round == 0 { 0 } else { sequence + 1 } + SAMPLED as u64 - 1;
            for _ in 0..SAMPLED + 2 {
                let _ = ledger.routes(&minted, &batch(&feeder, sequence)?);
                sequence += 1;
            }
            ledger.live(audited, false);
            assert!(ledger.end_audit() <= SAMPLED);
            ledger.live(audited, true);
            if round % 2 == 0 {
                // Replaced with no relay to take its place: still owed, within the bound.
                ledger.hand_owed(&minted, &[]);
            } else {
                let taken = ledger.take_owed(&minted);
                ledger.owe_again(minted, taken);
            }
            let owed = ledger.take_owed(&minted);
            assert!(
                !owed.is_empty() && owed.len() <= OWED_KEPT,
                "{}",
                owed.len()
            );
            // The newest are kept: the oldest go first.
            assert_eq!(owed.last().map(Batch::sequence), Some(held_last));
            ledger.owe_again(minted, owed);
        }
        ledger.hand_owed(&minted, &[successor]);
        assert!(ledger.take_owed(&minted).is_empty());
        let handed = ledger.take_owed(&successor);
        assert_eq!(handed.len(), OWED_KEPT);
        Ok(())
    }

    /// A session that ends while it sends what it was owed (its relay says goodbye under a send
    /// it is not reading) gives back every batch it did not finish sending, so its next session,
    /// or its successor, sends them. Before, they were dropped.
    #[tokio::test]
    async fn a_session_ended_while_sending_its_owed_batches_owes_them_still() -> Result<(), String>
    {
        let directory = directory_at(scratch(), Vec::new())?;
        // A pipe narrower than one batch: a send the relay does not read waits.
        let (session, mut relay_end, relay_key) = pipe(64).await?;
        let context = context(directory, relay_key, "relay.example:10900");
        let ledger = Arc::clone(&context.ledger);
        let (feeder, audited) = (Identity::generate().map_err(|e| e.to_string())?, key()?);
        ledger.live(audited, true);
        ledger.live(relay_key, true);
        ledger.audit(audited);
        for sequence in 0..3 {
            assert!(!ledger.routes(&relay_key, &batch(&feeder, sequence)?));
        }
        assert_eq!(ledger.end_audit(), 3);
        let (_out, batches) = broadcast::channel(64);
        let (records_in, mut records) = mpsc::channel(16);
        let version = session.version;
        let mut writer = session.writer;
        let running = tokio::spawn(async move {
            publish(
                &context,
                version,
                context.clocks.stamp_ms(),
                &mut writer,
                &mut records,
                batches,
            )
            .await
        });
        // Read what goes before the greeting is asked for, then read no more.
        loop {
            let mut got = Vec::new();
            tokio::time::timeout(HANG, relay_end.reader.recv(&mut got))
                .await
                .map_err(|_| "no heartbeat came".to_owned())?
                .map_err(|error| error.to_string())?;
            if got
                .iter()
                .any(|record| matches!(record, Record::TimedHeartbeat(_) | Record::Heartbeat))
            {
                break;
            }
        }
        let _ = records_in.try_send(Ok(vec![greeting()]));
        // It took what it is owed to send, and waits under the first.
        tokio::time::timeout(HANG, async {
            while ledger.held().1 > 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .map_err(|_| "the session never took what it was owed".to_owned())?;
        let _ = records_in.try_send(Ok(vec![Record::Goodbye {
            reason: Reason::Full,
            retry_after_secs: 60,
        }]));
        let ended = tokio::time::timeout(HANG, running)
            .await
            .map_err(|_| "the session did not end".to_owned())?
            .map_err(|error| error.to_string())?;
        assert!(matches!(ended, Ok(Outcome::Leave(_))), "{ended:?}");
        let owed: Vec<u64> = ledger
            .take_owed(&relay_key)
            .iter()
            .map(Batch::sequence)
            .collect();
        assert_eq!(owed, vec![0, 1, 2]);
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
        let feeder = Arc::new(Identity::generate().map_err(error)?);
        let dir = scratch();
        let directory = Directory::new(
            dir.clone(),
            vec![swallower.clone(), honest.clone(), reserve.clone()],
            Vec::new(),
            feeder.clone(),
            Some(location),
            (Clock::Dump1090, Arc::default()),
        )?;
        let area = directory.area().ok_or("no area")?;
        // Two members of the area's sharing group, which take no feeder.
        for (ip, network) in [("127.0.11.1", 11), ("127.0.12.1", 12)] {
            let identity = Arc::new(Identity::generate().map_err(error)?);
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
            clocks: Arc::default(),
            checker: DeliveryChecker::load(&dir),
            checking: Checking {
                every: Duration::from_secs(1),
                audit_for: Duration::from_secs(1),
                settle: Duration::from_millis(500),
                grant_every: Duration::from_millis(200),
            },
            prober: |relay, me, clocks| {
                Box::pin(async move {
                    let mut probed = probe::probe(&relay, &me, &clocks).await?;
                    probed.measured.rtt = LOOPBACK;
                    Ok(probed)
                })
            },
            source_address: None,
            health: Arc::default(),
            pacing: Pacing::default(),
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
        let feeder = Arc::new(Identity::generate().map_err(error)?);
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

    /// What a relay first says to a feeder (`publish` sends no batch before it): a rate at no
    /// ceiling, and no clock.
    fn greeting() -> Record {
        Record::RateLimit {
            bytes_per_sec: u32::MAX,
            burst: u32::MAX,
            wanted_per_sec: None,
            clock_ms: None,
            error_ms: None,
        }
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
            clocks: Arc::default(),
            source_address: None,
            clock_retry: CLOCK_RETRY,
            health: Arc::default(),
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
        let _ = records_in.try_send(Ok(vec![greeting()]));
        let context = context(directory, relay_key, "relay.example:10900");
        let version = version.unwrap_or(session.version);
        let mut writer = session.writer;
        let running = tokio::spawn(async move {
            publish(
                &context,
                version,
                context.clocks.stamp_ms(),
                &mut writer,
                &mut records,
                batches,
            )
            .await
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
        let feeder = Arc::new(Identity::generate().map_err(error)?);
        let mut batcher = Batcher::new(feeder, u32::MAX, Clock::Dump1090).always_anchored();
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
                assert_eq!(
                    arrived.format(),
                    tally_wire::batch::BATCH_FORMAT_ANCHORED_DEFLATE
                );
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
        let feeder = Arc::new(Identity::generate().map_err(error)?);
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
        let (records_in, mut records) = mpsc::channel(16);
        let _ = records_in.try_send(Ok(vec![greeting()]));
        let context = context(directory, relay_key, "relay.example:10900");
        let version = session.version;
        let mut writer = session.writer;
        let publishing = tokio::spawn(async move {
            publish(
                &context,
                version,
                context.clocks.stamp_ms(),
                &mut writer,
                &mut records,
                batches,
            )
            .await
        });
        // Batches as big as the batcher seals them, each a large part of the second's ceiling even
        // compressed: each message is noise (splitmix64 of its counter), which DEFLATE barely
        // shrinks.
        let mut batcher = Batcher::new(feeder, u32::MAX, Clock::Dump1090).always_anchored();
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

    /// RFC-0171 §3.6: possession never depends on a clock. A batch the session held longer than
    /// its relay uses one, one signed far ahead of every clock, and the ones between all go: the
    /// relay alone judges whether it can use each, and holds what it cannot use. Before, a
    /// session withheld what it judged too old or too far ahead, so a feeder with a wrong clock
    /// delivered nothing.
    #[tokio::test]
    async fn every_batch_goes_whatever_its_clock() -> Result<(), String> {
        let directory = directory_at(scratch(), Vec::new())?;
        let (running, mut reader, out, _records_in) = publishing(directory).await?;
        let feeder = Identity::generate().map_err(|error| error.to_string())?;
        let now = wall_ms();
        let hour = 3_600_000;
        let signed = [
            now - hour,
            now - tally_wire::budget::B
                .span::<tally_wire::clocks::Judged>()
                .ms()
                - 3_000,
            now,
            now + tally_wire::budget::F
                .span::<tally_wire::clocks::Judged>()
                .ms()
                + 1,
            now + hour,
        ];
        for (sequence, at) in signed.into_iter().enumerate() {
            let _ = out.send(Arc::new(Record::Batch(batch_at(
                &feeder,
                sequence as u64,
                at,
            )?)));
        }
        let mut sequences = Vec::new();
        let deadline = tokio::time::Instant::now() + HANG;
        while sequences.len() < signed.len() {
            let mut got = Vec::new();
            tokio::time::timeout_at(deadline, reader.recv(&mut got))
                .await
                .map_err(|_| format!("only {sequences:?} arrived"))?
                .map_err(|error| error.to_string())?;
            for record in got {
                if let Record::Batch(batch) = record {
                    sequences.push(batch.sequence());
                }
            }
        }
        running.abort();
        assert_eq!(sequences, vec![0, 1, 2, 3, 4]);
        Ok(())
    }

    /// The first `Record::Batch` the relay's end reads, with every timed heartbeat the feeder
    /// sent before it.
    async fn first_batch(
        reader: &mut noise::Reader<Pipe>,
        mut beat: impl FnMut(tally_wire::HeartbeatTimes),
    ) -> Result<Batch, String> {
        // One deadline for the whole wait: heartbeats keep coming, so a wait per read would never
        // end on a batch that never comes.
        let deadline = tokio::time::Instant::now() + HANG;
        loop {
            let mut got = Vec::new();
            tokio::time::timeout_at(deadline, reader.recv(&mut got))
                .await
                .map_err(|_| "no batch arrived".to_owned())?
                .map_err(|error| error.to_string())?;
            for record in got {
                match record {
                    Record::Batch(batch) => return Ok(batch),
                    Record::TimedHeartbeat(times) => beat(times),
                    _ => {}
                }
            }
        }
    }

    /// RFC-0171 §3.6: an unsynced relay (one stating its error unbounded) still receives every
    /// batch, whatever its stated clock: here it states a clock 200 s ahead, and a batch signed
    /// now and one signed by its clock both go, and the session goes on. Its sample is ignored
    /// (its error is past `E`). Before, a session judged each batch by the relay's stated clock
    /// and withheld the one signed now.
    #[tokio::test]
    async fn an_unsynced_relay_still_receives_every_batch() -> Result<(), String> {
        let directory = directory_at(scratch(), Vec::new())?;
        let (session, mut relay_end, relay_key) = pipe(1 << 20).await?;
        let context = context(directory, relay_key, "relay.example:10900");
        let ahead_by = 200_000;
        let stated = Record::RateLimit {
            bytes_per_sec: u32::MAX,
            burst: u32::MAX,
            wanted_per_sec: None,
            clock_ms: Some(wall_ms() + ahead_by),
            error_ms: Some(u64::MAX),
        };
        let (out, batches) = broadcast::channel(64);
        let (records_in, mut records) = mpsc::channel(16);
        let _ = records_in.try_send(Ok(vec![stated]));
        let feeder = Identity::generate().map_err(|error| error.to_string())?;
        let now = wall_ms();
        let _ = out.send(Arc::new(Record::Batch(batch_at(&feeder, 0, now)?)));
        let _ = out.send(Arc::new(Record::Batch(batch_at(
            &feeder,
            1,
            now + ahead_by,
        )?)));
        let version = session.version;
        let mut writer = session.writer;
        let running = tokio::spawn(async move {
            publish(
                &context,
                version,
                context.clocks.stamp_ms(),
                &mut writer,
                &mut records,
                batches,
            )
            .await
        });
        let first = first_batch(&mut relay_end.reader, |_| {}).await?;
        let second = first_batch(&mut relay_end.reader, |_| {}).await?;
        assert_eq!((first.sequence(), second.sequence()), (0, 1));
        assert!(!running.is_finished(), "the session ended over a clock");
        running.abort();
        drop(records_in);
        Ok(())
    }

    /// RFC-0171 §3.6: a synced relay stating a clock an hour off this feeder's (a relay whose
    /// host was set wrong, or this feeder's own clock wrong): the feeder withholds nothing from it
    /// (a batch signed by its own clock and one signed by the relay's both go), the session goes
    /// on, and its health reports the disagreement. Nothing it says of its clock replaces it.
    /// An older relay's clock goodbye is a retry like any other: a long session is dialled
    /// again, and a short one is held against it as any short session is (`Ends`). The relay holds
    /// every batch as possession and passes it on to its peers, which judge it by their own
    /// clocks (the relay's own tests). Before, a relay that refused a batch the session's
    /// measure said it promised to take was replaced after three.
    #[tokio::test]
    async fn a_relay_stating_a_clock_an_hour_off_is_sent_everything_and_never_replaced()
    -> Result<(), String> {
        const HOUR: u64 = 3_600_000;
        let directory = directory_at(scratch(), Vec::new())?;
        let (session, mut relay_end, relay_key) = pipe(1 << 20).await?;
        let clocks: Arc<RelayClocks> = Arc::default();
        let context = Context {
            clocks: Arc::clone(&clocks),
            ..context(directory, relay_key, "relay.example:10900")
        };
        let stated = Record::RateLimit {
            bytes_per_sec: u32::MAX,
            burst: u32::MAX,
            wanted_per_sec: None,
            clock_ms: Some(wall_ms() + HOUR),
            error_ms: Some(0),
        };
        let (out, batches) = broadcast::channel(64);
        let (records_in, mut records) = mpsc::channel(16);
        let _ = records_in.try_send(Ok(vec![stated]));
        let feeder = Identity::generate().map_err(|error| error.to_string())?;
        let now = wall_ms();
        for (sequence, at) in [now, now + HOUR, now - HOUR].into_iter().enumerate() {
            let _ = out.send(Arc::new(Record::Batch(batch_at(
                &feeder,
                sequence as u64,
                at,
            )?)));
        }
        let version = session.version;
        let mut writer = session.writer;
        let running = tokio::spawn(async move {
            publish(
                &context,
                version,
                context.clocks.stamp_ms(),
                &mut writer,
                &mut records,
                batches,
            )
            .await
        });
        let mut sequences = Vec::new();
        for _ in 0..3 {
            sequences.push(first_batch(&mut relay_end.reader, |_| {}).await?.sequence());
        }
        assert_eq!(sequences, vec![0, 1, 2]);
        assert!(!running.is_finished(), "the session ended over a clock");
        // The health's word: this feeder's clock is an hour behind the relay's.
        let disagree = clocks.disagreements();
        assert_eq!(disagree.len(), 1, "{disagree:?}");
        assert_eq!(disagree[0].0, relay_key);
        assert!(disagree[0].1 < -3_500_000, "{disagree:?}");
        // An older relay's clock goodbye: a retry like any other, the same relay again after at
        // least the protocol's minute; whether it counts against the relay is the run of ends
        // (`Ends`), as for any other reason.
        let _ = records_in.try_send(Ok(vec![Record::Goodbye {
            reason: Reason::Clock,
            retry_after_secs: 60,
        }]));
        let ended = tokio::time::timeout(HANG, running)
            .await
            .map_err(|_| "the session did not end".to_owned())?
            .map_err(|error| error.to_string())?;
        assert!(
            matches!(ended, Ok(Outcome::Retry(wait)) if wait == CLOCK_RETRY),
            "{ended:?}"
        );
        assert_eq!(after(&ended), Next::Redial { wait: CLOCK_RETRY });
        Ok(())
    }

    /// RFC-0171 §3.6: a Pi whose clock is an hour behind, unsynced, with one seed: before the seed
    /// is heard it signs by its own clock, an hour old, and every batch still goes; the relay
    /// holds them as possession, unused. Once the seed states its clock the selection flips to
    /// it mid-session, and that blames no one: the session goes on, sending every batch, and the
    /// relay's fate is no clock's. Before, the session withheld every batch an hour old, and the
    /// Pi delivered nothing; then a relay that refused after the flip was counted a broken
    /// promise.
    #[tokio::test]
    async fn a_pi_an_hour_behind_with_one_seed_still_sends_every_batch() -> Result<(), String> {
        const HOUR: u64 = 3_600_000;
        let directory = directory_at(scratch(), Vec::new())?;
        let (session, mut relay_end, relay_key) = pipe(1 << 20).await?;
        let real = wall_ms();
        let wall = Arc::new(std::sync::atomic::AtomicU64::new(real - HOUR));
        let monotonic = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let clocks = Arc::new(
            RelayClocks::on(crate::source::HostClock::set_by(&wall, &monotonic))
                .configured([relay_key]),
        );
        let context = Context {
            clocks: Arc::clone(&clocks),
            ..context(directory, relay_key, "relay.example:10900")
        };
        let (out, batches) = broadcast::channel(64);
        let (records_in, mut records) = mpsc::channel(16);
        let _ = records_in.try_send(Ok(vec![greeting()]));
        let feeder = Identity::generate().map_err(|error| error.to_string())?;
        // Signed by the Pi's own clock, the seed not yet heard: an hour old.
        assert_eq!(clocks.now_ms(), real - HOUR);
        for sequence in 0..3 {
            let _ = out.send(Arc::new(Record::Batch(batch_at(
                &feeder,
                sequence,
                clocks.now_ms(),
            )?)));
        }
        let version = session.version;
        let mut writer = session.writer;
        let running = tokio::spawn(async move {
            publish(
                &context,
                version,
                context.clocks.stamp_ms(),
                &mut writer,
                &mut records,
                batches,
            )
            .await
        });
        let mut sequences = Vec::new();
        for _ in 0..3 {
            sequences.push(first_batch(&mut relay_end.reader, |_| {}).await?.sequence());
        }
        assert_eq!(sequences, vec![0, 1, 2]);
        // The seed answers the session's timed heartbeat with its clock, the real time: the Pi
        // signs by it from now on (the seed is its one source; an unsynced host never votes), and
        // a batch so signed is one the seed promised to take.
        let asked = u64::try_from(clocks.anchored_ms()).unwrap_or(0);
        let _ = records_in.try_send(Ok(vec![Record::TimedHeartbeat(
            tally_wire::HeartbeatTimes {
                sent_ms: wall_ms(),
                echo: Some((asked, wall_ms())),
                error_ms: Some(0),
            },
        )]));
        let stated = tokio::time::Instant::now();
        while clocks.now_ms() < real - HOUR / 2 {
            tokio::time::timeout_at(stated + HANG, tokio::task::yield_now())
                .await
                .map_err(|_| "the seed's clock was never selected".to_owned())?;
        }
        let _ = out.send(Arc::new(Record::Batch(batch_at(
            &feeder,
            3,
            clocks.now_ms(),
        )?)));
        assert_eq!(
            first_batch(&mut relay_end.reader, |_| {}).await?.sequence(),
            3
        );
        // And one signed by the Pi's old clock after the flip, still on its way: it goes too.
        let _ = out.send(Arc::new(Record::Batch(batch_at(&feeder, 4, real - HOUR)?)));
        assert_eq!(
            first_batch(&mut relay_end.reader, |_| {}).await?.sequence(),
            4
        );
        assert!(!running.is_finished(), "the flip ended the session");
        running.abort();
        drop(records_in);
        Ok(())
    }

    /// A session sends no batch before its relay's greeting states the rate it takes and the
    /// clock it judges by (`RateLimit`), and asks that clock by a timed heartbeat at once. Then
    /// every batch goes, in order, whatever the stated clock: here it is 100 s behind, and the
    /// batch signed by this host's clock 30 s ago still goes first.
    #[tokio::test]
    async fn no_batch_goes_before_the_relays_greeting() -> Result<(), String> {
        let directory = directory_at(scratch(), Vec::new())?;
        let (session, mut relay_end, relay_key) = pipe(1 << 20).await?;
        let context = context(directory, relay_key, "relay.example:10900");
        let (out, batches) = broadcast::channel(64);
        let (records_in, mut records) = mpsc::channel(16);
        let feeder = Identity::generate().map_err(|error| error.to_string())?;
        let now = wall_ms();
        let behind_by = 100_000;
        let _ = out.send(Arc::new(Record::Batch(batch_at(&feeder, 0, now - 30_000)?)));
        let version = session.version;
        let mut writer = session.writer;
        let running = tokio::spawn(async move {
            publish(
                &context,
                version,
                context.clocks.stamp_ms(),
                &mut writer,
                &mut records,
                batches,
            )
            .await
        });
        // The timed heartbeat goes before the greeting is heard.
        let mut asked = false;
        loop {
            let mut got = Vec::new();
            tokio::time::timeout(HANG, relay_end.reader.recv(&mut got))
                .await
                .map_err(|_| "no timed heartbeat arrived".to_owned())?
                .map_err(|error| error.to_string())?;
            for record in got {
                match record {
                    Record::TimedHeartbeat(times) if times.echo.is_none() => asked = true,
                    Record::Batch(batch) => {
                        running.abort();
                        return Err(format!("batch {} went first", batch.sequence()));
                    }
                    _ => {}
                }
            }
            if asked {
                break;
            }
        }
        let stated = Record::RateLimit {
            bytes_per_sec: u32::MAX,
            burst: u32::MAX,
            wanted_per_sec: None,
            clock_ms: Some(wall_ms() - behind_by),
            error_ms: Some(0),
        };
        let _ = records_in.try_send(Ok(vec![stated]));
        let _ = out.send(Arc::new(Record::Batch(batch_at(
            &feeder,
            1,
            now - behind_by,
        )?)));
        let first = first_batch(&mut relay_end.reader, |_| {}).await?;
        let second = first_batch(&mut relay_end.reader, |_| {}).await?;
        running.abort();
        assert_eq!((first.sequence(), second.sequence()), (0, 1));
        Ok(())
    }

    /// RFC-0171 §3.6: every batch an ended audit owes a relay (`Ledger::end_audit`) goes, held
    /// past what the relay uses or signed ahead of its clock alike: the relay judges each, and
    /// holds what it cannot use. Before, the session withheld the two it judged by a clock.
    #[tokio::test]
    async fn every_owed_batch_goes_whatever_its_clock() -> Result<(), String> {
        let directory = directory_at(scratch(), Vec::new())?;
        let (session, mut relay_end, relay_key) = pipe(1 << 20).await?;
        let context = context(directory, relay_key, "relay.example:10900");
        let ledger = Arc::clone(&context.ledger);
        let (feeder, audited) = (Identity::generate().map_err(|e| e.to_string())?, key()?);
        ledger.live(audited, true);
        ledger.live(relay_key, true);
        ledger.audit(audited);
        let now = wall_ms();
        let held = batch_at(
            &feeder,
            0,
            now - tally_wire::budget::B
                .span::<tally_wire::clocks::Judged>()
                .ms()
                - 3_000,
        )?;
        let ahead = batch_at(
            &feeder,
            2,
            now + tally_wire::budget::F
                .span::<tally_wire::clocks::Judged>()
                .ms(),
        )?;
        let within = batch_at(&feeder, 1, now)?;
        for batch in [&held, &ahead, &within] {
            assert!(!ledger.routes(&relay_key, batch), "not held back");
            assert!(ledger.routes(&audited, batch));
        }
        assert_eq!(ledger.end_audit(), 3);
        let (_out, batches) = broadcast::channel(64);
        let (records_in, mut records) = mpsc::channel(16);
        let _ = records_in.try_send(Ok(vec![greeting()]));
        let version = session.version;
        let mut writer = session.writer;
        let running = tokio::spawn(async move {
            publish(
                &context,
                version,
                context.clocks.stamp_ms(),
                &mut writer,
                &mut records,
                batches,
            )
            .await
        });
        let mut sequences = Vec::new();
        let deadline = tokio::time::Instant::now() + HANG;
        while sequences.len() < 3 {
            let mut got = Vec::new();
            tokio::time::timeout_at(deadline, relay_end.reader.recv(&mut got))
                .await
                .map_err(|_| format!("only {sequences:?} arrived"))?
                .map_err(|error| error.to_string())?;
            for record in got {
                if let Record::Batch(batch) = record {
                    sequences.push(batch.sequence());
                }
            }
        }
        running.abort();
        sequences.sort_unstable();
        assert_eq!(sequences, vec![0, 1, 2]);
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
        publish(
            &context,
            version,
            context.clocks.stamp_ms(),
            &mut writer,
            &mut records,
            batches,
        )
        .await
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
        let ended = publish(
            &context,
            version,
            context.clocks.stamp_ms(),
            &mut writer,
            &mut records,
            batches,
        )
        .await;
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
        let feeder = Arc::new(Identity::generate().map_err(error)?);
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
            (Clock::Dump1090, Arc::default()),
        )?;
        let (batches, _) = broadcast::channel(64);
        let publisher = tokio::spawn(run(Publishing {
            directory: Arc::clone(&directory),
            identity: feeder.clone(),
            batches: batches.clone(),
            ceiling: 64_000,
            wanted: Arc::default(),
            clocks: Arc::default(),
            checker: DeliveryChecker::default(),
            checking: Checking::default(),
            prober: |relay, me, clocks| {
                Box::pin(async move {
                    let mut probed = probe::probe(&relay, &me, &clocks).await?;
                    probed.measured.rtt = LOOPBACK;
                    Ok(probed)
                })
            },
            source_address: None,
            health: Arc::default(),
            pacing: Pacing::default(),
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

    /// RFC-0171 §3.6, the whole publisher over loopback relays: a minted relay, ranked first,
    /// says `Goodbye{Clock}` at the first batch of every session (no relay of this version
    /// does). Each session reached it and ended short while the session to the other relay held
    /// stayed up, so the second in a row replaces it: the third relay takes its place and both
    /// serving relays take batches, and the minted relay was dialled for exactly two sessions
    /// before it was replaced, not one. Its waits are shortened (`Pacing`: the clock goodbye's
    /// retry, and the wait to judge an end), as a loopback test's must be; the rule is the
    /// protocol's. Before, a clock goodbye redialled the same relay for ever.
    #[tokio::test]
    async fn a_relay_saying_goodbye_for_its_clock_every_session_is_replaced() -> Result<(), String>
    {
        use crate::probe::tests::{Fake, Mode, echo_relay};
        const LOOPBACK: Duration = Duration::from_millis(1);
        let error = |error: tally_wire::WireError| error.to_string();
        let (taken, mut arrivals) = mpsc::unbounded_channel();
        let (roles, mut minted_roles) = mpsc::unbounded_channel();
        let mut fakes = Vec::new();
        for (ip, network, slots, mode) in [
            ("127.0.0.1", 1, 1, Mode::Serve),
            ("127.0.0.2", 2, 1_000_000, Mode::ClockGoodbyeOnBatch),
            ("127.0.0.3", 3, 1, Mode::Serve),
        ] {
            let fake = Fake {
                ip,
                batches: Some(taken.clone()),
                roles: (mode == Mode::ClockGoodbyeOnBatch).then(|| roles.clone()),
                ..Fake::new(Identity::generate().map_err(error)?, network, slots, mode)
            };
            fakes.push(echo_relay(fake).await?);
        }
        let feeder = Arc::new(Identity::generate().map_err(error)?);
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
            (Clock::Dump1090, Arc::default()),
        )?;
        let (batches, _) = broadcast::channel(64);
        let publisher = tokio::spawn(run(Publishing {
            directory: Arc::clone(&directory),
            identity: feeder.clone(),
            batches: batches.clone(),
            ceiling: 64_000,
            wanted: Arc::default(),
            clocks: Arc::default(),
            checker: DeliveryChecker::default(),
            checking: Checking::default(),
            prober: |relay, me, clocks| {
                Box::pin(async move {
                    let mut probed = probe::probe(&relay, &me, &clocks).await?;
                    probed.measured.rtt = LOOPBACK;
                    Ok(probed)
                })
            },
            source_address: None,
            health: Arc::default(),
            pacing: Pacing {
                clock_retry: Duration::from_millis(500),
                ended_together: Duration::from_secs(1),
            },
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
        waited.map_err(|_| format!("{} of the two serving relays took batches", heard.len()))?;
        let mut sessions = 0;
        while let Ok(role) = minted_roles.try_recv() {
            if role == Role::Feeder {
                sessions += 1;
            }
        }
        // Two short sessions in a row, not one: the second replaced it.
        assert_eq!(sessions, 2, "sessions of the minted relay");
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
        let feeder = Arc::new(Identity::generate().map_err(error)?);
        let directory = Directory::new(
            scratch(),
            vec![relay.clone()],
            Vec::new(),
            feeder.clone(),
            None,
            (Clock::Dump1090, Arc::default()),
        )?;
        let (batches, _) = broadcast::channel(64);
        let publisher = tokio::spawn(run(Publishing {
            directory,
            identity: feeder.clone(),
            batches: batches.clone(),
            ceiling: 64_000,
            wanted: Arc::default(),
            clocks: Arc::default(),
            checker: DeliveryChecker::default(),
            checking: Checking::default(),
            prober: |relay, me, clocks| {
                Box::pin(async move {
                    let unanswered = NOT_YET
                        .fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| n.checked_sub(1))
                        .is_ok();
                    if unanswered {
                        return Err("connection refused".to_owned());
                    }
                    probe::probe(&relay, &me, &clocks).await
                })
            },
            source_address: None,
            health: Arc::default(),
            pacing: Pacing::default(),
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

    /// One configured relay that never answers is polled for its clock on its own interval,
    /// doubling from `CLOCK_POLL_FIRST` to `ROUND_EVERY` (NTP's poll interval), and a clock that
    /// asks for probes never brings discovery's round forward. Over an hour the dead seed is
    /// probed a bounded number of times, fewer in the last stretch than the first, and a relay a
    /// hint named only by the rounds. Before, every round came 30 s after the last while the seed
    /// was unheard, so it and the whole round were probed twice a minute for ever, on every
    /// feeder.
    #[tokio::test(start_paused = true)]
    async fn a_dead_seed_is_polled_less_and_less_and_never_hastens_a_round() -> Result<(), String> {
        static PROBES: std::sync::Mutex<Vec<(PublicKey, tokio::time::Instant)>> =
            std::sync::Mutex::new(Vec::new());
        let error = |error: tally_wire::WireError| error.to_string();
        let seed = relay("127.0.0.1:9")?;
        let hinted = relay("127.0.0.1:10")?;
        let feeder = Arc::new(Identity::generate().map_err(error)?);
        let directory = Directory::new(
            scratch(),
            vec![seed.clone()],
            Vec::new(),
            feeder.clone(),
            None,
            (Clock::Dump1090, Arc::default()),
        )?;
        directory.learn(seed.key, std::slice::from_ref(&hinted));
        let wall = Arc::new(std::sync::atomic::AtomicU64::new(wall_ms()));
        let monotonic = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let clocks = Arc::new(
            RelayClocks::on(crate::source::HostClock::set_by(&wall, &monotonic))
                .configured([seed.key]),
        );
        let (batches, _) = broadcast::channel(64);
        let started = tokio::time::Instant::now();
        let publisher = tokio::spawn(run(Publishing {
            directory,
            identity: feeder,
            batches,
            ceiling: 64_000,
            wanted: Arc::default(),
            clocks: Arc::clone(&clocks),
            checker: DeliveryChecker::default(),
            checking: Checking::default(),
            prober: |relay, _, _| {
                Box::pin(async move {
                    if let Ok(mut probes) = PROBES.lock() {
                        probes.push((relay.key, tokio::time::Instant::now()));
                    }
                    Err("connection refused".to_owned())
                })
            },
            source_address: None,
            health: Arc::default(),
            pacing: Pacing::default(),
        }));
        // The batcher reads the clock as it signs, each second: each read with the seed unheard
        // asks for a probe of it.
        let hour = Duration::from_secs(3_600);
        while started.elapsed() < hour {
            let _ = clocks.now_ms();
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
        publisher.abort();
        let probes = PROBES.lock().map_err(|error| error.to_string())?.clone();
        let count = |key: PublicKey, from: u64, to: u64| {
            probes
                .iter()
                .filter(|(each, at)| {
                    *each == key && (from..to).contains(&at.duration_since(started).as_secs())
                })
                .count()
        };
        let (first, last) = (count(seed.key, 0, 600), count(seed.key, 3_000, 3_600));
        assert!(last < first, "it did not decay: {first} then {last}");
        // Past its first polls: a round and a poll each `ROUND_EVERY` at most, with the jitter's
        // slack, for the seed; the rounds alone for the relay a hint named.
        let rounds = (1_800 / ROUND_EVERY.as_secs()) as usize;
        let seed_late = count(seed.key, 1_800, 3_600);
        assert!(
            seed_late <= 2 * rounds + 3,
            "{seed_late} probes of the seed"
        );
        let hinted_late = count(hinted.key, 1_800, 3_600);
        assert!(hinted_late <= rounds + 2, "{hinted_late} rounds hastened");
        let all = count(seed.key, 0, 3_600);
        assert!(all <= 45, "{all} probes of the seed in an hour");
        Ok(())
    }

    /// A seed that answers every probe with no usable clock (its ClockBound down: an error it
    /// cannot bound) is polled as a dead one is, less and less, at most 45 times an hour: its
    /// answer makes no live sample, so it resets nothing (`ClockPolls::answered`). Before, any
    /// answer reset its poll, and the default feeder (one seed, no ClockBound of its own) probed
    /// it 3,641 times an hour.
    #[tokio::test(start_paused = true)]
    async fn a_seed_answering_with_no_usable_clock_is_polled_less_and_less() -> Result<(), String> {
        static PROBES: std::sync::Mutex<Vec<(PublicKey, tokio::time::Instant)>> =
            std::sync::Mutex::new(Vec::new());
        let error = |error: tally_wire::WireError| error.to_string();
        let seed = relay("127.0.0.1:9")?;
        let feeder = Arc::new(Identity::generate().map_err(error)?);
        let directory = Directory::new(
            scratch(),
            vec![seed.clone()],
            Vec::new(),
            feeder.clone(),
            None,
            (Clock::Dump1090, Arc::default()),
        )?;
        let wall = Arc::new(std::sync::atomic::AtomicU64::new(wall_ms()));
        let monotonic = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let clocks = Arc::new(
            RelayClocks::on(crate::source::HostClock::set_by(&wall, &monotonic))
                .configured([seed.key]),
        );
        let (batches, _) = broadcast::channel(64);
        let started = tokio::time::Instant::now();
        let publisher = tokio::spawn(run(Publishing {
            directory,
            identity: feeder,
            batches,
            ceiling: 64_000,
            wanted: Arc::default(),
            clocks: Arc::clone(&clocks),
            checker: DeliveryChecker::default(),
            checking: Checking::default(),
            prober: |relay, _, clocks| {
                Box::pin(async move {
                    if let Ok(mut probes) = PROBES.lock() {
                        probes.push((relay.key, tokio::time::Instant::now()));
                    }
                    tokio::time::sleep(Duration::from_millis(200)).await;
                    let at = clocks.stamp_ms();
                    Ok(Probed {
                        measured: crate::probe::tests::measured(relay.key, 20, 4, 1),
                        hints: Vec::new(),
                        clock: Some(crate::probe::ProbedClock {
                            asked_ms: at,
                            heard_ms: at,
                            took_ms: wall_ms(),
                            sent_ms: wall_ms(),
                            error_ms: Some(u64::MAX),
                        }),
                    })
                })
            },
            source_address: None,
            health: Arc::default(),
            pacing: Pacing::default(),
        }));
        // The batcher reads the clock as it signs, each second: each read with the seed unheard
        // asks for a probe of it.
        let hour = Duration::from_secs(3_600);
        while started.elapsed() < hour {
            let _ = clocks.now_ms();
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
        publisher.abort();
        let probes = PROBES.lock().map_err(|error| error.to_string())?.clone();
        let all = probes.iter().filter(|(key, _)| *key == seed.key).count();
        assert!(all <= 45, "{all} probes of the seed in an hour");
        Ok(())
    }

    #[test]
    fn full_leaving_and_refused_are_leave_me_and_the_rest_retry() {
        for reason in [Reason::Full, Reason::Leaving, Reason::Refused] {
            assert!(matches!(
                goodbye(reason, 60, CLOCK_RETRY),
                Outcome::Leave(_)
            ));
        }
        for reason in [Reason::Protocol, Reason::Version, Reason::Other(9)] {
            assert!(matches!(
                goodbye(reason, 60, CLOCK_RETRY),
                Outcome::Retry(_)
            ));
        }
    }

    /// A clock goodbye that says to come back at once (`retry_after_secs` 0) still waits the
    /// protocol's minute (`CLOCK_RETRY`): before, it was redialled about once a second for ever.
    #[test]
    fn a_clock_goodbye_waits_at_least_the_clock_retry() {
        assert_eq!(
            goodbye(Reason::Clock, 0, CLOCK_RETRY),
            Outcome::Retry(CLOCK_RETRY)
        );
        assert_eq!(
            goodbye(Reason::Clock, 90, CLOCK_RETRY),
            Outcome::Retry(Duration::from_secs(90))
        );
        assert_eq!(CLOCK_RETRY, Duration::from_secs(60));
    }

    /// The moment a test's ends are judged from: any instant, the judging is relative.
    fn ends_at() -> tokio::time::Instant {
        tokio::time::Instant::now()
    }

    /// RFC-0171 §3.6: whatever reason a relay gives, a session that reached it and ended short
    /// counts against it, but only two in a row replace it, and only while another session stayed
    /// up through each. One short session replaces nobody; a healthy one between clears the run.
    /// Before, the first short session replaced its relay, so an honest relay's one bad moment
    /// cost it every feeder.
    #[test]
    fn a_relay_is_replaced_after_two_short_sessions_in_a_row_while_another_stayed_up()
    -> Result<(), String> {
        let (relay, other) = (key()?, key()?);
        let t0 = ends_at();
        let stayed = |held: &(PublicKey, u64)| *held == (other, 1);
        let mut ends = Ends::default();
        for reason in [Reason::Clock, Reason::Protocol, Reason::Other(9)] {
            assert_eq!(
                after(&Ok(goodbye(reason, 90, CLOCK_RETRY))),
                Next::Redial {
                    wait: Duration::from_secs(90)
                },
                "{reason:?}"
            );
        }
        let short = Span {
            reached: true,
            up_for: Some(HEALTHY_SESSION / 2),
        };
        assert!(short.short());
        ends.ended(relay, t0, (short.short(), false), vec![(other, 1)]);
        assert_eq!(ends.next_due(), Some(t0 + ENDED_TOGETHER));
        assert!(
            ends.judge(t0 + ENDED_TOGETHER - Duration::from_millis(1), stayed)
                .is_empty()
        );
        assert!(
            ends.judge(t0 + ENDED_TOGETHER, stayed).is_empty(),
            "one short session"
        );
        // A healthy session clears the run: one more is again only one.
        ends.ended(relay, t0 + HEALTHY_SESSION, (false, true), vec![(other, 1)]);
        let t1 = t0 + HEALTHY_SESSION * 2;
        ends.ended(relay, t1, (true, false), vec![(other, 1)]);
        assert!(ends.judge(t1 + ENDED_TOGETHER, stayed).is_empty());
        // The second in a row replaces it.
        let t2 = t1 + Duration::from_secs(1);
        ends.ended(relay, t2, (true, false), vec![(other, 1)]);
        assert_eq!(ends.judge(t2 + ENDED_TOGETHER, stayed), vec![relay]);
        assert_eq!(ends.next_due(), None);
        Ok(())
    }

    /// RFC-0171 §3.6: an honest relay restarting is replaced by no feeder. Its long session ends
    /// (healthy), and the feeder's dials while it is down never reach it (refused, timed out): none
    /// of them counts against it, however many. Before, the first refused redial replaced it.
    #[test]
    fn an_honest_relay_restarting_is_replaced_by_no_one() -> Result<(), String> {
        let (relay, other) = (key()?, key()?);
        let t0 = ends_at();
        let mut ends = Ends::default();
        let long = Span {
            reached: true,
            up_for: Some(HEALTHY_SESSION * 60),
        };
        let unreached = Span::default();
        assert!(!long.short() && !unreached.short());
        ends.ended(
            relay,
            t0,
            (long.short(), healthy(long.up_for, false)),
            vec![(other, 1)],
        );
        for dial in 0..10 {
            ends.ended(
                relay,
                t0 + Duration::from_secs(dial),
                (unreached.short(), healthy(unreached.up_for, false)),
                vec![(other, 1)],
            );
        }
        assert_eq!(ends.next_due(), None);
        assert!(ends.judge(t0 + ENDED_TOGETHER * 10, |_| true).is_empty());
        Ok(())
    }

    /// RFC-0171 §3.6: a flap of the feeder's own network ends every session it holds together,
    /// and blames no one, however often it happens: each end waits `ENDED_TOGETHER`, and no session
    /// that was up when it ended stayed up. An end while an audit was in progress (dodging it)
    /// counts only if another session stayed up; with the other relay's session up throughout, two
    /// dodged audits replace the relay. Before, a flap during an audit replaced the audited relay
    /// however long its session had been up.
    #[test]
    fn a_feeder_network_flap_replaces_no_one_and_a_dodged_audit_counts_only_beside_a_live_session()
    -> Result<(), String> {
        let (relay, other) = (key()?, key()?);
        let mut ends = Ends::default();
        let mut checker = DeliveryChecker::default();
        let short = Span {
            reached: true,
            up_for: Some(Duration::from_secs(5)),
        };
        let mut at = ends_at();
        for flap in 0..20 {
            assert_eq!(checker.audit(&[relay], |_| true), Some(relay));
            let dodged = checker.session_ended(relay);
            assert!(dodged);
            ends.ended(
                relay,
                at,
                (short.short() || dodged, false),
                vec![(other, flap)],
            );
            ends.ended(other, at, (short.short(), false), vec![(relay, flap)]);
            // Neither session is up now: the generations that were up have ended.
            let up_now = |held: &(PublicKey, u64)| held.1 == flap + 1;
            assert!(ends.judge(at + ENDED_TOGETHER, up_now).is_empty(), "{flap}");
            at += ENDED_TOGETHER * 2;
        }
        // Dodged audits while the other relay's session stays up: held, and two replace it.
        let long = Some(HEALTHY_SESSION * 10);
        for round in 0..2 {
            assert_eq!(checker.audit(&[relay], |_| true), Some(relay));
            let dodged = checker.session_ended(relay);
            assert!(!healthy(long, dodged));
            ends.ended(
                relay,
                at,
                (dodged, healthy(long, dodged)),
                vec![(other, 99)],
            );
            let replaced = ends.judge(at + ENDED_TOGETHER, |held| *held == (other, 99));
            assert_eq!(replaced, if round == 1 { vec![relay] } else { Vec::new() });
            at += ENDED_TOGETHER * 2;
        }
        Ok(())
    }
}
