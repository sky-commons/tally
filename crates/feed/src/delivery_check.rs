//! The delivery check (RFC-0174 §2.2, RFC-0181 §7): every key period the feeder gives every
//! member of its area's sharing group a tag key of that member's own (`Keyring`, carried signed in
//! a `DeliveryQuery`), and a member tags each of the feeder's batches with it as the batch arrives.
//! Every few minutes the feeder samples a few of its recent batches and asks several members, on
//! distinct networks, for those tags (`DeliveryQuery`, `DeliveryAnswer`). A batch is delivered when
//! a majority of the networks that answered for it prove it; a relay whose batches fail that
//! majority is switched away from and remembered as one that swallows (avoided for days, saved
//! across restarts). One member's word alone convicts no one, and "I do not take this area" is no
//! evidence.
//!
//! Decisions the RFC leaves to the build:
//! - **Audited batches.** A feeder sends every batch to both its relays, so a batch one of them
//!   swallows still reaches the group through the other, and the group cannot say which relay
//!   failed. Each check therefore audits one held relay in turn: the next `SAMPLED` batches go to
//!   that relay alone (`audit`), and only those are sampled, so a verdict always names the one
//!   relay that alone carried the batches. A swallower is caught within two checks. When the
//!   audit ends, every audited batch the audited relay's session did not write (or every one, if
//!   that session ended during the audit) is sent to the other relay after all
//!   (`relays::Ledger::end_audit`), so an audit never costs the network a batch.
//! - **No one to ask, no audit.** A relay is audited only when the area has members to ask about
//!   it; otherwise nothing is held back from the other relay.
//! - **Batches are named by boot and sequence.** The proof is the tag the member made on arrival,
//!   a keyed hash of the batch's whole signed bytes under the key this feeder gave that member
//!   (`tally_wire::delivery_tag`), and the feeder checks it against its own copy of the audited
//!   batches, so a proof binds the exact batch and naming it by its hash would add nothing. A tag
//!   counts only under a key the feeder gave that member that was in force when the batch was sent
//!   (`tally_wire::delivery::tag_keys_for`): a tag under an older key (a replay) is no proof.
//! - **Keys on a schedule, never per audit.** The keys go to the members drawn at random for the
//!   period (at most `KEYED_MEMBERS` of every member the feeder may ask, drawn afresh each period,
//!   the keys of a member not drawn dropped: `Keyring`), every period, whether or not an audit
//!   runs, so a member learns nothing of when one does or of which batches it covers, and cannot
//!   tip off the relay audited. Only a member drawn and holding a key for the period is asked. The feeder keeps the bytes of the audited batches alone, and asks only
//!   within `TAG_WINDOW_MS` of sending, the window a member keeps its tags for.
//! - **Who counts.** An answer counts when it is signed by the member asked, names this query's
//!   nonce, this feeder and this boot, and says the member takes the area. The audited relay is
//!   never asked: it is the one being checked. The members asked are on networks known distinct
//!   from each other (`tally_wire::rendezvous::distinct_networks`: declared networks and observed
//!   address prefixes both differ), and at most one more whose network is not known (declared 0,
//!   or never observed), not known to share any asked member's, so unknowns cannot outvote.
//! - **Majority, per batch, over what was said.** A network votes on a batch only when one of its
//!   members said something of it: a proof that verifies against the batch, or a signed "not
//!   seen". A sequence a member left out is no vote: a relay leaves out the batches it held and
//!   has let go (`tally-relay`'s `delivery`), which says nothing against anyone. A network proves
//!   the batch when any of its members does. Delivered: more than half of the networks voting
//!   prove it. Failed: at least two networks voted and fewer than half prove it. A proof that does
//!   not verify proves nothing and denies nothing. Anything else says nothing.
//! - **An audit whose relay's session ended is void.** A relay that said "leave me" (a redirect, a
//!   full or leaving goodbye), restarted, or dropped the connection since the audit began may not
//!   have carried batches it was written, which is not swallowing them silently: the check says
//!   nothing of it (`session_ended`). A batch is listed as sent to a relay only once its session
//!   wrote it.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use tally_wire::delivery::{
    KEY_PERIOD_MS, Possession, SequenceRange, TAG_KEY_LEN, TAG_WINDOW_MS, TagKey, TagKeys,
    TagKeysContent, delivery_tag, key_period, tag_keys_for,
};
use tally_wire::noise;
use tally_wire::rendezvous::{Placement, distinct_networks, same_network};
use tally_wire::{
    Batch, DeliveryAnswer, DeliveryQuery, Identity, ProviderOffer, PublicKey, Record, Region,
    RelayAddress, Role, Streams,
};
use tokio::net::TcpStream;

use crate::source::wall_ms;

/// How often a check runs.
pub const CHECK_EVERY: Duration = Duration::from_secs(5 * 60);
/// Batches sampled per check.
pub const SAMPLED: usize = 4;
/// Members asked per check, on distinct networks.
pub const ASKED: usize = 3;
/// How long a relay found swallowing is avoided.
pub const AVOID_FOR: Duration = Duration::from_secs(3 * 24 * 3600);
/// How long an audit holds batches back from the other relay: batches are sealed about once a
/// second (`source`), so `SAMPLED` of them and a margin.
pub const AUDIT_FOR: Duration = Duration::from_secs(SAMPLED as u64 + 3);
/// How long after the audit ends the members are asked: time for the group to carry its batches.
pub const SETTLE: Duration = Duration::from_secs(30);
/// How often the members are given keys: a member new to the area, or one whose keys the period
/// has moved past, is given them within this long.
pub const GRANT_EVERY: Duration = Duration::from_secs(60);
/// The most members of the area given keys: every one the feeder may ask, at most this many.
pub const KEYED_MEMBERS: usize = 16;
/// The longest one member is waited for.
const ASK_TIMEOUT: Duration = Duration::from_secs(15);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// How long after sending a batch it may be asked about: the window a member keeps its tag for,
/// less the longest an ask takes, so the tag is still held when the question arrives.
pub const ASK_WITHIN_MS: u64 = TAG_WINDOW_MS - 2 * 15_000;
/// The state file of relays found swallowing.
const STATE_FILE: &str = "swallowers";

/// One of the feeder's audited batches, the relays its sessions wrote it to, and when (wall-clock
/// milliseconds) it was first written: which of its keys a tag of it may be under.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Sent {
    pub batch: Batch,
    pub relays: Vec<PublicKey>,
    pub sent_ms: u64,
}

/// One member's tag keys, by id (key period).
type MemberKeys = BTreeMap<u32, [u8; TAG_KEY_LEN]>;

/// The members drawn to be given tag keys, and the keys the feeder gave each, by id (key period):
/// the current period's and the next, and the two before, which tags of batches sent within the
/// window may be under. Older keys are forgotten, so a tag under one proves nothing.
///
/// **Who is keyed is drawn, never kept.** At most `KEYED_MEMBERS` members hold keys, drawn at
/// random from every member the feeder may ask afresh each key period (`draw`); a member not drawn
/// is given no key and its keys are dropped. So no fixed few are always the judges: whoever was
/// keyed first (a set of keys that reached the feeder first after a restart) holds the set for a
/// period at most, and every member of the area is drawn in turn.
#[derive(Default)]
pub struct Keyring {
    keys: HashMap<PublicKey, MemberKeys>,
    /// The members drawn, and the key period they were drawn for.
    drawn: HashSet<PublicKey>,
    drawn_for: Option<u32>,
}

impl Keyring {
    /// The members to give keys at `now_ms`, of `candidates` (every member the feeder may ask):
    /// at the first draw of a key period, `KEYED_MEMBERS` of them at random, and every key of a
    /// member not drawn dropped; later in the period, a member drawn stays drawn and a place left
    /// is filled at random from the rest. The members drawn among `candidates`, and the keys
    /// dropped (which a check already asked may still need to read its answers: `DeliveryChecker`).
    pub fn draw(
        &mut self,
        candidates: &[PublicKey],
        now_ms: u64,
    ) -> (Vec<PublicKey>, Vec<(PublicKey, MemberKeys)>) {
        let period = key_period(now_ms);
        if self.drawn_for != Some(period) {
            self.drawn_for = Some(period);
            self.drawn.clear();
        }
        let mut rest: Vec<PublicKey> = candidates
            .iter()
            .filter(|candidate| !self.drawn.contains(*candidate))
            .copied()
            .collect();
        rest.sort_unstable_by(|one, other| one.as_bytes().cmp(other.as_bytes()));
        rest.dedup();
        shuffle(&mut rest);
        let room = KEYED_MEMBERS.saturating_sub(self.drawn.len());
        self.drawn.extend(rest.into_iter().take(room));
        let dropped: Vec<PublicKey> = self
            .keys
            .keys()
            .filter(|member| !self.drawn.contains(*member))
            .copied()
            .collect();
        let dropped = dropped
            .into_iter()
            .filter_map(|member| self.keys.remove(&member).map(|keys| (member, keys)))
            .collect();
        let drawn = candidates
            .iter()
            .filter(|candidate| self.drawn.contains(*candidate))
            .copied()
            .collect();
        (drawn, dropped)
    }

    /// `member`'s grant at `now_ms`, signed by the feeder: the keys of this period and the next,
    /// made fresh the first time each is given and the same every time after. None for a member
    /// not drawn (`draw`).
    pub fn grant(
        &mut self,
        identity: &Identity,
        member: PublicKey,
        now_ms: u64,
    ) -> Option<TagKeys> {
        let period = key_period(now_ms);
        self.forget(now_ms);
        if !self.drawn.contains(&member) {
            return None;
        }
        let held = self.keys.entry(member).or_default();
        let mut key = |id: u32| TagKey {
            id,
            key: *held.entry(id).or_insert_with(random_hash),
        };
        let (current, next) = (key(period), key(period.checked_add(1)?));
        TagKeys::sign(
            identity,
            &TagKeysContent {
                member,
                current,
                next,
                switch_in_ms: KEY_PERIOD_MS - now_ms % KEY_PERIOD_MS,
            },
        )
        .ok()
    }

    /// Whether `member` is drawn and was given the key in force at `now_ms`: one that may be
    /// asked.
    pub fn keyed(&self, member: &PublicKey, now_ms: u64) -> bool {
        self.drawn.contains(member)
            && self
                .keys
                .get(member)
                .is_some_and(|held| held.contains_key(&key_period(now_ms)))
    }

    /// The key `id` given `member`, while it is kept.
    fn key(&self, member: &PublicKey, id: u32) -> Option<&[u8; TAG_KEY_LEN]> {
        self.keys.get(member)?.get(&id)
    }

    /// Whether `tag` is `member`'s tag of `sent`: under a key it was given that was in force when
    /// the batch was sent, over the batch's bytes. `dropped` are keys dropped since the check was
    /// asked, still read for its answers.
    fn proves(
        &self,
        member: &PublicKey,
        dropped: &HashMap<PublicKey, MemberKeys>,
        sent: &Sent,
        (key, tag): (u32, &tally_wire::Tag),
    ) -> bool {
        tag_keys_for(sent.sent_ms).contains(&key)
            && self
                .key(member, key)
                .or_else(|| dropped.get(member)?.get(&key))
                .is_some_and(|held| delivery_tag(held, sent.batch.as_bytes()) == *tag)
    }

    /// Forgets keys older than any a tag of a batch still askable about may be under, and members
    /// with none left.
    fn forget(&mut self, now_ms: u64) {
        let oldest = key_period(now_ms).saturating_sub(2);
        self.keys.retain(|_, held| {
            held.retain(|id, _| *id >= oldest);
            !held.is_empty()
        });
    }
}

/// What one check found of the relays the sampled batches were sent to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// A majority of networks proved every sampled batch.
    Delivered,
    /// These relays' batches failed the majority.
    Swallowed(Vec<PublicKey>),
    /// Too few answers to say.
    Unknown,
}

/// A member of the area's sharing group to ask.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Member {
    pub relay: RelayAddress,
    /// The autonomous system its signed offer names; 0 when it does not say.
    pub network: u32,
    /// The address the feeder observed it at, if it has.
    pub host: Option<IpAddr>,
}

impl Member {
    fn placement(&self) -> Placement {
        Placement {
            network: self.network,
            host: self.host,
        }
    }
}

/// The check asked and not yet judged.
struct Pending {
    query: DeliveryQuery,
    batches: Vec<Sent>,
    /// Keys dropped by a draw since it was asked (`Keyring::draw`): its answers are read under
    /// them still, and they go with it.
    dropped: HashMap<PublicKey, MemberKeys>,
}

/// The audit in progress: the relay audited, and whether its session ended since it began.
#[derive(Clone, Copy, Debug)]
struct Audit {
    relay: PublicKey,
    void: bool,
}

/// How often the checks run and how long each stage takes. The feeder's is `Checking::default()`.
#[derive(Clone, Copy, Debug)]
pub struct Checking {
    /// How often a check begins.
    pub every: Duration,
    /// How long an audit holds batches back from the other relay.
    pub audit_for: Duration,
    /// How long after the audit the members are asked.
    pub settle: Duration,
    /// How often the members are given keys they lack for the period.
    pub grant_every: Duration,
}

impl Default for Checking {
    fn default() -> Self {
        Self {
            every: CHECK_EVERY,
            audit_for: AUDIT_FOR,
            settle: SETTLE,
            grant_every: GRANT_EVERY,
        }
    }
}

/// The feeder's delivery checks, and its saved memory of relays that swallow.
#[derive(Default)]
pub struct DeliveryChecker {
    /// Where the memory is saved; none keeps it in memory only.
    state_dir: Option<PathBuf>,
    /// Relays found swallowing, and until when (wall-clock milliseconds) they are avoided.
    swallowers: HashMap<PublicKey, u64>,
    audit: Option<Audit>,
    pending: Option<Pending>,
    audits: usize,
    /// The tag keys given the members.
    pub keyring: Keyring,
}

impl DeliveryChecker {
    /// A checker whose memory is saved in `state_dir`, with what an earlier run saved there.
    pub fn load(state_dir: &Path) -> Self {
        let swallowers = std::fs::read_to_string(state_dir.join(STATE_FILE))
            .map(|text| text.lines().filter_map(read_swallower).collect())
            .unwrap_or_default();
        Self {
            state_dir: Some(state_dir.to_path_buf()),
            swallowers,
            ..Self::default()
        }
    }

    /// Begins the next audit: of the `held` relays (with a session up), the next in turn that
    /// `askable` says the area has members to ask about. Its next `SAMPLED` batches go to it
    /// alone. None, and no audit, when no held relay can be asked about.
    pub fn audit(
        &mut self,
        held: &[PublicKey],
        askable: impl Fn(&PublicKey) -> bool,
    ) -> Option<PublicKey> {
        let relay = (0..held.len())
            .map(|step| held[self.audits.wrapping_add(step) % held.len()])
            .find(|relay| askable(relay))?;
        self.audits = self.audits.wrapping_add(1);
        self.audit = Some(Audit { relay, void: false });
        self.pending = None;
        Some(relay)
    }

    /// The members of `candidates` (every member the feeder may ask) to give keys at `now_ms`
    /// (`Keyring::draw`). The keys of members not drawn are dropped, but for the check in flight,
    /// which reads its answers under them still.
    pub fn draw(&mut self, candidates: Vec<Member>, now_ms: u64) -> Vec<Member> {
        let keys: Vec<PublicKey> = candidates.iter().map(|member| member.relay.key).collect();
        let (drawn, dropped) = self.keyring.draw(&keys, now_ms);
        if let Some(pending) = &mut self.pending {
            pending.dropped.extend(dropped);
        }
        candidates
            .into_iter()
            .filter(|member| drawn.contains(&member.relay.key))
            .collect()
    }

    /// Whether a check has begun and is not yet judged or dropped.
    pub fn in_progress(&self) -> bool {
        self.audit.is_some()
    }

    /// `relay`'s session ended (it said "leave me", restarted, or the connection failed): if it is
    /// the relay audited, the audit says nothing of it.
    pub fn session_ended(&mut self, relay: PublicKey) {
        if let Some(audit) = &mut self.audit
            && audit.relay == relay
        {
            audit.void = true;
        }
    }

    /// A query over a sample of `recent` (the feeder's audited batches, newest last, each with the
    /// relays it was written to): the newest `SAMPLED` that the audited relay alone was written,
    /// sent within `ASK_WITHIN_MS`, of the newest boot among them. None with no audit, a void one,
    /// or none of those. It carries no keys: each member's are added as it is asked.
    pub fn sample(&mut self, recent: &[Sent]) -> Option<DeliveryQuery> {
        self.sample_at(recent, wall_ms())
    }

    fn sample_at(&mut self, recent: &[Sent], now_ms: u64) -> Option<DeliveryQuery> {
        let audit = self.audit.filter(|audit| !audit.void)?;
        let solo = |sent: &&Sent| {
            sent.relays == [audit.relay] && now_ms.saturating_sub(sent.sent_ms) < ASK_WITHIN_MS
        };
        let newest = recent.iter().rev().find(solo)?;
        let boot_id = newest.batch.boot_id();
        let receiver = newest.batch.receiver().ok()?;
        let mut chosen: BTreeMap<u64, Sent> = BTreeMap::new();
        for sent in recent
            .iter()
            .rev()
            .filter(solo)
            .filter(|sent| sent.batch.boot_id() == boot_id)
            .take(SAMPLED)
        {
            chosen.insert(sent.batch.sequence(), sent.clone());
        }
        let query = DeliveryQuery {
            nonce: random_hash(),
            receiver,
            boot_id,
            ranges: ranges(chosen.keys().copied()),
            keys: None,
        };
        self.pending = Some(Pending {
            query: query.clone(),
            batches: chosen.into_values().collect(),
            dropped: HashMap::new(),
        });
        Some(query)
    }

    /// The check is dropped unasked (no member to ask).
    pub fn abandon(&mut self) {
        self.pending = None;
        self.audit = None;
    }

    /// The relays the pending check's batches were sent to, which are not asked.
    pub fn checked_relays(&self) -> Vec<PublicKey> {
        let mut relays: Vec<PublicKey> = self
            .pending
            .iter()
            .flat_map(|pending| pending.batches.iter().flat_map(|sent| sent.relays.clone()))
            .collect();
        relays.sort_unstable_by(|one, other| one.as_bytes().cmp(other.as_bytes()));
        relays.dedup();
        relays
    }

    /// The verdict from the members' answers, each with the network its member is on.
    pub fn judge(&mut self, query: &DeliveryQuery, answers: &[(u32, DeliveryAnswer)]) -> Verdict {
        self.judge_at(query, answers, wall_ms())
    }

    fn judge_at(
        &mut self,
        query: &DeliveryQuery,
        answers: &[(u32, DeliveryAnswer)],
        now_ms: u64,
    ) -> Verdict {
        let Some(pending) = self
            .pending
            .take_if(|pending| pending.query.nonce == query.nonce)
        else {
            return Verdict::Unknown;
        };
        if self.audit.take().is_none_or(|audit| audit.void) {
            return Verdict::Unknown;
        }
        let checked: HashSet<PublicKey> = pending
            .batches
            .iter()
            .flat_map(|sent| sent.relays.iter().copied())
            .collect();
        // Per network, per sequence some member of it said something of: whether it proved it.
        // A sequence no member of a network named is no vote of that network's.
        let mut networks: HashMap<u32, HashMap<u64, bool>> = HashMap::new();
        let mut signers = HashSet::new();
        for (network, answer) in answers {
            let Ok(signer) = answer.signer() else {
                continue;
            };
            if checked.contains(&signer) || !signers.insert(signer) || answer.verify().is_err() {
                continue;
            }
            let Ok(content) = answer.content() else {
                continue;
            };
            if content.nonce != query.nonce
                || content.receiver != query.receiver
                || content.boot_id != query.boot_id
                || !content.takes_area
            {
                continue;
            }
            let said = networks.entry(*network).or_default();
            for (sequence, possession) in content.entries {
                let Some(sent) = pending
                    .batches
                    .iter()
                    .find(|sent| sent.batch.sequence() == sequence)
                else {
                    continue;
                };
                let proved = match possession {
                    Possession::Proved { key, tag } => {
                        if !self
                            .keyring
                            .proves(&signer, &pending.dropped, sent, (key, &tag))
                        {
                            // Not this member's tag of this batch under a key in force when it was
                            // sent: it proves nothing and denies nothing.
                            continue;
                        }
                        true
                    }
                    Possession::NotSeen => false,
                };
                *said.entry(sequence).or_insert(false) |= proved;
            }
        }
        let mut convicted: Vec<PublicKey> = Vec::new();
        let mut delivered = 0;
        for sent in &pending.batches {
            let sequence = sent.batch.sequence();
            let votes: Vec<bool> = networks
                .values()
                .filter_map(|said| said.get(&sequence).copied())
                .collect();
            let voting = votes.len();
            let proving = votes.iter().filter(|proved| **proved).count();
            if voting > 0 && 2 * proving > voting {
                delivered += 1;
            } else if voting >= 2 && 2 * proving < voting {
                for relay in &sent.relays {
                    if !convicted.contains(relay) {
                        convicted.push(*relay);
                    }
                }
            }
        }
        if !convicted.is_empty() {
            convicted.sort_unstable_by(|one, other| one.as_bytes().cmp(other.as_bytes()));
            self.remember(&convicted, now_ms);
            return Verdict::Swallowed(convicted);
        }
        if delivered == pending.batches.len() && delivered > 0 {
            Verdict::Delivered
        } else {
            Verdict::Unknown
        }
    }

    fn remember(&mut self, relays: &[PublicKey], now_ms: u64) {
        let until = now_ms.saturating_add(u64::try_from(AVOID_FOR.as_millis()).unwrap_or(u64::MAX));
        for relay in relays {
            self.swallowers.insert(*relay, until);
        }
        self.save(now_ms);
    }

    fn save(&mut self, now_ms: u64) {
        self.swallowers.retain(|_, until| *until > now_ms);
        let Some(state_dir) = &self.state_dir else {
            return;
        };
        let mut text = String::new();
        for (relay, until) in &self.swallowers {
            text.push_str(&format!("{relay} {until}\n"));
        }
        let path = state_dir.join(STATE_FILE);
        let written = std::fs::create_dir_all(state_dir)
            .and_then(|()| std::fs::write(path.with_extension("new"), text))
            .and_then(|()| std::fs::rename(path.with_extension("new"), &path));
        if let Err(error) = written {
            eprintln!("tally-feed: saving {}: {error}", path.display());
        }
    }

    /// The relays to avoid now (saved across restarts).
    pub fn avoided(&self) -> Vec<PublicKey> {
        self.avoided_at(wall_ms())
    }

    fn avoided_at(&self, now_ms: u64) -> Vec<PublicKey> {
        self.swallowers
            .iter()
            .filter(|(_, until)| **until > now_ms)
            .map(|(relay, _)| *relay)
            .collect()
    }
}

/// `KEY UNTIL_MS`, as the state file keeps a swallower.
fn read_swallower(line: &str) -> Option<(PublicKey, u64)> {
    let (key, until) = line.trim().split_once(' ')?;
    Some((
        PublicKey::from_base64(key.trim()).ok()?,
        until.trim().parse().ok()?,
    ))
}

/// Ascending sequences as the fewest ranges.
fn ranges(sequences: impl Iterator<Item = u64>) -> Vec<SequenceRange> {
    let mut ranges: Vec<SequenceRange> = Vec::new();
    for sequence in sequences {
        match ranges.last_mut() {
            Some(range) if range.last.checked_add(1) == Some(sequence) => range.last = sequence,
            _ => ranges.push(SequenceRange {
                first: sequence,
                last: sequence,
            }),
        }
    }
    ranges
}

/// A fresh nonce for a query.
pub fn fresh_nonce() -> [u8; 32] {
    random_hash()
}

fn random_hash() -> [u8; 32] {
    let mut bytes = [0; 32];
    let _ = getrandom::getrandom(&mut bytes);
    bytes
}

/// The members of `area`'s sharing group to ask, from the offers a relay gave: signed, alive at
/// `now_ms`, for the area or a cell above it, carrying raw, not one of `exclude`, given the key in
/// force now (`keyed`, from the `Keyring`: one without it has no tag to give); at most `ASKED`,
/// chosen at random, each on a network known distinct from every other chosen
/// (`rendezvous::distinct_networks`, over the offer's declared network and the address the feeder
/// observed it at, from `observed`), and at most one more whose network is not known, not known
/// to share one with any chosen. So no fixed few are always the judges, and no network judges
/// twice.
pub fn members(
    offers: &[ProviderOffer],
    area: Region,
    exclude: &[PublicKey],
    observed: &HashMap<PublicKey, IpAddr>,
    keyed: impl Fn(&PublicKey) -> bool,
    now_ms: u64,
) -> Vec<Member> {
    let mut candidates = candidates(offers, area, exclude, observed, now_ms);
    candidates.retain(|member| keyed(&member.relay.key));
    shuffle(&mut candidates);
    let known = |member: &Member| member.network != 0 && member.host.is_some();
    let mut chosen: Vec<Member> = Vec::new();
    for member in candidates.iter().filter(|member| known(member)) {
        if chosen.len() < ASKED
            && chosen
                .iter()
                .all(|other| distinct_networks(other.placement(), member.placement()))
        {
            chosen.push(member.clone());
        }
    }
    if let Some(unknown) = candidates.iter().find(|member| {
        !known(member)
            && chosen
                .iter()
                .all(|other| !same_network(other.placement(), member.placement()))
    }) && chosen.len() < ASKED
    {
        chosen.push(unknown.clone());
    }
    chosen
}

/// Every member of `area`'s sharing group the feeder may ask (the offers `members` chooses from,
/// none excluded): what the members given tag keys are drawn from (`DeliveryChecker::draw`).
pub fn keyable(
    offers: &[ProviderOffer],
    area: Region,
    observed: &HashMap<PublicKey, IpAddr>,
    now_ms: u64,
) -> Vec<Member> {
    candidates(offers, area, &[], observed, now_ms)
}

/// The members `offers` name for `area`: signed, alive at `now_ms`, for the area or a cell above
/// it, carrying raw, not one of `exclude`, each once.
fn candidates(
    offers: &[ProviderOffer],
    area: Region,
    exclude: &[PublicKey],
    observed: &HashMap<PublicKey, IpAddr>,
    now_ms: u64,
) -> Vec<Member> {
    let mut candidates: Vec<Member> = Vec::new();
    let mut seen = HashSet::new();
    for offer in offers {
        let (Ok(signer), Ok(())) = (offer.signer(), offer.verify()) else {
            continue;
        };
        let Ok(content) = offer.content() else {
            continue;
        };
        if exclude.contains(&signer)
            || !seen.insert(signer)
            || content.expires_ms <= now_ms
            || !content.cell.contains(area)
            || !content.products.contains(Streams::RAW)
        {
            continue;
        }
        candidates.push(Member {
            relay: RelayAddress {
                key: signer,
                address: content.address,
            },
            network: content.network,
            host: observed.get(&signer).copied(),
        });
    }
    candidates
}

fn shuffle<T>(items: &mut [T]) {
    for at in (1..items.len()).rev() {
        let mut bytes = [0; 8];
        let _ = getrandom::getrandom(&mut bytes);
        let other = usize::try_from(u64::from_be_bytes(bytes) % (at as u64 + 1)).unwrap_or(0);
        items.swap(at, other);
    }
}

/// Asks `member` the query (with its keys, or carrying only keys); its signed answer, if it gave
/// one signed by its key.
pub async fn ask(
    member: &RelayAddress,
    me: &Identity,
    query: &DeliveryQuery,
) -> Option<DeliveryAnswer> {
    tokio::time::timeout(ASK_TIMEOUT, ask_once(member, me, query))
        .await
        .ok()
        .flatten()
}

async fn ask_once(
    member: &RelayAddress,
    me: &Identity,
    query: &DeliveryQuery,
) -> Option<DeliveryAnswer> {
    let stream = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(&member.address))
        .await
        .ok()?
        .ok()?;
    let session = noise::connect_with(
        stream,
        me,
        &member.key,
        Role::Probe,
        &[Record::DeliveryQuery(query.clone())],
    )
    .await
    .ok()?;
    let mut reader = session.reader;
    loop {
        let mut got = Vec::new();
        reader.recv(&mut got).await.ok()?;
        for record in got {
            match record {
                Record::DeliveryAnswer(answer) => {
                    let own = answer.signer().is_ok_and(|signer| signer == member.key);
                    return own.then_some(answer);
                }
                Record::Redirect { .. } | Record::Goodbye { .. } => return None,
                _ => {}
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tally_wire::delivery::DeliveryAnswerContent;
    use tally_wire::directory::ProviderOfferContent;
    use tally_wire::{BatchContent, Location};

    fn error(error: tally_wire::WireError) -> String {
        error.to_string()
    }

    fn identity() -> Result<Identity, String> {
        Identity::generate().map_err(error)
    }

    fn batch(feeder: &Identity, sequence: u64) -> Result<Batch, String> {
        Batch::sign(
            feeder,
            &BatchContent {
                boot_id: 7,
                sequence,
                counter_epoch: 0,
                wall_ms: 1,
                dropped: 0,
                previous: [0; 32],
                observations: Vec::new(),
            },
        )
        .map_err(error)
    }

    struct Setup {
        checker: DeliveryChecker,
        feeder: Identity,
        query: DeliveryQuery,
        batches: Vec<Batch>,
        relay: PublicKey,
        sent_ms: u64,
    }

    /// A member of the area at `key`, as the feeder's directory names it.
    fn member_at(key: PublicKey) -> Member {
        Member {
            relay: RelayAddress {
                key,
                address: "member.example:1".to_owned(),
            },
            network: 0,
            host: None,
        }
    }

    impl Setup {
        /// A member of the area, drawn and given its keys.
        fn member(&mut self) -> Result<Identity, String> {
            let member = identity()?;
            self.give_keys(member.public(), self.sent_ms)?;
            Ok(member)
        }

        /// Draws `member` (a place is left) and gives it its keys at `now_ms`.
        fn give_keys(&mut self, member: PublicKey, now_ms: u64) -> Result<(), String> {
            let drawn = self.checker.draw(vec![member_at(member)], now_ms);
            assert_eq!(drawn.len(), 1, "a place was left");
            self.checker
                .keyring
                .grant(&self.feeder, member, now_ms)
                .ok_or("no grant")?;
            Ok(())
        }

        /// A member's answer: a tag of each of `held` (made as it arrived, under its key in force
        /// when the batch was sent), "not seen" of the rest of `batches`.
        fn answer(&mut self, batches: &[Batch], held: &[u64]) -> Result<DeliveryAnswer, String> {
            let member = self.member()?;
            self.answer_as(&member, batches, held)
        }

        /// `answer` over the first `count` audited batches.
        fn answer_first(&mut self, count: usize, held: &[u64]) -> Result<DeliveryAnswer, String> {
            let batches = self.batches[..count].to_vec();
            self.answer(&batches, held)
        }

        fn answer_as(
            &self,
            member: &Identity,
            batches: &[Batch],
            held: &[u64],
        ) -> Result<DeliveryAnswer, String> {
            let id = key_period(self.sent_ms);
            let key = *self
                .checker
                .keyring
                .key(&member.public(), id)
                .ok_or("no key")?;
            let entries = batches
                .iter()
                .map(|batch| {
                    let sequence = batch.sequence();
                    let possession = if held.contains(&sequence) {
                        Possession::Proved {
                            key: id,
                            tag: delivery_tag(&key, batch.as_bytes()),
                        }
                    } else {
                        Possession::NotSeen
                    };
                    (sequence, possession)
                })
                .collect();
            DeliveryAnswer::sign(
                member,
                &DeliveryAnswerContent {
                    nonce: self.query.nonce,
                    receiver: self.query.receiver,
                    boot_id: self.query.boot_id,
                    issued_ms: 1,
                    takes_area: true,
                    entries,
                },
            )
            .map_err(error)
        }

        fn judge(&mut self, answers: &[(u32, DeliveryAnswer)]) -> Verdict {
            let query = self.query.clone();
            self.checker.judge(&query, answers)
        }
    }

    /// A feeder whose last four batches were audited to one relay, and the query over them.
    fn audited() -> Result<Setup, String> {
        let feeder = identity()?;
        let relay = identity()?.public();
        let other = identity()?.public();
        let sent_ms = wall_ms();
        let mut recent = Vec::new();
        let mut batches = Vec::new();
        for sequence in 0..10 {
            let batch = batch(&feeder, sequence)?;
            let relays = if sequence >= 6 {
                batches.push(batch.clone());
                vec![relay]
            } else {
                vec![relay, other]
            };
            recent.push(Sent {
                batch,
                relays,
                sent_ms,
            });
        }
        let mut checker = DeliveryChecker::default();
        assert_eq!(checker.audit(&[relay], |_| true), Some(relay));
        let query = checker.sample(&recent).ok_or("no sample")?;
        assert_eq!(
            query.ranges,
            vec![SequenceRange { first: 6, last: 9 }],
            "the audited batches are the sample"
        );
        assert_eq!(checker.checked_relays(), vec![relay]);
        Ok(Setup {
            checker,
            feeder,
            query,
            batches,
            relay,
            sent_ms,
        })
    }

    const ALL: &[u64] = &[6, 7, 8, 9];

    #[test]
    fn a_majority_of_networks_proving_is_delivery() -> Result<(), String> {
        let mut setup = audited()?;
        let answers = vec![
            (1, setup.answer_first(4, ALL)?),
            (2, setup.answer_first(4, ALL)?),
            (3, setup.answer_first(4, &[])?),
        ];
        assert_eq!(setup.judge(&answers), Verdict::Delivered);
        assert!(setup.checker.avoided().is_empty());
        Ok(())
    }

    #[test]
    fn one_members_word_alone_convicts_no_one() -> Result<(), String> {
        let mut setup = audited()?;
        let alone = vec![(1, setup.answer_first(4, &[])?)];
        assert_eq!(setup.judge(&alone), Verdict::Unknown);
        // Nor several members of one network: they are one vote.
        let mut setup = audited()?;
        let one_network = vec![
            (5, setup.answer_first(4, &[])?),
            (5, setup.answer_first(4, &[])?),
            (5, setup.answer_first(4, &[])?),
        ];
        assert_eq!(setup.judge(&one_network), Verdict::Unknown);
        assert!(setup.checker.avoided().is_empty());
        Ok(())
    }

    #[test]
    fn a_swallowing_relay_is_caught_by_a_majority_of_networks() -> Result<(), String> {
        let mut setup = audited()?;
        let answers = vec![
            (1, setup.answer_first(4, &[])?),
            (2, setup.answer_first(4, &[])?),
            (3, setup.answer_first(4, ALL)?),
        ];
        assert_eq!(setup.judge(&answers), Verdict::Swallowed(vec![setup.relay]));
        assert_eq!(setup.checker.avoided(), vec![setup.relay]);
        Ok(())
    }

    #[test]
    fn a_relay_that_answers_echoes_but_drops_batches_is_caught_and_a_forged_proof_is_none()
    -> Result<(), String> {
        // The relay is healthy to every probe; only its audited batches say what it does. Two
        // members on two networks have none of them, and a third offers proofs that are not of
        // these batches (it never held them): no proof, no delivery.
        let mut setup = audited()?;
        let liar = setup.member()?;
        let mut forged = setup
            .answer_as(&liar, &setup.batches, &[])?
            .content()
            .map_err(error)?;
        let id = key_period(setup.sent_ms);
        forged.entries = ALL
            .iter()
            .map(|sequence| {
                (
                    *sequence,
                    Possession::Proved {
                        key: id,
                        tag: [0xaa; 16],
                    },
                )
            })
            .collect();
        let forged = DeliveryAnswer::sign(&liar, &forged).map_err(error)?;
        let answers = vec![
            (1, setup.answer_first(4, &[])?),
            (2, setup.answer_first(4, &[])?),
            (3, forged),
        ];
        assert_eq!(setup.judge(&answers), Verdict::Swallowed(vec![setup.relay]));
        Ok(())
    }

    #[test]
    fn a_relay_whose_session_ended_during_its_audit_is_never_counted_as_swallowing()
    -> Result<(), String> {
        // It said "leave me", restarted, or its connection failed after the audit began and
        // before the members were asked: the sample is taken after that, and says nothing.
        let mut setup = audited()?;
        setup.checker.session_ended(setup.relay);
        let answers = vec![
            (1, setup.answer_first(4, &[])?),
            (2, setup.answer_first(4, &[])?),
        ];
        assert_eq!(setup.judge(&answers), Verdict::Unknown);
        assert!(setup.checker.avoided().is_empty());
        // Ended mid-audit, before the sample: there is no sample to take.
        let feeder = identity()?;
        let relay = identity()?.public();
        let recent = (0..4)
            .map(|sequence| {
                Ok(Sent {
                    batch: batch(&feeder, sequence)?,
                    relays: vec![relay],
                    sent_ms: wall_ms(),
                })
            })
            .collect::<Result<Vec<_>, String>>()?;
        let mut checker = DeliveryChecker::default();
        checker.audit(&[relay], |_| true);
        checker.session_ended(relay);
        assert_eq!(checker.sample(&recent), None);
        // Another relay's session ending does not void it.
        checker.audit(&[relay], |_| true);
        checker.session_ended(identity()?.public());
        assert!(checker.sample(&recent).is_some());
        Ok(())
    }

    #[test]
    fn a_sequence_a_member_left_out_is_no_vote() -> Result<(), String> {
        // Two networks answer for the area and leave every sequence out: they held the batches
        // and let them go, which is no signed claim against anyone.
        let mut setup = audited()?;
        let answers = vec![
            (1, setup.answer_first(0, &[])?),
            (2, setup.answer_first(0, &[])?),
        ];
        assert_eq!(setup.judge(&answers), Verdict::Unknown);
        assert!(setup.checker.avoided().is_empty());
        // One network proves every batch; another has let two go and proves the rest. Every
        // batch has a majority of the networks that said anything of it.
        let mut setup = audited()?;
        let answers = vec![
            (1, setup.answer_first(4, ALL)?),
            (2, setup.answer_first(2, ALL)?),
        ];
        assert_eq!(setup.judge(&answers), Verdict::Delivered);
        // A signed "not seen" from a third network on the batches the second let go is a tie on
        // them (one proves, one denies): still no conviction.
        let mut setup = audited()?;
        let answers = vec![
            (1, setup.answer_first(4, ALL)?),
            (2, setup.answer_first(2, ALL)?),
            (3, setup.answer_first(4, &[])?),
        ];
        assert_eq!(setup.judge(&answers), Verdict::Unknown);
        assert!(setup.checker.avoided().is_empty());
        Ok(())
    }

    #[test]
    fn a_proof_binds_the_exact_batch_not_only_its_sequence() -> Result<(), String> {
        // The query names batches by boot and sequence; a relay holding another batch at the same
        // sequence (one the feeder never sent there) cannot prove the one the feeder holds.
        let mut setup = audited()?;
        let other_feeder = identity()?;
        let impostors: Vec<Batch> = ALL
            .iter()
            .map(|sequence| batch(&other_feeder, *sequence))
            .collect::<Result<_, String>>()?;
        let answers = vec![
            (1, setup.answer(&impostors, ALL)?),
            (2, setup.answer_first(4, &[])?),
        ];
        assert_eq!(
            setup.judge(&answers),
            Verdict::Unknown,
            "a proof of another batch proves nothing; one network's denial convicts no one"
        );
        Ok(())
    }

    #[test]
    fn a_tag_under_a_key_not_in_force_when_the_batch_was_sent_is_no_proof() -> Result<(), String> {
        // Two members prove every batch, one under the key it was given for the period the
        // batches were sent in, one under a key three periods old that it kept (a replay of
        // an old key): only the first is a proof, and the old key's network denies nothing.
        let mut setup = audited()?;
        let honest = setup.answer_first(4, ALL)?;
        let replayer = identity()?;
        let old = setup.sent_ms - 3 * KEY_PERIOD_MS;
        setup.give_keys(replayer.public(), old)?;
        // Granting now forgets keys past the window: the old one is gone, as rotation makes it.
        setup.give_keys(replayer.public(), setup.sent_ms)?;
        let stale = [7; TAG_KEY_LEN];
        let replayed = DeliveryAnswer::sign(
            &replayer,
            &DeliveryAnswerContent {
                nonce: setup.query.nonce,
                receiver: setup.query.receiver,
                boot_id: setup.query.boot_id,
                issued_ms: 1,
                takes_area: true,
                entries: setup
                    .batches
                    .iter()
                    .map(|batch| {
                        (
                            batch.sequence(),
                            Possession::Proved {
                                key: key_period(old),
                                tag: delivery_tag(&stale, batch.as_bytes()),
                            },
                        )
                    })
                    .collect(),
            },
        )
        .map_err(error)?;
        let deny = setup.answer_first(4, &[])?;
        // The honest network proves, the replayer says nothing, one network denies: a tie of
        // one each, no verdict. Without the replay counted, nobody is convicted.
        assert_eq!(
            setup.judge(&[(1, honest), (2, replayed), (3, deny)]),
            Verdict::Unknown
        );
        assert!(setup.checker.avoided().is_empty());
        Ok(())
    }

    #[test]
    fn a_tag_made_from_the_batch_hash_alone_is_no_proof() -> Result<(), String> {
        // A member that saw only a piece manifest (which lists the batch's hash) tags the hash:
        // no proof. Two networks deny; the swallower is caught.
        let mut setup = audited()?;
        let member = setup.member()?;
        let id = key_period(setup.sent_ms);
        let key = *setup
            .checker
            .keyring
            .key(&member.public(), id)
            .ok_or("no key")?;
        let from_hashes = DeliveryAnswer::sign(
            &member,
            &DeliveryAnswerContent {
                nonce: setup.query.nonce,
                receiver: setup.query.receiver,
                boot_id: setup.query.boot_id,
                issued_ms: 1,
                takes_area: true,
                entries: setup
                    .batches
                    .iter()
                    .map(|batch| {
                        (
                            batch.sequence(),
                            Possession::Proved {
                                key: id,
                                tag: delivery_tag(&key, &batch.hash()),
                            },
                        )
                    })
                    .collect(),
            },
        )
        .map_err(error)?;
        let answers = vec![
            (1, from_hashes),
            (2, setup.answer_first(4, &[])?),
            (3, setup.answer_first(4, &[])?),
        ];
        assert_eq!(setup.judge(&answers), Verdict::Swallowed(vec![setup.relay]));
        Ok(())
    }

    #[test]
    fn only_batches_within_the_window_are_asked_about() -> Result<(), String> {
        let feeder = identity()?;
        let relay = identity()?.public();
        let now = wall_ms();
        let recent = vec![Sent {
            batch: batch(&feeder, 1)?,
            relays: vec![relay],
            sent_ms: now - ASK_WITHIN_MS,
        }];
        let mut checker = DeliveryChecker::default();
        checker.audit(&[relay], |_| true);
        assert_eq!(checker.sample_at(&recent, now), None);
        assert!(checker.sample_at(&recent, now - 1).is_some());
        Ok(())
    }

    #[test]
    fn keys_are_the_same_all_period_and_rotate_with_it() -> Result<(), String> {
        let feeder = identity()?;
        let member = identity()?.public();
        let mut keyring = Keyring::default();
        let start = 100 * KEY_PERIOD_MS;
        keyring.draw(&[member], start);
        let first = keyring
            .grant(&feeder, member, start)
            .ok_or("no grant")?
            .content()
            .map_err(error)?;
        let again = keyring
            .grant(&feeder, member, start + KEY_PERIOD_MS / 2)
            .ok_or("no grant")?
            .content()
            .map_err(error)?;
        assert_eq!((first.current, first.next), (again.current, again.next));
        assert!(keyring.keyed(&member, start));
        assert!(!keyring.keyed(&identity()?.public(), start));
        keyring.draw(&[member], start + KEY_PERIOD_MS);
        let next = keyring
            .grant(&feeder, member, start + KEY_PERIOD_MS)
            .ok_or("no grant")?
            .content()
            .map_err(error)?;
        assert_eq!(next.current, first.next);
        assert_ne!(next.next, first.next);
        // Three periods on, the first key is forgotten.
        keyring.draw(&[member], start + 3 * KEY_PERIOD_MS);
        keyring.grant(&feeder, member, start + 3 * KEY_PERIOD_MS);
        assert!(keyring.key(&member, first.current.id).is_none());
        assert!(keyring.key(&member, first.current.id + 1).is_some());
        Ok(())
    }

    /// Item 14 of the sweep: the keyed members are drawn afresh at random each period, so a set
    /// keyed first (Sybils that reached the feeder first after a restart) holds it a period at
    /// most: a member not drawn is given no key and its keys are dropped, and every member is
    /// drawn in turn.
    #[test]
    fn the_keyed_members_are_drawn_afresh_each_period() -> Result<(), String> {
        let feeder = identity()?;
        let sybils: Vec<PublicKey> = (0..KEYED_MEMBERS)
            .map(|_| identity().map(|member| member.public()))
            .collect::<Result<_, _>>()?;
        let honest = identity()?.public();
        let mut keyring = Keyring::default();
        let start = 100 * KEY_PERIOD_MS;
        // The Sybils first: every place is theirs for this period, and the honest member, come a
        // moment later, has none.
        let (drawn, _) = keyring.draw(&sybils, start);
        assert_eq!(drawn.len(), KEYED_MEMBERS);
        for sybil in &sybils {
            keyring.grant(&feeder, *sybil, start).ok_or("no grant")?;
        }
        let everyone: Vec<PublicKey> = sybils.iter().copied().chain([honest]).collect();
        let (drawn, _) = keyring.draw(&everyone, start + 1);
        assert!(!drawn.contains(&honest));
        assert!(keyring.grant(&feeder, honest, start + 1).is_none());
        // Each period after, a fresh draw: the honest member is drawn in turn (here each period
        // with chance 16 in 17, so never in 40 is beyond any chance), and the member left out
        // each time has its keys dropped and is never asked.
        let mut honest_drawn = 0;
        for period in 1..=40 {
            let now = start + period * KEY_PERIOD_MS;
            let (drawn, dropped) = keyring.draw(&everyone, now);
            assert_eq!(drawn.len(), KEYED_MEMBERS);
            let left_out: Vec<PublicKey> = everyone
                .iter()
                .filter(|member| !drawn.contains(member))
                .copied()
                .collect();
            let [left_out] = left_out[..] else {
                return Err(format!("left out {left_out:?}"));
            };
            assert!(dropped.iter().all(|(member, _)| *member == left_out));
            assert!(keyring.grant(&feeder, left_out, now).is_none());
            assert!(!keyring.keyed(&left_out, now));
            assert!(keyring.key(&left_out, key_period(now)).is_none());
            for member in &drawn {
                keyring.grant(&feeder, *member, now).ok_or("no grant")?;
                assert!(keyring.keyed(member, now));
            }
            if drawn.contains(&honest) {
                honest_drawn += 1;
            }
        }
        assert!(honest_drawn > 0, "the honest member was never drawn");
        Ok(())
    }

    /// A draw that drops a member's keys while a check is in flight leaves that check able to
    /// read the member's answer: the keys it was asked under go with it.
    #[test]
    fn a_check_in_flight_reads_its_answers_under_keys_a_draw_dropped() -> Result<(), String> {
        let mut setup = audited()?;
        let answers = vec![
            (1, setup.answer_first(4, ALL)?),
            (2, setup.answer_first(4, ALL)?),
        ];
        // A new period's draw, from members the first two are not among.
        let later = setup.sent_ms + KEY_PERIOD_MS;
        let others: Vec<Member> = (0..KEYED_MEMBERS)
            .map(|_| identity().map(|member| member_at(member.public())))
            .collect::<Result<_, _>>()?;
        setup.checker.draw(others, later);
        assert_eq!(setup.judge(&answers), Verdict::Delivered);
        Ok(())
    }

    #[test]
    fn no_audit_begins_when_no_member_can_be_asked() -> Result<(), String> {
        let (one, other) = (identity()?.public(), identity()?.public());
        let mut checker = DeliveryChecker::default();
        assert_eq!(checker.audit(&[one, other], |_| false), None);
        // The next one that can be asked about is audited, in turn.
        assert_eq!(
            checker.audit(&[one, other], |relay| *relay == other),
            Some(other)
        );
        assert_eq!(checker.audit(&[], |_| true), None);
        Ok(())
    }

    #[test]
    fn only_batches_the_audited_relay_alone_carried_are_sampled() -> Result<(), String> {
        let feeder = identity()?;
        let (audited, other) = (identity()?.public(), identity()?.public());
        // Batches sent to both, and an earlier audit's of the other relay: neither is sampled.
        let mut recent = Vec::new();
        for sequence in 0..6 {
            let relays = if sequence < 3 {
                vec![audited, other]
            } else {
                vec![other]
            };
            recent.push(Sent {
                batch: batch(&feeder, sequence)?,
                relays,
                sent_ms: wall_ms(),
            });
        }
        let mut checker = DeliveryChecker::default();
        checker.audit(&[audited], |_| true);
        assert_eq!(checker.sample(&recent), None);
        recent.push(Sent {
            batch: batch(&feeder, 6)?,
            relays: vec![audited],
            sent_ms: wall_ms(),
        });
        let query = checker.sample(&recent).ok_or("no sample")?;
        assert_eq!(query.ranges, vec![SequenceRange { first: 6, last: 6 }]);
        assert_eq!(checker.checked_relays(), vec![audited]);
        Ok(())
    }

    #[test]
    fn not_my_area_and_the_checked_relay_itself_are_no_evidence() -> Result<(), String> {
        let mut setup = audited()?;
        let outside = DeliveryAnswer::sign(
            &identity()?,
            &DeliveryAnswerContent {
                nonce: setup.query.nonce,
                receiver: setup.query.receiver,
                boot_id: setup.query.boot_id,
                issued_ms: 1,
                takes_area: false,
                entries: Vec::new(),
            },
        )
        .map_err(error)?;
        let answers = vec![
            (1, outside.clone()),
            (2, outside),
            (3, setup.answer_first(4, &[])?),
        ];
        assert_eq!(setup.judge(&answers), Verdict::Unknown);
        Ok(())
    }

    fn scratch() -> PathBuf {
        let base = std::env::var_os("TEST_TMPDIR").map_or_else(std::env::temp_dir, PathBuf::from);
        let [a, b, c, d, e, f, g, h, ..] = random_hash();
        base.join(format!(
            "tally-feed-check-{:016x}",
            u64::from_be_bytes([a, b, c, d, e, f, g, h])
        ))
    }

    #[test]
    fn the_memory_survives_a_restart_and_lapses() -> Result<(), String> {
        let dir = scratch();
        let relay = identity()?.public();
        let now = 1_800_000_000_000;
        {
            let mut checker = DeliveryChecker::load(&dir);
            checker.remember(&[relay], now);
        }
        let checker = DeliveryChecker::load(&dir);
        assert_eq!(checker.avoided_at(now + 1), vec![relay]);
        let days = u64::try_from(AVOID_FOR.as_millis()).unwrap_or(u64::MAX);
        assert!(checker.avoided_at(now + days + 1).is_empty());
        let _ = std::fs::remove_dir_all(dir);
        Ok(())
    }

    /// A member on loopback that answers a `DeliveryQuery` sent with Hello, signed by `signer`.
    async fn member(identity: Identity, signer: Identity) -> Result<RelayAddress, String> {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .map_err(|error| error.to_string())?;
        let address = listener
            .local_addr()
            .map_err(|error| error.to_string())?
            .to_string();
        let key = identity.public();
        tokio::spawn(async move {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            let Ok(accepted) = noise::accept(stream, &[identity]).await else {
                return;
            };
            // A delivery check is a probe session: it takes no feeder slot.
            if accepted.role != Role::Probe {
                return;
            }
            let mut writer = accepted.session.writer;
            for record in accepted.first {
                if let Record::DeliveryQuery(query) = record {
                    let content = DeliveryAnswerContent {
                        nonce: query.nonce,
                        receiver: query.receiver,
                        boot_id: query.boot_id,
                        issued_ms: 1,
                        takes_area: true,
                        entries: vec![(query.ranges[0].first, Possession::NotSeen)],
                    };
                    if let Ok(answer) = DeliveryAnswer::sign(&signer, &content) {
                        let _ = writer.send(&[Record::DeliveryAnswer(answer)]).await;
                    }
                }
            }
            let mut reader = accepted.session.reader;
            let mut rest = Vec::new();
            let _ = reader.recv(&mut rest).await;
        });
        Ok(RelayAddress { key, address })
    }

    #[tokio::test]
    async fn a_member_is_asked_and_only_its_own_signature_counts() -> Result<(), String> {
        let mut setup = audited()?;
        let me = identity()?;
        let honest = identity()?;
        let asked = member(honest.clone(), honest).await?;
        let answer = ask(&asked, &me, &setup.query).await.ok_or("no answer")?;
        assert_eq!(answer.signer().map_err(error)?, asked.key);
        // A member answering under another key's signature has given no answer.
        let impostor = member(identity()?, identity()?).await?;
        assert_eq!(ask(&impostor, &me, &setup.query).await, None);
        // One member's "not seen" is no verdict.
        assert_eq!(setup.judge(&[(1, answer)]), Verdict::Unknown);
        Ok(())
    }

    fn offer(
        relay: &Identity,
        cell: Region,
        network: u32,
        products: Streams,
        expires_ms: u64,
    ) -> Result<ProviderOffer, String> {
        ProviderOffer::sign(
            relay,
            &ProviderOfferContent {
                address: "member.example:10900".to_owned(),
                cell,
                products,
                stripes_of: 1,
                stripes: 1,
                mlat_cores: 0,
                feeder_slots: 0,
                network,
                issued_ms: expires_ms - 1_000,
                expires_ms,
            },
        )
        .map_err(error)
    }

    #[test]
    fn members_are_on_distinct_networks_and_exclude_the_checked() -> Result<(), String> {
        let location = Location {
            lat_e7: 339_400_000,
            lon_e7: -1_184_000_000,
            alt_m: 0,
            precision_m: 0,
        };
        let area = tally_wire::rendezvous::area_of(&location).map_err(error)?;
        let parent = Region::containing(&location, 1).map_err(error)?;
        let elsewhere = Region::containing(
            &Location {
                lat_e7: 515_000_000,
                lon_e7: -1_000_000,
                alt_m: 0,
                precision_m: 0,
            },
            3,
        )
        .map_err(error)?;
        let now = 10_000;
        let checked = identity()?;
        let mut offers = vec![
            offer(&checked, area, 9, Streams::RAW, now + 60_000)?,
            offer(&identity()?, area, 1, Streams::RAW, now + 60_000)?,
            offer(&identity()?, area, 1, Streams::RAW, now + 60_000)?,
            offer(&identity()?, parent, 2, Streams::RAW, now + 60_000)?,
            offer(&identity()?, area, 0, Streams::RAW, now + 60_000)?,
            offer(&identity()?, area, 0, Streams::RAW, now + 60_000)?,
            // Not counted: another area, no raw, expired.
            offer(&identity()?, elsewhere, 3, Streams::RAW, now + 60_000)?,
            offer(&identity()?, area, 4, Streams::POSITIONS, now + 60_000)?,
            offer(&identity()?, area, 5, Streams::RAW, now)?,
        ];
        offers.rotate_left(2);
        // Every member seen at an address of its own /24.
        let observed: HashMap<PublicKey, IpAddr> = offers
            .iter()
            .zip(1u8..)
            .filter_map(|(offer, at)| {
                let host = IpAddr::V4(std::net::Ipv4Addr::new(192, 0, at, 1));
                offer.signer().ok().map(|key| (key, host))
            })
            .collect();
        for _ in 0..10 {
            let members = members(&offers, area, &[checked.public()], &observed, |_| true, now);
            let mut networks: Vec<u32> = members.iter().map(|member| member.network).collect();
            networks.sort_unstable();
            assert_eq!(networks, vec![0, 1, 2]);
            // Two members declaring distinct networks from one /24 are one network.
            let shared: HashMap<PublicKey, IpAddr> = observed
                .keys()
                .map(|key| (*key, IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 9))))
                .collect();
            let one_prefix =
                super::members(&offers, area, &[checked.public()], &shared, |_| true, now);
            assert_eq!(one_prefix.len(), 1, "{one_prefix:?}");
            assert!(
                members
                    .iter()
                    .all(|member| member.relay.key != checked.public())
            );
        }
        Ok(())
    }
}
