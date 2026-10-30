//! What each link may be sent, by type (RFC-0171 §3.5, wire version 3): a receiver's exact site is
//! relay-only data, and a client must be unable to read or derive one.
//!
//! Every link's write side is typed by its column of the egress table, chosen once from the role
//! its handshake established and the version it agreed ([`Column::of`]), and it can hold nothing
//! but that column's record type ([`Sendable`]), so no path, present or future, hands a link what
//! its column may not carry:
//!
//! | Column             | Who                                                | Carries                         |
//! | ------------------ | -------------------------------------------------- | ------------------------------- |
//! | [`Column::Sites`]  | a relay or an engine (version 3, the least either may agree) | every `Record`        |
//! | [`Column::Client`] | everyone else: subscribers, feeders, probes, of any version | `ClientRecord` and nothing else |
//!
//! A relay-role peer of an older version has no column: it is refused at its handshake
//! ([`Column::of`]), so no link can hold a relay that might pass a site on to a client.
//!
//! A client's type is the wire's own (`tally_wire::ClientRecord`): it has no variant for raw
//! batches, the deduplicated and regional batches' counters, full clock models, raw positions,
//! sites, or descriptions and evidence that carry one. A fan-out item's client form is made once,
//! by the fan-out, for every client that takes it ([`client_form`], `fanout::Router::publish`),
//! except positions, whose client form only the hub makes, once the relay has checked them
//! (`consistency`); a record that has none never reaches a client link, and is counted
//! ([`withheld`]).

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use tally_wire::noise::Writer;
use tally_wire::{ClientRecord, Outgoing, Record, Role, WireError, carries_sites};
use tokio::io::AsyncWrite;

use crate::hub::Item;
use crate::subscription::ClientItem;

/// Records a link's column would not carry, since the relay started: a client's fan-out item with
/// no client form. Each is simply not sent to that link.
static WITHHELD: AtomicU64 = AtomicU64::new(0);

/// Records withheld from a link by its column ([`WITHHELD`]).
pub fn withheld() -> u64 {
    WITHHELD.load(Ordering::Relaxed)
}

fn withhold<T>() -> Option<T> {
    WITHHELD.fetch_add(1, Ordering::Relaxed);
    None
}

/// A link's column of the egress table (module docs).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Column {
    /// A relay-role peer (a relay, an engine), which agreed version 3: it keeps sites off its own
    /// client links, so it may be sent them (`carries_sites`).
    Sites,
    /// Every other peer: a client, sent only what `ClientRecord` holds.
    Client,
}

/// A relay-role peer that agreed a version older than `SITES_VERSION`: refused at its handshake.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TooOld {
    pub version: u16,
}

impl std::fmt::Display for TooOld {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "a relay link of version {} (relays and engines speak {} or later)",
            self.version,
            tally_wire::SITES_VERSION
        )
    }
}

impl Column {
    /// The column of a link to a peer of `role` that agreed `version`: a relay or an engine of
    /// version 3 or later takes sites; one older has no column and is refused (RFC-0171 §3.3: the
    /// relays and their feeders move together, and the least a relay link agrees is 3); every
    /// other peer, of any version, is a client.
    pub fn of(role: Role, version: u16) -> Result<Self, TooOld> {
        if carries_sites(version, role) {
            Ok(Self::Sites)
        } else if matches!(role, Role::Relay | Role::Engine) {
            Err(TooOld { version })
        } else {
            Ok(Self::Client)
        }
    }
}

/// Whether `record` carries a receiver's site, or something carrying one: a `ReceiverSite`, a
/// format 1 description, or an evidence bundle that carries one whole.
pub fn bears_site(record: &Record) -> bool {
    match record {
        Record::EvidenceBundle(bundle) => bundle.carries_site(),
        record => record.carries_site(),
    }
}

/// What a client may be sent of `record` (`ClientRecord::try_from`): `None` for what is relay-only.
/// The kinds that never convert are answered without a copy of the record; every other answer is
/// the conversion's own.
pub fn client_form(record: &Record) -> Option<Arc<ClientRecord>> {
    let relay_only = match record {
        Record::Batch(_)
        | Record::RelayBatch(_)
        | Record::RegionalBatch(_)
        | Record::ClockModel(_)
        | Record::ClockModelPart(_)
        | Record::BundleIndex(_)
        | Record::Parity(_)
        | Record::PieceManifest(_)
        | Record::ReceiverSite(_) => true,
        Record::ReceiverInfo(info) => info.carries_site(),
        // A client's positions are made only where they are checked (`consistency`, by
        // `Hub::send_positions`), never by the form alone: a client cannot check them itself.
        Record::Positions(_) => true,
        _ => false,
    };
    if relay_only {
        return None;
    }
    ClientRecord::try_from(record.clone()).ok().map(Arc::new)
}

/// What a client may be sent of a fan-out item, with where it is routed (`ClientItem`): `None`
/// for what is relay-only (`client_form`). Made once per item, by the fan-out (`Router::publish`)
/// or where the item is made.
pub fn client_item(item: &Item) -> Option<Arc<ClientItem>> {
    client_form(&item.record).map(|record| Arc::new(ClientItem::new(record, item.points.as_ref())))
}

/// The record type of one column: what its links' write side holds and sends.
pub trait Sendable: Outgoing + Clone + Send + Sync + 'static {
    /// The column whose type this is.
    const COLUMN: Column;

    /// What the column carries of a fan-out item, or `None` (counted, [`withheld`]).
    fn of_item(item: &Item) -> Option<Self>;

    /// What the column carries of a record the relay sends it (a greeting, a reply, a dump, a
    /// member's addressed send), or `None` (counted).
    fn of_record(record: Arc<Record>) -> Option<Self>;

    /// Its kind byte, as written.
    fn kind(&self) -> u8;
}

impl Sendable for Arc<Record> {
    const COLUMN: Column = Column::Sites;

    fn of_item(item: &Item) -> Option<Self> {
        Some(Arc::clone(&item.record))
    }

    fn of_record(record: Arc<Record>) -> Option<Self> {
        Some(record)
    }

    fn kind(&self) -> u8 {
        Record::kind(self)
    }
}

impl Sendable for Arc<ClientRecord> {
    const COLUMN: Column = Column::Client;

    /// The client form the fan-out made (`Router::publish`), or, for an item no fan-out carried
    /// (a directory's answer), made here.
    fn of_item(item: &Item) -> Option<Self> {
        match &item.client {
            Some(client) => Some(Arc::clone(&client.record)),
            None => Self::of_record(Arc::clone(&item.record)),
        }
    }

    fn of_record(record: Arc<Record>) -> Option<Self> {
        match client_form(&record) {
            Some(client) => Some(client),
            None => withhold(),
        }
    }

    fn kind(&self) -> u8 {
        ClientRecord::kind(self)
    }
}

/// A session's write side, typed by its column: it sends `P` and nothing else.
pub struct Typed<'w, S, P> {
    writer: &'w mut Writer<S>,
    column: std::marker::PhantomData<P>,
}

impl<'w, S: AsyncWrite, P: Sendable> Typed<'w, S, P> {
    pub fn new(writer: &'w mut Writer<S>) -> Self {
        Self {
            writer,
            column: std::marker::PhantomData,
        }
    }

    /// Sends `records`, in order, as `Writer::send` does.
    pub async fn send(&mut self, records: &[P]) -> Result<(), WireError> {
        self.writer.send(records).await
    }

    /// Sends what the column carries of `records`, in order; the rest is withheld.
    pub async fn send_records(
        &mut self,
        records: impl IntoIterator<Item = Record>,
    ) -> Result<(), WireError> {
        let typed: Vec<P> = records
            .into_iter()
            .filter_map(|record| P::of_record(Arc::new(record)))
            .collect();
        if typed.is_empty() {
            return Ok(());
        }
        self.writer.send(&typed).await
    }
}

/// Sends what `column` carries of `records` on `writer`: for a write side not yet typed (answers
/// sent before a session is admitted).
pub async fn send_as<S: AsyncWrite>(
    column: Column,
    writer: &mut Writer<S>,
    records: Vec<Record>,
) -> Result<(), WireError> {
    match column {
        Column::Sites => {
            Typed::<S, Arc<Record>>::new(writer)
                .send_records(records)
                .await
        }
        Column::Client => {
            Typed::<S, Arc<ClientRecord>>::new(writer)
                .send_records(records)
                .await
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_column_is_decided_by_role_and_version_and_an_older_relay_has_none() {
        use tally_wire::SITES_VERSION;
        for role in [Role::Relay, Role::Engine] {
            assert_eq!(Column::of(role, SITES_VERSION), Ok(Column::Sites));
            assert_eq!(
                Column::of(role, SITES_VERSION - 1),
                Err(TooOld {
                    version: SITES_VERSION - 1
                })
            );
        }
        for role in [Role::Feeder, Role::Subscriber, Role::Probe, Role::Other(9)] {
            assert_eq!(Column::of(role, SITES_VERSION), Ok(Column::Client));
            assert_eq!(Column::of(role, 1), Ok(Column::Client));
        }
    }

    fn site() -> tally_wire::Location {
        tally_wire::Location {
            lat_e7: 515_012_345,
            lon_e7: -1_234_567,
            alt_m: 88,
            precision_m: 0,
        }
    }

    /// The two columns over every record that carries a site, or a client may not hold: a relay
    /// takes all, a client only what `ClientRecord` holds; and each refusal is counted.
    #[test]
    fn each_column_carries_only_what_it_may() -> Result<(), WireError> {
        use tally_wire::batch::{PublicInfoContent, ReceiverInfoContent};
        use tally_wire::{
            BatchContent, Clock, Identity, ReceiverInfo, ReceiverSite, ReceiverSiteContent, Region,
        };
        let receiver = Identity::from_seed([5; 32]);
        let format_one = Record::ReceiverInfo(ReceiverInfo::sign(
            &receiver,
            &ReceiverInfoContent {
                issued_ms: 1,
                location: Some(site()),
                clock: Clock::Dump1090,
                software: String::new(),
                relays: Vec::new(),
            },
        )?);
        let format_two = Record::ReceiverInfo(ReceiverInfo::sign_public(
            &receiver,
            &PublicInfoContent {
                issued_ms: 1,
                cell: Some(Region::public_cell(&site())?),
                clock: Clock::Dump1090,
                software: String::new(),
                relays: Vec::new(),
            },
        )?);
        let sited = Record::ReceiverSite(ReceiverSite::sign(
            &receiver,
            &ReceiverSiteContent {
                issued_ms: 1,
                location: site(),
                clock: Clock::Dump1090,
            },
        )?);
        let raw = Record::Batch(crate::anchors::anchored(
            &receiver,
            &BatchContent {
                boot_id: 1,
                sequence: 0,
                counter_epoch: 0,
                wall_ms: 0,
                dropped: 0,
                previous: [0; 32],
                observations: Vec::new(),
            },
        )?);
        for record in [&format_one, &sited] {
            assert!(bears_site(record));
            assert!(<Arc<Record>>::of_record(Arc::new(record.clone())).is_some());
            let before = withheld();
            assert!(<Arc<ClientRecord>>::of_record(Arc::new(record.clone())).is_none());
            assert!(withheld() > before);
        }
        // Raw is relay data, not site data: a relay takes it, a client never.
        assert!(!bears_site(&raw));
        assert!(<Arc<Record>>::of_record(Arc::new(raw.clone())).is_some());
        assert!(<Arc<ClientRecord>>::of_record(Arc::new(raw)).is_none());
        // A format 2 description goes everywhere.
        assert!(!bears_site(&format_two));
        assert!(<Arc<ClientRecord>>::of_record(Arc::new(format_two)).is_some());
        Ok(())
    }
}
