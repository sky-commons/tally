//! Where a receiver is, and the references that stand for it where a client can see them (wire
//! version 3; RFC-0171 §3.5, §8.3 as amended for site privacy).
//!
//! A receiver's exact site (latitude, longitude, altitude, and anything from which they can be
//! derived) is relay-only data. Relays need it for MLAT; clients must be unable to read it or
//! derive it to better than its public cell ([`PUBLIC_CELL_RESOLUTION`]). So:
//!
//! - **`ReceiverSite`** (kind 0x25, non-critical, its own signing domain) is the one record that
//!   carries a receiver's exact `Location`. A feeder sends it only on a link that negotiated wire
//!   version 3 ([`crate::record::SITES_VERSION`]) with a relay role
//!   ([`crate::record::carries_sites`]). An old build skips the kind as unknown.
//! - A **format 1 `ReceiverInfo`** (an old feeder's) also carries the exact site; it is forwarded
//!   byte for byte only to version 3 relay-role peers, never to a client. A format 2 `ReceiverInfo`
//!   carries only the public cell.
//! - **[`SiteId`]** names a site-bearing record without revealing it: BLAKE2s-256 over
//!   `"tally site id" 0x00` and the record's signed bytes, signature included. It covers a
//!   signature no client ever sees, so no client can test a guessed site against it. What a client
//!   sees in place of a site (a clock model's scope entry) is this id.
//! - **[`ReceptionKey`]** is what a reception's [`ReceptionTag`] is keyed by: BLAKE2s-256 over
//!   `"tally reception key" 0x00` and the same signed bytes. It is a second derivation, never
//!   published, not the site id itself, because the site id is published: a tag keyed by a public
//!   id over a 48-bit counter is a 2^48 search away from the counter (hours on one GPU), and a
//!   receiver's counters with the aircraft's published positions are its site by reverse MLAT. A
//!   relay holding the site-bearing record derives both; a client derives neither.
//! - **[`ReceptionTag`]** stands for one raw reception `(receiver, epoch, counter)` of a message
//!   in what a client receives (`TaggedSet`, tagged `Positions`): 16 bytes of BLAKE2s-256 over
//!   `"tally reception tag" 0x00`, the reception key, the epoch (4 bytes), the counter (6 bytes)
//!   and the message, length first. The same reception is the same tag from every engine, so
//!   clients still merge solutions by comparing tag sets; a relay rematches tags against its own
//!   raw by computing them.
//!
//! The tags of a receiver change when its site-bearing record is reissued (a new signature is a
//! new key): a relay computes a reception's tag from the record current when it was heard.

use blake2::{Blake2s256, Digest};

use crate::WireError;
use crate::batch::{Clock, Hash, Location, domain};
use crate::key::PublicKey;
use crate::record::Body;
use crate::region::Region;
use crate::signed::{Check, Checked, Fields, Unchecked, signed_record};

/// The resolution of a receiver's public cell: H3 resolution 6, about 36 km². The finest place a
/// client may learn of a receiver, from any record or any routing behaviour.
pub const PUBLIC_CELL_RESOLUTION: u8 = 6;
/// The resolution of a receiver's sharing area: the resolution 3 parent of its public cell.
pub const SHARING_AREA_RESOLUTION: u8 = 3;

const SITE_ID_DOMAIN: &[u8] = b"tally site id";
const RECEPTION_KEY_DOMAIN: &[u8] = b"tally reception key";
const RECEPTION_TAG_DOMAIN: &[u8] = b"tally reception tag";
/// A reception tag's length: 128 bits, collision-free across every reception the network hears.
pub const TAG_LEN: usize = 16;

/// A reference to a site-bearing record that does not reveal the site (module docs).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SiteId(pub Hash);

impl SiteId {
    /// Of a site-bearing record's signed bytes, signature included.
    pub fn of_signed(bytes: &[u8]) -> Self {
        Self(Blake2s256::digest(domain(SITE_ID_DOMAIN, bytes)).into())
    }
}

/// The relay-only key a receiver's reception tags are made under (module docs). Never written on
/// any wire.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct ReceptionKey(Hash);

impl std::fmt::Debug for ReceptionKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ReceptionKey(..)")
    }
}

impl ReceptionKey {
    /// Of a site-bearing record's signed bytes, signature included.
    pub fn of_signed(bytes: &[u8]) -> Self {
        Self(Blake2s256::digest(domain(RECEPTION_KEY_DOMAIN, bytes)).into())
    }
}

/// One reception as a client sees it (module docs).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ReceptionTag(pub [u8; TAG_LEN]);

impl ReceptionTag {
    /// The tag of the reception `(epoch, counter)` of `message` by the receiver whose current
    /// site-bearing record gives `key`. Refused: a counter past 48 bits, a message past 255 bytes.
    pub fn of(
        key: &ReceptionKey,
        epoch: u32,
        counter: u64,
        message: &[u8],
    ) -> Result<Self, WireError> {
        if counter >= crate::observation_set::COUNTER_LIMIT {
            return Err(WireError::Invalid {
                field: "reception counter",
                value: counter,
            });
        }
        let length = u8::try_from(message.len()).map_err(|_| WireError::Oversize(message.len()))?;
        let mut hasher = Blake2s256::new();
        hasher.update(RECEPTION_TAG_DOMAIN);
        hasher.update([0]);
        hasher.update(key.0);
        hasher.update(epoch.to_be_bytes());
        hasher.update(&counter.to_be_bytes()[2..]);
        hasher.update([length]);
        hasher.update(message);
        let digest: Hash = hasher.finalize().into();
        let mut tag = [0; TAG_LEN];
        tag.copy_from_slice(&digest[..TAG_LEN]);
        Ok(Self(tag))
    }
}

/// What a receiver says of where it is: relay-only.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReceiverSiteContent {
    /// Unix milliseconds. The newest a relay has seen for a key wins.
    pub issued_ms: u64,
    pub location: Location,
    pub clock: Clock,
}

impl Check for ReceiverSiteContent {
    /// A location on the globe.
    fn check(&self) -> Result<(), WireError> {
        self.location.check()
    }
}

impl Fields for ReceiverSiteContent {
    fn write(site: Checked<'_, Self>, out: &mut Vec<u8>) -> Result<(), WireError> {
        out.extend_from_slice(&site.issued_ms.to_be_bytes());
        out.extend_from_slice(&site.location.lat_e7.to_be_bytes());
        out.extend_from_slice(&site.location.lon_e7.to_be_bytes());
        out.extend_from_slice(&site.location.alt_m.to_be_bytes());
        out.extend_from_slice(&site.location.precision_m.to_be_bytes());
        out.push(site.clock.byte());
        Ok(())
    }

    fn read(reader: &mut Body<'_>) -> Result<Unchecked<Self>, WireError> {
        Ok(Unchecked::new(Self {
            issued_ms: reader.u64()?,
            location: Location {
                lat_e7: reader.i32()?,
                lon_e7: reader.i32()?,
                alt_m: reader.i32()?,
                precision_m: reader.u32()?,
            },
            clock: Clock::from_byte(reader.u8()?),
        }))
    }
}

signed_record!(
    /// A receiver's signed `ReceiverSiteContent`: its exact site, for relays only (module docs).
    ReceiverSite,
    ReceiverSiteContent,
    b"tally receiver site",
    1,
    1 + 32 + 8 + 16 + 1 + 64
);

impl ReceiverSite {
    /// The receiver whose site it is.
    pub fn receiver(&self) -> Result<PublicKey, WireError> {
        self.signer()
    }

    /// The reference clients see in its place.
    pub fn site_id(&self) -> SiteId {
        SiteId::of_signed(self.as_bytes())
    }

    /// What this receiver's reception tags are keyed by while this record is current.
    pub fn reception_key(&self) -> ReceptionKey {
        ReceptionKey::of_signed(self.as_bytes())
    }
}

impl Region {
    /// The public cell of a location ([`PUBLIC_CELL_RESOLUTION`]): what a feeder writes in its
    /// format 2 description, and the finest place a client may learn of it.
    pub fn public_cell(location: &Location) -> Result<Self, WireError> {
        Self::containing(location, PUBLIC_CELL_RESOLUTION)
    }

    /// A region as a client may route by it: itself when it is no finer than the public cell's
    /// resolution, else its ancestor of that resolution. A client's `Subscribe` regions are
    /// clamped by it, so no subscription tells a receiver's place finer than its public cell.
    pub fn clamped_to_public(self) -> Self {
        self.ancestor(PUBLIC_CELL_RESOLUTION).unwrap_or(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key::Identity;

    fn content() -> ReceiverSiteContent {
        ReceiverSiteContent {
            issued_ms: 1_791_220_000_000,
            location: Location {
                lat_e7: 374_100_000,
                lon_e7: -1_221_000_000,
                alt_m: 31,
                precision_m: 0,
            },
            clock: Clock::Dump1090,
        }
    }

    #[test]
    fn a_site_round_trips_under_its_own_domain() -> Result<(), WireError> {
        let feeder = Identity::generate()?;
        let site = ReceiverSite::sign(&feeder, &content())?;
        let back = ReceiverSite::from_bytes(site.as_bytes().to_vec())?;
        back.verify()?;
        assert_eq!(back.content()?, content());
        assert_eq!(back.receiver()?, feeder.public());
        assert_eq!(back.as_bytes().len(), ReceiverSite::MAX_LEN);
        // Its signature is no receiver description's, and no description's is its.
        assert!(
            crate::ReceiverInfo::from_bytes(site.as_bytes().to_vec())?
                .verify()
                .is_err()
        );
        let off = ReceiverSiteContent {
            location: Location {
                lat_e7: 900_000_001,
                ..content().location
            },
            ..content()
        };
        assert!(ReceiverSite::sign(&feeder, &off).is_err());
        Ok(())
    }

    #[test]
    fn the_id_and_the_key_differ_and_follow_the_signed_bytes() -> Result<(), WireError> {
        let feeder = Identity::from_seed([4; 32]);
        let site = ReceiverSite::sign(&feeder, &content())?;
        let reissued = ReceiverSite::sign(
            &feeder,
            &ReceiverSiteContent {
                issued_ms: content().issued_ms + 1,
                ..content()
            },
        )?;
        assert_ne!(site.site_id(), reissued.site_id());
        assert_ne!(site.reception_key(), reissued.reception_key());
        assert_ne!(site.site_id().0, site.reception_key().0);
        assert_eq!(site.site_id(), SiteId::of_signed(site.as_bytes()));
        Ok(())
    }

    #[test]
    fn a_tag_is_one_reception_and_needs_the_key() -> Result<(), WireError> {
        let key = ReceptionKey::of_signed(b"one record");
        let other = ReceptionKey::of_signed(b"another record");
        let message = [0x8d, 1, 2, 3];
        let tag = ReceptionTag::of(&key, 1, 42, &message)?;
        assert_eq!(tag, ReceptionTag::of(&key, 1, 42, &message)?);
        for different in [
            ReceptionTag::of(&other, 1, 42, &message)?,
            ReceptionTag::of(&key, 2, 42, &message)?,
            ReceptionTag::of(&key, 1, 43, &message)?,
            ReceptionTag::of(&key, 1, 42, &message[..3])?,
        ] {
            assert_ne!(different, tag);
        }
        assert!(
            ReceptionTag::of(&key, 0, crate::observation_set::COUNTER_LIMIT, &message).is_err()
        );
        assert!(ReceptionTag::of(&key, 0, 0, &[0; 256]).is_err());
        Ok(())
    }

    /// The tag is part of the protocol: every engine and relay must make the same one.
    #[test]
    fn the_tag_is_a_fixed_known_answer() -> Result<(), WireError> {
        let key = ReceptionKey::of_signed(b"site");
        let tag = ReceptionTag::of(&key, 3, 0x0102_0304_0506, &[0x8d, 0x4c])?;
        let id = SiteId::of_signed(b"site");
        assert_eq!(crate::observation_set::tests::hex(&id.0), KNOWN_SITE_ID);
        assert_eq!(crate::observation_set::tests::hex(&tag.0), KNOWN_TAG);
        Ok(())
    }

    /// Computed independently (Python `hashlib.blake2s` over the documented encoding).
    const KNOWN_SITE_ID: &str = "dda98ac62b444b86b317d2ebcb3e8201538dfc42304fa24b80cdadc7b23d492d";
    const KNOWN_TAG: &str = "cbed11f335ab6b0982ed0b9975add294";

    #[test]
    fn a_region_is_clamped_to_the_public_resolution() -> Result<(), WireError> {
        let location = content().location;
        let point = Region::point(&location)?;
        let public = Region::public_cell(&location)?;
        assert_eq!(public.resolution(), PUBLIC_CELL_RESOLUTION);
        assert_eq!(point.clamped_to_public(), public);
        assert_eq!(public.clamped_to_public(), public);
        let coarse = Region::containing(&location, 2)?;
        assert_eq!(coarse.clamped_to_public(), coarse);
        assert!(public.contains(point));
        Ok(())
    }
}
