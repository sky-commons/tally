//! The provider directory (RFC-0174 §2.6, §2.3): a relay offers a cell (an area, or a parent of
//! areas it has gathered as a bundle) with the products and stripes it serves, the MLAT cores and
//! feeder slots it has, and the network it is on, signed and short-lived. Relays gossip offers
//! (after checking, by a handshake with the address, that the key answers there), hold each until
//! it expires, and answer a `ProviderQuery` with the offers they hold for a cell and its
//! ancestors. An offer is a hint, never a promise: a reader ranks providers by what they delivered.

use crate::WireError;
use crate::record::{Body, Streams};
use crate::region::Region;
use crate::signed::{Check, Checked, Fields, Unchecked, put_str, read_str, signed_record};

/// The longest an offer may live: a relay re-signs while it serves.
pub const MAX_OFFER_LIFETIME_MS: u64 = 60 * 60 * 1000;
/// The most stripes a stream is cut into (RFC-0174 §2.5).
pub const MAX_STRIPES: u8 = 32;

/// What a relay offers for one cell.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProviderOfferContent {
    /// Where to reach it, as a dialler names it (`host:port`).
    pub address: String,
    /// The cell offered; its resolution is its level in the area tree.
    pub cell: Region,
    /// The products offered for it.
    pub products: Streams,
    /// How many stripes its streams are cut into, and which of them it forwards (bit `i` is
    /// stripe `i`).
    pub stripes_of: u8,
    pub stripes: u32,
    /// Cores offered for the cell's MLAT; zero when it runs none (§2.3's k-of-ranking reads it).
    pub mlat_cores: u16,
    /// Feeders it would admit now.
    pub feeder_slots: u32,
    /// The autonomous system it says it is on; 0 when it does not say.
    pub network: u32,
    pub issued_ms: u64,
    /// After this, by the reader's clock, the offer is gone.
    pub expires_ms: u64,
}

impl Check for ProviderOfferContent {
    /// A lifetime of at most `MAX_OFFER_LIFETIME_MS`, ending after it begins, and stripes inside
    /// their count.
    fn check(&self) -> Result<(), WireError> {
        let lifetime = self.expires_ms.saturating_sub(self.issued_ms);
        if self.expires_ms <= self.issued_ms || lifetime > MAX_OFFER_LIFETIME_MS {
            return Err(WireError::Invalid {
                field: "offer lifetime",
                value: lifetime,
            });
        }
        check_stripes(self.stripes_of, self.stripes)
    }
}

/// `stripes` names only stripes below `stripes_of`, which is 1 to `MAX_STRIPES`.
pub(crate) fn check_stripes(stripes_of: u8, stripes: u32) -> Result<(), WireError> {
    let beyond = if stripes_of >= 32 {
        0
    } else {
        stripes >> stripes_of
    };
    if stripes_of == 0 || stripes_of > MAX_STRIPES || beyond != 0 {
        return Err(WireError::Invalid {
            field: "stripes",
            value: u64::from(stripes),
        });
    }
    Ok(())
}

impl Fields for ProviderOfferContent {
    fn write(offer: Checked<'_, Self>, out: &mut Vec<u8>) -> Result<(), WireError> {
        put_str(out, &offer.address)?;
        out.extend_from_slice(&offer.cell.as_u64().to_be_bytes());
        offer.products.write(out);
        out.push(offer.stripes_of);
        out.extend_from_slice(&offer.stripes.to_be_bytes());
        out.extend_from_slice(&offer.mlat_cores.to_be_bytes());
        out.extend_from_slice(&offer.feeder_slots.to_be_bytes());
        out.extend_from_slice(&offer.network.to_be_bytes());
        out.extend_from_slice(&offer.issued_ms.to_be_bytes());
        out.extend_from_slice(&offer.expires_ms.to_be_bytes());
        Ok(())
    }

    fn read(reader: &mut Body<'_>) -> Result<Unchecked<Self>, WireError> {
        Ok(Unchecked::new(Self {
            address: read_str(reader)?,
            cell: Region::from_u64(reader.u64()?)?,
            products: Streams::read(reader)?,
            stripes_of: reader.u8()?,
            stripes: reader.u32()?,
            mlat_cores: reader.u16()?,
            feeder_slots: reader.u32()?,
            network: reader.u32()?,
            issued_ms: reader.u64()?,
            expires_ms: reader.u64()?,
        }))
    }
}

signed_record!(
    /// A relay's signed `ProviderOfferContent`.
    ProviderOffer,
    ProviderOfferContent,
    b"tally provider offer",
    1,
    1 + 32 + 1 + 255 + 8 + 2 + 1 + 4 + 2 + 4 + 4 + 8 + 8 + 64
);

/// "Who offers this cell?" Answered with the offers held for it and its ancestors.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProviderQuery {
    pub cell: Region,
    pub products: Streams,
}

impl Check for ProviderQuery {
    /// Any cell and any products: a query names what it asks, and nothing it can name is wrong.
    fn check(&self) -> Result<(), WireError> {
        Ok(())
    }
}

impl Fields for ProviderQuery {
    fn write(query: Checked<'_, Self>, out: &mut Vec<u8>) -> Result<(), WireError> {
        out.extend_from_slice(&query.cell.as_u64().to_be_bytes());
        query.products.write(out);
        Ok(())
    }

    fn read(reader: &mut Body<'_>) -> Result<Unchecked<Self>, WireError> {
        Ok(Unchecked::new(Self {
            cell: Region::from_u64(reader.u64()?)?,
            products: Streams::read(reader)?,
        }))
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::batch::Location;
    use crate::key::Identity;

    pub(crate) fn cell() -> Result<Region, WireError> {
        Region::containing(
            &Location {
                lat_e7: 337_490_000,
                lon_e7: -843_880_000,
                alt_m: 0,
                precision_m: 0,
            },
            3,
        )
    }

    #[test]
    fn an_offer_round_trips_and_its_lifetime_and_stripes_are_bounded() -> Result<(), WireError> {
        let relay = Identity::generate()?;
        let content = ProviderOfferContent {
            address: "relay.example:7450".to_owned(),
            cell: cell()?,
            products: Streams::POSITIONS.with(Streams::REGIONAL),
            stripes_of: 4,
            stripes: 0b0101,
            mlat_cores: 16,
            feeder_slots: 300,
            network: 24_940,
            issued_ms: 1_000,
            expires_ms: 1_000 + 10 * 60 * 1000,
        };
        let offer = ProviderOffer::sign(&relay, &content)?;
        let back = ProviderOffer::from_bytes(offer.as_bytes().to_vec())?;
        back.verify()?;
        assert_eq!(back.content()?, content);
        let forever = ProviderOfferContent {
            expires_ms: u64::MAX,
            ..content.clone()
        };
        assert!(ProviderOffer::sign(&relay, &forever).is_err());
        let stray = ProviderOfferContent {
            stripes: 1 << 4,
            ..content
        };
        assert!(ProviderOffer::sign(&relay, &stray).is_err());
        let query = ProviderQuery {
            cell: cell()?,
            products: Streams::WORLD,
        };
        assert_eq!(ProviderQuery::from_body(&query.to_bytes()?)?, query);
        Ok(())
    }
}
