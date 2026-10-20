//! What the mathematics takes in: receptions with their identity, and the receivers that made
//! them.

use blake2::{Blake2s256, Digest};
use tally_wire::{Clock, Location, Observation, PublicKey, SiteId};

/// An observation's identity (RFC-0171 §3.8): receiver key, counter epoch, raw counter and the
/// Blake2s-256 of the message bytes. The same whichever relay delivered it; ordered by those four
/// fields in that order, which is the order every list of them is kept in.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ObservationId {
    pub receiver: PublicKey,
    pub epoch: u32,
    pub timestamp: u64,
    pub message: [u8; 32],
}

/// The Blake2s-256 of a message's bytes.
pub fn message_hash(data: &[u8]) -> [u8; 32] {
    Blake2s256::digest(data).into()
}

/// One reception as a batch carried it: who heard it, in which counter epoch, the observation
/// unchanged, and the wall clock of the signed batch that carried it (of several copies, the
/// earliest), which places it in a window (crate docs, § Windows) and nothing else.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Reception {
    pub receiver: PublicKey,
    pub epoch: u32,
    pub observation: Observation,
    pub wall_ms: u64,
}

impl Reception {
    pub fn id(&self) -> ObservationId {
        ObservationId {
            receiver: self.receiver,
            epoch: self.epoch,
            timestamp: self.observation.timestamp,
            message: message_hash(&self.observation.data),
        }
    }
}

/// A receiver as its site-bearing record (a `ReceiverSite`, or an old feeder's format 1
/// `ReceiverInfo`) places it: relay-only, since its location is the receiver's exact site. A
/// client sees nothing of it: `id` enters only the model's inputs hash.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Site {
    pub receiver: PublicKey,
    pub clock: Clock,
    pub location: Location,
    /// The site-bearing record's reference (`tally_wire::SiteId`): what a model's inputs id
    /// hashes in place of the location, and what a client's view of the model names.
    pub id: SiteId,
}

/// The largest declared location precision a receiver may have and still take part, metres.
/// 30 m is 100 ns of light time, the timing noise of a good 12 MHz receiver: a coarser location
/// would be the largest error in every solve it joins.
pub const MAX_SITE_PRECISION_M: u32 = 30;

impl Site {
    /// The antenna in ECEF, rounded to whole millimetres: the form every rule and the model use.
    pub fn mm(&self) -> [i64; 3] {
        crate::geo::to_mm(crate::geo::to_ecef(crate::geo::Geodetic {
            lat_deg: f64::from(self.location.lat_e7) * 1e-7,
            lon_deg: f64::from(self.location.lon_e7) * 1e-7,
            height_m: f64::from(self.location.alt_m),
        }))
    }

    /// Whether the receiver can take part: a known clock and a precise enough location.
    pub fn usable(&self) -> bool {
        crate::clock::Timebase::of(self.clock).is_some()
            && self.location.precision_m <= MAX_SITE_PRECISION_M
    }

    /// One standard deviation of the antenna position along any axis, millimetres: a declared
    /// precision `p` is taken as uniform over `±p`, so `p / sqrt(3)`.
    pub fn sigma_mm(&self) -> i64 {
        (f64::from(self.location.precision_m) * 1000.0 / 3f64.sqrt()).round() as i64
    }
}
