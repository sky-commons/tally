//! What the mathematics takes in: receptions with their identity, and the receivers that made
//! them.

use blake2::{Blake2s256, Digest};
use tally_wire::{Clock, Location, PublicKey, SiteId};

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

/// A table keyed by a message's hash ([`message_hash`]) hashes it by its first eight bytes: the
/// hash is already a digest, so hashing it again (`SipHash`, twice the bytes) bought nothing, and
/// the table it builds is the same on every run, so what it holds is measured, not drawn. As hard
/// to crowd as the fixed-key `SipHash` it replaced, whose keys are as public.
#[derive(Clone, Copy, Debug, Default)]
pub struct DigestHasher(u64);

impl std::hash::Hasher for DigestHasher {
    fn finish(&self) -> u64 {
        self.0
    }

    fn write(&mut self, bytes: &[u8]) {
        let mut word = [0u8; 8];
        let len = bytes.len().min(8);
        word[..len].copy_from_slice(&bytes[..len]);
        self.0 = self.0.rotate_left(29) ^ u64::from_le_bytes(word);
    }

    /// A slice's length, which every hash of one table shares: nothing to it.
    fn write_usize(&mut self, _: usize) {}
}

/// What a table keyed by message hashes is built with ([`DigestHasher`]).
pub type ByDigest = std::hash::BuildHasherDefault<DigestHasher>;

/// A Mode S message's bytes, held inline: every reception MLAT holds is a Mode S short or long
/// message (`tally_wire::modes::wanted_reception`), so a reception is copied, kept and let go
/// with no allocation of its own. Before (2026-10-27), each reception carried the wire's
/// `Observation`, its bytes a `Vec` allocated for every copy of every reception (a due set's
/// receptions made, split into transmissions, weighed, solved), and freeing them was a step's
/// largest teardown.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ModeS {
    len: u8,
    bytes: [u8; tally_wire::modes::LONG],
}

impl ModeS {
    /// `data` held, `None` when it is longer than a Mode S long message.
    pub fn new(data: &[u8]) -> Option<Self> {
        let mut bytes = [0u8; tally_wire::modes::LONG];
        bytes.get_mut(..data.len())?.copy_from_slice(data);
        Some(Self {
            len: u8::try_from(data.len()).ok()?,
            bytes,
        })
    }

    pub fn bytes(&self) -> &[u8] {
        &self.bytes[..usize::from(self.len)]
    }

    /// Its BEAST format, by its length: long at 14 bytes, short otherwise.
    pub fn format(&self) -> u8 {
        if usize::from(self.len) == tally_wire::modes::LONG {
            tally_wire::batch::format::MODE_S_LONG
        } else {
            tally_wire::batch::format::MODE_S_SHORT
        }
    }
}

impl std::ops::Deref for ModeS {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        self.bytes()
    }
}

impl std::fmt::Debug for ModeS {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ModeS(")?;
        for byte in self.bytes() {
            write!(f, "{byte:02x}")?;
        }
        write!(f, ")")
    }
}

/// One reception as a batch carried it: who heard it, in which counter epoch, its counter and
/// message unchanged, and the wall clock of the signed batch that carried it (of several copies,
/// the earliest), which places it in a window (crate docs, § Windows) and nothing else.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Reception {
    pub receiver: PublicKey,
    pub epoch: u32,
    /// The receiver's 48-bit counter, raw.
    pub timestamp: u64,
    pub message: ModeS,
    pub wall_ms: u64,
}

impl Reception {
    /// A held Mode S reception as a batch carries it: `None` for bytes longer than a Mode S
    /// message.
    pub fn mode_s(
        receiver: PublicKey,
        epoch: u32,
        timestamp: u64,
        wall_ms: u64,
        data: &[u8],
    ) -> Option<Self> {
        Some(Self {
            receiver,
            epoch,
            timestamp,
            message: ModeS::new(data)?,
            wall_ms,
        })
    }

    /// The observation a batch carries it as, at signal level `signal` (MLAT reads none).
    pub fn observation(&self, signal: u8) -> tally_wire::Observation {
        tally_wire::Observation {
            format: self.message.format(),
            timestamp: self.timestamp,
            signal,
            data: self.message.to_vec(),
        }
    }

    pub fn id(&self) -> ObservationId {
        ObservationId {
            receiver: self.receiver,
            epoch: self.epoch,
            timestamp: self.timestamp,
            message: message_hash(&self.message),
        }
    }
}

/// Each reception's identity ([`Reception::id`]), in their order, each run of one message's bytes
/// hashed once: a transmission's receptions are all of one message, so its identities cost one
/// Blake2s, not one a reception.
pub fn ids(receptions: &[Reception]) -> Vec<ObservationId> {
    let mut last: Option<(&[u8], [u8; 32])> = None;
    receptions
        .iter()
        .map(|reception| {
            let data = reception.message.bytes();
            let message = match last {
                Some((bytes, hash)) if bytes == data => hash,
                _ => {
                    let hash = message_hash(data);
                    last = Some((data, hash));
                    hash
                }
            };
            ObservationId {
                receiver: reception.receiver,
                epoch: reception.epoch,
                timestamp: reception.timestamp,
                message,
            }
        })
        .collect()
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
