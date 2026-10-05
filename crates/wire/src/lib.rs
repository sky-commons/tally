//! The only code that speaks Tally's wire (RFC-0166 §3): the BEAST frames a receiver's decoder
//! emits, the signed batches that carry them, the records that move between feeders, relays and
//! subscribers, and the Noise transport every hop runs over. Every binary goes through this crate.

pub mod backoff;
pub mod batch;
pub mod beast;
pub mod key;
pub mod noise;
pub mod positions;
pub mod record;
pub mod region;

pub use batch::{Batch, BatchContent, Clock, Location, Observation, ReceiverInfo};
pub use beast::{Frame, FrameKind};
pub use key::{Identity, PublicKey};
pub use noise::{Accepted, Reader, Session, Writer};
pub use positions::{Position, Positions, PositionsContent};
pub use record::{Reason, Record, RelayAddress, Role, Streams};
pub use region::Region;

/// Everything that can go wrong on the wire. Any of these ends the connection.
#[derive(Debug, thiserror::Error)]
pub enum WireError {
    #[error("i/o: {0}")]
    Io(#[from] std::io::Error),
    #[error("noise: {0}")]
    Noise(#[from] snow::Error),
    #[error("timed out")]
    Timeout,
    #[error("preamble: {0}")]
    Preamble(&'static str),
    #[error("refused by the peer ({reason:?}), retry after {retry_after_secs} s")]
    Refused {
        reason: Reason,
        retry_after_secs: u32,
    },
    #[error("unknown critical record kind {0:#04x}")]
    UnknownCritical(u8),
    #[error("record truncated: needed {needed} bytes, had {had}")]
    Truncated { needed: usize, had: usize },
    #[error("too large for its field: {0}")]
    Oversize(usize),
    #[error("invalid {field}: {value}")]
    Invalid { field: &'static str, value: u64 },
    #[error("bad key: {0}")]
    Key(String),
    #[error("signature does not verify")]
    BadSignature,
}
