//! A relay's signed overload cut (RFC-0181 §10, "MLAT seats and the overload cut"): from step
//! `from_ms` the signer asks that MLAT seat only its `seats` best ranked receivers. It travels to
//! the relays that hold the same areas, which apply it at the same step, so they solve the same
//! receivers and make the same bytes. A fact of the signer's stamps, never of a clock.
//!
//! A kind of its own and non-critical: a build that predates it skips it (RFC-0171 §3.4), and
//! applies no cut, which is the overload behaviour it always had.

use crate::WireError;
use crate::signed::{Check, Checked, Fields, Unchecked, signed_record};

/// The most seats a cut may ask for: a hosted relay's seats are far fewer.
pub const MAX_CUT_SEATS: u32 = 1 << 24;

/// What a cut says: the step it takes effect from (a stamp in milliseconds) and the seats it asks
/// for. Who asks is the signer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MlatCutContent {
    pub from_ms: u64,
    pub seats: u32,
}

impl Check for MlatCutContent {
    /// At most [`MAX_CUT_SEATS`] seats.
    fn check(&self) -> Result<(), WireError> {
        if self.seats > MAX_CUT_SEATS {
            return Err(WireError::Invalid {
                field: "cut seats",
                value: u64::from(self.seats),
            });
        }
        Ok(())
    }
}

impl Fields for MlatCutContent {
    fn write(cut: Checked<'_, Self>, out: &mut Vec<u8>) -> Result<(), WireError> {
        out.extend_from_slice(&cut.from_ms.to_be_bytes());
        out.extend_from_slice(&cut.seats.to_be_bytes());
        Ok(())
    }

    fn read(reader: &mut crate::record::Body<'_>) -> Result<Unchecked<Self>, WireError> {
        Ok(Unchecked::new(Self {
            from_ms: reader.u64()?,
            seats: reader.u32()?,
        }))
    }
}

signed_record!(
    /// A relay's signed `MlatCutContent`.
    MlatCut,
    MlatCutContent,
    b"tally mlat cut",
    1,
    128
);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key::Identity;
    use crate::record::Record;

    #[test]
    fn a_cut_round_trips_signed_and_a_forged_one_is_refused() -> Result<(), WireError> {
        let relay = Identity::generate()?;
        let content = MlatCutContent {
            from_ms: 1_791_244_805_000,
            seats: 500,
        };
        let cut = MlatCut::sign(&relay, &content)?;
        cut.verify()?;
        assert_eq!(cut.signer()?, relay.public());
        assert_eq!(cut.content()?, content);
        let mut out = Vec::new();
        Record::MlatCut(cut.clone()).encode(&mut out)?;
        let (read, used) = Record::decode(&out)?;
        assert_eq!(used, out.len());
        assert_eq!(read, Some(Record::MlatCut(cut.clone())));
        // Another key's signature, or one bit flipped, does not verify.
        let mut bytes = cut.as_bytes().to_vec();
        let at = bytes.len() / 2;
        bytes[at] ^= 1;
        assert!(
            MlatCut::from_bytes(bytes)
                .and_then(|cut| cut.verify())
                .is_err()
        );
        let too_many = MlatCutContent {
            from_ms: 0,
            seats: MAX_CUT_SEATS + 1,
        };
        assert!(MlatCut::sign(&relay, &too_many).is_err());
        Ok(())
    }

    /// A build that predates the kind skips it whole and reads what follows.
    #[test]
    fn a_build_that_predates_the_kind_skips_it() -> Result<(), WireError> {
        let relay = Identity::generate()?;
        let cut = MlatCut::sign(
            &relay,
            &MlatCutContent {
                from_ms: 5_000,
                seats: 10,
            },
        )?;
        let mut out = Vec::new();
        Record::MlatCut(cut).encode(&mut out)?;
        Record::Heartbeat.encode(&mut out)?;
        let mut read = Vec::new();
        let (first, used) =
            Record::decode_knowing(&out, |kind| kind < crate::record::KIND_MLAT_CUT)?;
        assert_eq!(first, None);
        let (second, _) =
            Record::decode_knowing(&out[used..], |kind| kind < crate::record::KIND_MLAT_CUT)?;
        read.extend(second);
        assert_eq!(read, vec![Record::Heartbeat]);
        Ok(())
    }
}
