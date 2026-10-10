//! A relay's signed overload cut of its MLAT solving (RFC-0181 §10, "MLAT seats and the overload
//! cut"): from step `from_ms`, in the `areas` it names, solve only the receivers whose rank draw is
//! below `below`. The cut is a rank threshold, never a count of seats, so every relay holding an
//! area solves exactly the receivers ranked below it whatever it has described or can seat. It
//! travels to the relays that hold the same areas, which apply it at the same stamped step, so they
//! make the same bytes. A fact of the signer's stamps, never of a clock.
//!
//! It stands for [`CUT_TTL_STEPS`] steps from `from_ms` and is announced again while it stands
//! (`CUT_REFRESH_STEPS`), each announcement a record of its own: a relay that was down, or that
//! started late, learns a standing cut at the next, and a cut its signer stopped announcing
//! expires. `below` of `u128::MAX` lifts the cut.
//!
//! A kind of its own and non-critical: a build that predates it skips it (RFC-0171 §3.4), and
//! applies no cut, which is the overload behaviour it always had.

use crate::WireError;
use crate::region::Region;
use crate::rendezvous::AREA_RESOLUTION;
use crate::signed::{Check, Checked, Fields, Unchecked, signed_record};

/// The most areas (cells) one cut may name: a signer with more announces more records.
pub const MAX_CUT_AREAS: usize = 32;

/// The latest step a cut may be stamped for, in milliseconds: far past any clock, so that adding a
/// cut's lifetime to it can never overflow.
pub const MAX_CUT_FROM_MS: u64 = 1 << 52;

/// Steps (of a second) a cut stands from its step unless announced again.
pub const CUT_TTL_STEPS: u64 = 40;

/// Steps between a standing cut's announcements.
pub const CUT_REFRESH_STEPS: u64 = 10;

/// What a cut says: the step it takes effect from (a stamp in milliseconds), the areas it is for
/// (cells no finer than an area, strictly ascending), and the rank threshold: a receiver in one of
/// the areas is solved only if its draw is below `below`. Who asks is the signer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MlatCutContent {
    pub from_ms: u64,
    pub below: u128,
    pub areas: Vec<Region>,
}

impl Check for MlatCutContent {
    /// A step no later than [`MAX_CUT_FROM_MS`], and one to [`MAX_CUT_AREAS`] areas, each no finer
    /// than an area, strictly ascending (so one cut has one spelling and names no area twice).
    fn check(&self) -> Result<(), WireError> {
        if self.from_ms > MAX_CUT_FROM_MS {
            return Err(WireError::Invalid {
                field: "cut from_ms",
                value: self.from_ms,
            });
        }
        if self.areas.is_empty() || self.areas.len() > MAX_CUT_AREAS {
            return Err(WireError::Invalid {
                field: "cut areas",
                value: self.areas.len() as u64,
            });
        }
        let mut last = None;
        for area in &self.areas {
            if area.resolution() > AREA_RESOLUTION || last.is_some_and(|last| last >= area.as_u64())
            {
                return Err(WireError::Invalid {
                    field: "cut area",
                    value: area.as_u64(),
                });
            }
            last = Some(area.as_u64());
        }
        Ok(())
    }
}

impl Fields for MlatCutContent {
    fn write(cut: Checked<'_, Self>, out: &mut Vec<u8>) -> Result<(), WireError> {
        out.extend_from_slice(&cut.from_ms.to_be_bytes());
        out.extend_from_slice(&cut.below.to_be_bytes());
        out.push(u8::try_from(cut.areas.len()).map_err(|_| WireError::Oversize(cut.areas.len()))?);
        for area in &cut.areas {
            out.extend_from_slice(&area.as_u64().to_be_bytes());
        }
        Ok(())
    }

    fn read(reader: &mut crate::record::Body<'_>) -> Result<Unchecked<Self>, WireError> {
        let from_ms = reader.u64()?;
        let below = u128::from_be_bytes(reader.array()?);
        let count = usize::from(reader.u8()?);
        if count > MAX_CUT_AREAS {
            return Err(WireError::Invalid {
                field: "cut areas",
                value: count as u64,
            });
        }
        let areas = (0..count)
            .map(|_| Region::from_u64(reader.u64()?))
            .collect::<Result<_, _>>()?;
        Ok(Unchecked::new(Self {
            from_ms,
            below,
            areas,
        }))
    }
}

signed_record!(
    /// A relay's signed `MlatCutContent`.
    MlatCut,
    MlatCutContent,
    b"tally mlat cut",
    1,
    512
);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key::Identity;
    use crate::record::Record;
    use crate::rendezvous::area_at;

    fn content(from_ms: u64) -> Result<MlatCutContent, WireError> {
        Ok(MlatCutContent {
            from_ms,
            below: 1 << 100,
            areas: vec![area_at(51.5, -0.1)?],
        })
    }

    #[test]
    fn a_cut_round_trips_signed_and_a_forged_one_is_refused() -> Result<(), WireError> {
        let relay = Identity::generate()?;
        let content = content(1_791_244_805_000)?;
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
        Ok(())
    }

    /// A step that would overflow a lifetime added to it, no areas, too many, a cell finer than an
    /// area, or areas out of order or twice are refused at the signer and at the reader.
    #[test]
    fn a_cut_that_cannot_be_applied_safely_is_refused() -> Result<(), WireError> {
        let relay = Identity::generate()?;
        let sound = content(5_000)?;
        for bad in [
            MlatCutContent {
                from_ms: u64::MAX,
                ..sound.clone()
            },
            MlatCutContent {
                from_ms: MAX_CUT_FROM_MS + 1,
                ..sound.clone()
            },
            MlatCutContent {
                areas: Vec::new(),
                ..sound.clone()
            },
            MlatCutContent {
                areas: vec![Region::containing(
                    &crate::batch::Location {
                        lat_e7: 515_000_000,
                        lon_e7: -1_000_000,
                        alt_m: 0,
                        precision_m: 0,
                    },
                    AREA_RESOLUTION + 1,
                )?],
                ..sound.clone()
            },
            MlatCutContent {
                areas: vec![sound.areas[0], sound.areas[0]],
                ..sound.clone()
            },
        ] {
            assert!(MlatCut::sign(&relay, &bad).is_err(), "{bad:?}");
        }
        // The most areas fit the record; one more does not.
        let parent = sound.areas[0].ancestor(1).ok_or(WireError::Invalid {
            field: "H3 cell",
            value: 0,
        })?;
        let mut sorted: Vec<Region> = crate::rendezvous::areas_of(parent)?
            .into_iter()
            .take(MAX_CUT_AREAS + 1)
            .collect();
        sorted.sort_by_key(|cell| cell.as_u64());
        let many = |n: usize| MlatCutContent {
            areas: sorted[..n].to_vec(),
            ..sound.clone()
        };
        assert!(MlatCut::fits(&many(MAX_CUT_AREAS)));
        assert!(!MlatCut::fits(&many(MAX_CUT_AREAS + 1)));
        Ok(())
    }

    /// A build that predates the kind skips it whole and reads what follows.
    #[test]
    fn a_build_that_predates_the_kind_skips_it() -> Result<(), WireError> {
        let relay = Identity::generate()?;
        let cut = MlatCut::sign(&relay, &content(5_000)?)?;
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
