//! Round-trip probes (RFC-0174 §2.2): a feeder measures how near a relay is by the time an `Echo`
//! takes to come back, never by where the relay says it is. The reply is signed and carries the
//! relay's headroom (how many more feeders it takes, how much of its upload cap is spare, the MLAT
//! cores it offers) and the network it is on, so the feeder ranks a band of relays by measured time
//! and signed capacity alone.

use crate::WireError;
use crate::record::Body;
use crate::signed::{Check, Checked, Fields, Unchecked, signed_record};

/// A probe: a nonce and nothing else (unsigned; the reply names the nonce).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Echo {
    pub nonce: u64,
}

impl Check for Echo {
    /// Any nonce.
    fn check(&self) -> Result<(), WireError> {
        Ok(())
    }
}

impl Fields for Echo {
    fn write(echo: Checked<'_, Self>, out: &mut Vec<u8>) -> Result<(), WireError> {
        out.extend_from_slice(&echo.nonce.to_be_bytes());
        Ok(())
    }

    fn read(reader: &mut Body<'_>) -> Result<Unchecked<Self>, WireError> {
        Ok(Unchecked::new(Self {
            nonce: reader.u64()?,
        }))
    }
}

/// What a relay has spare, as it declares it now.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Headroom {
    /// More feeders it would admit now (RFC-0171 §3.6's admission).
    pub feeder_slots: u32,
    /// Its upload cap less what it is committed to send, bytes a second.
    pub pace_headroom_bytes_per_sec: u64,
    /// Cores it offers for MLAT (RFC-0174 §2.3); zero when it runs none.
    pub mlat_cores: u16,
}

/// A signed answer to an `Echo`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EchoReplyContent {
    /// The probe's nonce.
    pub nonce: u64,
    /// The relay's judging clock as it answered, Unix milliseconds; 0 when that clock did not
    /// judge (`EchoReply::answer`): a reply never states a time its relay could not judge. A
    /// feeder weighs it for nothing: the nonce is what makes the reply fresh.
    pub issued_ms: u64,
    /// The autonomous system the relay says it is on (0 when it does not say): two destinations on
    /// different networks (§2.2).
    pub network: u32,
    pub headroom: Headroom,
}

impl Check for EchoReplyContent {
    /// Every field is a count or a stamp a reader weighs for itself; none is out of range.
    fn check(&self) -> Result<(), WireError> {
        Ok(())
    }
}

impl Fields for EchoReplyContent {
    fn write(reply: Checked<'_, Self>, out: &mut Vec<u8>) -> Result<(), WireError> {
        out.extend_from_slice(&reply.nonce.to_be_bytes());
        out.extend_from_slice(&reply.issued_ms.to_be_bytes());
        out.extend_from_slice(&reply.network.to_be_bytes());
        out.extend_from_slice(&reply.headroom.feeder_slots.to_be_bytes());
        out.extend_from_slice(&reply.headroom.pace_headroom_bytes_per_sec.to_be_bytes());
        out.extend_from_slice(&reply.headroom.mlat_cores.to_be_bytes());
        Ok(())
    }

    fn read(reader: &mut Body<'_>) -> Result<Unchecked<Self>, WireError> {
        Ok(Unchecked::new(Self {
            nonce: reader.u64()?,
            issued_ms: reader.u64()?,
            network: reader.u32()?,
            headroom: Headroom {
                feeder_slots: reader.u32()?,
                pace_headroom_bytes_per_sec: reader.u64()?,
                mlat_cores: reader.u16()?,
            },
        }))
    }
}

signed_record!(
    /// A relay's signed `EchoReplyContent`.
    EchoReply,
    EchoReplyContent,
    b"tally echo reply",
    1,
    256
);

impl EchoReply {
    /// A relay's answer to `echo`, signed by `signer` whatever its clock: a probe is how a feeder
    /// finds and chooses a relay, and possession never depends on a clock (RFC-0171 §3.6), so a
    /// relay that cannot judge time still answers, and is still chosen and fed. The answer decides
    /// the time it states (`issued_ms`) itself: `at`'s milliseconds only while `signer`'s clock
    /// judges and `at` is a reading of that clock that judged, else 0. `at` is a reading
    /// (`clocks::Judged`), never a number, and a signer whose clock does not judge states 0
    /// whatever reading it is handed, so no code holding a `Signer` signs a time its clock could
    /// not judge by asking for an answer. The one record signed apart from the judging clock
    /// (`Signer::untimed`). Before, the answer took the time as a number and stated it whatever
    /// the signer's clock, so any code with a `Signer` could get an arbitrary time signed.
    ///
    /// A number is refused by the compiler:
    ///
    /// ```compile_fail,E0308
    /// # use tally_wire::{Echo, EchoReply, Headroom, Signer};
    /// fn forged(signer: &Signer) -> Result<EchoReply, tally_wire::WireError> {
    ///     EchoReply::answer(signer, Echo { nonce: 1 }, Some(4_102_444_800_000), 0, Headroom::default())
    /// }
    /// ```
    pub fn answer(
        signer: &crate::key::Signer,
        echo: Echo,
        at: Option<crate::clocks::Judged>,
        network: u32,
        headroom: Headroom,
    ) -> Result<Self, WireError> {
        let issued_ms = match at {
            Some(judged) if signer.signs() => judged.ms(),
            _ => 0,
        };
        Self::sign(
            &signer.untimed(),
            &EchoReplyContent {
                nonce: echo.nonce,
                issued_ms,
                network,
                headroom,
            },
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key::Identity;

    /// A relay whose clock does not judge still answers a probe, signed, its time unstated
    /// whatever reading it is handed; one whose clock judges states the judged reading. Before,
    /// the time was a number stated whatever the signer's clock.
    #[test]
    #[allow(
        clippy::disallowed_methods,
        reason = "a test's signers, on clocks scripted to judge and not to, and its readings"
    )]
    fn an_answer_is_signed_whatever_the_clock_and_states_only_a_judged_time()
    -> Result<(), WireError> {
        let public = Identity::from_seed([3; 32]).public();
        let unjudging =
            crate::key::Signer::new(Identity::from_seed([3; 32]), std::sync::Arc::new(|| false));
        let headroom = Headroom {
            feeder_slots: 4,
            pace_headroom_bytes_per_sec: 1 << 20,
            mlat_cores: 0,
        };
        let reading = crate::clocks::recorded::judged(1_791_244_800_000);
        for at in [
            None,
            Some(reading),
            Some(crate::clocks::recorded::judged(u64::MAX)),
        ] {
            let reply = EchoReply::answer(&unjudging, Echo { nonce: 11 }, at, 7, headroom)?;
            reply.verify()?;
            assert_eq!(reply.signer()?, public);
            assert_eq!(
                reply.content()?,
                EchoReplyContent {
                    nonce: 11,
                    issued_ms: 0,
                    network: 7,
                    headroom,
                }
            );
        }
        let judging =
            crate::key::Signer::new(Identity::from_seed([3; 32]), std::sync::Arc::new(|| true));
        let judged = EchoReply::answer(&judging, Echo { nonce: 12 }, Some(reading), 7, headroom)?;
        assert_eq!(judged.content()?.issued_ms, 1_791_244_800_000);
        let unread = EchoReply::answer(&judging, Echo { nonce: 13 }, None, 7, headroom)?;
        assert_eq!(unread.content()?.issued_ms, 0);
        Ok(())
    }

    #[test]
    fn an_echo_reply_round_trips_and_is_bound_to_its_signer() -> Result<(), WireError> {
        let relay = Identity::generate()?;
        let content = EchoReplyContent {
            nonce: 7,
            issued_ms: 1_791_244_800_000,
            network: 64_512,
            headroom: Headroom {
                feeder_slots: 120,
                pace_headroom_bytes_per_sec: 1 << 20,
                mlat_cores: 16,
            },
        };
        let reply = EchoReply::sign(&relay, &content)?;
        let back = EchoReply::from_bytes(reply.as_bytes().to_vec())?;
        back.verify()?;
        assert_eq!(back.content()?, content);
        assert_eq!(back.signer()?, relay.public());
        let mut bytes = reply.as_bytes().to_vec();
        bytes[40] ^= 1;
        assert!(EchoReply::from_bytes(bytes).is_ok_and(|bad| bad.verify().is_err()));
        assert_eq!(
            Echo::from_body(&Echo { nonce: 9 }.to_bytes()?)?,
            Echo { nonce: 9 }
        );
        Ok(())
    }
}
