//! The relay's key as everything it signs reaches it (RFC-0171 §3.6): `tally_wire::Signer`, on the
//! relay's judging clock.
//!
//! Every record a relay signs carries its judging clock's time, or is judged by it where it is
//! read (a manifest, a receipt, a bundle index, an offer, a product, its figures, the MLAT
//! engine's models and positions). So nothing is signed while that clock is not synced
//! (`clock::RelayClock::judging`): a [`Signer`] lends the key to sign with only while it is, for
//! one call (`Signer::sign_with`, `Signer::with`), as a `tally_wire::Signing` that cannot be kept.
//! `Identity` is not `Clone`: `main` moves the relay's newest key into its one `Signer`, which
//! every part that signs is handed (the network's duties, the MLAT host), so no part holds a key
//! of its own and a signer added later cannot reach it without asking. The one other use of the
//! key, a transport handshake (Noise), states no time and is named apart (`Signer::handshake`), by
//! a `tally_wire::NoiseKey`, which cannot sign. The one record signed whatever the clock is the
//! answer to a probe (`tally_wire::EchoReply::answer`, `admission::Admission::echo`), which
//! decides the time it states itself, a judging reading's while this signer's clock judges and 0
//! while it does not, never a number its caller passes: a feeder chooses only a relay whose answer
//! verifies, and a relay that cannot judge must still be chosen and fed (RFC-0171 §3.6).

pub use tally_wire::Signer;

use crate::clock::RelayClock;
use tally_wire::{Signing, WireError};

/// `then` given `signer`'s key for this one call when `at`, the reading the record states its
/// time by or is judged by, was taken while the judging clock judged, and the clock judges still
/// (`Signer::with`): a reading taken while it did not judge signs nothing, though the clock judge
/// again by the time it would be signed (RFC-0171 §3.6). The relay's one way to lend its key, so
/// no part of it signs a time without saying which reading it is.
#[allow(
    clippy::disallowed_methods,
    reason = "the one place the relay lends its key, by the reading it signs"
)]
pub fn with<T>(
    signer: &Signer,
    at: impl Into<crate::strikes::Now>,
    then: impl FnOnce(Option<&Signing<'_>>) -> T,
) -> T {
    if at.into().judges() {
        signer.with(then)
    } else {
        then(None)
    }
}

/// As [`with`], `sign` called only with the key, else [`WireError::Unsynced`] and `sign` is not
/// called.
pub fn sign_with<T>(
    signer: &Signer,
    at: impl Into<crate::strikes::Now>,
    sign: impl FnOnce(&Signing<'_>) -> Result<T, WireError>,
) -> Result<T, WireError> {
    with(signer, at, |signing| {
        sign(signing.ok_or(WireError::Unsynced)?)
    })
}

/// `identity`, signing while `clock` is synced: the relay's one signer, on its own judging clock.
#[allow(
    clippy::disallowed_methods,
    reason = "the relay's one signer, made on its own judging clock"
)]
pub fn on(identity: tally_wire::Identity, clock: RelayClock) -> Signer {
    Signer::new(identity, std::sync::Arc::new(move || clock.judging()))
}

/// A test's signer, on a clock that is always synced.
#[cfg(test)]
#[allow(
    clippy::disallowed_methods,
    reason = "a test's signer, on a scripted clock"
)]
pub fn synced(identity: tally_wire::Identity) -> Signer {
    on(
        identity,
        RelayClock::scripted(std::sync::Arc::new(|| 1_791_244_800_000)),
    )
}

/// The same key again, for a test that signs as the relay (or checks what it signed) beside the
/// signer the relay holds: `Identity` is not `Clone`, so a test makes its twin from the seed, as
/// a second process reading the same key file would.
#[cfg(test)]
pub fn twin(identity: &tally_wire::Identity) -> tally_wire::Identity {
    match tally_wire::Identity::from_base64(&identity.to_base64()) {
        Ok(twin) => twin,
        Err(error) => unreachable!("a key's own file form reads back: {error}"),
    }
}

#[cfg(test)]
#[allow(
    clippy::disallowed_methods,
    reason = "a test of the signer itself and its scripted readings"
)]
mod tests {
    use super::*;
    use tally_wire::Identity;

    /// The key is handed out to sign with only while the clock is synced; the public key and the
    /// handshake key always.
    #[test]
    fn a_signer_signs_only_while_its_clock_is_synced() {
        let clock = RelayClock::scripted(std::sync::Arc::new(|| 1_791_244_800_000));
        let public = Identity::from_seed([5; 32]).public();
        let signer = on(Identity::from_seed([5; 32]), clock.clone());
        assert!(signer.signs());
        assert!(signer.with(|signing| signing.is_some()));
        clock.set_error(None);
        assert!(!signer.signs());
        assert!(signer.with(|signing| signing.is_none()));
        let mut called = false;
        assert!(matches!(
            signer.sign_with(|_| {
                called = true;
                Ok(())
            }),
            Err(tally_wire::WireError::Unsynced)
        ));
        assert!(!called, "an unsynced signer calls no signing");
        assert_eq!(signer.public(), public);
        assert_eq!(signer.handshake().public(), public);
        clock.set_error(Some(3));
        assert!(signer.sign_with(|_| Ok(())).is_ok());
    }

    /// A record is signed by the reading it states its time by: one taken while the clock did not
    /// judge signs nothing, though the clock judges again by the time it is signed. Before, the
    /// key was lent by whether the clock judged as the record was signed, so a reading taken
    /// unsynced a moment before was signed once the clock synced.
    #[test]
    fn a_reading_taken_while_the_clock_did_not_judge_signs_nothing_once_it_judges() {
        let clock = RelayClock::scripted(std::sync::Arc::new(|| 1_791_244_800_000));
        let signer = on(Identity::from_seed([6; 32]), clock.clone());
        clock.set_error(None);
        let unsynced = clock.stamp(0);
        clock.set_error(Some(3));
        let synced = clock.stamp(0);
        assert!(signer.signs());
        assert!(with(&signer, unsynced, |signing| signing.is_none()));
        assert!(matches!(
            sign_with(&signer, unsynced, |_| Ok(())),
            Err(WireError::Unsynced)
        ));
        assert!(with(&signer, synced, |signing| signing.is_some()));
        // And a reading that judged signs nothing once the clock no longer does.
        clock.set_error(None);
        assert!(with(&signer, synced, |signing| signing.is_none()));
    }
}
