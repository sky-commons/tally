//! A receiver's or relay's identity is one Ed25519 key (RFC-0171 §3.2). It signs what the holder
//! publishes, and the X25519 key the Noise handshake uses is derived from it (the libsodium
//! `sk_to_curve25519` conversion), so one key is the identity everywhere and forever. Keys are
//! written as base64 on one line, the way WireGuard writes them.

use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use blake2::{Blake2s256, Digest};
use ed25519_dalek::{Signature, Signer as _, SigningKey, VerifyingKey};

use crate::WireError;

pub const KEY_LEN: usize = 32;
pub const SIGNATURE_LEN: usize = 64;
/// The prefix of a key's hash that names it in a connection preamble.
pub const KEY_HINT_LEN: usize = 8;

/// A public identity: who signed a batch, which relay a feeder is dialling.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PublicKey([u8; KEY_LEN]);

impl PublicKey {
    /// Accepts only a valid Ed25519 point, so every key in circulation can verify and derive.
    pub fn from_bytes(bytes: [u8; KEY_LEN]) -> Result<Self, WireError> {
        Self::point_of(&bytes)?;
        Ok(Self(bytes))
    }

    /// The key in `bytes` as a decompressed point: the one decompression a holder that verifies
    /// by the key more than once does (a `Batch` keeps it), checking the key as `from_slice` does.
    /// There is no way to decompress a `PublicKey` already checked into a point, so no reader
    /// checks a key and then decompresses it again (RFC-0181 §2).
    pub(crate) fn point_of(bytes: &[u8]) -> Result<VerifyingKey, WireError> {
        let array: [u8; KEY_LEN] = bytes.try_into().map_err(|_| {
            WireError::Key(format!("expected {KEY_LEN} bytes, got {}", bytes.len()))
        })?;
        VerifyingKey::from_bytes(&array).map_err(|error| WireError::Key(error.to_string()))
    }

    /// The key in `bytes`, already checked as a point when these same bytes were read before
    /// (`positions::Positions`, its receivers): its length alone is checked again.
    pub(crate) fn checked_before(bytes: &[u8]) -> Result<Self, WireError> {
        let array: [u8; KEY_LEN] = bytes.try_into().map_err(|_| {
            WireError::Key(format!("expected {KEY_LEN} bytes, got {}", bytes.len()))
        })?;
        Ok(Self(array))
    }

    pub fn from_slice(bytes: &[u8]) -> Result<Self, WireError> {
        let array: [u8; KEY_LEN] = bytes.try_into().map_err(|_| {
            WireError::Key(format!("expected {KEY_LEN} bytes, got {}", bytes.len()))
        })?;
        Self::from_bytes(array)
    }

    pub fn as_bytes(&self) -> &[u8; KEY_LEN] {
        &self.0
    }

    fn verifying(&self) -> Result<VerifyingKey, WireError> {
        VerifyingKey::from_bytes(&self.0).map_err(|error| WireError::Key(error.to_string()))
    }

    /// The key a decompressed point is: no check, the point already is one.
    pub(crate) fn of_point(point: &VerifyingKey) -> Self {
        Self(point.to_bytes())
    }

    /// `verify`, by a key already decompressed (`point`).
    pub(crate) fn verify_by(
        point: &VerifyingKey,
        message: &[u8],
        signature: &[u8; SIGNATURE_LEN],
    ) -> Result<(), WireError> {
        point
            .verify_strict(message, &Signature::from_bytes(signature))
            .map_err(|_| WireError::BadSignature)
    }

    /// The X25519 public key the Noise handshake authenticates.
    pub fn noise_key(&self) -> Result<[u8; KEY_LEN], WireError> {
        Ok(self.verifying()?.to_montgomery().to_bytes())
    }

    /// The first bytes of BLAKE2s over the Noise key: what a dialler names in its preamble so a
    /// relay holding several keys (a rotation) knows which one to answer with.
    pub fn hint(&self) -> Result<[u8; KEY_HINT_LEN], WireError> {
        Ok(hint_of(&self.noise_key()?))
    }

    /// Strict Ed25519 verification (no malleable signatures, no small-order keys).
    pub fn verify(&self, message: &[u8], signature: &[u8; SIGNATURE_LEN]) -> Result<(), WireError> {
        Self::verify_by(&self.verifying()?, message, signature)
    }

    pub fn to_base64(&self) -> String {
        STANDARD.encode(self.0)
    }

    pub fn from_base64(text: &str) -> Result<Self, WireError> {
        let bytes = STANDARD
            .decode(text.trim())
            .map_err(|error| WireError::Key(error.to_string()))?;
        Self::from_slice(&bytes)
    }

    /// The form a URL path carries: base64url without padding, since the file form's `/`, `+`
    /// and `=` are not path-safe.
    pub fn to_base64url(&self) -> String {
        URL_SAFE_NO_PAD.encode(self.0)
    }

    pub fn from_base64url(text: &str) -> Result<Self, WireError> {
        let bytes = URL_SAFE_NO_PAD
            .decode(text)
            .map_err(|error| WireError::Key(error.to_string()))?;
        Self::from_slice(&bytes)
    }
}

pub(crate) fn hint_of(noise_key: &[u8; KEY_LEN]) -> [u8; KEY_HINT_LEN] {
    let digest = Blake2s256::digest(noise_key);
    let mut hint = [0; KEY_HINT_LEN];
    hint.copy_from_slice(&digest[..KEY_HINT_LEN]);
    hint
}

impl std::fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.to_base64())
    }
}

impl std::fmt::Display for PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.to_base64())
    }
}

/// A private identity. The seed never leaves the box that generated it.
///
/// It is not `Clone`: one value per key, moved to its one owner. A relay moves its key into its
/// [`Signer`], which shares it (an `Arc`) with nothing but its own signings and handshakes, so no
/// part of the relay holds a copy it could sign with outside that seam:
///
/// ```compile_fail,E0599
/// let identity = tally_wire::Identity::from_seed([7; 32]);
/// let copy = identity.clone();
/// ```
pub struct Identity {
    signing: SigningKey,
    public: PublicKey,
}

impl Identity {
    pub fn generate() -> Result<Self, WireError> {
        let mut seed = [0; KEY_LEN];
        getrandom::getrandom(&mut seed).map_err(|error| WireError::Key(error.to_string()))?;
        Ok(Self::from_seed(seed))
    }

    pub fn from_seed(seed: [u8; KEY_LEN]) -> Self {
        let signing = SigningKey::from_bytes(&seed);
        let public = PublicKey(signing.verifying_key().to_bytes());
        Self { signing, public }
    }

    pub fn public(&self) -> PublicKey {
        self.public
    }

    /// The public key as a point, which the signing key already holds: nothing decompressed.
    pub(crate) fn point(&self) -> VerifyingKey {
        self.signing.verifying_key()
    }

    pub fn sign(&self, message: &[u8]) -> [u8; SIGNATURE_LEN] {
        self.signing.sign(message).to_bytes()
    }

    /// The X25519 private key for Noise, derived from the seed; X25519 clamps it.
    pub(crate) fn noise_private(&self) -> [u8; KEY_LEN] {
        self.signing.to_scalar_bytes()
    }

    /// The key file's form: base64 of the seed, one line.
    pub fn to_base64(&self) -> String {
        STANDARD.encode(self.signing.to_bytes())
    }

    pub fn from_base64(text: &str) -> Result<Self, WireError> {
        let bytes = STANDARD
            .decode(text.trim())
            .map_err(|error| WireError::Key(error.to_string()))?;
        let seed: [u8; KEY_LEN] = bytes.as_slice().try_into().map_err(|_| {
            WireError::Key(format!("expected {KEY_LEN} bytes, got {}", bytes.len()))
        })?;
        Ok(Self::from_seed(seed))
    }
}

/// The seal on [`Signs`] and [`Handshakes`]: a crate outside wire cannot name `Sealed`, so it
/// implements neither, and neither has a method that hands out the [`Identity`] behind it. A
/// signer lends a [`Signing`] (it signs and states its public key, nothing else), a handshake key
/// a [`sealed::Handshaking`] (outside wire, nothing at all), and wire reaches the key behind
/// either through their private fields ([`key_of`], [`handshake_key_of`]). Before, the path was a
/// trait method guarded by a zero-sized token, which a crate outside wire could forge with
/// `transmute`. Every crate that reaches a key forbids `unsafe` code (`#![forbid(unsafe_code)]`:
/// the MLAT engine, the solver, the merge, the API, the calibration, and the relay's, feeder's,
/// API's, calibration's and load harness's binaries), or, where one libc module needs it, denies
/// it outside that module, which reaches no key: this crate's `kernel_clock`, the relay's `os`,
/// the feeder's `privilege`, the load harness's `os`. A test's counting allocator is the
/// test-support crate's (`tally_counting`), which no production build reaches.
mod sealed {
    /// Unnameable outside wire: what [`super::Signs`] and [`super::Handshakes`] require.
    pub trait Sealed {}

    /// A handshake key lent to wire's Noise for one handshake: nothing outside wire can read it.
    pub struct Handshaking<'a>(pub(super) &'a super::Identity);
}

/// The key behind `signs`, for wire's own signing.
pub(crate) fn key_of(signs: &(impl Signs + ?Sized)) -> &Identity {
    signs.signing().identity
}

/// The key behind `handshakes`, for wire's own handshakes.
pub(crate) fn handshake_key_of(handshakes: &(impl Handshakes + ?Sized)) -> &Identity {
    handshakes.handshaking().0
}

/// What a record can be signed by: an [`Identity`] its owner holds, or a [`Signing`] a [`Signer`]
/// lends for one call. Sealed: nothing outside wire implements it,
///
/// ```compile_fail,E0277
/// struct Mine;
/// impl tally_wire::Signs for Mine {
///     fn signing(&self) -> tally_wire::Signing<'_> {
///         unimplemented!()
///     }
/// }
/// ```
///
/// and nothing reaches the key behind it, even generically: it lends a [`Signing`], which has no
/// path to its [`Identity`]:
///
/// ```compile_fail,E0599
/// fn leak<T: tally_wire::Signs>(signing: &T) -> &tally_wire::Identity {
///     signing.signing().identity()
/// }
/// ```
pub trait Signs: sealed::Sealed + Sync {
    /// The key lent to sign with, for as long as `self` is borrowed.
    fn signing(&self) -> Signing<'_>;

    /// The public key the signature verifies under.
    fn public(&self) -> PublicKey {
        key_of(self).public()
    }

    /// The signature over `message`.
    fn sign(&self, message: &[u8]) -> [u8; SIGNATURE_LEN] {
        key_of(self).sign(message)
    }
}

/// What a transport handshake (Noise) can be made with: an [`Identity`], or a [`NoiseKey`] a
/// [`Signer`] hands out. Sealed as [`Signs`] is: nothing else handshakes, and what it lends
/// ([`sealed::Handshaking`]) is opaque outside wire.
pub trait Handshakes: sealed::Sealed + Sync {
    /// The key lent to wire's Noise for one handshake.
    fn handshaking(&self) -> sealed::Handshaking<'_>;
}

impl sealed::Sealed for Identity {}

impl Signs for Identity {
    fn signing(&self) -> Signing<'_> {
        Signing { identity: self }
    }
}

impl Handshakes for Identity {
    fn handshaking(&self) -> sealed::Handshaking<'_> {
        sealed::Handshaking(self)
    }
}

/// A key its owner shares among its own tasks (a feeder's sessions, probes and batcher): the
/// owner's still, so it signs and handshakes as the key does. A relay never holds one: its key is
/// its [`Signer`]'s.
impl sealed::Sealed for std::sync::Arc<Identity> {}

impl Signs for std::sync::Arc<Identity> {
    fn signing(&self) -> Signing<'_> {
        Signing { identity: self }
    }
}

impl Handshakes for std::sync::Arc<Identity> {
    fn handshaking(&self) -> sealed::Handshaking<'_> {
        sealed::Handshaking(self)
    }
}

impl Identity {
    /// This key, lent to sign with for as long as it is borrowed (a test's, or a caller that owns
    /// its key: a feeder).
    pub fn signing(&self) -> Signing<'_> {
        Signing { identity: self }
    }
}

/// A key lent by its [`Signer`] for one signing ([`Signer::sign_with`]): it signs, and states its
/// public key, and nothing else. It is neither `Clone` nor `Copy` and only ever lent by reference,
/// for the length of the call, so a part cannot keep it to sign with after its clock has stopped
/// judging:
///
/// ```compile_fail,E0521
/// let signer = tally_wire::Signer::new(
///     tally_wire::Identity::from_seed([7; 32]),
///     std::sync::Arc::new(|| true),
/// );
/// let mut kept = None;
/// let _ = signer.sign_with(|signing| {
///     kept = Some(signing);
///     Ok(())
/// });
/// ```
pub struct Signing<'a> {
    identity: &'a Identity,
}

impl sealed::Sealed for Signing<'_> {}

impl Signs for Signing<'_> {
    fn signing(&self) -> Signing<'_> {
        Signing {
            identity: self.identity,
        }
    }
}

impl std::fmt::Debug for Signing<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Signing")
            .field("public", &self.identity.public)
            .finish_non_exhaustive()
    }
}

/// A key for a transport handshake (Noise), which signs no record and states no time: it opens
/// a handshake and does nothing else (it does not implement [`Signs`]), so a handshake's key
/// cannot sign a record:
///
/// ```compile_fail,E0599
/// use tally_wire::Signs;
/// let signer = tally_wire::Signer::new(
///     tally_wire::Identity::from_seed([7; 32]),
///     std::sync::Arc::new(|| true),
/// );
/// let _ = signer.handshake().sign(b"a record");
/// ```
#[derive(Clone)]
pub struct NoiseKey {
    identity: std::sync::Arc<Identity>,
}

impl NoiseKey {
    /// A key that only handshakes: an older key a relay still answers under, kept for no record.
    pub fn of(identity: Identity) -> Self {
        Self {
            identity: std::sync::Arc::new(identity),
        }
    }

    pub fn public(&self) -> PublicKey {
        self.identity.public()
    }
}

impl sealed::Sealed for NoiseKey {}

impl Handshakes for NoiseKey {
    fn handshaking(&self) -> sealed::Handshaking<'_> {
        sealed::Handshaking(&self.identity)
    }
}

impl std::fmt::Debug for NoiseKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NoiseKey")
            .field("public", &self.identity.public)
            .finish_non_exhaustive()
    }
}

/// A key as everything a relay signs reaches it (RFC-0171 §3.6): the one seam between the key and
/// a record's signature. Every record a relay signs carries its judging clock's time or is judged
/// by it where it is read, so nothing is signed while that clock is not synced: a `Signer` lends
/// the key to sign with only while `judging` says so, for one call ([`Signer::sign_with`]), as a
/// [`Signing`] that cannot be kept. A part handed a `Signer` (the MLAT engine, the products, the
/// directory, the members) holds no [`Identity`] of its own (it is not `Clone`, and the `Signer`
/// keeps it), so a step that finishes after the clock lost sync signs nothing, and a signer added
/// later cannot reach the key without asking. The one other use of the key, a transport
/// handshake (Noise), states no time and is named apart ([`Signer::handshake`]), by a key that
/// cannot sign ([`NoiseKey`]). The one record signed whatever the clock is a relay's answer to a
/// probe (`EchoReply::answer`), through a lending this crate keeps to itself: the answer decides
/// the time it states, a judging reading (never a number) while this signer's clock judges and 0
/// while it does not, so no code holding a `Signer` gets a time signed through it.
///
/// What a signing looks like, and what the compile-fail examples beside it change by one line:
///
/// ```
/// use tally_wire::Signs;
/// let identity = tally_wire::Identity::from_seed([7; 32]);
/// let public = identity.public();
/// let signer = tally_wire::Signer::new(identity, std::sync::Arc::new(|| true));
/// let signature = signer.sign_with(|signing| Ok(signing.sign(b"a record")))?;
/// assert!(public.verify(b"a record", &signature).is_ok());
/// let _handshake: tally_wire::NoiseKey = signer.handshake();
/// let unsynced = tally_wire::Signer::new(
///     tally_wire::Identity::from_seed([7; 32]),
///     std::sync::Arc::new(|| false),
/// );
/// assert!(unsynced.sign_with(|signing| Ok(signing.sign(b"a record"))).is_err());
/// # Ok::<(), tally_wire::WireError>(())
/// ```
#[derive(Clone)]
pub struct Signer {
    identity: NoiseKey,
    judging: std::sync::Arc<dyn Fn() -> bool + Send + Sync>,
}

impl Signer {
    /// `identity`, signing while `judging` is true.
    pub fn new(
        identity: Identity,
        judging: std::sync::Arc<dyn Fn() -> bool + Send + Sync>,
    ) -> Self {
        Self {
            identity: NoiseKey::of(identity),
            judging,
        }
    }

    /// The public key: what it is known by, whatever its clock.
    pub fn public(&self) -> PublicKey {
        self.identity.public()
    }

    /// Whether it signs now: false while the clock is not judging.
    pub fn signs(&self) -> bool {
        (self.judging)()
    }

    /// `sign`, given the key for this one call, while the clock is judging; else
    /// [`WireError::Unsynced`], and `sign` is not called.
    #[allow(
        clippy::disallowed_methods,
        reason = "the signer's own two ways to lend its key"
    )]
    pub fn sign_with<T>(
        &self,
        sign: impl FnOnce(&Signing<'_>) -> Result<T, WireError>,
    ) -> Result<T, WireError> {
        self.with(|signing| sign(signing.ok_or(WireError::Unsynced)?))
    }

    /// `then` given the key for this one call while the clock is judging, and none while it is
    /// not: for a caller that does other work either way.
    pub fn with<T>(&self, then: impl FnOnce(Option<&Signing<'_>>) -> T) -> T {
        if self.signs() {
            then(Some(&Signing {
                identity: handshake_key_of(&self.identity),
            }))
        } else {
            then(None)
        }
    }

    /// The key for a record that states no unjudged time, whatever the clock: wire's own, for the
    /// one record a relay must sign while its clock does not judge, its answer to a probe
    /// (`probe::EchoReply::answer`), which decides its time itself: a judging reading's while this
    /// signer's clock judges, 0 while it does not, never a number its caller passes. A
    /// relay that cannot judge must still be reached and chosen (RFC-0171 §3.6: no clock decides
    /// what a feeder sends, and an unsynced relay still receives everything), and a feeder
    /// chooses only a relay whose answer verifies. Crate-private, so no part of a relay can sign
    /// a time by it.
    pub(crate) fn untimed(&self) -> Signing<'_> {
        Signing {
            identity: handshake_key_of(&self.identity),
        }
    }

    /// The key for a transport handshake (Noise), which signs no record and states no time: never
    /// a record's signature.
    pub fn handshake(&self) -> NoiseKey {
        self.identity.clone()
    }
}

impl std::fmt::Debug for Signer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Signer")
            .field("public", &self.identity.public())
            .finish_non_exhaustive()
    }
}

impl std::fmt::Debug for Identity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Identity")
            .field("public", &self.public)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use snow::params::DHChoice;
    use snow::resolvers::{CryptoResolver, DefaultResolver};

    #[test]
    fn an_identity_survives_its_file_form() -> Result<(), WireError> {
        let identity = Identity::generate()?;
        let back = Identity::from_base64(&format!("{}\n", identity.to_base64()))?;
        assert_eq!(back.public(), identity.public());
        assert_eq!(
            PublicKey::from_base64(&identity.public().to_base64())?,
            identity.public()
        );
        Ok(())
    }

    #[test]
    fn a_key_survives_its_url_form_and_the_file_form_is_not_it() -> Result<(), WireError> {
        // Generated until the file form carries a character a URL path cannot.
        let key = loop {
            let key = Identity::generate()?.public();
            if key.to_base64().contains(['/', '+']) {
                break key;
            }
        };
        let url = key.to_base64url();
        assert!(!url.contains(['/', '+', '=']), "{url}");
        assert_eq!(PublicKey::from_base64url(&url)?, key);
        assert!(PublicKey::from_base64url(&key.to_base64()).is_err());
        Ok(())
    }

    #[test]
    fn the_derived_noise_keys_are_one_pair() -> Result<(), WireError> {
        let identity = Identity::generate()?;
        let mut dh = DefaultResolver
            .resolve_dh(&DHChoice::Curve25519)
            .ok_or_else(|| WireError::Key("no Curve25519".to_owned()))?;
        dh.set(&identity.noise_private());
        assert_eq!(dh.pubkey(), identity.public().noise_key()?.as_slice());
        Ok(())
    }

    #[test]
    fn a_signature_verifies_only_for_its_message_and_key() -> Result<(), WireError> {
        let identity = Identity::generate()?;
        let other = Identity::generate()?;
        let signature = identity.sign(b"batch");
        identity.public().verify(b"batch", &signature)?;
        assert!(identity.public().verify(b"other", &signature).is_err());
        assert!(other.public().verify(b"batch", &signature).is_err());
        Ok(())
    }

    #[test]
    fn a_key_of_the_wrong_length_is_refused() {
        assert!(PublicKey::from_base64("AAAA").is_err());
        assert!(Identity::from_base64("AAAA").is_err());
    }
}
