//! A receiver's or relay's identity is one Ed25519 key (RFC-0166 §3.2). It signs what the holder
//! publishes, and the X25519 key the Noise handshake uses is derived from it (the libsodium
//! `sk_to_curve25519` conversion), so one key is the identity everywhere and forever. Keys are
//! written as base64 on one line, the way WireGuard writes them.

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use blake2::{Blake2s256, Digest};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};

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
        VerifyingKey::from_bytes(&bytes).map_err(|error| WireError::Key(error.to_string()))?;
        Ok(Self(bytes))
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
        self.verifying()?
            .verify_strict(message, &Signature::from_bytes(signature))
            .map_err(|_| WireError::BadSignature)
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
#[derive(Clone)]
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
