//! The one shape of RFC-0174's signed records: `format u8 | signer key [32] | body | signature
//! [64]`, the signature Ed25519 over `domain 0x00` and every byte before it, each record kind under
//! a domain of its own, so no record verifies as another. Fields a later format appends after a
//! body are signed and ignored by this reader (RFC-0171 §3.4). Unsigned records (a probe, a query)
//! are bodies alone. A body type says how it is written and read ([`Fields`]) and what makes it
//! well formed ([`Check`]), and the check runs on every encode and every decode; `signed_record!`
//! gives each signed kind its constructor, reader and checks.

use blake2::{Blake2s256, Digest};

use crate::WireError;
use crate::batch::{Hash, domain, split_signature};
use crate::key::{KEY_LEN, PublicKey, SIGNATURE_LEN, Signs};
use crate::record::{Body, MAX_BODY};

/// The rules a value of a record body obeys beyond parsing: one function per type, run by both
/// [`Fields::encode`] and [`Fields::decode`], so a value that breaks them is neither written nor
/// read (RFC-0171 §3.4). Public so a caller may ask of a value it built before it sends it; the
/// codec asks regardless.
pub trait Check {
    /// `Ok` when the value is one the wire carries; the first rule it breaks otherwise.
    fn check(&self) -> Result<(), WireError>;
}

/// A value whose [`Check`] passed: the only thing [`Fields::write`] is handed, so no body is
/// written unchecked. Built only here, by [`Fields::encode`].
pub(crate) struct Checked<'a, T>(&'a T);

impl<'a, T: Check> Checked<'a, T> {
    fn of(value: &'a T) -> Result<Self, WireError> {
        value.check()?;
        Ok(Self(value))
    }

    /// Past the check, as a hostile writer would: for tests that a reader refuses what it wrote.
    #[cfg(test)]
    pub(crate) fn forged(value: &'a T) -> Self {
        Self(value)
    }
}

impl<T> std::ops::Deref for Checked<'_, T> {
    type Target = T;

    fn deref(&self) -> &T {
        self.0
    }
}

/// A value [`Fields::read`] parsed and nobody has checked yet. Its value is reachable only here,
/// through [`Fields::decode`], which checks it first, so no body is read unchecked.
pub(crate) struct Unchecked<T>(T);

impl<T> Unchecked<T> {
    pub(crate) fn new(value: T) -> Self {
        Self(value)
    }
}

impl<T: Check> Unchecked<T> {
    fn checked(self) -> Result<T, WireError> {
        self.0.check()?;
        Ok(self.0)
    }
}

/// How a record body is written and read. A type says how its fields are laid out (`write`,
/// `read`) and what makes a value of it well formed ([`Check`]); `encode` and `decode` are the
/// only ways in or out, and both run the check.
pub(crate) trait Fields: Check + Sized {
    /// Lays out a checked value's fields. Called only by `encode`.
    fn write(value: Checked<'_, Self>, out: &mut Vec<u8>) -> Result<(), WireError>;
    /// Parses the fields. Called only by `decode`.
    fn read(reader: &mut Body<'_>) -> Result<Unchecked<Self>, WireError>;

    /// Checks the value, then writes it.
    fn encode(&self, out: &mut Vec<u8>) -> Result<(), WireError> {
        Self::write(Checked::of(self)?, out)
    }

    /// Reads a value, then checks it.
    fn decode(reader: &mut Body<'_>) -> Result<Self, WireError> {
        Self::read(reader)?.checked()
    }

    /// Written alone, as an unsigned record's body (in a record, `Record::encode` writes it).
    #[cfg(test)]
    fn to_bytes(&self) -> Result<Vec<u8>, WireError> {
        let mut out = Vec::new();
        self.encode(&mut out)?;
        if out.len() > MAX_BODY {
            return Err(WireError::Oversize(out.len()));
        }
        Ok(out)
    }

    /// Read alone, from an unsigned record's body, without a session.
    #[cfg(test)]
    fn from_body(bytes: &[u8]) -> Result<Self, WireError> {
        Self::decode(&mut Body::new(bytes))
    }

    /// Read alone, from an unsigned record's body that arrived on a session that negotiated
    /// `version` (`Record::decode`), which is what a stream bit it names is read by.
    fn from_session(bytes: &[u8], version: u16) -> Result<Self, WireError> {
        Self::decode(&mut Body::at(bytes, version))
    }
}

/// A signed record's bytes.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(crate) struct Signed {
    bytes: Vec<u8>,
}

const PREFIX_LEN: usize = 1 + KEY_LEN;

impl Signed {
    /// Signs `body` under `label`, refused past `max` bytes in all (at most a record's body).
    pub(crate) fn sign(
        label: &[u8],
        format: u8,
        identity: &impl Signs,
        body: &[u8],
        max: usize,
    ) -> Result<Self, WireError> {
        let mut bytes = Vec::with_capacity(PREFIX_LEN + body.len() + SIGNATURE_LEN);
        bytes.push(format);
        bytes.extend_from_slice(identity.public().as_bytes());
        bytes.extend_from_slice(body);
        let total = bytes.len() + SIGNATURE_LEN;
        if !Self::fits(body.len(), max) {
            return Err(WireError::Oversize(total));
        }
        let signature = identity.sign(&domain(label, &bytes));
        bytes.extend_from_slice(&signature);
        Ok(Self { bytes })
    }

    /// What its bytes allocate (`footprint::vec`): their capacity.
    pub(crate) fn allocated(&self) -> usize {
        crate::footprint::vec::<u8>(self.bytes.capacity())
    }

    /// Whether a body of `body` bytes makes a record of at most `max` bytes, signature included.
    pub(crate) fn fits(body: usize, max: usize) -> bool {
        PREFIX_LEN + body + SIGNATURE_LEN <= max.min(MAX_BODY)
    }

    /// Accepts any format whose prefix is well formed. Does not check the signature.
    pub(crate) fn from_bytes(bytes: Vec<u8>) -> Result<Self, WireError> {
        if bytes.len() < PREFIX_LEN + SIGNATURE_LEN {
            return Err(WireError::Truncated {
                needed: PREFIX_LEN + SIGNATURE_LEN,
                had: bytes.len(),
            });
        }
        PublicKey::from_slice(&bytes[1..PREFIX_LEN])?;
        Ok(Self { bytes })
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn format(&self) -> u8 {
        self.bytes[0]
    }

    pub fn signer(&self) -> Result<PublicKey, WireError> {
        PublicKey::from_slice(&self.bytes[1..PREFIX_LEN])
    }

    /// BLAKE2s over every byte, signature included: the record's identity.
    pub fn hash(&self) -> Hash {
        Blake2s256::digest(&self.bytes).into()
    }

    pub(crate) fn verify(&self, label: &[u8]) -> Result<(), WireError> {
        let (signed, signature) = split_signature(&self.bytes)?;
        self.signer()?.verify(&domain(label, signed), &signature)
    }

    /// The body, for a format this build reads.
    pub(crate) fn body(&self, format: u8) -> Result<Body<'_>, WireError> {
        if self.format() != format {
            return Err(WireError::Invalid {
                field: "record format",
                value: u64::from(self.format()),
            });
        }
        Ok(Body::new(
            &self.bytes[PREFIX_LEN..self.bytes.len() - SIGNATURE_LEN],
        ))
    }
}

/// A signed record kind: its bytes, built by signing a body of `$content` under `$domain` in
/// format `$format`, at most `$max` bytes.
macro_rules! signed_record {
    ($(#[$doc:meta])* $name:ident, $content:ty, $domain:expr, $format:expr, $max:expr) => {
        $(#[$doc])*
        #[derive(Clone, Debug, PartialEq, Eq)]
        pub struct $name($crate::signed::Signed);

        impl $name {
            /// What the signature is computed under: no other record kind's.
            pub const DOMAIN: &'static [u8] = $domain;
            /// The layout this build writes.
            pub const FORMAT: u8 = $format;
            /// The most bytes one may have, signature included.
            pub const MAX_LEN: usize = $max;

            pub fn sign(
                identity: &impl $crate::key::Signs,
                content: &$content,
            ) -> Result<Self, $crate::WireError> {
                let mut body = Vec::new();
                $crate::signed::Fields::encode(content, &mut body)?;
                $crate::signed::Signed::sign($domain, $format, identity, &body, $max).map(Self)
            }

            /// Whether `content` is a valid record of this kind that `sign` would make: its
            /// fields check, and it fits the kind's size. Decided without signing, so a caller can
            /// cut what it signs to fit before numbering it.
            pub fn fits(content: &$content) -> bool {
                let mut body = Vec::new();
                $crate::signed::Fields::encode(content, &mut body).is_ok()
                    && $crate::signed::Signed::fits(body.len(), $max)
            }

            /// Any format with a well-formed prefix. Does not check the signature.
            pub fn from_bytes(bytes: Vec<u8>) -> Result<Self, $crate::WireError> {
                $crate::signed::Signed::from_bytes(bytes).map(Self)
            }

            pub fn as_bytes(&self) -> &[u8] {
                self.0.as_bytes()
            }

            /// What it allocates of its own: its bytes' capacity.
            pub fn allocated(&self) -> usize {
                self.0.allocated()
            }

            pub fn format(&self) -> u8 {
                self.0.format()
            }

            /// Who signed it.
            pub fn signer(&self) -> Result<$crate::key::PublicKey, $crate::WireError> {
                self.0.signer()
            }

            pub fn hash(&self) -> $crate::batch::Hash {
                self.0.hash()
            }

            pub fn verify(&self) -> Result<(), $crate::WireError> {
                self.0.verify($domain)
            }

            /// The content, for a format this build reads.
            pub fn content(&self) -> Result<$content, $crate::WireError> {
                let mut body = self.0.body($format)?;
                <$content as $crate::signed::Fields>::decode(&mut body)
            }
        }
    };
}
pub(crate) use signed_record;

/// Writes a list's length as a `u16`, refused past `max` items.
pub(crate) fn count_u16(out: &mut Vec<u8>, len: usize, max: usize) -> Result<(), WireError> {
    if len > max {
        return Err(WireError::Oversize(len));
    }
    let count = u16::try_from(len).map_err(|_| WireError::Oversize(len))?;
    out.extend_from_slice(&count.to_be_bytes());
    Ok(())
}

/// Reads a list's `u16` length, refused past `max` items.
pub(crate) fn read_count(reader: &mut Body<'_>, max: usize) -> Result<usize, WireError> {
    let count = usize::from(reader.u16()?);
    if count > max {
        return Err(WireError::Invalid {
            field: "list length",
            value: count as u64,
        });
    }
    Ok(count)
}

/// Writes a string of at most 255 bytes, length first.
pub(crate) fn put_str(out: &mut Vec<u8>, text: &str) -> Result<(), WireError> {
    let bytes = text.as_bytes();
    let length = u8::try_from(bytes.len()).map_err(|_| WireError::Oversize(bytes.len()))?;
    out.push(length);
    out.extend_from_slice(bytes);
    Ok(())
}

pub(crate) fn read_str(reader: &mut Body<'_>) -> Result<String, WireError> {
    let length = usize::from(reader.u8()?);
    std::str::from_utf8(reader.bytes(length)?)
        .map(str::to_owned)
        .map_err(|_| WireError::Invalid {
            field: "text",
            value: length as u64,
        })
}

/// Writes a byte string of at most `u32::MAX` bytes, length first: a signed record carried whole.
pub(crate) fn put_blob(out: &mut Vec<u8>, bytes: &[u8]) -> Result<(), WireError> {
    let length = u32::try_from(bytes.len()).map_err(|_| WireError::Oversize(bytes.len()))?;
    out.extend_from_slice(&length.to_be_bytes());
    out.extend_from_slice(bytes);
    Ok(())
}

pub(crate) fn read_blob(reader: &mut Body<'_>) -> Result<Vec<u8>, WireError> {
    let length = reader.u32()? as usize;
    Ok(reader.bytes(length)?.to_vec())
}
