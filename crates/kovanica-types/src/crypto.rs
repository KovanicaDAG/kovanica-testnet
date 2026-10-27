//! Cryptographic primitives re-exports and wrappers.

use ed25519_dalek::{Signature as DalekSignature, VerifyingKey};
use serde::de::Visitor;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;

/// Ed25519 signing key wrapper (re-export from ed25519_dalek).
pub type SigningKey = ed25519_dalek::SigningKey;

/// Ed25519 public key wrapper.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Debug)]
pub struct PublicKey(pub [u8; 32]);

impl PublicKey {
    /// Return the raw 32-byte public key.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Create a PublicKey from raw 32 bytes.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

/// Ed25519 signature wrapper.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Signature(pub [u8; 64]);

impl Signature {
    /// Return the raw 64-byte signature.
    pub fn as_bytes(&self) -> &[u8; 64] {
        &self.0
    }
}

impl Serialize for Signature {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(&self.0)
    }
}

impl<'de> Deserialize<'de> for Signature {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct SigVisitor;
        impl<'de> Visitor<'de> for SigVisitor {
            type Value = Signature;
            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("64-byte Ed25519 signature")
            }
            fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                if v.len() != 64 {
                    return Err(E::invalid_length(v.len(), &"64 bytes"));
                }
                let mut arr = [0u8; 64];
                arr.copy_from_slice(v);
                Ok(Signature(arr))
            }
        }
        deserializer.deserialize_bytes(SigVisitor)
    }
}

// Convenience conversions
impl From<VerifyingKey> for PublicKey {
    fn from(vk: VerifyingKey) -> Self {
        Self(vk.to_bytes())
    }
}

impl From<DalekSignature> for Signature {
    fn from(sig: DalekSignature) -> Self {
        Self(sig.to_bytes())
    }
}

/// Serde adapter for a 96-byte ECVRF proof.
///
/// `[u8; 96]` is past the array size serde implements. The proof is stored
/// as raw bytes, the same way [`Signature`] is.
pub mod vrf_proof_bytes {
    use serde::de::{SeqAccess, Visitor};
    use serde::{Deserializer, Serializer};
    use std::fmt;

    /// Encode a 96-byte proof.
    pub fn serialize<S>(proof: &[u8; 96], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(proof)
    }

    /// Decode a 96-byte proof from raw bytes or a sequence of bytes.
    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 96], D::Error>
    where
        D: Deserializer<'de>,
    {
        struct ProofVisitor;
        impl<'de> Visitor<'de> for ProofVisitor {
            type Value = [u8; 96];

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("96-byte ECVRF proof")
            }

            fn visit_bytes<E>(self, value: &[u8]) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                if value.len() != 96 {
                    return Err(E::invalid_length(value.len(), &"96 bytes"));
                }
                let mut proof = [0u8; 96];
                proof.copy_from_slice(value);
                Ok(proof)
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let mut proof = [0u8; 96];
                let mut seen = 0;
                while seen < proof.len() {
                    let Some(byte) = seq.next_element()? else {
                        return Err(serde::de::Error::invalid_length(seen, &"96 bytes"));
                    };
                    proof[seen] = byte;
                    seen += 1;
                }
                Ok(proof)
            }
        }
        deserializer.deserialize_bytes(ProofVisitor)
    }
}

impl Signature {
    /// Verify this signature over the given message using the provided public key.
    pub fn verify(&self, message: &[u8], public_key: &PublicKey) -> bool {
        use ed25519_dalek::{Signature as DalekSignature, Verifier, VerifyingKey};
        // Convert our signature to dalek's Signature type
        let dalek_sig = match DalekSignature::try_from(self.0.as_slice()) {
            Ok(sig) => sig,
            Err(_) => return false,
        };
        let dalek_pk = match VerifyingKey::from_bytes(&public_key.0) {
            Ok(pk) => pk,
            Err(_) => return false,
        };
        dalek_pk.verify(message, &dalek_sig).is_ok()
    }

    /// Strict Ed25519 verification over the given message.
    ///
    /// Uses `verify_strict`, which additionally rejects small-order/weak
    /// public keys and non-canonical `R`/`A`/`S` encodings. Equivocation
    /// evidence is a consensus-critical proof: a signature that only passes
    /// the malleable check must not be enough to slash a validator.
    pub fn verify_strict(&self, message: &[u8], public_key: &PublicKey) -> bool {
        use ed25519_dalek::{Signature as DalekSignature, VerifyingKey};
        let dalek_sig = match DalekSignature::try_from(self.0.as_slice()) {
            Ok(sig) => sig,
            Err(_) => return false,
        };
        let dalek_pk = match VerifyingKey::from_bytes(&public_key.0) {
            Ok(pk) => pk,
            Err(_) => return false,
        };
        dalek_pk.verify_strict(message, &dalek_sig).is_ok()
    }
}
