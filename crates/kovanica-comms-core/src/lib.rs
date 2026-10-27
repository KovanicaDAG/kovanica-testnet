#![deny(unsafe_code)]

//! Comms identity for the Kovanica comms app (control plane).
//!
//! This crate is intentionally tiny and dependency-light. It defines the single
//! canonical, domain-separated identity used across the whole comms stack so the
//! Rust core, the `kovanica` CLI harness and the TypeScript client all derive the
//! *same* id:
//!
//! ```text
//! comms_id = BLAKE3( b"kvnc/comms/id" || <32-byte Ed25519 public key> )
//! ```
//!
//! The 32-byte digest is rendered as 64 lowercase hex characters. The domain
//! prefix must stay identical to `packages/comms/src/identity.ts`
//! (`COMMS_ID_DOMAIN = "kvnc/comms/id"`); change both in lockstep.
//!
//! Nothing here is consensus-critical: it is a pure, deterministic derivation
//! over public key material and never touches private key material.

use core::fmt;

/// Domain-separation prefix for the comms identity.
///
/// Kept as bytes so it can be concatenated with raw key material without an
/// intermediate `str`/allocation. Its ASCII value is `kvnc/comms/id`.
pub const COMMS_ID_DOMAIN: &[u8] = b"kvnc/comms/id";

/// Length of an Ed25519 public key, in bytes.
pub const PUBLIC_KEY_LEN: usize = 32;

/// A 32-byte Kovanica comms identity.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct CommsId([u8; 32]);

impl CommsId {
    /// Wrap a raw 32-byte digest.
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// The underlying 32-byte digest.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Lowercase hex encoding (64 characters).
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }
}

impl fmt::Display for CommsId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

impl fmt::Debug for CommsId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "CommsId({})", self.to_hex())
    }
}

/// Derive the comms id from a 32-byte Ed25519 public key.
///
/// Uses the house convention `hash(domain_prefix_ascii || fixed_width_fields)`
/// via [`kovanica_common::hash`] (BLAKE3-256), matching every other derived ID in
/// the workspace.
pub fn comms_id(public_key: &[u8; PUBLIC_KEY_LEN]) -> CommsId {
    let mut input = [0u8; COMMS_ID_DOMAIN.len() + PUBLIC_KEY_LEN];
    input[..COMMS_ID_DOMAIN.len()].copy_from_slice(COMMS_ID_DOMAIN);
    input[COMMS_ID_DOMAIN.len()..].copy_from_slice(public_key);
    CommsId(kovanica_common::hash(&input))
}

/// Fallible variant for untrusted input: validates the key length.
///
/// Returns `None` when `public_key` is not exactly [`PUBLIC_KEY_LEN`] bytes,
/// mirroring the TypeScript `deriveCommsId*` guards.
pub fn comms_id_from_slice(public_key: &[u8]) -> Option<CommsId> {
    let key: &[u8; PUBLIC_KEY_LEN] = public_key.try_into().ok()?;
    Some(comms_id(key))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn domain_prefix_is_the_agreed_literal() {
        assert_eq!(COMMS_ID_DOMAIN, b"kvnc/comms/id");
    }

    #[test]
    fn derivation_is_deterministic() {
        let key = [0x2a; PUBLIC_KEY_LEN];
        assert_eq!(comms_id(&key), comms_id(&key));
        assert_eq!(comms_id(&key).to_hex(), comms_id(&key).to_hex());
    }

    #[test]
    fn id_is_64_lowercase_hex_characters() {
        let id = comms_id(&[7u8; PUBLIC_KEY_LEN]).to_hex();
        assert_eq!(id.len(), 64);
        assert!(
            id.chars()
                .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c)),
            "not lowercase hex: {id}"
        );
    }

    #[test]
    fn distinct_keys_give_distinct_ids() {
        assert_ne!(
            comms_id(&[0u8; PUBLIC_KEY_LEN]),
            comms_id(&[1u8; PUBLIC_KEY_LEN])
        );
    }

    #[test]
    fn slice_variant_rejects_wrong_lengths() {
        assert!(comms_id_from_slice(&[0u8; PUBLIC_KEY_LEN]).is_some());
        assert!(comms_id_from_slice(&[0u8; PUBLIC_KEY_LEN - 1]).is_none());
        assert!(comms_id_from_slice(&[0u8; PUBLIC_KEY_LEN + 1]).is_none());
    }

    #[test]
    fn domain_separation_differs_from_bare_hash() {
        // A bare BLAKE3 of the key must not collide with the domain-separated id.
        let key = [0x11; PUBLIC_KEY_LEN];
        assert_ne!(comms_id(&key).as_bytes(), &kovanica_common::hash(&key));
    }

    #[test]
    fn known_answer_vector() {
        // Cross-language KAT: the TypeScript client asserts the same hex in
        // `packages/comms/src/identity.test.ts`.
        let key = [0x01u8; PUBLIC_KEY_LEN];
        assert_eq!(
            comms_id(&key).to_hex(),
            "6076cc6f05dbd8ad851ba6aa6b7e85c8dce112186e16d3e267663641d9fa9339"
        );
    }
}
