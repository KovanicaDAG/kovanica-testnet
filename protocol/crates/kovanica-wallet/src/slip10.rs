//! The **frozen** Kovanica key-derivation path: SLIP-0010 ed25519 over
//! `m/44'/3007'/0'/0'/i'`.
//!
//! This module is the single Rust source of truth inside the protocol
//! repository. The node, the CLI, and the TUI all derive keys through it, so
//! there is exactly one implementation of the path in the consensus-side tree.
//!
//! # Why this is frozen
//!
//! The path, the coin type, and the hardened-index convention are **not**
//! negotiable without a coordinated breaking change across every client:
//! altering any of them changes every derived address and therefore every
//! on-chain balance. See `docs/DERIVATION.md` in the project vault.
//!
//! # Relationship to the official SLIP-0010 vectors
//!
//! The primitives here are genuine SLIP-0010 ed25519 and are pinned against
//! the **official** spec vectors (test vector 1) in `tests/slip10_vectors.rs`,
//! so "SLIP-0010" is a verified claim rather than a label. The Kovanica path
//! itself (`m/44'/3007'/0'/0'/i'` applied to a 64-byte BIP-39 seed) is pinned
//! separately against the project's own frozen vectors, which are mirrored by
//! the SDK crate `kovanica-keys` and the TypeScript web wallet.
//!
//! # Layering
//!
//! **Client-side only.** Nothing in this module participates in consensus, and
//! a node never needs it: consensus addresses come from a 32-byte seed handed
//! to [`kovanica_state::KeyPair::from_seed`]. This crate exists so that the
//! mnemonic → seed → address rule is shared library code rather than a detail
//! duplicated across binaries.

use hmac::{Hmac, Mac};
use sha2::Sha512;

type HmacSha512 = Hmac<Sha512>;

/// SLIP-44 coin type for Kovanica. Frozen; unregistered upstream.
pub const SLIP44_COIN_TYPE: u32 = 3007;

/// SLIP-44 account segment. Frozen.
pub const DERIVATION_ACCOUNT: u32 = 0;

/// The frozen derivation path, for display and documentation.
pub const DERIVATION_PATH: &str = "m/44'/3007'/0'/0'/i'";

/// HMAC key that separates ed25519 master keys from other curves (SLIP-0010).
const ED25519_CURVE: &[u8] = b"ed25519 seed";

/// Hardened-child marker. SLIP-0010 defines a hardened child as `i >= 2^31`;
/// ed25519 supports no normal children, so every segment is hardened.
const HARDENED: u32 = 0x8000_0000;

/// Derive the 32-byte Ed25519 key material at `m/44'/3007'/0'/0'/index'` from a
/// 64-byte BIP-39 seed.
///
/// `seed` is the raw PBKDF2 output of a BIP-39 mnemonic (plus optional
/// passphrase), i.e. exactly [`bip39::Mnemonic::to_seed`]. Callers that already
/// hold a 32-byte seed should use [`kovanica_state::KeyPair::from_seed`]
/// directly and skip this module — no derivation applies to a raw seed.
pub fn derive_ed25519(seed: &[u8; 64], index: u32) -> [u8; 32] {
    derive_path(seed, &[44, SLIP44_COIN_TYPE, DERIVATION_ACCOUNT, 0, index])
}

/// SLIP-0010 ed25519 over an arbitrary hardened path, from arbitrary key
/// material.
///
/// Every segment is hardened: ed25519 defines no normal children, and SLIP-0010
/// spells a hardened child as an index `>= 2^31`, which this applies
/// unconditionally. An empty `path` yields the master key.
///
/// This is the general form. [`derive_ed25519`] is the frozen Kovanica path and
/// is what production code should call; this exists so the algorithm can be
/// checked against the official specification vectors, which use their own path.
pub fn derive_path(material: &[u8], path: &[u32]) -> [u8; 32] {
    // Master node: I = HMAC-SHA512(key = curve, data = material).
    let (mut key, mut chain) = split_master(material);

    // Child nodes, in path order.
    for &segment in path {
        let (child_key, child_chain) = derive_child(&key, &chain, segment | HARDENED);
        key = child_key;
        chain = child_chain;
    }
    key
}

/// `I = HMAC-SHA512(key = "ed25519 seed", data = material)` → `(key, chain)`.
///
/// The spec allows 128 to 512 bits of input, so the length is not constrained
/// here. ed25519 has no invalid-key case, so SLIP-0010's retry rule never
/// applies: every 32-byte string is a usable Ed25519 secret.
fn split_master(material: &[u8]) -> ([u8; 32], [u8; 32]) {
    let i = hmac_sha512(ED25519_CURVE, material);
    let key = i[..32].try_into().expect("HMAC-SHA512 yields 64 bytes");
    let chain = i[32..].try_into().expect("HMAC-SHA512 yields 64 bytes");
    (key, chain)
}

/// One hardened CKDpriv step: `I = HMAC-SHA512(c_par, 0x00 || k_par || ser32(i))`.
///
/// For ed25519 the child key is `I[..32]` verbatim — there is no `+ k_par (mod n)`
/// step, because an ed25519 secret is a byte string and not a scalar multiple.
fn derive_child(key: &[u8; 32], chain: &[u8; 32], index: u32) -> ([u8; 32], [u8; 32]) {
    // The leading 0x00 pads the key to 33 bytes so the layout is unambiguous.
    let mut data = [0u8; 1 + 32 + 4];
    data[1..33].copy_from_slice(key);
    data[33..].copy_from_slice(&index.to_be_bytes());

    let i = hmac_sha512(chain, &data);
    let child_key = i[..32].try_into().expect("HMAC-SHA512 yields 64 bytes");
    let child_chain = i[32..].try_into().expect("HMAC-SHA512 yields 64 bytes");
    (child_key, child_chain)
}

fn hmac_sha512(key: &[u8], data: &[u8]) -> [u8; 64] {
    let mut mac = <HmacSha512 as Mac>::new_from_slice(key).expect("HMAC accepts any key size");
    mac.update(data);
    // `into_bytes` on a 512-bit digest is already a `GenericArray<u8, _64>`,
    // so widening to a plain array is infallible.
    mac.finalize().into_bytes().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn index_changes_the_key() {
        let material = [0x5au8; 64];
        assert_ne!(derive_ed25519(&material, 0), derive_ed25519(&material, 1));
    }

    #[test]
    fn derivation_is_deterministic() {
        let material = [0x17u8; 64];
        assert_eq!(derive_ed25519(&material, 7), derive_ed25519(&material, 7));
    }

    /// The frozen path must be exactly the generic path with the documented
    /// segments — otherwise the constants and the code can drift apart.
    #[test]
    fn frozen_path_matches_generic_path() {
        let material = [0x42u8; 64];
        for index in 0..4u32 {
            assert_eq!(
                derive_ed25519(&material, index),
                derive_path(&material, &[44, 3007, 0, 0, index])
            );
        }
    }

    /// An empty path is the master key, and each prefix is a distinct node —
    /// i.e. the chain is really being walked, not recomputed from `material`.
    #[test]
    fn path_prefixes_are_distinct_nodes() {
        let material = [0x9cu8; 32];
        let nodes: Vec<[u8; 32]> = [vec![], vec![0], vec![0, 1], vec![0, 1, 2], vec![0, 1, 2, 2]]
            .iter()
            .map(|path| derive_path(&material, path))
            .collect();

        for (i, a) in nodes.iter().enumerate() {
            for (j, b) in nodes.iter().enumerate() {
                assert_eq!(i == j, a == b, "paths {i} and {j} must be distinct");
            }
        }
    }
}
