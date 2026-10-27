//! BLAKE3-based hash type.

use blake3::Hasher;
use serde::{Deserialize, Serialize};
use std::fmt;

/// 32-byte BLAKE3 hash.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
pub struct Hash(pub [u8; 32]);

impl Hash {
    /// Compute BLAKE3 hash of the given data.
    pub fn new(data: impl AsRef<[u8]>) -> Self {
        let mut hasher = Hasher::new();
        hasher.update(data.as_ref());
        Self(*hasher.finalize().as_bytes())
    }

    /// Compute BLAKE3 hash with a domain key (domain separation).
    pub fn new_keyed(domain: &[u8], data: impl AsRef<[u8]>) -> Self {
        let mut key = [0u8; 32];
        let len = domain.len().min(32);
        key[..len].copy_from_slice(&domain[..len]);
        let mut hasher = Hasher::new_keyed(&key);
        hasher.update(data.as_ref());
        Self(*hasher.finalize().as_bytes())
    }

    /// Domain tag for block digests.
    pub const DOMAIN_BLOCK: &'static [u8] = b"KUNA-BLOCK-v1";
    /// Domain tag for transactions.
    pub const DOMAIN_TX: &'static [u8] = b"KUNA-TX-v1";
    /// Domain tag for digest/merkle pairing.
    pub const DOMAIN_DIGEST: &'static [u8] = b"KUNA-DIGEST-v1";
    /// Domain tag for merkle tree pairing.
    pub const DOMAIN_MERKLE: &'static [u8] = b"KUNA-MERKLE-v1";
    /// Domain tag for a committed-leader header.
    pub const DOMAIN_HEADER: &'static [u8] = b"KUNA-HEADER-v1";
    /// Domain tag for an account-tree leaf.
    pub const DOMAIN_ACCOUNT: &'static [u8] = b"KUNA-ACCOUNT-v1";
    /// Domain tag for an empty account-tree subtree.
    pub const DOMAIN_ACCOUNT_EMPTY: &'static [u8] = b"KUNA-ACCT-EMPTY";
    /// Domain tag for an account-tree internal node.
    pub const DOMAIN_SMT: &'static [u8] = b"KUNA-SMT-v1";
    /// Domain tag for the committee bound into a commit seal.
    pub const DOMAIN_COMMITTEE: &'static [u8] = b"KUNA-COMMITTEE-v1";
    /// Domain tag for an equivocation-evidence id.
    pub const DOMAIN_EVIDENCE: &'static [u8] = b"KUNA-EVIDENCE-v1";

    /// Zero hash (useful for genesis).
    pub fn zero() -> Self {
        Self([0u8; 32])
    }

    /// Convert to hex string.
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }
}

impl fmt::Display for Hash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", &self.to_hex()[..16]) // short form
    }
}

impl fmt::Debug for Hash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Hash({})", self.to_hex())
    }
}

impl AsRef<[u8]> for Hash {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

#[cfg(test)]
mod domain_tests {
    use super::Hash;

    /// Toni's 2026-10-19 decision: every hash domain is `KUNA-*` (chain 4
    /// reset). The tags must also stay pairwise distinct so no two hash uses
    /// can collide.
    #[test]
    fn hash_domains_are_kuna_and_distinct() {
        let domains: [&[u8]; 10] = [
            Hash::DOMAIN_BLOCK,
            Hash::DOMAIN_TX,
            Hash::DOMAIN_DIGEST,
            Hash::DOMAIN_MERKLE,
            Hash::DOMAIN_HEADER,
            Hash::DOMAIN_ACCOUNT,
            Hash::DOMAIN_ACCOUNT_EMPTY,
            Hash::DOMAIN_SMT,
            Hash::DOMAIN_COMMITTEE,
            Hash::DOMAIN_EVIDENCE,
        ];
        for (i, d) in domains.iter().enumerate() {
            assert!(
                d.starts_with(b"KUNA-"),
                "domain {} is not KUNA-*",
                String::from_utf8_lossy(d)
            );
            for other in &domains[i + 1..] {
                assert_ne!(d, other, "duplicate hash domain");
            }
        }
    }

    /// `new_keyed` uses the tag as a 32-byte BLAKE3 key and truncates
    /// anything longer, so two long tags with the same 32-byte prefix would
    /// silently collide. Every tag must fit.
    #[test]
    fn hash_domains_fit_the_32_byte_key() {
        for d in [
            Hash::DOMAIN_BLOCK,
            Hash::DOMAIN_TX,
            Hash::DOMAIN_DIGEST,
            Hash::DOMAIN_MERKLE,
            Hash::DOMAIN_HEADER,
            Hash::DOMAIN_ACCOUNT,
            Hash::DOMAIN_ACCOUNT_EMPTY,
            Hash::DOMAIN_SMT,
            Hash::DOMAIN_COMMITTEE,
            Hash::DOMAIN_EVIDENCE,
        ] {
            assert!(
                d.len() <= 32,
                "{} is longer than 32 B",
                String::from_utf8_lossy(d)
            );
        }
    }

    /// Known-answer digests: `new_keyed(domain, b"kovanica-kat")`, computed
    /// independently (Python `blake3`, key = tag zero-padded to 32 B). A
    /// change to a tag or to the keying shows up here.
    #[test]
    fn hash_domain_known_answers() {
        let cases: [(&[u8], &str); 10] = [
            (
                Hash::DOMAIN_BLOCK,
                "a29004f9acd71f82fbac7162cbad0cda4e3ef6c8d8f2717dd2c91bce7a7a650f",
            ),
            (
                Hash::DOMAIN_TX,
                "59fc894f29e7e64f83760f04f8a522fa3bb22a10c592ad3a51928d0cc70b8c5d",
            ),
            (
                Hash::DOMAIN_DIGEST,
                "89803e36915e574052298400377ae4c79e493756ba23828bb186146e76c6e612",
            ),
            (
                Hash::DOMAIN_MERKLE,
                "f57fb2d2c1a213fcddd4f61ab2925b963f7d8541e43b0e01adcf74379ca7e251",
            ),
            (
                Hash::DOMAIN_HEADER,
                "a2abb5e9b5ae67a2b5c55573ebc35eab86e3fad707c59c67de29abe8f342cf20",
            ),
            (
                Hash::DOMAIN_ACCOUNT,
                "cad10474fa0dae6e2fb200f5bce4400853e82da907bda26ae86013352c024889",
            ),
            (
                Hash::DOMAIN_ACCOUNT_EMPTY,
                "9694849c8c5b7de5bbd0b6d510442c90381a493e78ad19ce677241cfa476614f",
            ),
            (
                Hash::DOMAIN_SMT,
                "2ff0c13806b0dcc20b792799fb7b5de2a44f223b24dd14edb72d29923cf1ae7b",
            ),
            (
                Hash::DOMAIN_COMMITTEE,
                "8d0f7b7c55d1245f87ef605d186925aaa807e4b07abc996567b0fcc9b8b3f2a8",
            ),
            (
                Hash::DOMAIN_EVIDENCE,
                "e53ec284e86d16e720e16f0d5b80d7916853b9a7d71b15b24b40f44f31b47678",
            ),
        ];
        for (domain, hex) in cases {
            assert_eq!(
                Hash::new_keyed(domain, b"kovanica-kat").to_hex(),
                hex,
                "{}",
                String::from_utf8_lossy(domain)
            );
        }
    }
}
