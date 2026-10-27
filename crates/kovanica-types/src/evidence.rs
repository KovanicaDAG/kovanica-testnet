//! Self-contained equivocation (double-sign) evidence.
//!
//! A validator equivocates when it authors two different blocks for the same
//! round. The proof is the two signed block headers: each carries the author
//! address and a signature over the block digest, so only the holder of that
//! key could have produced both. No historical committee is needed to verify
//! it — which matters because the node only keeps the *current* active set,
//! so an epoch-scoped key lookup cannot be reconstructed after the fact.
//!
//! Evidence is only *formatted* here. Whether it is actionable (author is an
//! active validator, evidence is fresh enough) is decided by the execution
//! layer, which has the staking state and the round being executed.

use crate::address::Address;
use crate::block::StatementBlock;
use crate::crypto::{PublicKey, Signature};
use crate::hash::Hash;
use crate::Round;
use serde::{Deserialize, Serialize};

/// Maximum age, in leader rounds, of actionable equivocation evidence.
///
/// Without an age bound, a validator that equivocated long ago could be
/// slashed at any point in the future by replaying the proof, after its stake
/// has been redelegated or its unbonding entries have matured. Well inside the
/// 100 000-committed-leader unbonding window, so a pending unbond can still be
/// cut (H2). At 4 s per round this is roughly 33 hours.
pub const EVIDENCE_MAX_AGE_ROUNDS: Round = 30_000;

/// One block header signed by its author.
///
/// This is the minimum needed to prove authorship: the signature covers the
/// block digest, exactly as `StatementBlock.signature` does.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct SignedBlockHeader {
    /// Block author (also the Ed25519 public key that signed it).
    pub author: Address,
    /// Leader round of the block.
    pub round: Round,
    /// Block digest (what the signature covers).
    pub digest: Hash,
    /// Author's Ed25519 signature over `digest`.
    pub signature: Signature,
}

impl SignedBlockHeader {
    /// Extract the header from a block.
    ///
    /// `StatementBlock` identifies its author by authority index, not by
    /// address, and committee indices rotate across epochs. The caller (the
    /// engine, which holds the current committee) passes the address that the
    /// index mapped to when the block was accepted. The signature check below
    /// binds the proof to that address, so a wrong mapping simply fails to
    /// verify — it cannot be used to slash somebody who did not sign.
    pub fn from_block(block: &StatementBlock, author: Address) -> Self {
        Self {
            author,
            round: block.round,
            digest: block.digest,
            signature: block.signature,
        }
    }

    /// Whether the signature is a valid strict Ed25519 signature by `author`
    /// over `digest`.
    pub fn verify(&self) -> bool {
        let public_key = PublicKey(self.author.0);
        self.signature
            .verify_strict(self.digest.as_ref(), &public_key)
    }
}

/// Why a pair of headers is not valid equivocation evidence.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum EvidenceError {
    /// The two headers were signed by different authors.
    #[error("evidence headers name different authors")]
    AuthorMismatch,
    /// The two headers belong to different rounds.
    #[error("evidence headers are for different rounds")]
    RoundMismatch,
    /// The two headers carry the same digest: same block, not equivocation.
    #[error("evidence headers carry the same digest")]
    SameDigest,
    /// At least one header signature does not verify.
    #[error("evidence header signature is invalid")]
    BadSignature,
}

/// Proof that `header_a.author` signed two different blocks in one round.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct EquivocationEvidence {
    /// First signed header.
    pub header_a: SignedBlockHeader,
    /// Second signed header, same author and round, different digest.
    pub header_b: SignedBlockHeader,
}

impl EquivocationEvidence {
    /// Build evidence from two blocks, if they really are an equivocation.
    pub fn from_blocks(
        first: &StatementBlock,
        second: &StatementBlock,
        author: Address,
    ) -> Result<Self, EvidenceError> {
        let evidence = Self {
            header_a: SignedBlockHeader::from_block(first, author),
            header_b: SignedBlockHeader::from_block(second, author),
        };
        evidence.offender()?;
        Ok(evidence)
    }

    /// Validate the evidence and return the offending validator.
    ///
    /// Purely local: no staking or round context is consulted.
    pub fn offender(&self) -> Result<Address, EvidenceError> {
        let (a, b) = (&self.header_a, &self.header_b);
        if a.author != b.author {
            return Err(EvidenceError::AuthorMismatch);
        }
        if a.round != b.round {
            return Err(EvidenceError::RoundMismatch);
        }
        if a.digest == b.digest {
            return Err(EvidenceError::SameDigest);
        }
        if !a.verify() || !b.verify() {
            return Err(EvidenceError::BadSignature);
        }
        Ok(a.author)
    }

    /// Round both headers belong to.
    ///
    /// Meaningful only after [`Self::offender`] succeeded.
    pub fn round(&self) -> Round {
        self.header_a.round
    }

    /// Stable id of the equivocation event: one slash per (author, round),
    /// independent of which pair of conflicting blocks proves it.
    pub fn id(&self) -> Hash {
        let mut data = [0u8; 40];
        data[..32].copy_from_slice(&self.header_a.author.0);
        data[32..].copy_from_slice(&self.header_a.round.to_le_bytes());
        Hash::new_keyed(Hash::DOMAIN_EVIDENCE, data)
    }

    /// Whether evidence for round `evidence_round` is still actionable when
    /// the sub-DAG for `leader_round` is executed.
    pub fn is_fresh_at(&self, leader_round: Round) -> bool {
        leader_round.saturating_sub(self.round()) <= EVIDENCE_MAX_AGE_ROUNDS
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::SigningKey;

    fn key(tag: u8) -> SigningKey {
        SigningKey::from_bytes(&[tag; 32])
    }

    fn header(signer: &SigningKey, round: Round, seed: u8) -> SignedBlockHeader {
        let digest = Hash::new([seed]);
        SignedBlockHeader {
            author: Address(signer.verifying_key().to_bytes()),
            round,
            digest,
            signature: crate::crypto::Signature(
                ed25519_dalek::Signer::sign(signer, digest.as_ref()).to_bytes(),
            ),
        }
    }

    fn evidence(round: Round) -> EquivocationEvidence {
        let k = key(3);
        EquivocationEvidence {
            header_a: header(&k, round, 1),
            header_b: header(&k, round, 2),
        }
    }

    #[test]
    fn valid_evidence_names_the_offender() {
        let ev = evidence(7);
        assert_eq!(
            ev.offender().unwrap(),
            Address(key(3).verifying_key().to_bytes())
        );
        assert_eq!(ev.round(), 7);
    }

    #[test]
    fn id_depends_only_on_author_and_round() {
        // Which pair of conflicting digests proves the event must not matter:
        // one slash per (author, round).
        let a = evidence(7);
        let k = key(3);
        let b = EquivocationEvidence {
            header_a: header(&k, 7, 9),
            header_b: header(&k, 7, 10),
        };
        assert_eq!(a.id(), b.id());
        assert_ne!(a.id(), evidence(8).id());
        assert_ne!(
            a.id(),
            EquivocationEvidence {
                header_a: header(&key(4), 7, 1),
                header_b: header(&key(4), 7, 2),
            }
            .id()
        );
    }

    #[test]
    fn same_digest_is_not_equivocation() {
        let k = key(3);
        let h = header(&k, 7, 1);
        let ev = EquivocationEvidence {
            header_a: h.clone(),
            header_b: h,
        };
        assert_eq!(ev.offender(), Err(EvidenceError::SameDigest));
    }

    #[test]
    fn different_rounds_are_not_equivocation() {
        let k = key(3);
        let ev = EquivocationEvidence {
            header_a: header(&k, 7, 1),
            header_b: header(&k, 8, 2),
        };
        assert_eq!(ev.offender(), Err(EvidenceError::RoundMismatch));
    }

    #[test]
    fn different_authors_are_not_equivocation() {
        let ev = EquivocationEvidence {
            header_a: header(&key(3), 7, 1),
            header_b: header(&key(4), 7, 2),
        };
        assert_eq!(ev.offender(), Err(EvidenceError::AuthorMismatch));
    }

    #[test]
    fn forged_signature_is_rejected() {
        let mut ev = evidence(7);
        ev.header_b.signature = header(&key(4), 7, 2).signature;
        assert_eq!(ev.offender(), Err(EvidenceError::BadSignature));
    }

    #[test]
    fn mismatched_digest_and_signature_is_rejected() {
        // A valid signature over a different digest must not authenticate.
        let mut ev = evidence(7);
        ev.header_a.digest = Hash::new(b"swapped");
        assert_eq!(ev.offender(), Err(EvidenceError::BadSignature));
    }

    #[test]
    fn freshness_boundary() {
        let ev = evidence(1_000);
        assert!(ev.is_fresh_at(1_000));
        assert!(ev.is_fresh_at(1_000 + EVIDENCE_MAX_AGE_ROUNDS));
        assert!(!ev.is_fresh_at(1_000 + EVIDENCE_MAX_AGE_ROUNDS + 1));
    }
}
