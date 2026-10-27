//! Leader-slot timeouts and quorum-certified skips (PRO-40 (b)).
//!
//! A validator that has waited `T_skip` for leader slot `R` without voting
//! for it signs a [`Timeout`] for `R`. A [`SkipCert`] is a set of timeouts for
//! the same `R` from a stake quorum of the committee; it is the only thing
//! that lets the commit walk move past a slot without committing it.
//!
//! Safety: an honest validator records **either** a vote **or** a timeout for
//! a slot, never both. Any two quorums intersect in at least one honest
//! validator, so a vote quorum and a skip certificate for the same slot cannot
//! both exist, and every honest node either commits `R` or skips it.
//!
//! The author of the slot is not part of the preimage, so nodes that disagree
//! on the leader schedule still certify the same skip.

use crate::crypto::Signature;
use crate::hash::Hash;
use crate::signing::domain_tag16;
use crate::{epoch_for_round, AuthorityIndex, Round};
use serde::{Deserialize, Serialize};

/// Domain tag (16 bytes, `0x00`-padded) of the timeout preimage.
pub const TIMEOUT_DOMAIN_TAG: [u8; 16] = domain_tag16(b"KUNA/timeout/v1");

/// A validator's signed statement that it gave up waiting for leader slot
/// `round` without voting for it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Timeout {
    /// The leader slot being timed out.
    pub round: Round,
    /// Authority index of the signer.
    pub voter: AuthorityIndex,
    /// Ed25519 signature over [`Timeout::signature_data`].
    pub signature: Signature,
}

impl Timeout {
    /// Length in bytes of [`Timeout::signature_data`]:
    /// tag 16 ‖ chain_id 8 ‖ genesis_hash 32 ‖ epoch 8 ‖ voter 2 ‖ round 8.
    pub const SIGNATURE_DATA_LEN: usize = 16 + 8 + 32 + 8 + 2 + 8;

    /// Canonical signed bytes:
    /// `KUNA/timeout/v1 ‖ chain_id ‖ genesis_hash ‖ epoch(round) ‖ voter ‖ round`,
    /// integers little-endian. The epoch is the pure function of the round.
    #[must_use]
    pub fn signature_data(&self, chain_id: u64, genesis_hash: &Hash) -> Vec<u8> {
        let mut data = Vec::with_capacity(Self::SIGNATURE_DATA_LEN);
        data.extend_from_slice(&TIMEOUT_DOMAIN_TAG);
        data.extend_from_slice(&chain_id.to_le_bytes());
        data.extend_from_slice(&genesis_hash.0);
        data.extend_from_slice(&epoch_for_round(self.round).to_le_bytes());
        data.extend_from_slice(&self.voter.to_le_bytes());
        data.extend_from_slice(&self.round.to_le_bytes());
        data
    }
}

/// Timeouts for one leader slot from a stake quorum of the committee.
///
/// Verified by the consensus engine against the committee, the node's own
/// `chain_id` and genesis hash. Gossiped as a whole so a node that missed
/// individual timeouts can still move past the slot.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SkipCert {
    /// The skipped leader slot.
    pub round: Round,
    /// One timeout per signer, all for `round`.
    pub timeouts: Vec<Timeout>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn domain_tag_and_preimage_layout() {
        assert_eq!(&TIMEOUT_DOMAIN_TAG[..15], b"KUNA/timeout/v1");
        assert_eq!(TIMEOUT_DOMAIN_TAG[15], 0);
        let t = Timeout {
            round: 7_203,
            voter: 3,
            signature: Signature([0u8; 64]),
        };
        let genesis = Hash([9u8; 32]);
        let data = t.signature_data(4, &genesis);
        assert_eq!(data.len(), Timeout::SIGNATURE_DATA_LEN);
        assert_eq!(data.len(), 74);
        assert_eq!(&data[..16], &TIMEOUT_DOMAIN_TAG);
        assert_eq!(&data[16..24], &4u64.to_le_bytes());
        assert_eq!(&data[24..56], &genesis.0);
        assert_eq!(&data[56..64], &1u64.to_le_bytes(), "epoch(7 203) = 1");
        assert_eq!(&data[64..66], &3u16.to_le_bytes());
        assert_eq!(&data[66..74], &7_203u64.to_le_bytes());
    }

    #[test]
    fn preimage_binds_chain_genesis_and_round() {
        let t = Timeout {
            round: 12,
            voter: 1,
            signature: Signature([0u8; 64]),
        };
        let g = Hash([1u8; 32]);
        let base = t.signature_data(4, &g);
        assert_ne!(base, t.signature_data(1, &g));
        assert_ne!(base, t.signature_data(4, &Hash([2u8; 32])));
        let other = Timeout {
            round: 15,
            ..t.clone()
        };
        assert_ne!(base, other.signature_data(4, &g));
    }
}
