//! Committee and Authority definitions.

use crate::crypto::PublicKey;
use crate::Address;
use serde::{Deserialize, Serialize};

/// Stake amount (in smallest units of KUNA).
pub type Stake = u64;

/// Single authority (validator).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Authority {
    /// Index of this authority in the committee.
    pub index: u16,
    /// Ed25519 public key for block signing.
    pub public_key: PublicKey,
    /// VRF public key for verifiable leader selection.
    pub vrf_public_key: Option<PublicKey>,
    /// Account address (derived from public key).
    pub address: Address,
    /// Stake amount in base units.
    pub stake: Stake,
    /// Network address (multiaddr or host:port) for P2P.
    pub network_address: String,
}

/// Current committee (validator set).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Committee {
    /// Epoch number for this committee.
    pub epoch: u64,
    /// List of authorities in this committee.
    pub authorities: Vec<Authority>,
    /// Total stake of all authorities.
    pub total_stake: Stake,
    /// Quorum threshold (2f+1 stake).
    pub quorum_threshold: Stake,
    /// Validity threshold (f+1 stake).
    pub validity_threshold: Stake,
}

impl Committee {
    /// Create a new committee and compute thresholds.
    pub fn new(epoch: u64, authorities: Vec<Authority>) -> Self {
        let total_stake: Stake = authorities.iter().map(|a| a.stake).sum();
        // Classic BFT: quorum = 2f+1 → floor(2/3 * total) + 1
        let quorum_threshold = (total_stake * 2) / 3 + 1;
        let validity_threshold = total_stake / 3 + 1;

        Self {
            epoch,
            authorities,
            total_stake,
            quorum_threshold,
            validity_threshold,
        }
    }

    /// Return the number of authorities in the committee.
    pub fn size(&self) -> usize {
        self.authorities.len()
    }

    /// Look up an authority by its index.
    pub fn get_by_index(&self, index: u16) -> Option<&Authority> {
        self.authorities.iter().find(|a| a.index == index)
    }

    /// Stake-weighted VRF-based leader election.
    ///
    /// Uses VRF output from each validator for the given round. The leader is
    /// the validator with the lowest VRF hash output (highest priority), weighted
    /// by stake. Validators without VRF keys fall back to deterministic selection.
    pub fn leader(&self, round: u64) -> u16 {
        self.leader_with_vrf(round, &std::collections::HashMap::new())
    }

    /// VRF-aware leader selection.
    ///
    /// `vrf_outputs` maps authority index → verified 32-byte VRF hash. The
    /// authority with the lowest `hash / stake` wins. Ordering is exact:
    /// priorities are cross-multiplied into 192-bit products by
    /// [`crate::vrf_priority_cmp`] instead of being packed into a `u128`,
    /// which saturated (`hash * total_stake` overflows) and collapsed every
    /// authority to one value, pinning the leader to the lowest index.
    ///
    /// Authorities with no output fall back to nothing: if no authority has a
    /// hash in `vrf_outputs`, this is identical to [`Self::leader`]
    /// (round-robin). That fallback is the pre-upgrade behaviour: live blocks
    /// do not yet carry a VRF proof, so the engine must not invent a different
    /// leader.
    ///
    /// Ties break to the lower authority index.
    pub fn leader_with_vrf(
        &self,
        round: u64,
        vrf_outputs: &std::collections::HashMap<u16, [u8; 32]>,
    ) -> u16 {
        if self.authorities.is_empty() {
            return 0;
        }

        let mut best: Option<(u16, [u8; 32], Stake)> = None;

        for authority in &self.authorities {
            let Some(vrf_hash) = vrf_outputs.get(&authority.index) else {
                continue;
            };
            let wins = match best {
                None => true,
                Some((index, best_hash, best_stake)) => {
                    match crate::vrf_priority_cmp(vrf_hash, authority.stake, &best_hash, best_stake)
                    {
                        std::cmp::Ordering::Less => true,
                        std::cmp::Ordering::Equal => authority.index < index,
                        std::cmp::Ordering::Greater => false,
                    }
                }
            };
            if wins {
                best = Some((authority.index, *vrf_hash, authority.stake));
            }
        }

        if let Some((idx, _, _)) = best {
            return idx;
        }

        // Fallback: deterministic rotation one leader per wave (no VRF outputs
        // available). Seeding from the leader slot (`round / WAVE_LENGTH`)
        // instead of the raw round keeps consecutive leader rounds on
        // different authorities for every committee size; seeding from the
        // round degenerated to a single permanent leader whenever the
        // committee size divided `WAVE_LENGTH` (e.g. a 3-validator committee
        // with `WAVE_LENGTH == 3` always elected index 0).
        let slot = round / crate::WAVE_LENGTH;
        let idx = (slot as usize) % self.authorities.len();
        self.authorities[idx].index
    }
}

#[cfg(test)]
mod leader_rotation_tests {
    use super::*;

    fn authority(index: u16) -> Authority {
        Authority {
            index,
            public_key: PublicKey([index as u8; 32]),
            vrf_public_key: None,
            address: Address([index as u8; 32]),
            stake: 1,
            network_address: format!("/ip4/127.0.0.1/tcp/90{index:02}"),
        }
    }

    /// Regression for the 3-validator testnet: with `len == WAVE_LENGTH` the
    /// old round-seeded fallback pinned every leader round to authority 0.
    #[test]
    fn committee_of_wave_length_size_rotates_leaders() {
        let authorities: Vec<Authority> = (0..crate::WAVE_LENGTH as u16).map(authority).collect();
        let committee = Committee::new(0, authorities);
        let leaders: Vec<u16> = (0..9u64)
            .map(|wave| committee.leader(wave * crate::WAVE_LENGTH))
            .collect();
        assert_eq!(leaders, vec![0, 1, 2, 0, 1, 2, 0, 1, 2]);
    }

    #[test]
    fn leader_is_deterministic_and_rotates_every_wave() {
        let committee = Committee::new(0, (0..4).map(authority).collect());
        for wave in 0..8u64 {
            let current = committee.leader(wave * crate::WAVE_LENGTH);
            assert_eq!(current, committee.leader(wave * crate::WAVE_LENGTH));
            let next = committee.leader((wave + 1) * crate::WAVE_LENGTH);
            assert_ne!(current, next, "wave {wave} must not repeat its leader");
        }
    }
}
