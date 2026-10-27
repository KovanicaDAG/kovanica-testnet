//! Consensus-specific types.

#![allow(missing_docs)]
pub use kovanica_types::CommittedSubDag;
use kovanica_types::{block::StatementBlock, AuthorityIndex, Round, Stake};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

/// Status of a leader slot.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum LeaderStatus {
    /// Decision not yet possible.
    Undecided,
    /// Should be committed.
    Commit,
    /// Should be skipped.
    Skip,
}

/// Information about a leader in a round.
#[derive(Clone, Debug)]
pub struct LeaderInfo {
    /// Round number.
    pub round: Round,
    /// Authority index of the leader.
    pub author: AuthorityIndex,
    /// Block hash if the leader block exists.
    pub block_hash: Option<kovanica_types::hash::Hash>,
    /// Current status.
    pub status: LeaderStatus,
    /// Votes received (author -> vote block hash).
    pub votes: HashMap<AuthorityIndex, kovanica_types::hash::Hash>,
}

/// Committee information for consensus.
#[derive(Clone, Debug)]
pub struct CommitteeInfo {
    /// Current epoch.
    epoch: u64,
    /// Authorities in the committee.
    authorities: Vec<AuthorityInfo>,
    /// Total stake.
    total_stake: Stake,
    /// Quorum threshold (2f+1).
    quorum_threshold: Stake,
    /// Validity threshold (f+1).
    validity_threshold: Stake,
}

/// Errors returned when constructing an invalid consensus committee.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum CommitteeInfoError {
    /// A consensus committee must contain at least one authority.
    #[error("committee must not be empty")]
    EmptyCommittee,
    /// An authority must have non-zero voting stake.
    #[error("authority {index} has zero stake")]
    ZeroStake { index: AuthorityIndex },
    /// Authority indices must uniquely identify committee members.
    #[error("duplicate authority index {index}")]
    DuplicateAuthorityIndex { index: AuthorityIndex },
    /// Each committee member must use a distinct public key.
    #[error("duplicate authority public key")]
    DuplicatePublicKey,
    /// Total committee stake must fit in `Stake`.
    #[error("total committee stake overflows u64")]
    StakeOverflow,
}

impl CommitteeInfo {
    /// Construct a validated committee and derive its voting thresholds.
    pub fn try_new(
        epoch: u64,
        authorities: Vec<AuthorityInfo>,
    ) -> Result<Self, CommitteeInfoError> {
        if authorities.is_empty() {
            return Err(CommitteeInfoError::EmptyCommittee);
        }

        let mut indices = HashSet::with_capacity(authorities.len());
        let mut public_keys = HashSet::with_capacity(authorities.len());
        let mut total_stake: Stake = 0;
        for authority in &authorities {
            if authority.stake == 0 {
                return Err(CommitteeInfoError::ZeroStake {
                    index: authority.index,
                });
            }
            if !indices.insert(authority.index) {
                return Err(CommitteeInfoError::DuplicateAuthorityIndex {
                    index: authority.index,
                });
            }
            if !public_keys.insert(authority.public_key) {
                return Err(CommitteeInfoError::DuplicatePublicKey);
            }
            total_stake = total_stake
                .checked_add(authority.stake)
                .ok_or(CommitteeInfoError::StakeOverflow)?;
        }

        // Compute thresholds in u128 so doubling the u64 total cannot
        // overflow. For positive T, both results are <= T and therefore fit
        // in Stake.
        let quorum_threshold = (u128::from(total_stake) * 2 / 3 + 1) as Stake;
        let validity_threshold = (u128::from(total_stake) / 3 + 1) as Stake;

        Ok(Self {
            epoch,
            authorities,
            total_stake,
            quorum_threshold,
            validity_threshold,
        })
    }

    /// Current committee epoch.
    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    /// Authorities in this committee.
    pub fn authorities(&self) -> &[AuthorityInfo] {
        &self.authorities
    }

    /// Total voting stake in this committee.
    pub fn total_stake(&self) -> Stake {
        self.total_stake
    }

    /// Quorum voting threshold, `floor(2T/3) + 1`.
    pub fn quorum_threshold(&self) -> Stake {
        self.quorum_threshold
    }

    /// Validity voting threshold, `floor(T/3) + 1`.
    pub fn validity_threshold(&self) -> Stake {
        self.validity_threshold
    }

    pub fn size(&self) -> usize {
        self.authorities.len()
    }

    pub fn get_by_index(&self, index: AuthorityIndex) -> Option<&AuthorityInfo> {
        self.authorities.iter().find(|a| a.index == index)
    }

    pub fn stake_of(&self, index: AuthorityIndex) -> Option<Stake> {
        self.get_by_index(index).map(|a| a.stake)
    }

    /// Check if we have quorum (2f+1) of votes **for the leader block**.
    ///
    /// Only votes whose hash matches `leader_hash` are counted. A vote for a
    /// different block (equivocation, or a stale/foreign vote) must never
    /// contribute to committing this leader. When the leader block is unknown
    /// (`None`), no quorum can exist.
    pub fn has_quorum(
        &self,
        votes: &HashMap<AuthorityIndex, kovanica_types::hash::Hash>,
        leader_hash: Option<&kovanica_types::hash::Hash>,
    ) -> bool {
        self.stake_for(votes, leader_hash) >= self.quorum_threshold
    }

    /// Check if we have the validity threshold (f+1) of votes **for the leader block**.
    pub fn has_validity(
        &self,
        votes: &HashMap<AuthorityIndex, kovanica_types::hash::Hash>,
        leader_hash: Option<&kovanica_types::hash::Hash>,
    ) -> bool {
        self.stake_for(votes, leader_hash) >= self.validity_threshold
    }

    /// Sum the stake of voters whose vote hash matches `leader_hash`.
    /// Returns 0 when the leader block is unknown.
    fn stake_for(
        &self,
        votes: &HashMap<AuthorityIndex, kovanica_types::hash::Hash>,
        leader_hash: Option<&kovanica_types::hash::Hash>,
    ) -> Stake {
        match leader_hash {
            Some(target) => votes
                .iter()
                .filter(|(_, h)| *h == target)
                .filter_map(|(idx, _)| self.stake_of(*idx))
                .sum(),
            None => 0,
        }
    }

    /// Get the leader for a given round using deterministic rotation.
    ///
    /// Leaders are drawn one per *leader slot* (one per wave), walking the
    /// authority list in index order as waves advance. The seed is therefore
    /// `round / WAVE_LENGTH`, not the raw round.
    ///
    /// This matters because leader rounds are exactly the rounds where
    /// `round % WAVE_LENGTH == 0`. Seeding from `round` collapsed to a single
    /// permanent leader whenever `authorities.len()` divided `WAVE_LENGTH`:
    /// with the 3-validator committee and `WAVE_LENGTH == 3` every leader round
    /// satisfied `round % 3 == 0` and so always elected index 0, which stalled
    /// commit liveness (no other authority could ever lead). Seeding from the
    /// leader slot rotates for every committee size, including
    /// `len == WAVE_LENGTH`.
    pub fn leader(&self, round: Round) -> AuthorityIndex {
        if self.authorities.is_empty() {
            return 0;
        }
        let slot = round / kovanica_types::WAVE_LENGTH;
        let idx = (slot as usize) % self.authorities.len();
        self.authorities[idx].index
    }

    /// Stake-weighted VRF leader selection.
    ///
    /// `vrf_outputs` maps authority index → verified 32-byte VRF hash.
    /// An authority is eligible only when it has both a committee VRF public
    /// key and an output in the map. If no authority is eligible, this is
    /// identical to [`Self::leader`] (round-robin). That fallback is the
    /// pre-upgrade behaviour: live blocks do not yet carry a VRF proof, so
    /// the engine must not invent a different leader.
    ///
    /// Priority is the exact `hash / stake` ratio (lower wins), compared via
    /// [`kovanica_types::vrf_priority_cmp`]. The previous implementation packed
    /// it into a `u128` as `hash * total_stake / stake`, which saturated to the
    /// same value for every authority and always elected the lowest index.
    /// Ties break to the lower authority index.
    pub fn leader_with_vrf(
        &self,
        round: Round,
        vrf_outputs: &std::collections::HashMap<AuthorityIndex, [u8; 32]>,
    ) -> AuthorityIndex {
        if self.authorities.is_empty() {
            return 0;
        }

        let mut best: Option<(AuthorityIndex, [u8; 32], Stake)> = None;
        for authority in &self.authorities {
            if authority.vrf_public_key.is_none() {
                continue;
            }
            let Some(vrf_hash) = vrf_outputs.get(&authority.index) else {
                continue;
            };
            let wins = match best {
                None => true,
                Some((index, best_hash, best_stake)) => {
                    match kovanica_types::vrf_priority_cmp(
                        vrf_hash,
                        authority.stake,
                        &best_hash,
                        best_stake,
                    ) {
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
        self.leader(round)
    }

    /// Deterministic stake-weighted leader selection.
    ///
    /// Uses `round` as a seed against total stake so the same
    /// (committee, round) pair always selects the same leader.
    pub fn stake_weighted_leader(&self, round: Round) -> AuthorityIndex {
        if self.authorities.is_empty() {
            return 0;
        }
        let seed = round as u128;
        let total = self.total_stake.max(1) as u128;
        let target = (seed % total) as Stake;
        let mut sorted: Vec<&AuthorityInfo> = self.authorities.iter().collect();
        sorted.sort_by_key(|a| a.index);
        let mut cumulative = 0u128;
        for auth in sorted {
            cumulative += auth.stake as u128;
            if cumulative > target as u128 {
                return auth.index;
            }
        }
        // Fallback (should not reach here for non-empty, positive-stake committee)
        self.authorities.last().unwrap().index
    }
}

#[cfg(test)]
mod stake_weighted_tests {
    use super::*;
    use kovanica_types::crypto::PublicKey;

    fn info(index: AuthorityIndex, stake: Stake) -> AuthorityInfo {
        AuthorityInfo {
            index,
            stake,
            public_key: PublicKey([index as u8; 32]),
            vrf_public_key: None,
            address: kovanica_types::Address([index as u8; 32]),
            network_address: format!("/ip4/127.0.0.1/tcp/900{}", index),
        }
    }

    #[test]
    fn stake_weighted_deterministic() {
        let authorities = vec![info(0, 100), info(1, 200), info(2, 300)];
        let committee = CommitteeInfo::try_new(0, authorities).unwrap();
        assert_eq!(
            committee.stake_weighted_leader(42),
            committee.stake_weighted_leader(42)
        );
    }

    #[test]
    fn leader_with_vrf_empty_map_matches_round_robin() {
        let authorities = vec![info(0, 100), info(1, 200), info(2, 300)];
        let committee = CommitteeInfo::try_new(0, authorities).unwrap();
        let empty = std::collections::HashMap::new();
        for round in [0_u64, 1, 2, 7, 42] {
            assert_eq!(
                committee.leader_with_vrf(round, &empty),
                committee.leader(round),
                "no verified VRF output must not change the scheduled leader"
            );
        }
    }

    #[test]
    fn leader_with_vrf_prefers_lower_stake_weighted_hash() {
        let mut low = info(0, 100);
        let mut high = info(1, 100);
        low.vrf_public_key = Some(PublicKey([1u8; 32]));
        high.vrf_public_key = Some(PublicKey([2u8; 32]));
        let committee = CommitteeInfo::try_new(0, vec![low, high]).unwrap();
        let mut outputs = std::collections::HashMap::new();
        outputs.insert(0, [0xff; 32]);
        outputs.insert(1, [0x01; 32]);
        assert_eq!(committee.leader_with_vrf(3, &outputs), 1);
    }

    /// Regression for the devnet stall: `hash * total_stake` saturated to
    /// `u128::MAX`, so every authority got the same priority and index 0 was
    /// elected for every round. With the exact comparison the validator with
    /// the lowest `hash / stake` must win instead.
    #[test]
    fn leader_with_vrf_does_not_saturate_to_the_lowest_index() {
        let mut authorities = Vec::new();
        for index in 0..3u16 {
            let mut authority = info(index, 50_000_000_000_000);
            authority.vrf_public_key = Some(PublicKey([index as u8; 32]));
            authorities.push(authority);
        }
        let committee = CommitteeInfo::try_new(0, authorities).unwrap();

        // Hashes chosen so the winner is 1, then 2, then 0.
        let cases: [(u64, [[u8; 32]; 3], AuthorityIndex); 3] = [
            (3, [[0x30; 32], [0x10; 32], [0x20; 32]], 1),
            (6, [[0x30; 32], [0x20; 32], [0x10; 32]], 2),
            (9, [[0x10; 32], [0x20; 32], [0x30; 32]], 0),
        ];
        for (round, hashes, expected) in cases {
            let mut outputs = std::collections::HashMap::new();
            for index in 0..3u16 {
                outputs.insert(index, hashes[index as usize]);
            }
            assert_eq!(
                committee.leader_with_vrf(round, &outputs),
                expected,
                "round {round}"
            );
        }
    }

    #[test]
    fn stake_weighted_splits_by_stake() {
        let authorities = vec![info(0, 100), info(1, 100)];
        let committee = CommitteeInfo::try_new(0, authorities).unwrap();
        // With equal stake and seed 0, target = 0 % 200 = 0; first auth (cum 100 > 0) wins
        assert_eq!(committee.stake_weighted_leader(0), 0);
        // Seed 99 → target = 99; first auth (cum 100 > 99) still wins
        assert_eq!(committee.stake_weighted_leader(99), 0);
        // Seed 100 → target = 100; first auth cum 100 > 100? No (100 > 100 false). Second wins.
        assert_eq!(committee.stake_weighted_leader(100), 1);
    }
}

/// Individual authority information.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuthorityInfo {
    pub index: AuthorityIndex,
    pub stake: Stake,
    pub public_key: kovanica_types::crypto::PublicKey,
    pub vrf_public_key: Option<kovanica_types::crypto::PublicKey>,
    pub address: kovanica_types::Address,
    pub network_address: String,
}

/// Result of a commit attempt.
#[derive(Debug)]
pub struct CommitResult {
    /// Committed sub-DAG if successful.
    pub subdag: Option<CommittedSubDag>,
    /// The round that was committed.
    pub round: Round,
    /// Whether a new leader was committed.
    pub committed_new: bool,
}
