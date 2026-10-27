//! Quorum-certified leader skips (PRO-40 (b)).
//!
//! A validator that waited `T_skip` for a leader slot without voting for it
//! signs a [`Timeout`]. Timeouts from a stake quorum of the committee form a
//! [`SkipCert`], the only thing that lets the commit walk move past a slot
//! without committing it.
//!
//! The quorum is the same as the vote quorum (`2f + 1` of stake; 4 of 5 equal
//! validators). That equality is what makes a skip safe: a vote quorum and a
//! skip quorum for the same slot intersect in at least one honest validator,
//! and an honest validator signs a vote **or** a timeout for a slot, never
//! both (see `ConsensusEngine::vote_for_leader` / `sign_timeout`).
//!
//! Signatures cover `KUNA/timeout/v1 ‖ chain_id ‖ genesis_hash ‖ epoch(R) ‖
//! voter ‖ R` ([`Timeout::signature_data`]); a timeout from another chain, a
//! reset of the same chain, or another epoch never verifies.

use crate::is_leader_round;
use crate::types::CommitteeInfo;
use kovanica_types::{AuthorityIndex, Hash, Round, SkipCert, Timeout};
use std::collections::{BTreeMap, BTreeSet};

/// Why a timeout or a skip certificate was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TimeoutRejection {
    /// The signer is not a committee member.
    #[error("timeout signer {0} is not a committee member")]
    UnknownVoter(AuthorityIndex),
    /// The signature does not verify for this chain, genesis and epoch.
    #[error("invalid timeout signature from {0}")]
    BadSignature(AuthorityIndex),
    /// The round is not a leader slot.
    #[error("round {0} is not a leader round")]
    NotLeaderRound(Round),
    /// The slot is already decided here, or too far ahead of this node.
    #[error("timeout for round {round} is outside the accepted range ({low}, {high}]")]
    OutOfRange {
        round: Round,
        low: Round,
        high: Round,
    },
    /// A certificate holds a timeout for another round.
    #[error("skip certificate for round {cert} holds a timeout for round {timeout}")]
    MixedRounds { cert: Round, timeout: Round },
    /// A certificate lists the same signer twice.
    #[error("skip certificate lists signer {0} twice")]
    DuplicateSigner(AuthorityIndex),
    /// The certificate signers do not hold a stake quorum.
    #[error("skip certificate for round {round} has stake {stake}, quorum is {quorum}")]
    NoQuorum {
        round: Round,
        stake: u64,
        quorum: u64,
    },
}

/// Verify one timeout's membership and signature (not its round range).
pub fn verify_timeout(
    committee: &CommitteeInfo,
    chain_id: u64,
    genesis_hash: &Hash,
    timeout: &Timeout,
) -> Result<(), TimeoutRejection> {
    if !is_leader_round(timeout.round) {
        return Err(TimeoutRejection::NotLeaderRound(timeout.round));
    }
    let Some(authority) = committee.get_by_index(timeout.voter) else {
        return Err(TimeoutRejection::UnknownVoter(timeout.voter));
    };
    kovanica_crypto::verify(
        &authority.public_key,
        &timeout.signature_data(chain_id, genesis_hash),
        &timeout.signature,
    )
    .map_err(|_| TimeoutRejection::BadSignature(timeout.voter))
}

/// Verify a whole skip certificate: one round, distinct committee members,
/// valid signatures, stake at least the quorum threshold.
pub fn verify_skip_cert(
    committee: &CommitteeInfo,
    chain_id: u64,
    genesis_hash: &Hash,
    cert: &SkipCert,
) -> Result<(), TimeoutRejection> {
    if !is_leader_round(cert.round) {
        return Err(TimeoutRejection::NotLeaderRound(cert.round));
    }
    let mut seen = BTreeSet::new();
    let mut stake: u64 = 0;
    for timeout in &cert.timeouts {
        if timeout.round != cert.round {
            return Err(TimeoutRejection::MixedRounds {
                cert: cert.round,
                timeout: timeout.round,
            });
        }
        if !seen.insert(timeout.voter) {
            return Err(TimeoutRejection::DuplicateSigner(timeout.voter));
        }
        verify_timeout(committee, chain_id, genesis_hash, timeout)?;
        stake = stake.saturating_add(committee.stake_of(timeout.voter).unwrap_or(0));
    }
    let quorum = committee.quorum_threshold();
    if stake < quorum {
        return Err(TimeoutRejection::NoQuorum {
            round: cert.round,
            stake,
            quorum,
        });
    }
    Ok(())
}

/// Verified timeouts per undecided leader slot, at most one per signer.
///
/// Memory is bounded by the caller's accepted range (`(cursor, current +
/// lookahead]`) and [`Self::prune_through`] on every cursor move.
#[derive(Default)]
pub struct TimeoutPool {
    by_round: BTreeMap<Round, BTreeMap<AuthorityIndex, Timeout>>,
}

impl TimeoutPool {
    /// Add a verified timeout. Returns `false` for a duplicate signer.
    pub fn insert(&mut self, timeout: Timeout) -> bool {
        let slot = self.by_round.entry(timeout.round).or_default();
        if slot.contains_key(&timeout.voter) {
            return false;
        }
        slot.insert(timeout.voter, timeout);
        true
    }

    /// Whether `voter` has a timeout recorded for `round`.
    pub fn contains(&self, round: Round, voter: AuthorityIndex) -> bool {
        self.by_round
            .get(&round)
            .is_some_and(|slot| slot.contains_key(&voter))
    }

    /// A certificate for `round` if the recorded signers hold a quorum.
    pub fn certificate(&self, committee: &CommitteeInfo, round: Round) -> Option<SkipCert> {
        let slot = self.by_round.get(&round)?;
        let stake: u64 = slot
            .keys()
            .map(|voter| committee.stake_of(*voter).unwrap_or(0))
            .fold(0u64, u64::saturating_add);
        (stake >= committee.quorum_threshold()).then(|| SkipCert {
            round,
            timeouts: slot.values().cloned().collect(),
        })
    }

    /// Drop every slot at or below `round` (decided).
    pub fn prune_through(&mut self, round: Round) {
        self.by_round = self.by_round.split_off(&(round + 1));
    }

    /// Number of slots with at least one timeout.
    pub fn len(&self) -> usize {
        self.by_round.len()
    }

    /// Whether no timeout is held.
    pub fn is_empty(&self) -> bool {
        self.by_round.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::AuthorityInfo;
    use kovanica_types::{Address, Signature, SigningKey};

    const CHAIN: u64 = 4;

    fn genesis() -> Hash {
        Hash([7u8; 32])
    }

    /// Five equal-stake validators; quorum is 4.
    fn committee() -> (CommitteeInfo, Vec<SigningKey>) {
        let mut keys = Vec::new();
        let mut authorities = Vec::new();
        for i in 0..5u16 {
            let (key, public_key) = kovanica_crypto::generate_keypair();
            keys.push(key);
            authorities.push(AuthorityInfo {
                index: i,
                stake: 1,
                public_key,
                vrf_public_key: None,
                address: Address::default(),
                network_address: String::new(),
            });
        }
        (CommitteeInfo::try_new(0, authorities).unwrap(), keys)
    }

    fn signed(keys: &[SigningKey], voter: u16, round: Round, chain: u64, g: &Hash) -> Timeout {
        let mut t = Timeout {
            round,
            voter,
            signature: Signature([0u8; 64]),
        };
        t.signature = kovanica_crypto::sign(&keys[voter as usize], &t.signature_data(chain, g));
        t
    }

    fn cert(keys: &[SigningKey], voters: &[u16], round: Round) -> SkipCert {
        SkipCert {
            round,
            timeouts: voters
                .iter()
                .map(|v| signed(keys, *v, round, CHAIN, &genesis()))
                .collect(),
        }
    }

    #[test]
    fn four_of_five_certifies_three_of_five_does_not() {
        let (c, keys) = committee();
        assert_eq!(c.quorum_threshold(), 4);
        assert_eq!(
            verify_skip_cert(&c, CHAIN, &genesis(), &cert(&keys, &[0, 1, 2, 3], 12)),
            Ok(())
        );
        assert_eq!(
            verify_skip_cert(&c, CHAIN, &genesis(), &cert(&keys, &[0, 2, 4], 12)),
            Err(TimeoutRejection::NoQuorum {
                round: 12,
                stake: 3,
                quorum: 4
            })
        );
    }

    #[test]
    fn wrong_chain_genesis_or_round_never_verifies() {
        let (c, keys) = committee();
        let other_chain = signed(&keys, 1, 12, 1, &genesis());
        let other_genesis = signed(&keys, 1, 12, CHAIN, &Hash([8u8; 32]));
        for t in [&other_chain, &other_genesis] {
            assert_eq!(
                verify_timeout(&c, CHAIN, &genesis(), t),
                Err(TimeoutRejection::BadSignature(1))
            );
        }
        // A signature for one round does not carry over to another round
        // (and so not to another epoch: the epoch is a function of the round).
        let mut moved = signed(&keys, 1, 12, CHAIN, &genesis());
        moved.round = 7_200 + 12;
        assert_eq!(
            verify_timeout(&c, CHAIN, &genesis(), &moved),
            Err(TimeoutRejection::BadSignature(1))
        );
    }

    #[test]
    fn duplicates_non_members_mixed_rounds_and_non_leader_rounds_are_refused() {
        let (c, keys) = committee();
        let mut dup = cert(&keys, &[0, 1, 2], 12);
        dup.timeouts.push(dup.timeouts[0].clone());
        assert_eq!(
            verify_skip_cert(&c, CHAIN, &genesis(), &dup),
            Err(TimeoutRejection::DuplicateSigner(0))
        );

        let mut stranger = cert(&keys, &[0, 1, 2], 12);
        let mut t = signed(&keys, 3, 12, CHAIN, &genesis());
        t.voter = 9;
        stranger.timeouts.push(t);
        assert_eq!(
            verify_skip_cert(&c, CHAIN, &genesis(), &stranger),
            Err(TimeoutRejection::UnknownVoter(9))
        );

        let mut mixed = cert(&keys, &[0, 1, 2], 12);
        mixed.timeouts.push(signed(&keys, 3, 15, CHAIN, &genesis()));
        assert_eq!(
            verify_skip_cert(&c, CHAIN, &genesis(), &mixed),
            Err(TimeoutRejection::MixedRounds {
                cert: 12,
                timeout: 15
            })
        );

        assert_eq!(
            verify_timeout(
                &c,
                CHAIN,
                &genesis(),
                &signed(&keys, 0, 13, CHAIN, &genesis())
            ),
            Err(TimeoutRejection::NotLeaderRound(13))
        );
    }

    #[test]
    fn pool_dedups_builds_a_cert_at_quorum_and_prunes_decided_rounds() {
        let (c, keys) = committee();
        let mut pool = TimeoutPool::default();
        for v in 0..3 {
            assert!(pool.insert(signed(&keys, v, 12, CHAIN, &genesis())));
        }
        assert!(
            !pool.insert(signed(&keys, 2, 12, CHAIN, &genesis())),
            "dedup"
        );
        assert!(pool.certificate(&c, 12).is_none(), "3 of 5 is not a quorum");
        assert!(pool.insert(signed(&keys, 4, 12, CHAIN, &genesis())));
        let cert = pool.certificate(&c, 12).expect("4 of 5");
        assert_eq!(cert.timeouts.len(), 4);
        assert_eq!(verify_skip_cert(&c, CHAIN, &genesis(), &cert), Ok(()));

        assert!(pool.insert(signed(&keys, 0, 15, CHAIN, &genesis())));
        pool.prune_through(12);
        assert!(!pool.contains(12, 0));
        assert!(pool.contains(15, 0));
        assert_eq!(pool.len(), 1);
    }

    /// Property: with honest signers that sign a vote xor a timeout per slot,
    /// a vote quorum and a skip quorum can never both form, for every split
    /// of five equal validators.
    #[test]
    fn vote_quorum_and_skip_quorum_never_coexist_for_honest_signers() {
        let (c, _) = committee();
        let q = c.quorum_threshold();
        for mask in 0u32..(1 << 5) {
            let votes = u64::from(mask.count_ones());
            let timeouts = 5 - votes;
            assert!(!(votes >= q && timeouts >= q), "mask {mask:05b}");
        }
    }
}
