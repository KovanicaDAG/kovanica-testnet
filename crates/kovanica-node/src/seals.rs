//! Post-execution commit seals.
//!
//! After a committed sub-DAG is executed, the node stores the leader header
//! it computed and, when it is a validator, signs that header. Consensus
//! does not wait for the seal. A gossiped seal is stored only when its
//! header hash equals the header local execution already saved.

use std::sync::Arc;

use anyhow::Result;
use kovanica_consensus::{AuthorityInfo, CommitteeInfo};
use kovanica_staking::StakingState;
use kovanica_storage::Storage;
use kovanica_types::{
    CommitSeal, CommittedSubDag, Hash, LeaderHeader, SealAnnouncement, SigningKey,
};
use tracing::warn;

use kovanica_network::LocalHeaderHash;

/// Header stored for a commit, plus the seal to gossip when we signed one.
pub struct LocalSeal {
    /// Header written to the state database.
    pub header: LeaderHeader,
    /// Our seal, present only for a committee signer.
    pub gossip: Option<SealAnnouncement>,
}

/// What this process needs in order to seal a commit.
pub struct SealContext {
    /// Chain id mixed into the seal message. Taken from local configuration.
    pub chain_id: u64,
    /// Validator index and key. `None` on a full node that does not vote.
    pub signer: Option<(u16, SigningKey)>,
    /// Mirrors `ConsensusConfig::use_mysticghost`. Default on.
    pub mysticghost: bool,
}

/// Build committee for a specific seal epoch from staking state.
/// Used by `publish_local_seal` to compute committee_hash matching the seal epoch.
pub(crate) fn build_committee_for_seal_epoch(
    staking_state: &StakingState,
    seal_epoch: u64,
) -> Result<CommitteeInfo> {
    // The committee order lives in ONE place: `StakingState::committee_order`
    // (active and stake >= MIN, stake desc with address tie-break, top
    // MAX_ACTIVE_VALIDATORS, re-sorted by address). Reusing it keeps the seal
    // snapshot, the RPC committee and execution's authority indices on the
    // same ordering.
    let committee = staking_state.committee_order();
    if committee.is_empty() {
        anyhow::bail!("no active validators in staking state; committee cannot be empty");
    }

    let mut authorities = Vec::with_capacity(committee.len());
    for (index, validator) in committee.iter().enumerate() {
        let public_key = validator
            .public_key
            .ok_or_else(|| anyhow::anyhow!("validator {} missing public key", validator.address))?;

        let vrf_public_key = validator
            .vrf_public_key
            .as_ref()
            .map(|v| kovanica_types::PublicKey(v.0));

        let authority = AuthorityInfo {
            index: index as u16,
            stake: validator.stake,
            public_key,
            vrf_public_key,
            address: validator.address,
            network_address: String::new(), // not used for seal
        };
        authorities.push(authority);
    }

    if authorities.is_empty() {
        anyhow::bail!("no validators with registered public keys; committee cannot be empty");
    }

    Ok(CommitteeInfo::try_new(seal_epoch, authorities)?)
}

/// Reads leader-header hashes out of the state database for the gossip edge.
pub struct StateHeaderIndex {
    /// State database that holds `leader_headers`.
    pub storage: Arc<Storage>,
}

impl LocalHeaderHash for StateHeaderIndex {
    fn local_header_hash(&self, committed_height: u64) -> Option<Hash> {
        let txn = self.storage.begin_read().ok()?;
        let header = self
            .storage
            .state()
            .get_leader_header(&txn, committed_height)
            .ok()??;
        Some(header.hash())
    }
}

/// Save the header for this commit and sign it when we are a validator.
///
/// Returns the stored header and, for a validator, the announcement to
/// gossip. Replacing a stored header with a different hash drops seals for
/// that height before the new seal is written.
pub fn publish_local_seal(
    storage: &Storage,
    ctx: &SealContext,
    subdag: &CommittedSubDag,
    committed_height: u64,
    state_root: Hash,
) -> Result<LocalSeal> {
    // Seal epoch MUST derive from leader_round (same as vote signing ctx)
    // to avoid restart mismatch. Use the ONE shared round→epoch unit.
    let seal_epoch = kovanica_types::epoch_for_round(subdag.leader_round);

    // Freeze the seal committee for `seal_epoch`: the first seal of an epoch
    // pins the committee snapshot, and every later seal in that epoch hashes
    // the SAME snapshot (option (a), decision recorded in TASKLIST). Without
    // this a mid-epoch join/evict/unbond would change the hashed set while the
    // RPC committee still served the epoch-boundary snapshot, so the sealed
    // header's `committee_hash` and the light-client recomputation would
    // disagree.
    let committee_hash = freeze_epoch_committee_hash(storage, seal_epoch, subdag.leader_round)?;

    let parent_leader_digest = parent_digest(storage, committed_height)?;
    let header = kovanica_types::leader_header(
        subdag,
        committed_height,
        parent_leader_digest,
        state_root,
        seal_epoch,
        committee_hash,
        ctx.mysticghost,
    );
    let hashes = kovanica_types::executed_tx_hashes(subdag);
    let txn = storage.begin_write()?;
    storage.state().save_leader_header(&txn, &header)?;
    storage
        .state()
        .save_executed_tx_hashes(&txn, committed_height, &hashes)?;
    let gossip = match ctx.signer.as_ref() {
        Some((index, key)) if *index != u16::MAX => {
            let signature = kovanica_crypto::sign(key, &header.seal_message(ctx.chain_id));
            let seal = CommitSeal {
                authority_index: *index,
                signature,
            };
            storage
                .state()
                .save_commit_seal(&txn, committed_height, &seal)?;
            Some(SealAnnouncement {
                header: header.clone(),
                seal,
            })
        }
        _ => None,
    };
    txn.commit()?;
    Ok(LocalSeal { header, gossip })
}

/// Freeze (or read) the seal committee for `seal_epoch` and return its hash.
///
/// The snapshot is the committee built from the current active validator set;
/// it is written on the first call for an epoch and reused afterwards (first
/// writer wins, see [`kovanica_storage::state_store::StateStore::put_epoch_committee_if_absent`]).
/// Both the seal producer here and the RPC `getCommittee` path call this, so
/// the committee a light client recomputes is exactly the one the sealed header
/// was hashed against — even after a mid-epoch active-set change.
///
/// `round` is only used for diagnostics by callers; the epoch alone keys the
/// snapshot.
pub(crate) fn freeze_epoch_committee_hash(
    storage: &Storage,
    seal_epoch: u64,
    round: u64,
) -> Result<Hash> {
    let _ = round;
    // Already frozen for this epoch: reuse it verbatim.
    {
        let read = storage.begin_read()?;
        if let Some(members) = storage.state().get_epoch_committee(&read, seal_epoch)? {
            return Ok(kovanica_types::committee_seal_hash(
                seal_epoch,
                &kovanica_types::snapshot_seal_members(&members),
            ));
        }
    }
    // First seal of this epoch: build the committee from the live active set,
    // then write it as the frozen snapshot (first writer wins, so a concurrent
    // writer's snapshot is the one kept).
    let read = storage.begin_read()?;
    let staking_state = storage.state().load_staking_state(&read)?;
    let committee = build_committee_for_seal_epoch(&staking_state, seal_epoch)?;
    let proposed: Vec<_> = committee
        .authorities()
        .iter()
        .map(|a| kovanica_types::SealCommitteeSnapshotMember {
            index: a.index,
            public_key: a.public_key,
            stake: a.stake,
            vrf_public_key: a.vrf_public_key,
        })
        .collect();
    let write = storage.begin_write()?;
    let frozen = storage
        .state()
        .put_epoch_committee_if_absent(&write, seal_epoch, &proposed)?;
    write.commit()?;
    Ok(kovanica_types::committee_seal_hash(
        seal_epoch,
        &kovanica_types::snapshot_seal_members(&frozen),
    ))
}

/// Store a gossiped seal when it signs the header local execution saved.
///
/// Returns `false` when this node has no header at that height, or the
/// header hash differs. The foreign header is not kept.
pub fn store_matching_seal(storage: &Storage, announcement: &SealAnnouncement) -> Result<bool> {
    let txn = storage.begin_write()?;
    let stored = storage.state().save_seal_if_header(
        &txn,
        announcement.header.committed_height,
        &announcement.header.hash(),
        &announcement.seal,
    )?;
    if !stored {
        return Ok(false);
    }
    txn.commit()?;
    Ok(true)
}

/// Leader round certified by a quorum of seals on the latest local header.
///
/// Returns `Ok(None)` when there is no header, the epoch committee is
/// missing, or the stored seals do not verify for `chain_id`. The round is
/// `LeaderHeader::leader_round`, which stays correct once skip certificates
/// advance the round without a height. The caller notes it on the consensus
/// store only; this function does not move a commit cursor by itself.
pub fn certified_leader_round(storage: &Storage, chain_id: u64) -> Result<Option<u64>> {
    let read = storage.begin_read()?;
    let Some(header) = storage.state().get_latest_leader_header(&read)? else {
        return Ok(None);
    };
    let seals = storage.state().seals_for(&read, header.committed_height)?;
    if seals.is_empty() {
        return Ok(None);
    }
    let Some(members) = storage.state().get_epoch_committee(&read, header.epoch)? else {
        return Ok(None);
    };
    let authorities = members
        .into_iter()
        .map(|member| kovanica_types::Authority {
            index: member.index,
            public_key: member.public_key,
            vrf_public_key: member.vrf_public_key,
            address: kovanica_types::Address::from_public_key(&member.public_key),
            stake: member.stake,
            network_address: String::new(),
        })
        .collect();
    let committee = kovanica_types::Committee::new(header.epoch, authorities);
    match kovanica_crypto::verify_commit_seals(chain_id, &header, &seals, &committee) {
        Ok(()) => Ok(Some(header.leader_round)),
        Err(e) => {
            warn!(
                error = %e,
                leader_round = header.leader_round,
                "latest leader header has no verified seal quorum"
            );
            Ok(None)
        }
    }
}

fn parent_digest(storage: &Storage, committed_height: u64) -> Result<Hash> {
    if committed_height == 0 {
        return Ok(Hash::zero());
    }
    let txn = storage.begin_read()?;
    match storage
        .state()
        .get_leader_header(&txn, committed_height - 1)?
    {
        Some(header) => Ok(header.leader_digest),
        None => {
            warn!(
                height = committed_height,
                "no parent leader header; parent digest is zero"
            );
            Ok(Hash::zero())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kovanica_types::{block::StatementBlock, Signature};
    use tempfile::tempdir;

    fn empty_block(author: u16, round: u64) -> StatementBlock {
        let digest = StatementBlock::compute_digest(author, round, &[], &[]);
        StatementBlock {
            author,
            round,
            parents: vec![],
            transactions: vec![],
            statements: vec![],
            signature: Signature([0; 64]),
            digest,
            merkle_root: Hash::zero(),
        }
    }

    fn subdag(round: u64) -> CommittedSubDag {
        let leader = empty_block(0, round);
        CommittedSubDag {
            blocks: vec![leader.clone()],
            leader,
            leader_round: round,
            leader_author: 0,
            non_blue: vec![],
        }
    }

    fn context(signer: Option<(u16, SigningKey)>) -> SealContext {
        SealContext {
            chain_id: 1337,
            signer,
            mysticghost: false,
        }
    }

    fn storage_with_validator() -> (Storage, SigningKey) {
        let dir = tempdir().unwrap();
        let storage = Storage::new(dir.path().join("state.redb")).unwrap();
        let key = SigningKey::from_bytes(&[7u8; 32]);
        let pk_bytes = key.verifying_key().to_bytes();
        let pk = kovanica_types::PublicKey(pk_bytes);
        let addr = kovanica_types::Address::from_public_key(&pk);

        let mut staking = kovanica_staking::StakingState::new();
        staking.init_treasury(kovanica_types::Address([0xcc; 32]));
        staking
            .join_validator(
                addr,
                kovanica_staking::MIN_VALIDATOR_STAKE,
                0,
                Some(addr),
                Some(pk),
                None,
            )
            .unwrap();
        staking.committed_leader_height = 0;

        let txn = storage.begin_write().unwrap();
        storage.state().save_staking_state(&txn, &staking).unwrap();
        txn.commit().unwrap();

        (storage, key)
    }

    #[test]
    fn local_seal_chains_parent_digests_and_rejects_a_foreign_header() {
        let (storage, key) = storage_with_validator();
        let ctx = context(Some((0, key.clone())));
        let first = subdag(3);
        let announcement = publish_local_seal(&storage, &ctx, &first, 0, Hash::new([1u8]))
            .unwrap()
            .gossip
            .expect("validator signs");
        assert_eq!(announcement.header.timestamp, 0);
        assert_eq!(announcement.header.parent_leader_digest, Hash::zero());
        assert_eq!(announcement.header.blue_root, Hash::zero());
        assert!(announcement.header.colouring_roots_match_flag());
        kovanica_crypto::verify_commit_seal(
            1337,
            &announcement.header,
            &announcement.seal,
            &kovanica_types::PublicKey::from(key.verifying_key()),
        )
        .unwrap();

        let second = subdag(6);
        let next = publish_local_seal(&storage, &ctx, &second, 1, Hash::new([2u8]))
            .unwrap()
            .gossip
            .unwrap();
        assert_eq!(next.header.parent_leader_digest, first.leader.digest);

        let mut foreign = announcement.clone();
        foreign.header.state_root = Hash::new([9u8]);
        foreign.seal.authority_index = 1;
        assert!(!store_matching_seal(&storage, &foreign).unwrap());

        let mut other = next.clone();
        other.seal.authority_index = 3;
        other.seal.signature = Signature([4; 64]);
        assert!(store_matching_seal(&storage, &other).unwrap());

        let read = storage.begin_read().unwrap();
        let seals = storage.state().seals_for(&read, 1).unwrap();
        assert_eq!(seals.len(), 2);
        assert!(storage
            .state()
            .get_leader_header(&read, 0)
            .unwrap()
            .is_some());
    }

    #[test]
    fn certified_leader_round_follows_a_quorum_seal() {
        let (storage, key) = storage_with_validator();
        assert!(certified_leader_round(&storage, 1337).unwrap().is_none());

        let ctx = context(Some((0, key)));
        publish_local_seal(&storage, &ctx, &subdag(3), 0, Hash::new([1u8])).unwrap();
        assert_eq!(certified_leader_round(&storage, 1337).unwrap(), Some(3));
        // A seal for another network is not a certificate on this chain.
        assert!(certified_leader_round(&storage, 1).unwrap().is_none());

        publish_local_seal(&storage, &ctx, &subdag(6), 1, Hash::new([2u8])).unwrap();
        assert_eq!(
            certified_leader_round(&storage, 1337).unwrap(),
            Some(6),
            "the latest verified header is the anchor"
        );
    }

    #[test]
    fn a_non_validator_stores_the_header_without_a_seal() {
        let (storage, _key) = storage_with_validator();
        let local =
            publish_local_seal(&storage, &context(None), &subdag(3), 0, Hash::zero()).unwrap();
        assert!(local.gossip.is_none());
        let read = storage.begin_read().unwrap();
        assert!(storage.state().seals_for(&read, 0).unwrap().is_empty());
        assert!(storage
            .state()
            .get_leader_header(&read, 0)
            .unwrap()
            .is_some());
    }
}
