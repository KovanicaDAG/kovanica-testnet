//! Shared helpers for the kovanica-consensus test suite.
//!
//! Provides block/committee builders plus an in-memory [`MockDag`] that
//! implements [`DagStoreTrait`] with the same `get_ancestors` semantics as the
//! real `kovanica_dag::DagStore` (BFS over parents, `min_round` filtering, self
//! excluded, duplicate pushes on diamond paths).

#![allow(dead_code)]

use kovanica_consensus::engine::{BlockManagerTrait, DagStoreTrait};
use kovanica_consensus::{AuthorityInfo, CommitteeInfo, LeaderInfo, LeaderStatus};
use kovanica_dag::{BlockManagerError, DagStoreError};
use kovanica_types::block::{BlockReference, StatementBlock};
use kovanica_types::hash::Hash;
use kovanica_types::{
    Address, AuthorityIndex, PublicKey, Round, Signature, SigningKey, Stake, Transaction,
};
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

/// Committee of `n` authorities with equal stake of 1.
pub fn committee(n: u16) -> CommitteeInfo {
    committee_with_stakes(&vec![1u64; n as usize])
}

/// Committee with explicit per-authority stakes (index = position).
pub fn committee_with_stakes(stakes: &[Stake]) -> CommitteeInfo {
    let authorities = stakes
        .iter()
        .enumerate()
        .map(|(i, &stake)| AuthorityInfo {
            index: i as AuthorityIndex,
            stake,
            public_key: validator_public_key(i as AuthorityIndex),
            vrf_public_key: None,
            address: Address([i as u8; 32]),
            network_address: format!("/ip4/127.0.0.1/tcp/90{:02}", i),
        })
        .collect();
    CommitteeInfo::try_new(0, authorities).expect("test committee is valid")
}

/// Deterministic test signing key for authority `index`.
///
/// `committee`/`committee_with_stakes` register the matching public key, so
/// votes signed with this key verify against the committee.
pub fn validator_signing_key(index: AuthorityIndex) -> SigningKey {
    let mut seed = [0u8; 32];
    seed[..2].copy_from_slice(&index.to_le_bytes());
    seed[31] = 0x6b; // keep every seed distinct from the all-zero key
    SigningKey::from_bytes(&seed)
}

/// Public key matching [`validator_signing_key`].
pub fn validator_public_key(index: AuthorityIndex) -> PublicKey {
    PublicKey::from(validator_signing_key(index).verifying_key())
}

/// A vote for `leader_hash` at `leader_round` by `voter`, signed with `key`.
pub fn vote_signed_with(
    key: &SigningKey,
    leader_round: Round,
    voter: AuthorityIndex,
    leader_hash: Hash,
) -> kovanica_types::Vote {
    let mut vote = kovanica_types::Vote {
        leader_round,
        leader_hash,
        voter,
        signature: Signature([0u8; 64]),
    };
    vote.signature = kovanica_crypto::sign(
        key,
        &vote.signature_data(&kovanica_types::SigningContext::new(
            kovanica_types::signing::chain_id::LOCAL,
        )),
    );
    vote
}

/// A correctly signed vote from `voter` (using [`validator_signing_key`]).
pub fn signed_vote(
    leader_round: Round,
    voter: AuthorityIndex,
    leader_hash: Hash,
) -> kovanica_types::Vote {
    vote_signed_with(
        &validator_signing_key(voter),
        leader_round,
        voter,
        leader_hash,
    )
}

/// Build a block. `tag` must be unique within a test; it determines the digest.
pub fn make_block(
    author: AuthorityIndex,
    round: Round,
    parents: Vec<BlockReference>,
    tag: &str,
) -> StatementBlock {
    StatementBlock {
        merkle_root: Hash::zero(),
        author,
        round,
        parents,
        transactions: Vec::new(),
        statements: tag.as_bytes().to_vec(),
        signature: Signature([0u8; 64]),
        digest: Hash::new(format!("kovanica-test/{tag}").as_bytes()),
    }
}

/// Reference to a block (author + round + digest).
pub fn block_ref(block: &StatementBlock) -> BlockReference {
    BlockReference {
        author: block.author,
        round: block.round,
        digest: block.digest,
    }
}

/// Canonical genesis block used by most tests.
pub fn genesis() -> StatementBlock {
    make_block(0, 0, Vec::new(), "genesis")
}

/// Build a [`LeaderInfo`] with the given status and votes.
pub fn leader_info(
    round: Round,
    author: AuthorityIndex,
    block_hash: Option<Hash>,
    status: LeaderStatus,
    votes: &[(AuthorityIndex, Hash)],
) -> LeaderInfo {
    LeaderInfo {
        round,
        author,
        block_hash,
        status,
        votes: votes.iter().copied().collect(),
    }
}

/// Total stake of the voters present in `votes` (unknown voters contribute 0).
pub fn voter_stake(committee: &CommitteeInfo, votes: &HashMap<AuthorityIndex, Hash>) -> Stake {
    votes
        .keys()
        .filter_map(|idx| committee.stake_of(*idx))
        .sum()
}

/// In-memory DAG store implementing [`DagStoreTrait`].
///
/// `get_ancestors` mirrors `kovanica_dag::DagStore::get_ancestors`: BFS from
/// `hash`, self excluded, a parent is reported (and traversed) only when its
/// round `>= min_round`, missing blocks surface as `NotFound`.
#[derive(Default)]
pub struct MockDag {
    blocks: parking_lot::RwLock<HashMap<Hash, StatementBlock>>,
    digest_aliases: parking_lot::RwLock<HashMap<Hash, Hash>>,
    decisions: parking_lot::Mutex<Vec<(Round, Hash)>>,
    fail_next_decision_mark: AtomicBool,
    decision_mark_observer: parking_lot::Mutex<Option<Box<dyn Fn() + Send + Sync>>>,
}

impl MockDag {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_blocks(blocks: impl IntoIterator<Item = StatementBlock>) -> Self {
        let dag = Self::new();
        for block in blocks {
            dag.put(block);
        }
        dag
    }

    pub fn put(&self, block: StatementBlock) {
        self.blocks.write().insert(block.digest, block);
    }

    /// Resolve `alias` to the stored block identified by `actual_digest`.
    /// Useful for testing stores that return inconsistent digest metadata.
    pub fn alias_digest(&self, alias: Hash, actual_digest: Hash) {
        assert_ne!(alias, actual_digest, "digest alias must be distinct");
        self.digest_aliases.write().insert(alias, actual_digest);
    }

    fn resolve_digest(&self, digest: &Hash) -> Hash {
        self.digest_aliases
            .read()
            .get(digest)
            .copied()
            .unwrap_or(*digest)
    }

    pub fn contains(&self, digest: &Hash) -> bool {
        self.blocks.read().contains_key(digest)
    }

    pub fn blocks(&self) -> Vec<StatementBlock> {
        self.blocks.read().values().cloned().collect()
    }

    pub fn set_fail_next_decision_mark(&self) {
        self.fail_next_decision_mark.store(true, Ordering::SeqCst);
    }

    pub fn decisions(&self) -> Vec<(Round, Hash)> {
        self.decisions.lock().clone()
    }

    pub fn set_decision_mark_observer(&self, observer: impl Fn() + Send + Sync + 'static) {
        *self.decision_mark_observer.lock() = Some(Box::new(observer));
    }
}

impl DagStoreTrait for MockDag {
    fn get_block(&self, hash: &Hash) -> Result<StatementBlock, DagStoreError> {
        let digest = self.resolve_digest(hash);
        self.blocks
            .read()
            .get(&digest)
            .cloned()
            .ok_or_else(|| DagStoreError::NotFound(format!("block {hash}")))
    }

    fn get_parents(&self, hash: &Hash) -> Result<Vec<Hash>, DagStoreError> {
        let digest = self.resolve_digest(hash);
        let blocks = self.blocks.read();
        let block = blocks
            .get(&digest)
            .ok_or_else(|| DagStoreError::NotFound(format!("block {hash}")))?;
        Ok(block.parents.iter().map(|p| p.digest).collect())
    }

    fn get_ancestors(&self, hash: &Hash, min_round: Round) -> Result<Vec<Hash>, DagStoreError> {
        let root_digest = self.resolve_digest(hash);
        let blocks = self.blocks.read();
        let mut ancestors = Vec::new();
        let mut visited: HashSet<Hash> = HashSet::new();
        let mut queue: VecDeque<Hash> = VecDeque::new();
        queue.push_back(root_digest);

        while let Some(current) = queue.pop_front() {
            if visited.contains(&current) {
                continue;
            }
            visited.insert(current);

            let current_block = blocks
                .get(&current)
                .ok_or_else(|| DagStoreError::NotFound(format!("block {current}")))?;
            for parent in &current_block.parents {
                if parent.digest == current {
                    continue;
                }
                let parent_block = blocks
                    .get(&parent.digest)
                    .ok_or_else(|| DagStoreError::NotFound(format!("block {}", parent.digest)))?;
                if parent_block.round >= min_round {
                    ancestors.push(parent.digest);
                    queue.push_back(parent.digest);
                }
            }
        }

        Ok(ancestors)
    }

    fn get_block_by_author_round(
        &self,
        author: AuthorityIndex,
        round: Round,
    ) -> Result<Option<StatementBlock>, DagStoreError> {
        Ok(self
            .blocks
            .read()
            .values()
            .find(|b| b.author == author && b.round == round)
            .cloned())
    }

    fn get_blocks_by_round(&self, round: Round) -> Result<Vec<StatementBlock>, DagStoreError> {
        let mut out: Vec<StatementBlock> = self
            .blocks
            .read()
            .values()
            .filter(|b| b.round == round)
            .cloned()
            .collect();
        out.sort_by_key(|b| (b.author, b.digest.0));
        Ok(out)
    }

    fn has_block(&self, hash: &Hash) -> Result<bool, DagStoreError> {
        let digest = self.resolve_digest(hash);
        Ok(self.blocks.read().contains_key(&digest))
    }

    fn put_block(&self, block: &StatementBlock) -> Result<(), DagStoreError> {
        self.blocks.write().insert(block.digest, block.clone());
        Ok(())
    }

    fn find_parents(
        &self,
        _round: Round,
        _max_parents: usize,
    ) -> Result<Vec<BlockReference>, DagStoreError> {
        Ok(Vec::new())
    }

    fn commit_leader(&self, _leader_hash: &Hash) -> Result<u64, DagStoreError> {
        Ok(0)
    }

    fn mark_decided_and_commit_leader(
        &self,
        round: Round,
        leader_hash: &Hash,
    ) -> Result<u64, DagStoreError> {
        self.mark_round_decided(round, leader_hash)?;
        self.commit_leader(leader_hash)
    }

    fn mark_round_decided(&self, round: Round, leader_hash: &Hash) -> Result<(), DagStoreError> {
        if let Some(observer) = self.decision_mark_observer.lock().as_ref() {
            observer();
        }
        if self.fail_next_decision_mark.swap(false, Ordering::SeqCst) {
            return Err(DagStoreError::NotFound(
                "injected decision-mark failure".into(),
            ));
        }
        let mut decisions = self.decisions.lock();
        if !decisions.contains(&(round, *leader_hash)) {
            decisions.push((round, *leader_hash));
        }
        Ok(())
    }

    fn mergeset(&self, _leader: &Hash) -> Result<Vec<Hash>, DagStoreError> {
        Ok(Vec::new())
    }

    fn get_blocks(&self, hashes: &[Hash]) -> Result<Vec<StatementBlock>, DagStoreError> {
        let blocks = self.blocks.read();
        Ok(hashes
            .iter()
            .filter_map(|h| {
                let digest = self.resolve_digest(h);
                blocks.get(&digest).cloned()
            })
            .collect())
    }

    fn get_decided_leaders(&self, round: Round) -> Result<Vec<Hash>, DagStoreError> {
        Ok(self
            .decisions
            .lock()
            .iter()
            .filter(|(r, _)| *r == round)
            .map(|(_, h)| *h)
            .collect())
    }

    fn get_decided_rounds(&self, max_round: Round) -> Result<Vec<Round>, DagStoreError> {
        Ok(self
            .decisions
            .lock()
            .iter()
            .filter(|(r, _)| *r <= max_round)
            .map(|(r, _)| *r)
            .collect())
    }

    fn prune_non_blue(
        &self,
        _blue_hashes: &[Hash],
        _committed_wave: u64,
    ) -> Result<u64, DagStoreError> {
        // Test implementation: no-op
        Ok(0)
    }

    fn prune_waves_before(
        &self,
        _wave: u64,
        _prune_window_waves: u64,
    ) -> Result<u64, DagStoreError> {
        // Test implementation: no-op
        Ok(0)
    }
}

/// In-memory block manager for `kovanica_consensus::ConsensusEngine` tests.
pub struct MockBlockManager {
    authority: AuthorityIndex,
    dag: std::sync::Arc<MockDag>,
    signing_key: parking_lot::RwLock<Option<SigningKey>>,
    fail_process: AtomicBool,
    process_calls: AtomicUsize,
    propose_calls: AtomicUsize,
    signing_key_set: AtomicBool,
}

impl MockBlockManager {
    pub fn new(authority: AuthorityIndex, dag: std::sync::Arc<MockDag>) -> Self {
        Self {
            authority,
            dag,
            signing_key: parking_lot::RwLock::new(None),
            fail_process: AtomicBool::new(false),
            process_calls: AtomicUsize::new(0),
            propose_calls: AtomicUsize::new(0),
            signing_key_set: AtomicBool::new(false),
        }
    }

    /// Make `process_block` fail (used for error-propagation tests).
    pub fn set_fail_process(&self, fail: bool) {
        self.fail_process.store(fail, Ordering::SeqCst);
    }

    pub fn process_calls(&self) -> usize {
        self.process_calls.load(Ordering::SeqCst)
    }

    pub fn propose_calls(&self) -> usize {
        self.propose_calls.load(Ordering::SeqCst)
    }

    pub fn signing_key_set(&self) -> bool {
        self.signing_key_set.load(Ordering::SeqCst)
    }
}

impl BlockManagerTrait for MockBlockManager {
    fn propose_block(&self, round: Round) -> Result<StatementBlock, BlockManagerError> {
        self.propose_block_with_txs(round, Vec::new())
    }

    fn propose_block_with_txs(
        &self,
        round: Round,
        _transactions: Vec<Transaction>,
    ) -> Result<StatementBlock, BlockManagerError> {
        let parents = Vec::new();
        let transactions = Vec::new();
        let digest = StatementBlock::compute_digest(self.authority, round, &parents, &transactions);
        let key = self.signing_key.read().clone().ok_or_else(|| {
            BlockManagerError::InvalidBlock("validator signing key is not installed".into())
        })?;
        let block = StatementBlock {
            merkle_root: Hash::zero(),
            author: self.authority,
            round,
            parents,
            transactions,
            statements: Vec::new(),
            signature: kovanica_crypto::sign(&key, digest.as_ref()),
            digest,
        };
        self.dag.put(block.clone());
        self.propose_calls.fetch_add(1, Ordering::SeqCst);
        Ok(block)
    }

    fn process_block(&self, block: &StatementBlock) -> Result<(), BlockManagerError> {
        self.process_calls.fetch_add(1, Ordering::SeqCst);
        if self.fail_process.load(Ordering::SeqCst) {
            return Err(BlockManagerError::InvalidBlock(
                "mock block manager rejects".into(),
            ));
        }
        self.dag.put(block.clone());
        Ok(())
    }

    fn our_authority(&self) -> AuthorityIndex {
        self.authority
    }

    fn set_signing_key(&self, key: SigningKey) {
        *self.signing_key.write() = Some(key);
        self.signing_key_set.store(true, Ordering::SeqCst);
    }
}

/// Drive `try_commit` to quiescence, returning every committed sub-DAG in order.
///
/// Panics instead of looping forever: a committer that keeps returning
/// `Some(...)` for the same or an earlier round would hang (and that panic is
/// exactly the signal we want from a broken implementation).
pub fn drive_try_commit(
    committer: &kovanica_consensus::UniversalCommitter,
    dag: &MockDag,
) -> Vec<kovanica_consensus::CommittedSubDag> {
    let mut out = Vec::new();
    for _ in 0..10_000 {
        match committer
            .try_commit_and_mark_durable(dag)
            .expect("persist committed decision")
        {
            Some(subdag) => out.push(subdag),
            None => return out,
        }
    }
    panic!("try_commit did not quiesce within 10000 iterations (repeated commits?)");
}

/// Build a `ConsensusEngine` wired to fresh mock DAG store + block manager.
pub fn make_engine(
    authority: AuthorityIndex,
    committee: kovanica_consensus::CommitteeInfo,
    config: kovanica_consensus::ConsensusConfig,
) -> (
    kovanica_consensus::ConsensusEngine<MockDag, MockBlockManager>,
    std::sync::Arc<MockDag>,
    std::sync::Arc<parking_lot::RwLock<MockBlockManager>>,
) {
    let signing_key = validator_signing_key(authority);
    let public_key = validator_public_key(authority);
    let mut authorities = committee.authorities().to_vec();
    if let Some(info) = authorities.iter_mut().find(|info| info.index == authority) {
        info.public_key = public_key;
    }
    let committee = kovanica_consensus::CommitteeInfo::try_new(committee.epoch(), authorities)
        .expect("updated test committee is valid");
    let dag = std::sync::Arc::new(MockDag::new());
    let manager = std::sync::Arc::new(parking_lot::RwLock::new(MockBlockManager::new(
        authority,
        dag.clone(),
    )));
    let engine = kovanica_consensus::ConsensusEngine::new(
        config,
        committee,
        dag.clone(),
        manager.clone(),
        signing_key,
        None, // No mempool for tests
        kovanica_types::SigningContext::new(kovanica_types::signing::chain_id::LOCAL),
    );
    (engine, dag, manager)
}
