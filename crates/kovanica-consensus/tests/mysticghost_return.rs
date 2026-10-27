//! #13 (MysticGhost variant A): red mergeset blocks are reported in
//! `CommittedSubDag::non_blue`, never executed as blocks, never pruned by the
//! committer, and their transactions are recoverable via
//! `non_blue_transactions` - identically on the live and the recovery path.

mod common;

use common::{block_ref, committee, make_block};
use kovanica_consensus::engine::DagStoreTrait;
use kovanica_consensus::{
    non_blue_refs, non_blue_transactions, CommittedSubDag, UniversalCommitter,
};
use kovanica_dag::{DagStore, DagStoreError};
use kovanica_types::block::{BlockReference, StatementBlock};
use kovanica_types::hash::Hash;
use kovanica_types::transaction::{Transaction, TransactionKind};
use kovanica_types::{Address, AuthorityIndex, Round, Signature};
use std::collections::HashSet;
use std::sync::Arc;

/// Same thin adapter as the node's `NodeDagStore`, over a real redb store.
struct RealDag {
    inner: Arc<DagStore>,
}

impl DagStoreTrait for RealDag {
    fn get_block(&self, hash: &Hash) -> Result<StatementBlock, DagStoreError> {
        self.inner.get_block(hash)
    }
    fn get_ancestors(&self, hash: &Hash, min_round: Round) -> Result<Vec<Hash>, DagStoreError> {
        self.inner.get_ancestors(hash, min_round)
    }
    fn get_parents(&self, hash: &Hash) -> Result<Vec<Hash>, DagStoreError> {
        self.inner.get_parents(hash)
    }
    fn get_block_by_author_round(
        &self,
        author: AuthorityIndex,
        round: Round,
    ) -> Result<Option<StatementBlock>, DagStoreError> {
        self.inner.get_block_by_author_round(author, round)
    }
    fn get_blocks_by_round(&self, round: Round) -> Result<Vec<StatementBlock>, DagStoreError> {
        self.inner.get_blocks_by_round(round)
    }
    fn has_block(&self, hash: &Hash) -> Result<bool, DagStoreError> {
        self.inner.has_block(hash)
    }
    fn put_block(&self, block: &StatementBlock) -> Result<(), DagStoreError> {
        self.inner.put_block(block)
    }
    fn find_parents(
        &self,
        round: Round,
        max_parents: usize,
    ) -> Result<Vec<BlockReference>, DagStoreError> {
        self.inner.find_parents(round, max_parents)
    }
    fn commit_leader(&self, leader_hash: &Hash) -> Result<u64, DagStoreError> {
        self.inner.commit_leader(leader_hash)
    }
    fn mark_round_decided(&self, round: Round, leader_hash: &Hash) -> Result<(), DagStoreError> {
        self.inner.mark_round_decided(round, leader_hash)
    }
    fn mark_decided_and_commit_leader(
        &self,
        round: Round,
        leader_hash: &Hash,
    ) -> Result<u64, DagStoreError> {
        self.inner
            .mark_decided_and_commit_leader(round, leader_hash)
    }
    fn mergeset(&self, leader: &Hash) -> Result<Vec<Hash>, DagStoreError> {
        self.inner.mergeset(leader)
    }
    fn get_blocks(&self, hashes: &[Hash]) -> Result<Vec<StatementBlock>, DagStoreError> {
        Ok(hashes
            .iter()
            .filter_map(|h| self.inner.get_block(h).ok())
            .collect())
    }
    fn get_decided_leaders(&self, round: Round) -> Result<Vec<Hash>, DagStoreError> {
        self.inner.get_decided_leaders(round)
    }
    fn get_decided_rounds(&self, max_round: Round) -> Result<Vec<Round>, DagStoreError> {
        self.inner.get_decided_rounds(max_round)
    }
    fn prune_non_blue(&self, blue: &[Hash], wave: u64) -> Result<u64, DagStoreError> {
        self.inner.prune_non_blue(blue, wave)
    }
    fn prune_waves_before(&self, wave: u64, window: u64) -> Result<u64, DagStoreError> {
        self.inner.prune_waves_before(wave, window)
    }
}

fn tx(n: u64) -> Transaction {
    Transaction {
        sender: Address([7; 32]),
        nonce: n,
        kind: TransactionKind::Stake { amount: n },
        fee: 1,
        signature: Signature([0; 64]),
        hash: Hash::new(format!("tx-{n}").as_bytes()),
    }
}

fn with_txs(mut b: StatementBlock, txs: &[u64]) -> StatementBlock {
    b.transactions = txs.iter().map(|n| tx(*n)).collect();
    b
}

fn store(dir: &tempfile::TempDir) -> RealDag {
    let storage = kovanica_storage::Storage::new(dir.path().join("dag.redb")).unwrap();
    RealDag {
        inner: Arc::new(DagStore::new(storage).unwrap()),
    }
}

/// Wide wave: 6 mutually-unordered round-1 blocks under one leader at round
/// 3. With k = 3 every one has an anticone of 5, so GHOSTDAG colours some red.
/// Tx 100 is in a red-candidate block AND the leader (must be excluded from
/// the red list); tx 7 is duplicated across two round-1 blocks.
fn wide_wave(dag: &RealDag) -> (StatementBlock, Vec<StatementBlock>) {
    let genesis = make_block(0, 0, vec![], "genesis");
    dag.put_block(&genesis).unwrap();
    let mut wide = Vec::new();
    for i in 0..6u64 {
        let txs: Vec<u64> = match i {
            0 => vec![100, 1],
            4 => vec![7, 4],
            5 => vec![7, 5],
            _ => vec![i],
        };
        let b = with_txs(
            make_block(
                i as AuthorityIndex % 4,
                1,
                vec![block_ref(&genesis)],
                &format!("w{i}"),
            ),
            &txs,
        );
        dag.put_block(&b).unwrap();
        wide.push(b);
    }
    let leader = with_txs(
        make_block(3, 3, wide.iter().map(block_ref).collect(), "leader-3"),
        &[100, 300],
    );
    dag.put_block(&leader).unwrap();
    (leader, wide)
}

fn commit(
    c: &UniversalCommitter,
    dag: &RealDag,
    round: Round,
    leader: &StatementBlock,
) -> CommittedSubDag {
    c.update_leader(common::leader_info(
        round,
        leader.author,
        Some(leader.digest),
        kovanica_consensus::LeaderStatus::Undecided,
        Default::default(),
    ));
    for v in [0u16, 1, 2] {
        c.add_vote(round, v, leader.digest);
    }
    c.try_commit_and_mark_durable(dag)
        .expect("no storage error")
        .expect("leader with quorum commits")
}

fn all_txs(blocks: &[StatementBlock]) -> HashSet<Hash> {
    blocks
        .iter()
        .flat_map(|b| b.transactions.iter().map(|t| t.hash))
        .collect()
}

#[test]
fn red_block_txs_are_not_lost_and_red_blocks_are_not_executed() {
    let dir = tempfile::tempdir().unwrap();
    let dag = store(&dir);
    let (leader, wide) = wide_wave(&dag);
    let c = UniversalCommitter::new(committee(4), true, 100);
    let subdag = commit(&c, &dag, 3, &leader);

    assert!(
        !subdag.non_blue.is_empty(),
        "wide wave must have red blocks reported in non_blue"
    );
    // non_blue never in the execution list.
    let executed: HashSet<Hash> = subdag.blocks.iter().map(|b| b.digest).collect();
    for r in &subdag.non_blue {
        assert!(
            !executed.contains(&r.digest),
            "red block {} executed",
            r.digest
        );
        assert_ne!(r.digest, subdag.leader.digest);
        // Not pruned by the committer.
        assert!(
            dag.has_block(&r.digest).unwrap(),
            "red block deleted before delivery"
        );
    }
    // Deterministic order: by (round, digest).
    let mut sorted = subdag.non_blue.clone();
    sorted.sort_by_key(|r| (r.round, r.digest.0));
    assert_eq!(sorted, subdag.non_blue);

    // No transaction lost: blue + red-returned covers every tx of the wave,
    // without duplicates and without re-returning blue txs.
    let red = non_blue_transactions(&dag, &subdag).unwrap();
    let red_hashes: Vec<Hash> = red.iter().map(|t| t.hash).collect();
    let red_set: HashSet<Hash> = red_hashes.iter().copied().collect();
    assert_eq!(red_set.len(), red_hashes.len(), "red txs deduped");
    let mut blue_blocks = subdag.blocks.clone();
    blue_blocks.push(subdag.leader.clone());
    let blue_set = all_txs(&blue_blocks);
    assert!(
        red_set.is_disjoint(&blue_set),
        "blue txs excluded from red list"
    );
    let mut wave = wide.clone();
    wave.push(leader.clone());
    let delivered: HashSet<Hash> = blue_set.union(&red_set).copied().collect();
    assert_eq!(delivered, all_txs(&wave), "no transaction of the wave lost");
}

#[test]
fn live_and_recovery_helpers_agree_over_the_same_dag() {
    let dir = tempfile::tempdir().unwrap();
    let dag = store(&dir);
    let (leader, _) = wide_wave(&dag);
    let c = UniversalCommitter::new(committee(4), true, 100);
    let live = commit(&c, &dag, 3, &leader);

    // Recovery: recompute from the durable DAG with the same public helpers
    // (mergeset -> colouring -> non_blue_refs), as the node's recovery does.
    let mergeset = dag
        .get_blocks(&dag.mergeset(&leader.digest).unwrap())
        .unwrap();
    let colouring = match kovanica_consensus::mysticghost::order_committed_wave(
        &kovanica_consensus::mysticghost::MysticGhostConfig {
            enabled: true,
            k: 3,
            max_mergeset_blocks: 2_000,
        },
        &mergeset,
        &[],
    ) {
        kovanica_consensus::mysticghost::MysticGhostOrder::Ghost { colouring } => colouring,
        _ => panic!("expected Ghost colouring"),
    };
    let recovered_refs = non_blue_refs(&mergeset, &colouring.blue, &leader.digest);
    assert_eq!(
        recovered_refs, live.non_blue,
        "same non_blue live vs recovery"
    );
    let recovered = CommittedSubDag {
        non_blue: recovered_refs,
        ..live.clone()
    };
    let a: Vec<Hash> = non_blue_transactions(&dag, &live)
        .unwrap()
        .iter()
        .map(|t| t.hash)
        .collect();
    let b: Vec<Hash> = non_blue_transactions(&dag, &recovered)
        .unwrap()
        .iter()
        .map(|t| t.hash)
        .collect();
    assert_eq!(a, b, "same red tx list live vs recovery");
    // Input order does not matter.
    let mut rev = mergeset.clone();
    rev.reverse();
    assert_eq!(
        non_blue_refs(&rev, &colouring.blue, &leader.digest),
        live.non_blue
    );
}

#[test]
fn no_redelivery_after_mysticghost_commit_and_round_pruning() {
    let dir = tempfile::tempdir().unwrap();
    let dag = store(&dir);
    let (leader3, _) = wide_wave(&dag);
    // Tiny prune window so round pruning removes the first wave mid-run.
    let c = UniversalCommitter::new(committee(4), true, 1);
    let mut delivered: Vec<Hash> = Vec::new();
    let s = commit(&c, &dag, 3, &leader3);
    assert!(
        !s.non_blue.is_empty(),
        "first commit reports its red blocks"
    );
    for r in &s.non_blue {
        assert!(
            dag.has_block(&r.digest).unwrap(),
            "red block must survive until round pruning"
        );
    }
    delivered.extend(s.blocks.iter().map(|b| b.digest));
    delivered.extend(s.non_blue.iter().map(|r| r.digest));
    let mut prev = leader3;
    for round in [6u64, 9, 12, 15] {
        let side = make_block(
            0,
            round - 1,
            vec![block_ref(&prev)],
            &format!("side-{round}"),
        );
        dag.put_block(&side).unwrap();
        let author = (round % 4) as AuthorityIndex;
        let l = make_block(
            author,
            round,
            vec![block_ref(&prev), block_ref(&side)],
            &format!("leader-{round}"),
        );
        dag.put_block(&l).unwrap();
        let s = commit(&c, &dag, round, &l);
        delivered.extend(s.blocks.iter().map(|b| b.digest));
        delivered.extend(s.non_blue.iter().map(|r| r.digest));
        // Red refs must be readable while their subdag is delivered.
        non_blue_transactions(&dag, &s).expect("red blocks of this commit still stored");
        prev = l;
    }
    let unique: HashSet<Hash> = delivered.iter().copied().collect();
    assert_eq!(unique.len(), delivered.len(), "a block was delivered twice");
    assert!(
        dag.inner.prune_boundary().unwrap() > 0,
        "round pruning ran during the test"
    );
}

#[test]
fn real_mysticghost_commit_puts_canonical_genesis_in_blocks() {
    // Wide wave under the canonical genesis: some round-1 blocks are red,
    // genesis is blue (executed) and the sub-DAG is the genesis sub-DAG.
    let dir = tempfile::tempdir().unwrap();
    let dag = store(&dir);
    let g = StatementBlock {
        merkle_root: Default::default(),
        author: 0,
        round: 0,
        parents: Vec::new(),
        transactions: Vec::new(),
        statements: Vec::new(),
        signature: Signature([0; 64]),
        digest: StatementBlock::compute_digest(0, 0, &[], &[]),
    };
    dag.put_block(&g).unwrap();
    let mut wide = Vec::new();
    for i in 0..6u16 {
        let b = make_block(i % 4, 1, vec![block_ref(&g)], &format!("gw{i}"));
        dag.put_block(&b).unwrap();
        wide.push(block_ref(&b));
    }
    let leader = make_block(3, 3, wide, "g-leader-3");
    dag.put_block(&leader).unwrap();
    let c = UniversalCommitter::new(committee(4), true, 100);
    let s = commit(&c, &dag, 3, &leader);
    assert!(!s.non_blue.is_empty(), "wide wave has red blocks");
    assert!(
        s.blocks.iter().any(|b| b.digest == g.digest),
        "canonical genesis is executed (in blocks)"
    );
    assert!(s.non_blue.iter().all(|r| r.digest != g.digest));
    assert!(kovanica_consensus::is_genesis_subdag(&s));
}
