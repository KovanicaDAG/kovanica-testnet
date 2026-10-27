//! State sync: `is_genesis_subdag` (pure, content-only) and its behaviour on
//! sub-DAGs produced by the committer.

mod common;

use common::{block_ref, committee, drive_try_commit, leader_info, make_block, MockDag};
use kovanica_consensus::{is_genesis_subdag, CommittedSubDag, LeaderStatus, UniversalCommitter};
use kovanica_types::block::{BlockReference, StatementBlock};
use kovanica_types::Signature;

/// The canonical genesis block (as written by the node).
fn canonical_genesis() -> StatementBlock {
    StatementBlock {
        merkle_root: Default::default(),
        author: 0,
        round: 0,
        parents: Vec::new(),
        transactions: Vec::new(),
        statements: Vec::new(),
        signature: Signature([0; 64]),
        digest: StatementBlock::compute_digest(0, 0, &[], &[]),
    }
}

fn register_with_quorum(c: &UniversalCommitter, b: &StatementBlock) {
    c.update_leader(leader_info(
        b.round,
        b.author,
        Some(b.digest),
        LeaderStatus::Undecided,
        &[],
    ));
    for v in [0u16, 1, 2] {
        c.add_vote(b.round, v, b.digest);
    }
}

/// genesis <- r1 <- L3 <- L6 <- L9 (linearizer path).
fn chain() -> (MockDag, Vec<StatementBlock>) {
    let g = canonical_genesis();
    let r1 = make_block(1, 1, vec![block_ref(&g)], "r1");
    let l3 = make_block(3, 3, vec![block_ref(&r1)], "l3");
    let l6 = make_block(2, 6, vec![block_ref(&l3)], "l6");
    let l9 = make_block(1, 9, vec![block_ref(&l6)], "l9");
    let dag = MockDag::with_blocks([g, r1, l3.clone(), l6.clone(), l9.clone()]);
    (dag, vec![l3, l6, l9])
}

#[test]
fn first_committed_subdag_is_genesis_later_ones_are_not() {
    let (dag, leaders) = chain();
    let c = UniversalCommitter::new(committee(4), false, 100);
    for l in &leaders {
        register_with_quorum(&c, l);
    }
    let subdags = drive_try_commit(&c, &dag);
    let rounds: Vec<u64> = subdags.iter().map(|s| s.leader_round).collect();
    assert_eq!(rounds, vec![3, 6, 9]);
    let flags: Vec<bool> = subdags.iter().map(is_genesis_subdag).collect();
    assert_eq!(flags, vec![true, false, false]);
}

#[test]
fn first_leader_skipped_genesis_is_first_commit_at_later_round() {
    let (dag, leaders) = chain();
    let c = UniversalCommitter::new(committee(4), false, 100);
    // PRO-35 fix: L3 registered without votes (no own quorum -> chain STALLS).
    // L6 and L9 are registered with quorum but the chain cannot pass over L3.
    c.update_leader(leader_info(
        3,
        leaders[0].author,
        Some(leaders[0].digest),
        LeaderStatus::Undecided,
        &[],
    ));
    register_with_quorum(&c, &leaders[1]);
    register_with_quorum(&c, &leaders[2]);
    let subdags = drive_try_commit(&c, &dag);
    // Chain stalls at L3 (no quorum) - no commits at all
    assert!(subdags.is_empty(), "chain must stall at L3 (no quorum)");

    // Now give L3 its quorum
    for v in [0u16, 1, 2] {
        c.add_vote(3, v, leaders[0].digest);
    }
    let subdags = drive_try_commit(&c, &dag);
    assert_eq!(subdags.len(), 3, "after L3 quorum, all three commit");
    assert_eq!(subdags[0].leader_round, 3);
    assert_eq!(subdags[1].leader_round, 6);
    assert_eq!(subdags[2].leader_round, 9);
    let flags: Vec<bool> = subdags.iter().map(is_genesis_subdag).collect();
    assert_eq!(flags, vec![true, false, false]);
}

fn subdag_with(blocks: Vec<StatementBlock>, non_blue: Vec<BlockReference>) -> CommittedSubDag {
    let leader = make_block(3, 3, vec![], "leader");
    CommittedSubDag {
        leader: leader.clone(),
        blocks,
        leader_round: 3,
        leader_author: 3,
        non_blue,
    }
}

#[test]
fn genesis_only_in_non_blue_does_not_count() {
    // Execution only executes `blocks`; non_blue is ignored.
    let g = canonical_genesis();
    let s = subdag_with(vec![make_block(1, 1, vec![], "b1")], vec![block_ref(&g)]);
    assert!(!is_genesis_subdag(&s));
}

#[test]
#[cfg(debug_assertions)]
#[should_panic(expected = "canonical genesis block must never be in non_blue")]
fn non_blue_refs_debug_asserts_genesis_is_never_red() {
    // Constructed case: genesis handed in as not blue.
    let g = canonical_genesis();
    let leader = make_block(3, 3, vec![block_ref(&g)], "leader");
    let _ =
        kovanica_consensus::non_blue_refs(&[g, leader.clone()], &[leader.digest], &leader.digest);
}

#[test]
fn round_zero_with_non_canonical_digest_is_not_genesis() {
    let forged = make_block(0, 0, vec![], "forged-genesis");
    assert!(!is_genesis_subdag(&subdag_with(
        vec![forged.clone()],
        vec![block_ref(&forged)]
    )));
    assert!(!is_genesis_subdag(&subdag_with(vec![], vec![])));
}

#[test]
fn replay_of_stored_subdag_after_pruning_gives_same_answer() {
    let (dag, leaders) = chain();
    let c = UniversalCommitter::new(committee(4), false, 100);
    for l in &leaders {
        register_with_quorum(&c, l);
    }
    let live = drive_try_commit(&c, &dag);
    let live_flags: Vec<bool> = live.iter().map(is_genesis_subdag).collect();
    // Stored sub-DAGs replayed with the DAG gone entirely (pruned).
    let stored: Vec<CommittedSubDag> = live.clone();
    drop(dag);
    let replay_flags: Vec<bool> = stored.iter().map(is_genesis_subdag).collect();
    assert_eq!(live_flags, replay_flags);
    assert_eq!(replay_flags, vec![true, false, false]);
}
