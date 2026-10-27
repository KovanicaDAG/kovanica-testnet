//! Tests for PRO-40 (a): Consensus Late Vote Acceptance and Cascade Commit Draining.
//!
//! Covers:
//! 1. Early vote buffered before leader block arrival and committed upon block arrival.
//! 2. Cascade commit when a late vote unblocks an earlier stalled leader.
//! 3. Bounded buffer limits (deduplication, max votes per round, and pruning on commit).

mod common;

use common::{block_ref, committee, make_block, make_engine, signed_vote};
use kovanica_consensus::{ConsensusConfig, ConsensusError, VoteRejection};

#[test]
fn test_early_vote_buffered_and_committed_on_late_block_arrival() {
    let members = committee(4);
    let (engine, _dag, _manager) = make_engine(0, members.clone(), ConsensusConfig::default());
    let (sender, mut receiver) = tokio::sync::mpsc::unbounded_channel();
    engine.set_commit_sender(sender);

    // Leader for round 3 is authority (3 / 3) % 4 = 1.
    let leader_author = members.leader(3);
    assert_eq!(leader_author, 1);
    let leader_block = make_block(leader_author, 3, Vec::new(), "pro40-round-3-leader");

    // 1. Quorum of votes arrive BEFORE the leader block itself arrives.
    // In committee(4), quorum is 3. Authorities 0, 1, and 2 cast votes.
    let vote0 = signed_vote(3, 0, leader_block.digest);
    let vote1 = signed_vote(3, 1, leader_block.digest);
    let vote2 = signed_vote(3, 2, leader_block.digest);

    assert!(engine.process_vote(&vote0).is_ok());
    assert!(engine.process_vote(&vote1).is_ok());
    assert!(engine.process_vote(&vote2).is_ok());

    // Verify votes are held in the pending buffer and not yet committed
    assert_eq!(engine.pending_votes_count(3), 3);
    assert_eq!(engine.pending_vote_rounds(), vec![3]);
    assert!(
        receiver.try_recv().is_err(),
        "cannot commit before the leader block itself arrives"
    );

    // 2. Late leader block arrives and is ingested into consensus.
    engine
        .process_block(&leader_block)
        .expect("leader block processed successfully");

    // 3. Ingestion flushes buffered votes, reaching quorum and triggering commit.
    let committed = receiver
        .try_recv()
        .expect("buffered votes must trigger immediate commit on block arrival");
    assert_eq!(committed.leader.round, 3);
    assert_eq!(committed.leader.digest, leader_block.digest);

    // 4. On commit, pending votes for round <= committed round must be pruned.
    assert_eq!(engine.pending_votes_count(3), 0);
    assert!(!engine.pending_vote_rounds().contains(&3));
}

#[test]
fn test_cascade_commit_on_late_vote_unblock() {
    let members = committee(4);
    let (engine, _dag, _manager) = make_engine(0, members.clone(), ConsensusConfig::default());
    let (sender, mut receiver) = tokio::sync::mpsc::unbounded_channel();
    engine.set_commit_sender(sender);

    // Round 3 leader: authority 1
    let leader3_author = members.leader(3);
    let leader3_block = make_block(leader3_author, 3, Vec::new(), "cascade-leader-3");

    // Round 6 leader: authority 2
    let leader6_author = members.leader(6);
    let leader6_block = make_block(
        leader6_author,
        6,
        vec![block_ref(&leader3_block)],
        "cascade-leader-6",
    );

    // Ingest both blocks
    engine
        .process_block(&leader3_block)
        .expect("leader 3 block");
    engine
        .process_block(&leader6_block)
        .expect("leader 6 block");

    // Round 6 receives quorum votes FIRST (ahead of round 3).
    for voter in 0..3 {
        let vote = signed_vote(6, voter, leader6_block.digest);
        engine.process_vote(&vote).expect("vote for round 6");
    }

    // Round 6 cannot commit yet because earlier round 3 is undecided.
    assert!(
        receiver.try_recv().is_err(),
        "round 6 must remain blocked until round 3 is decided"
    );

    // Now late votes arrive for round 3.
    // First 2 votes: below quorum (2 < 3)
    engine
        .process_vote(&signed_vote(3, 0, leader3_block.digest))
        .expect("vote 3.0");
    engine
        .process_vote(&signed_vote(3, 1, leader3_block.digest))
        .expect("vote 3.1");
    assert!(
        receiver.try_recv().is_err(),
        "still below quorum for round 3"
    );

    // 3rd vote arrives: completes quorum for round 3.
    // The engine's drain_commits() immediately unblocks and cascades to commit round 6!
    engine
        .process_vote(&signed_vote(3, 2, leader3_block.digest))
        .expect("vote 3.2 unblocks commit cascade");

    let first_commit = receiver
        .try_recv()
        .expect("round 3 must be committed first");
    assert_eq!(first_commit.leader.round, 3);
    assert_eq!(first_commit.leader.digest, leader3_block.digest);

    let second_commit = receiver
        .try_recv()
        .expect("round 6 must be committed immediately in cascade");
    assert_eq!(second_commit.leader.round, 6);
    assert_eq!(second_commit.leader.digest, leader6_block.digest);

    assert!(
        receiver.try_recv().is_err(),
        "no additional commits expected"
    );
}

#[test]
fn test_pending_votes_bounded_and_pruned() {
    // Large committee to test vote capping (50 members).
    let members = committee(50);
    let (engine, _dag, _manager) = make_engine(0, members.clone(), ConsensusConfig::default());
    let (sender, mut receiver) = tokio::sync::mpsc::unbounded_channel();
    engine.set_commit_sender(sender);

    let dummy_digest = kovanica_types::hash::Hash::new(b"unanchored-test-block");

    // 1. Deduplication: duplicate vote from same voter does not increase count
    let vote0 = signed_vote(3, 0, dummy_digest);
    assert!(engine.process_vote(&vote0).is_ok());
    assert_eq!(engine.pending_votes_count(3), 1);

    // Same vote again
    assert!(engine.process_vote(&vote0).is_ok());
    assert_eq!(
        engine.pending_votes_count(3),
        1,
        "duplicate vote from voter 0 must be deduplicated"
    );

    // 2. Bound per round: MAX_PENDING_VOTES_PER_ROUND = 32
    // Send votes from 35 distinct authorities (1..=35)
    for voter in 1..=35 {
        let v = signed_vote(3, voter, dummy_digest);
        let _ = engine.process_vote(&v);
    }
    assert_eq!(
        engine.pending_votes_count(3),
        32,
        "votes per round must be capped at MAX_PENDING_VOTES_PER_ROUND = 32"
    );

    // 3. Out-of-window votes: round too far in the future (> current_round + 3 * WAVE_LENGTH)
    // Here current_round is 0, so max allowed leader round is 0 + 9 = 9.
    let far_vote = signed_vote(12, 0, dummy_digest);
    let err = engine
        .process_vote(&far_vote)
        .expect_err("far future unanchored vote must be rejected");
    assert!(matches!(
        err,
        ConsensusError::VoteRejected(VoteRejection::UnknownLeaderRound(12))
    ));

    // 4. Pruning on commit:
    // Create and ingest the real leader block for round 3
    let leader_author = members.leader(3);
    let real_block = make_block(leader_author, 3, Vec::new(), "real-round-3-block");
    engine.process_block(&real_block).expect("real block");

    // Feed quorum votes for the real block to commit it
    let quorum = members.quorum_threshold(); // For 50 members, quorum is 34
    for voter in 0..quorum as u16 {
        let vote = signed_vote(3, voter, real_block.digest);
        let _ = engine.process_vote(&vote);
    }

    let committed = receiver.try_recv().expect("round 3 commits");
    assert_eq!(committed.leader.round, 3);

    // Pending votes for round 3 must be cleaned up / pruned
    assert_eq!(engine.pending_votes_count(3), 0);
    assert!(!engine.pending_vote_rounds().contains(&3));
}
