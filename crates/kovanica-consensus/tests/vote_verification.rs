//! `ConsensusEngine::process_vote` is the vote authentication boundary.
//!
//! Every test uses a 4-member equal-stake committee (quorum = 3) and a single
//! registered leader block at round 3 (scheduled author:
//! `(3 / WAVE_LENGTH) % 4 = 1`).

mod common;

use common::{committee, make_block, make_engine, signed_vote, validator_signing_key};
use kovanica_consensus::{ConsensusConfig, ConsensusEngine, ConsensusError, VoteRejection};
use kovanica_types::block::StatementBlock;
use kovanica_types::{CommittedSubDag, Signature, Vote};
use tokio::sync::mpsc::UnboundedReceiver;

const LEADER_ROUND: u64 = 3;

fn setup() -> (
    ConsensusEngine<common::MockDag, common::MockBlockManager>,
    UnboundedReceiver<CommittedSubDag>,
    StatementBlock,
) {
    let members = committee(4);
    let leader_author = members.leader(LEADER_ROUND);
    let (engine, _dag, _manager) = make_engine(0, members, ConsensusConfig::default());
    let (sender, receiver) = tokio::sync::mpsc::unbounded_channel();
    engine.set_commit_sender(sender);
    let leader = make_block(
        leader_author,
        LEADER_ROUND,
        Vec::new(),
        "vote-verification-leader",
    );
    engine
        .process_block(&leader)
        .expect("leader block accepted");
    (engine, receiver, leader)
}

fn rejection(result: Result<(), ConsensusError>) -> VoteRejection {
    match result {
        Err(ConsensusError::VoteRejected(reason)) => reason,
        other => panic!("expected the vote to be rejected, got {other:?}"),
    }
}

#[test]
fn forged_signature_vote_does_not_commit() {
    let (engine, mut receiver, leader) = setup();
    engine
        .process_vote(&signed_vote(LEADER_ROUND, 0, leader.digest))
        .unwrap();
    engine
        .process_vote(&signed_vote(LEADER_ROUND, 1, leader.digest))
        .unwrap();

    // Voter 2's vote with a garbage signature would complete the quorum.
    let mut forged = signed_vote(LEADER_ROUND, 2, leader.digest);
    forged.signature = Signature([0xAB; 64]);
    assert_eq!(
        rejection(engine.process_vote(&forged)),
        VoteRejection::BadSignature(2)
    );
    assert!(
        receiver.try_recv().is_err(),
        "a forged vote must not complete the quorum"
    );

    // Tampering with a validly signed vote (different round) also fails.
    let mut tampered: Vote = signed_vote(LEADER_ROUND + 3, 2, leader.digest);
    tampered.leader_round = LEADER_ROUND;
    assert_eq!(
        rejection(engine.process_vote(&tampered)),
        VoteRejection::BadSignature(2)
    );
    assert!(receiver.try_recv().is_err());
}

#[test]
fn vote_signed_with_another_validators_key_is_rejected() {
    let (engine, mut receiver, leader) = setup();
    engine
        .process_vote(&signed_vote(LEADER_ROUND, 0, leader.digest))
        .unwrap();
    engine
        .process_vote(&signed_vote(LEADER_ROUND, 1, leader.digest))
        .unwrap();

    // Validator 1 signs a vote claiming to be validator 2.
    let impersonation =
        common::vote_signed_with(&validator_signing_key(1), LEADER_ROUND, 2, leader.digest);
    assert_eq!(
        rejection(engine.process_vote(&impersonation)),
        VoteRejection::BadSignature(2)
    );
    assert!(
        receiver.try_recv().is_err(),
        "a vote signed with another validator's key must not count"
    );
}

#[test]
fn duplicate_vote_is_counted_once() {
    let (engine, mut receiver, leader) = setup();
    let vote0 = signed_vote(LEADER_ROUND, 0, leader.digest);
    let vote1 = signed_vote(LEADER_ROUND, 1, leader.digest);

    engine.process_vote(&vote0).unwrap();
    for _ in 0..3 {
        assert_eq!(
            rejection(engine.process_vote(&vote0)),
            VoteRejection::Duplicate {
                round: LEADER_ROUND,
                voter: 0
            }
        );
    }
    engine.process_vote(&vote1).unwrap();
    assert_eq!(
        rejection(engine.process_vote(&vote1)),
        VoteRejection::Duplicate {
            round: LEADER_ROUND,
            voter: 1
        }
    );
    assert!(
        receiver.try_recv().is_err(),
        "two distinct voters (plus duplicates) are below quorum"
    );
}

#[test]
fn quorum_of_valid_votes_commits() {
    let (engine, mut receiver, leader) = setup();
    for voter in [0, 1] {
        engine
            .process_vote(&signed_vote(LEADER_ROUND, voter, leader.digest))
            .unwrap();
        assert!(receiver.try_recv().is_err(), "below quorum");
    }
    engine
        .process_vote(&signed_vote(LEADER_ROUND, 2, leader.digest))
        .unwrap();
    let committed = receiver.try_recv().expect("quorum commits the leader");
    assert_eq!(committed.leader.digest, leader.digest);
    assert_eq!(committed.leader_round, LEADER_ROUND);
    assert!(receiver.try_recv().is_err(), "committed exactly once");
}
