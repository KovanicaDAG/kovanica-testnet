//! Tests for `ConsensusEngine`: construction/state, error propagation, and a
//! short live round loop (round advancement + proposing as leader).

mod common;

use common::signed_vote;
use common::{committee, make_engine};
use kovanica_consensus::{ConsensusConfig, ConsensusError, VoteRejection};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Fast config so round-loop tests complete in milliseconds.
fn fast_config() -> ConsensusConfig {
    ConsensusConfig {
        round_duration_ms: 5,
        lookahead_rounds: 3,
        max_pending_rounds: 100,
        use_mysticghost: true,
        leader_timeout_ms: 3000,
        leader_timeout_factor: 2,
        late_vote_window_rounds: kovanica_types::WAVE_LENGTH,
        prune_window_waves: 100,
        use_vrf_leader: false,
        use_min_digest_fork: false,
        genesis_hash: kovanica_types::Hash::zero(),
        // Certified skips are exercised by their own tests; with 1-5 ms
        // rounds a 6-round T_skip would turn scheduling jitter into skips.
        skip_timeout_rounds: 1_000_000,
    }
}

#[test]
fn test_engine_new_initial_state() {
    let (engine, _dag, manager) = make_engine(1, committee(4), ConsensusConfig::default());

    assert_eq!(engine.current_round(), 0);
    let state = engine.state();
    assert_eq!(state.our_authority, 1);
    assert_eq!(
        state.our_stake, 1,
        "committee(4) uses stake 1 per authority"
    );
    assert_eq!(state.current_round, 0);
    assert!(!state.is_leader, "no round advanced yet");
    assert!(!state.proposed);

    let c = engine.committee();
    assert_eq!(c.size(), 4);
    assert_eq!(c.quorum_threshold(), 3);
    assert_eq!(c.stake_of(1), Some(1));
    assert!(
        !manager.read().signing_key_set(),
        "key is installed by start()"
    );
}

#[test]
fn test_engine_config_defaults() {
    let config = ConsensusConfig::default();
    assert_eq!(config.round_duration_ms, 4000);
    assert_eq!(config.lookahead_rounds, 3);
    assert_eq!(config.max_pending_rounds, 100);
    assert!(config.use_mysticghost);
    assert!(config.use_vrf_leader);
}

#[test]
fn test_engine_process_block_ok_and_error_propagation() {
    let (engine, dag, manager) = make_engine(0, committee(4), ConsensusConfig::default());
    let block = make_block_received(1);

    // Happy path: block is handed to the block manager. Round 1 is a vote
    // round, so it is not registered as a leader candidate.
    assert!(engine.process_block(&block).is_ok());
    assert_eq!(manager.read().process_calls(), 1);
    assert!(
        dag.contains(&block.digest),
        "non-leader block remains in the DAG"
    );

    // Failure path: the block manager's error surfaces as ConsensusError.
    manager.read().set_fail_process(true);
    let err = engine
        .process_block(&block)
        .expect_err("must propagate error");
    assert!(
        matches!(err, ConsensusError::BlockManager(_)),
        "got {err:?}"
    );
    assert_eq!(
        manager.read().process_calls(),
        2,
        "the rejection still counted"
    );

    // ... and a successful call afterwards still works.
    manager.read().set_fail_process(false);
    assert!(engine.process_block(&block).is_ok());
    assert_eq!(manager.read().process_calls(), 3);
}

#[test]
fn test_competing_author_blocks_commit_the_scheduled_leader_in_either_arrival_order() {
    fn run(reverse_arrival_order: bool) -> (kovanica_types::hash::Hash, bool, bool) {
        let (engine, dag, _manager) = make_engine(0, committee(2), ConsensusConfig::default());
        let (sender, mut receiver) = tokio::sync::mpsc::unbounded_channel();
        engine.set_commit_sender(sender);

        // Round 3 is a leader slot, and CommitteeInfo::leader(3) selects
        // authority 1 for this two-member committee. Authority 0's block is
        // still accepted into the DAG, but it cannot register as the leader.
        let non_leader = common::make_block(0, 3, Vec::new(), "round-3-non-leader");
        let scheduled_leader = common::make_block(1, 3, Vec::new(), "round-3-scheduled-leader");
        let arrivals = if reverse_arrival_order {
            [&scheduled_leader, &non_leader]
        } else {
            [&non_leader, &scheduled_leader]
        };
        for block in arrivals {
            engine.process_block(block).expect("accepted DAG block");
        }

        assert!(dag.contains(&non_leader.digest));
        assert!(dag.contains(&scheduled_leader.digest));
        engine
            .process_vote(&signed_vote(3, 0, scheduled_leader.digest))
            .expect("first valid vote");
        engine
            .process_vote(&signed_vote(3, 1, scheduled_leader.digest))
            .expect("quorum vote");

        let committed = receiver.try_recv().expect("leader slot commits");
        (
            committed.leader.digest,
            dag.contains(&non_leader.digest),
            dag.contains(&scheduled_leader.digest),
        )
    }

    let forward = run(false);
    let reverse = run(true);
    assert_eq!(forward, reverse, "arrival order must not alter the commit");
    assert!(
        forward.1 && forward.2,
        "both valid blocks remain in the DAG"
    );
    assert_eq!(
        forward.0,
        common::make_block(1, 3, Vec::new(), "round-3-scheduled-leader").digest,
        "only the committee-scheduled leader block is committed"
    );
}

#[test]
fn test_engine_rejects_invalid_votes_without_counting_them() {
    // Round 3 is a leader slot. Only the block authored by the committee's
    // scheduled leader can register, so derive the author instead of assuming
    // one: the rotation is `leader = (round / WAVE_LENGTH) % committee_size`.
    let members = committee(3);
    let leader_author = members.leader(3);
    let (engine, _dag, manager) = make_engine(0, members, ConsensusConfig::default());
    let (sender, mut receiver) = tokio::sync::mpsc::unbounded_channel();
    engine.set_commit_sender(sender);
    let block = common::make_block(leader_author, 3, Vec::new(), "round-3-scheduled-leader");
    engine.process_block(&block).expect("process_block");

    let rejection = |vote: kovanica_types::Vote| match engine.process_vote(&vote) {
        Err(ConsensusError::VoteRejected(reason)) => reason,
        other => panic!("expected a vote rejection, got {other:?}"),
    };

    // Unknown authority (signed with some key; membership is checked first).
    assert_eq!(
        rejection(common::vote_signed_with(
            &common::validator_signing_key(99),
            3,
            99,
            block.digest
        )),
        VoteRejection::UnknownVoter(99)
    );
    // Not a leader round.
    assert_eq!(
        rejection(signed_vote(4, 2, block.digest)),
        VoteRejection::NotLeaderRound(4)
    );
    // Leader round with no registered leader block.
    assert_eq!(
        rejection(signed_vote(99, 2, block.digest)),
        VoteRejection::UnknownLeaderRound(99)
    );
    // Hash that is not the registered leader block.
    assert_eq!(
        rejection(signed_vote(
            3,
            2,
            kovanica_types::hash::Hash::new(b"wrong-vote-hash")
        )),
        VoteRejection::LeaderHashMismatch(3)
    );

    // None of the rejected votes contributed stake: quorum (3 of 3) still
    // needs every valid vote.
    engine
        .process_vote(&signed_vote(3, 0, block.digest))
        .unwrap();
    engine
        .process_vote(&signed_vote(3, 1, block.digest))
        .unwrap();
    assert!(receiver.try_recv().is_err(), "two votes are below quorum");
    engine
        .process_vote(&signed_vote(3, 2, block.digest))
        .unwrap();
    assert_eq!(receiver.try_recv().unwrap().leader.digest, block.digest);

    assert_eq!(
        manager.read().process_calls(),
        1,
        "no extra block processing"
    );
}

#[test]
fn test_engine_stop_before_start_does_not_panic() {
    let (engine, _dag, manager) = make_engine(0, committee(4), fast_config());
    engine.stop();
    engine.stop(); // idempotent
    assert!(!manager.read().signing_key_set());
    assert_eq!(engine.current_round(), 0);
}

/// A single-validator committee (n = 1) is the leader every round: the round
/// loop must advance rounds, propose blocks each round, install the signing
/// key, and exit cleanly on `stop()`.
#[tokio::test]
async fn test_engine_round_loop_advances_proposes_and_stops() {
    let info = committee(1);
    assert_eq!(info.quorum_threshold(), 1);
    let (engine, dag, manager) = make_engine(0, info, fast_config());
    let manager_for_check = manager.clone();

    let engine = Arc::new(engine);
    let task_engine = Arc::clone(&engine);
    let handle = tokio::spawn(async move { task_engine.start().await });

    // Wait (generously) for the loop to install the key and propose a few
    // rounds — n = 1 means we are the leader of every round.
    let deadline = Instant::now() + Duration::from_secs(10);
    while manager_for_check.read().propose_calls() < 3
        || !manager_for_check.read().signing_key_set()
    {
        assert!(
            Instant::now() < deadline,
            "round loop made no progress: {} proposals, key installed = {}",
            manager_for_check.read().propose_calls(),
            manager_for_check.read().signing_key_set()
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    engine.stop();
    let result = handle.await.expect("round-loop task panicked");
    assert!(
        result.is_ok(),
        "start() must return Ok after stop(): {result:?}"
    );
    assert!(manager_for_check.read().propose_calls() >= 3);
    let proposal = dag
        .blocks()
        .into_iter()
        .next()
        .expect("round loop produced a proposal");
    let public_key = engine
        .committee()
        .get_by_index(0)
        .expect("local validator is in committee")
        .public_key;
    kovanica_crypto::verify_block_signature(&public_key, &proposal.digest, &proposal.signature)
        .expect("startup installed the explicitly configured validator key");
}

fn make_block_received(round: kovanica_types::Round) -> kovanica_types::block::StatementBlock {
    common::make_block(2, round, Vec::new(), &format!("received-{round}"))
}
