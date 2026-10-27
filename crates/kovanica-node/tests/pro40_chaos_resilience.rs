//! PRO-40 (b) Chaos & Resilience Multi-Node Integration Tests.
//!
//! Validates stability, fault tolerance, and recovery of a 5-validator cluster
//! (Chain 4 public testnet: 5 validators, quorum threshold 4/5).
//!
//! # Scenarios Covered:
//!
//! 1. **Scenario 1 (1 of 5 offline)**:
//!    - 5-validator cluster with equal stake (total 5, quorum threshold = 4).
//!    - 1 validator is offline (node 4). Nodes 0, 1, 2, 3 remain online.
//!    - Active nodes produce blocks and cast votes, reaching the 4/5 quorum.
//!    - When the offline validator is the scheduled leader (round 12), the 4 active
//!      nodes time out the slot, assemble a 4/5 `SkipCert`, and continue committing
//!      subsequent leaders (round 15) without stalling or diverging.
//!
//! 2. **Scenario 2 (2 of 5 offline - Liveness Halt & Cascade Unblock)**:
//!    - 2 of 5 validators are offline (nodes 3 and 4). Nodes 0, 1, 2 remain online.
//!    - 3 active validators represent 3/5 stake, strictly below the 4/5 quorum threshold.
//!    - The cluster safely halts (liveness halt without fork or split-brain; 0 new commits).
//!    - Node 3 is restarted / reconnected.
//!    - Quorum is restored (4/5 stake online), causing a cascade unblock of the pending leader.
//!    - All online nodes resume and converge on an identical sequence of committed sub-DAGs.
//!
//! 3. **Scenario 3 (SkipCert Domain & Preimage Verification)**:
//!    - Verifies the exact domain tag (`KUNA/timeout/v1` with 0x00 padding, 16 bytes).
//!    - Verifies canonical preimage construction (exactly 74 bytes):
//!      `tag (16B) ‖ chain_id (8B) ‖ genesis_hash (32B) ‖ epoch (8B) ‖ voter (2B) ‖ round (8B)`.
//!    - Validates verification of timeouts and skip certificates against 5-node committees.
//!    - Validates strict rejection of cross-chain replay, genesis mismatch, non-leader rounds,
//!      unknown voters, under-quorum certificates, duplicate signers, and mixed rounds.
//!    - Verifies the consensus engine's direct processing and rejection of invalid timeouts/certs.

#[path = "../../kovanica-consensus/tests/common/mod.rs"]
mod common;

use common::{block_ref, committee, genesis, make_block, MockBlockManager, MockDag};
use kovanica_consensus::skip::{verify_skip_cert, verify_timeout, TimeoutRejection};
use kovanica_consensus::{ConsensusConfig, ConsensusEngine, ConsensusError, VoteRejection};
use kovanica_types::block::StatementBlock;
use kovanica_types::hash::Hash;
use kovanica_types::signing::chain_id;
use kovanica_types::timeout::{SkipCert, Timeout, TIMEOUT_DOMAIN_TAG};
use kovanica_types::{
    epoch_for_round, AuthorityIndex, CommittedSubDag, Round, Signature, SigningContext, WAVE_LENGTH,
};
use tokio::sync::mpsc;

/// Cluster size matching Chain 4 testnet specification.
const NODES: usize = 5;

/// Genesis hash for testing.
const TEST_GENESIS_HASH: Hash = Hash([0x42; 32]);

/// Deterministic, fast consensus config for in-process cluster execution.
fn engine_config(genesis_hash: Hash) -> ConsensusConfig {
    ConsensusConfig {
        round_duration_ms: 1,
        lookahead_rounds: 30,
        max_pending_rounds: 100,
        use_mysticghost: false,
        prune_window_waves: 100,
        leader_timeout_ms: 3000,
        leader_timeout_factor: 2,
        late_vote_window_rounds: WAVE_LENGTH,
        use_vrf_leader: false,
        use_min_digest_fork: false,
        genesis_hash,
        skip_timeout_rounds: 1_000_000,
    }
}

/// Gossip wire event between validators.
#[derive(Clone)]
enum Wire {
    Block(StatementBlock),
    Vote {
        leader_round: Round,
        voter: AuthorityIndex,
        leader_hash: Hash,
    },
    Timeout(Timeout),
    Cert(SkipCert),
}

/// An in-process validator instance.
struct Node {
    _authority: AuthorityIndex,
    engine: ConsensusEngine<MockDag, MockBlockManager>,
    rx: mpsc::UnboundedReceiver<CommittedSubDag>,
    commits: Vec<CommittedSubDag>,
}

fn make_node_engine(
    authority: AuthorityIndex,
    committee: kovanica_consensus::CommitteeInfo,
    config: kovanica_consensus::ConsensusConfig,
    chain_id: u64,
) -> (
    kovanica_consensus::ConsensusEngine<MockDag, MockBlockManager>,
    std::sync::Arc<MockDag>,
    std::sync::Arc<parking_lot::RwLock<MockBlockManager>>,
) {
    let signing_key = common::validator_signing_key(authority);
    let public_key = common::validator_public_key(authority);
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
        None,
        SigningContext::new(chain_id),
    );
    (engine, dag, manager)
}

impl Node {
    fn new(authority: AuthorityIndex, genesis_hash: Hash, chain_id: u64) -> Self {
        let (engine, _dag, _manager) = make_node_engine(
            authority,
            committee(NODES as u16),
            engine_config(genesis_hash),
            chain_id,
        );
        let (tx, rx) = mpsc::unbounded_channel();
        engine.set_commit_sender(tx);
        Self {
            _authority: authority,
            engine,
            rx,
            commits: Vec::new(),
        }
    }

    fn drain(&mut self) {
        while let Ok(subdag) = self.rx.try_recv() {
            self.commits.push(subdag);
        }
    }
}

fn cluster(genesis_hash: Hash, chain_id: u64) -> Vec<Node> {
    (0..NODES as u16)
        .map(|idx| Node::new(idx, genesis_hash, chain_id))
        .collect()
}

fn signed_vote(
    leader_round: Round,
    voter: AuthorityIndex,
    leader_hash: Hash,
) -> kovanica_types::Vote {
    let mut vote = kovanica_types::Vote {
        leader_round,
        leader_hash,
        voter,
        signature: Signature([0; 64]),
    };
    vote.signature = kovanica_crypto::sign(
        &common::validator_signing_key(voter),
        &vote.signature_data(&SigningContext::new(chain_id::TESTNET_V2)),
    );
    vote
}

fn deliver(nodes: &mut [Node], targets: &[usize], wire: &Wire) {
    for &target in targets {
        match wire {
            Wire::Block(block) => nodes[target]
                .engine
                .process_block(block)
                .expect("block accepted"),
            Wire::Vote {
                leader_round,
                voter,
                leader_hash,
            } => {
                let vote = signed_vote(*leader_round, *voter, *leader_hash);
                match nodes[target].engine.process_vote(&vote) {
                    Ok(()) | Err(ConsensusError::VoteRejected(VoteRejection::Duplicate { .. })) => {
                    }
                    Err(e) => panic!("vote rejected for target {target}: {e:?}"),
                }
            }
            Wire::Timeout(timeout) => match nodes[target].engine.process_timeout(timeout) {
                Ok(()) => {}
                Err(e) => panic!("timeout rejected for target {target}: {e:?}"),
            },
            Wire::Cert(cert) => match nodes[target].engine.process_skip_cert(cert) {
                Ok(()) => {}
                Err(e) => panic!("cert rejected for target {target}: {e:?}"),
            },
        }
    }
}

fn drain_all(nodes: &mut [Node]) {
    for node in nodes.iter_mut() {
        node.drain();
    }
}

/// Sign a timeout with the given parameters and authority key.
fn signed_timeout(
    round: Round,
    voter: AuthorityIndex,
    chain_id: u64,
    genesis_hash: &Hash,
) -> Timeout {
    let mut timeout = Timeout {
        round,
        voter,
        signature: Signature([0; 64]),
    };
    timeout.signature = kovanica_crypto::sign(
        &common::validator_signing_key(voter),
        &timeout.signature_data(chain_id, genesis_hash),
    );
    timeout
}

/// Build a canonical chain of blocks for 5 validators up to `max_round`.
fn canonical_chain(max_round: Round) -> Vec<StatementBlock> {
    let members = committee(NODES as u16);
    let mut chain = vec![genesis()];
    for round in 1..=max_round {
        let author = members.leader(round);
        let parent = block_ref(chain.last().expect("previous block exists"));
        let block = make_block(author, round, vec![parent], &format!("r{round}"));
        chain.push(block);
    }
    chain
}

fn committed_rounds(node: &Node) -> Vec<Round> {
    node.commits.iter().map(|s| s.leader_round).collect()
}

fn fingerprints(node: &Node) -> Vec<(Round, AuthorityIndex, Hash, Vec<Hash>)> {
    node.commits
        .iter()
        .map(|subdag| {
            (
                subdag.leader_round,
                subdag.leader_author,
                subdag.leader.digest,
                subdag.blocks.iter().map(|b| b.digest).collect(),
            )
        })
        .collect()
}

// ============================================================================
// Scenarij 1: 1 od 5 offline (4 čvora online)
// ============================================================================

#[test]
fn test_scenario1_one_of_five_offline_quorum_and_progress() {
    let members = committee(NODES as u16);
    assert_eq!(
        members.quorum_threshold(),
        4,
        "5 validators require 4/5 quorum"
    );

    let chain = canonical_chain(15);
    let mut nodes = cluster(TEST_GENESIS_HASH, chain_id::TESTNET_V2);

    // Node 4 is offline. Only nodes 0, 1, 2, 3 receive blocks.
    let online_targets: Vec<usize> = vec![0, 1, 2, 3];
    let online_voters: Vec<AuthorityIndex> = vec![0, 1, 2, 3];

    // Deliver blocks for rounds 1..=9 to all online nodes
    for block in &chain[..=9] {
        deliver(&mut nodes, &online_targets, &Wire::Block(block.clone()));
    }

    // Rounds 3, 6, 9: scheduled leaders are authorities 1, 2, 3 (all online).
    // The 4 online nodes cast votes.
    for &leader_round in &[3u64, 6, 9] {
        let leader_hash = chain[leader_round as usize].digest;
        for &voter in &online_voters {
            deliver(
                &mut nodes,
                &online_targets,
                &Wire::Vote {
                    leader_round,
                    voter,
                    leader_hash,
                },
            );
        }
    }
    drain_all(&mut nodes);

    // Verify online nodes reached 4/5 quorum and committed rounds 3, 6, 9
    for &idx in &online_targets {
        assert_eq!(
            committed_rounds(&nodes[idx]),
            vec![3, 6, 9],
            "node {idx} must commit rounds 3, 6, 9 with 4/5 quorum"
        );
        assert_eq!(nodes[idx].engine.last_decided_round(), 9);
    }

    // Node 4 (offline) has zero commits
    assert_eq!(committed_rounds(&nodes[4]), Vec::<Round>::new());
    assert_eq!(nodes[4].engine.last_decided_round(), 0);

    // Verify zero divergence across all online nodes
    let baseline = fingerprints(&nodes[0]);
    for &idx in &online_targets {
        assert_eq!(fingerprints(&nodes[idx]), baseline, "node {idx} diverged");
    }

    // Now test when the scheduled leader IS the offline node 4 (round 12):
    // In round 12, leader is Authority 4.
    assert_eq!(
        members.leader(12),
        4,
        "Authority 4 is the scheduled leader of round 12"
    );

    // Deliver blocks for rounds 10..=15 (block 12 arrives too late for votes)
    for block in &chain[10..=15] {
        deliver(&mut nodes, &online_targets, &Wire::Block(block.clone()));
    }

    // The 4 online nodes time out round 12
    let timeouts_12: Vec<Timeout> = online_voters
        .iter()
        .map(|&voter| signed_timeout(12, voter, chain_id::TESTNET_V2, &TEST_GENESIS_HASH))
        .collect();

    for timeout in &timeouts_12 {
        deliver(&mut nodes, &online_targets, &Wire::Timeout(timeout.clone()));
    }

    // Assemble and deliver 4/5 SkipCert for round 12
    let cert_12 = SkipCert {
        round: 12,
        timeouts: timeouts_12,
    };
    deliver(&mut nodes, &online_targets, &Wire::Cert(cert_12));

    // Next leader is round 15 (Leader = Authority 0, who is online).
    // The 4 online nodes vote for round 15.
    let leader_15_hash = chain[15].digest;
    for &voter in &online_voters {
        deliver(
            &mut nodes,
            &online_targets,
            &Wire::Vote {
                leader_round: 15,
                voter,
                leader_hash: leader_15_hash,
            },
        );
    }
    drain_all(&mut nodes);

    // Verify round 12 was skipped and round 15 committed on every online node
    for &idx in &online_targets {
        let rounds = committed_rounds(&nodes[idx]);
        assert_eq!(
            rounds,
            vec![3, 6, 9, 15],
            "node {idx} must skip round 12 and commit round 15"
        );
        assert!(
            !rounds.contains(&12),
            "skipped slot 12 must not be committed"
        );
        assert_eq!(nodes[idx].engine.last_decided_round(), 15);
    }

    // Ensure state consistency across all online nodes
    let final_baseline = fingerprints(&nodes[0]);
    for &idx in &online_targets {
        assert_eq!(
            fingerprints(&nodes[idx]),
            final_baseline,
            "node {idx} diverged after skip"
        );
    }
}

// ============================================================================
// Scenarij 2: 2 od 5 offline (3 čvora online - Liveness Halt & Cascade Unblock)
// ============================================================================

#[test]
fn test_scenario2_two_of_five_offline_liveness_halt_and_cascade_unblock() {
    let chain = canonical_chain(12);
    let mut nodes = cluster(TEST_GENESIS_HASH, chain_id::TESTNET_V2);

    // Deliver all blocks to nodes 0, 1, 2, 3
    for block in &chain {
        deliver(&mut nodes, &[0, 1, 2, 3], &Wire::Block(block.clone()));
    }

    // 2 of 5 offline: nodes 3 and 4 are down. Only 0, 1, 2 are active.
    let active_targets: Vec<usize> = vec![0, 1, 2];
    let active_voters: Vec<AuthorityIndex> = vec![0, 1, 2];

    // Nodes 0, 1, 2 vote for leader round 3
    let leader_3_hash = chain[3].digest;
    for &voter in &active_voters {
        deliver(
            &mut nodes,
            &active_targets,
            &Wire::Vote {
                leader_round: 3,
                voter,
                leader_hash: leader_3_hash,
            },
        );
    }
    drain_all(&mut nodes);

    // ASSERTION: Liveness halt without fork or split-brain.
    // 3 votes < 4 quorum threshold. No node may commit.
    for &idx in &active_targets {
        assert!(
            nodes[idx].commits.is_empty(),
            "node {idx} committed with only 3 of 5 votes (below quorum 4)"
        );
        assert_eq!(
            nodes[idx].engine.last_decided_round(),
            0,
            "node {idx} decided a round below quorum"
        );
    }

    // Even if nodes 0, 1, 2 time out, 3 timeouts do not reach the 4/5 skip quorum
    let cert_under_quorum = SkipCert {
        round: 3,
        timeouts: active_voters
            .iter()
            .map(|&v| signed_timeout(3, v, chain_id::TESTNET_V2, &TEST_GENESIS_HASH))
            .collect(),
    };
    for &idx in &active_targets {
        let res = nodes[idx].engine.process_skip_cert(&cert_under_quorum);
        assert!(
            res.is_err(),
            "skip cert with 3 of 5 signers must be rejected by node {idx}"
        );
    }

    // CASCADE UNBLOCK:
    // Node 3 is restored / comes back online!
    // Node 3 now casts its vote for round 3.
    deliver(
        &mut nodes,
        &[0, 1, 2, 3],
        &Wire::Vote {
            leader_round: 3,
            voter: 3,
            leader_hash: leader_3_hash,
        },
    );
    // Also deliver earlier votes from 0, 1, 2 to node 3
    for &voter in &active_voters {
        deliver(
            &mut nodes,
            &[3],
            &Wire::Vote {
                leader_round: 3,
                voter,
                leader_hash: leader_3_hash,
            },
        );
    }
    drain_all(&mut nodes);

    // Quorum is restored: 4 votes (0, 1, 2, 3) >= 4 threshold.
    // Cascade unblock: all 4 active nodes commit round 3.
    for (idx, node) in nodes.iter().take(4).enumerate() {
        assert_eq!(
            committed_rounds(node),
            vec![3],
            "node {idx} must commit round 3 after quorum restoration"
        );
        assert_eq!(node.engine.last_decided_round(), 3);
    }

    // Continue progress with the 4 restored nodes for round 6
    let leader_6_hash = chain[6].digest;
    for voter in 0..4u16 {
        deliver(
            &mut nodes,
            &[0, 1, 2, 3],
            &Wire::Vote {
                leader_round: 6,
                voter,
                leader_hash: leader_6_hash,
            },
        );
    }
    drain_all(&mut nodes);

    for (idx, node) in nodes.iter().take(4).enumerate() {
        assert_eq!(
            committed_rounds(node),
            vec![3, 6],
            "node {idx} must continue progress and commit round 6"
        );
        assert_eq!(node.engine.last_decided_round(), 6);
    }

    // Check complete convergence and identical commit sequences
    let baseline = fingerprints(&nodes[0]);
    for (idx, node) in nodes.iter().take(4).enumerate() {
        assert_eq!(
            fingerprints(node),
            baseline,
            "node {idx} diverged after cascade unblock"
        );
    }
}

// ============================================================================
// Scenarij 3: SkipCert domena, preimage i verifikacija
// ============================================================================

#[test]
fn test_scenario3_skip_cert_domain_preimage_and_validation() {
    let members = committee(NODES as u16);
    let genesis = TEST_GENESIS_HASH;
    let target_chain_id = chain_id::TESTNET_V2; // Chain 4

    // 1. Domain tag check
    assert_eq!(
        &TIMEOUT_DOMAIN_TAG[..15],
        b"KUNA/timeout/v1",
        "domain tag must be KUNA/timeout/v1"
    );
    assert_eq!(
        TIMEOUT_DOMAIN_TAG[15], 0,
        "domain tag must be null-padded to 16 bytes"
    );

    // 2. Exact signature data length and byte layout
    let t = Timeout {
        round: 3,
        voter: 1,
        signature: Signature([0; 64]),
    };
    let data = t.signature_data(target_chain_id, &genesis);
    assert_eq!(data.len(), Timeout::SIGNATURE_DATA_LEN);
    assert_eq!(data.len(), 74, "preimage must be exactly 74 bytes");
    assert_eq!(&data[0..16], &TIMEOUT_DOMAIN_TAG);
    assert_eq!(&data[16..24], &target_chain_id.to_le_bytes());
    assert_eq!(&data[24..56], &genesis.0);
    assert_eq!(
        &data[56..64],
        &epoch_for_round(3).to_le_bytes(),
        "epoch of round 3"
    );
    assert_eq!(&data[64..66], &1u16.to_le_bytes(), "voter index");
    assert_eq!(&data[66..74], &3u64.to_le_bytes(), "round number");

    // 3. Valid timeout and skip cert verification (4 of 5 signers)
    let signers: Vec<AuthorityIndex> = vec![0, 1, 2, 3];
    let valid_timeouts: Vec<Timeout> = signers
        .iter()
        .map(|&v| signed_timeout(3, v, target_chain_id, &genesis))
        .collect();

    for timeout in &valid_timeouts {
        assert!(
            verify_timeout(&members, target_chain_id, &genesis, timeout).is_ok(),
            "valid timeout must pass verification"
        );
    }

    let valid_cert = SkipCert {
        round: 3,
        timeouts: valid_timeouts,
    };
    assert!(
        verify_skip_cert(&members, target_chain_id, &genesis, &valid_cert).is_ok(),
        "valid 4/5 skip cert must pass verification"
    );

    // 4. Cross-chain replay rejection (e.g. timeout signed for Chain 2 on Chain 4)
    let cross_chain_timeout = signed_timeout(3, 1, chain_id::TESTNET, &genesis); // chain 2
    let cross_chain_err = verify_timeout(&members, target_chain_id, &genesis, &cross_chain_timeout);
    assert_eq!(
        cross_chain_err,
        Err(TimeoutRejection::BadSignature(1)),
        "timeout signed for different chain_id must be rejected"
    );

    // 5. Genesis hash mismatch rejection (e.g. from an old or different chain instance)
    let foreign_genesis = Hash([0x99; 32]);
    let foreign_genesis_timeout = signed_timeout(3, 1, target_chain_id, &foreign_genesis);
    let foreign_genesis_err = verify_timeout(
        &members,
        target_chain_id,
        &genesis,
        &foreign_genesis_timeout,
    );
    assert_eq!(
        foreign_genesis_err,
        Err(TimeoutRejection::BadSignature(1)),
        "timeout signed for foreign genesis hash must be rejected"
    );

    // 6. Non-leader round rejection
    let non_leader_timeout = signed_timeout(4, 1, target_chain_id, &genesis);
    let non_leader_err = verify_timeout(&members, target_chain_id, &genesis, &non_leader_timeout);
    assert_eq!(
        non_leader_err,
        Err(TimeoutRejection::NotLeaderRound(4)),
        "timeout for non-leader round must be rejected"
    );

    // 7. Unknown voter rejection
    let mut unknown_voter_timeout = signed_timeout(3, 0, target_chain_id, &genesis);
    unknown_voter_timeout.voter = 99; // Not in committee
    let unknown_voter_err =
        verify_timeout(&members, target_chain_id, &genesis, &unknown_voter_timeout);
    assert_eq!(
        unknown_voter_err,
        Err(TimeoutRejection::UnknownVoter(99)),
        "timeout from non-committee authority must be rejected"
    );

    // 8. SkipCert with insufficient quorum (only 3 of 5 signers)
    let under_quorum_cert = SkipCert {
        round: 3,
        timeouts: vec![
            signed_timeout(3, 0, target_chain_id, &genesis),
            signed_timeout(3, 1, target_chain_id, &genesis),
            signed_timeout(3, 2, target_chain_id, &genesis),
        ],
    };
    let under_quorum_err =
        verify_skip_cert(&members, target_chain_id, &genesis, &under_quorum_cert);
    assert_eq!(
        under_quorum_err,
        Err(TimeoutRejection::NoQuorum {
            round: 3,
            stake: 3,
            quorum: 4
        }),
        "certificate with 3/5 stake must be rejected for quorum failure"
    );

    // 9. SkipCert with duplicate signer
    let duplicate_signer_cert = SkipCert {
        round: 3,
        timeouts: vec![
            signed_timeout(3, 0, target_chain_id, &genesis),
            signed_timeout(3, 1, target_chain_id, &genesis),
            signed_timeout(3, 2, target_chain_id, &genesis),
            signed_timeout(3, 2, target_chain_id, &genesis), // duplicate!
        ],
    };
    let duplicate_err =
        verify_skip_cert(&members, target_chain_id, &genesis, &duplicate_signer_cert);
    assert_eq!(
        duplicate_err,
        Err(TimeoutRejection::DuplicateSigner(2)),
        "certificate with duplicate signer must be rejected"
    );

    // 10. SkipCert with mixed rounds
    let mixed_rounds_cert = SkipCert {
        round: 6,
        timeouts: vec![
            signed_timeout(6, 0, target_chain_id, &genesis),
            signed_timeout(6, 1, target_chain_id, &genesis),
            signed_timeout(6, 2, target_chain_id, &genesis),
            signed_timeout(3, 3, target_chain_id, &genesis), // round 3 inside round 6 cert!
        ],
    };
    let mixed_rounds_err =
        verify_skip_cert(&members, target_chain_id, &genesis, &mixed_rounds_cert);
    assert_eq!(
        mixed_rounds_err,
        Err(TimeoutRejection::MixedRounds {
            cert: 6,
            timeout: 3
        }),
        "certificate with mixed rounds must be rejected"
    );
}

#[test]
fn test_scenario3_engine_enforces_domain_and_rejects_replays() {
    let node = Node::new(0, TEST_GENESIS_HASH, chain_id::TESTNET_V2);

    // 1. Cross-chain timeout sent to engine is rejected
    let cross_chain_timeout = signed_timeout(3, 1, chain_id::MAINNET, &TEST_GENESIS_HASH); // Chain 1 on Chain 4 node
    let err = node.engine.process_timeout(&cross_chain_timeout);
    assert!(
        matches!(err, Err(ConsensusError::TimeoutRejected(_))),
        "consensus engine must reject timeout with wrong chain_id"
    );

    // 2. Genesis mismatch timeout sent to engine is rejected
    let wrong_genesis = Hash([0xee; 32]);
    let wrong_genesis_timeout = signed_timeout(3, 1, chain_id::TESTNET_V2, &wrong_genesis);
    let err2 = node.engine.process_timeout(&wrong_genesis_timeout);
    assert!(
        matches!(err2, Err(ConsensusError::TimeoutRejected(_))),
        "consensus engine must reject timeout with mismatched genesis hash"
    );

    // 3. Under-quorum skip cert sent to engine is rejected
    let under_quorum_cert = SkipCert {
        round: 3,
        timeouts: vec![
            signed_timeout(3, 1, chain_id::TESTNET_V2, &TEST_GENESIS_HASH),
            signed_timeout(3, 2, chain_id::TESTNET_V2, &TEST_GENESIS_HASH),
            signed_timeout(3, 3, chain_id::TESTNET_V2, &TEST_GENESIS_HASH),
        ],
    };
    let err3 = node.engine.process_skip_cert(&under_quorum_cert);
    assert!(
        matches!(err3, Err(ConsensusError::TimeoutRejected(_))),
        "consensus engine must reject under-quorum skip cert"
    );

    // 4. Valid 4/5 skip cert sent to engine is accepted
    let valid_cert = SkipCert {
        round: 3,
        timeouts: vec![
            signed_timeout(3, 0, chain_id::TESTNET_V2, &TEST_GENESIS_HASH),
            signed_timeout(3, 1, chain_id::TESTNET_V2, &TEST_GENESIS_HASH),
            signed_timeout(3, 2, chain_id::TESTNET_V2, &TEST_GENESIS_HASH),
            signed_timeout(3, 3, chain_id::TESTNET_V2, &TEST_GENESIS_HASH),
        ],
    };
    let ok = node.engine.process_skip_cert(&valid_cert);
    assert!(
        ok.is_ok(),
        "consensus engine must accept valid 4/5 skip cert: {ok:?}"
    );
}
