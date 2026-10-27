//! Multi-node (4-validator) in-process consensus integration test.
//!
//! Drives four independent consensus engines entirely in-process: no sockets,
//! no async runtime, no wall-clock timing. Blocks and votes are exchanged as
//! explicit [`Wire`] events through an in-memory delivery harness so every
//! schedule is fully deterministic and runs in well under a second.
//!
//! The consensus `common` helpers live in the sibling crate's test tree and are
//! included by path (a single source of truth for `MockDag`,
//! `MockBlockManager`, and the block/committee builders), exactly as the
//! single-node integration test does.
//!
//! # Partition model
//!
//! Full DAG networking is out of scope for an in-process test, so partitions
//! are modelled at the *message delivery* layer instead of by faking TCP:
//!
//! * All four nodes first receive the complete canonical block DAG. This is the
//!   "blocks propagated before the partition" phase. Every node therefore holds
//!   an identical block set, so committed sub-DAG ancestry is always complete
//!   and the test never has to reason about missing-parent recovery.
//! * A partition then restricts *vote* delivery to within each side. A side
//!   whose total vote stake reaches the committee quorum threshold
//!   (`floor(2T/3) + 1`) commits; a side below it stalls.
//! * Healing re-delivers the withheld votes so the stalled side reaches quorum
//!   and commits the identical leader sequence.
//!
//! For a 4-authority committee with equal stake, `quorum_threshold = 3`. This
//! makes the partition arithmetic exact: 3 votes commit, 2 votes (or 1) do not.

#[path = "../../kovanica-consensus/tests/common/mod.rs"]
mod common;

use common::{block_ref, committee, genesis, make_block, make_engine, MockBlockManager, MockDag};
use kovanica_consensus::{ConsensusConfig, ConsensusEngine, ConsensusError, VoteRejection};
use kovanica_types::block::StatementBlock;
use kovanica_types::hash::Hash;
use kovanica_types::{AuthorityIndex, CommittedSubDag, Round};
use tokio::sync::mpsc;

/// Number of authorities in the test cluster.
const NODES: usize = 4;

/// Fast, deterministic config. The async round loop is never started: the test
/// drives `process_block` / `process_vote` directly, so timing is irrelevant.
fn engine_config() -> ConsensusConfig {
    ConsensusConfig {
        round_duration_ms: 1,
        lookahead_rounds: 3,
        max_pending_rounds: 100,
        use_mysticghost: false,
        prune_window_waves: 100,
        leader_timeout_ms: 3000,
        leader_timeout_factor: 2,
        late_vote_window_rounds: kovanica_types::WAVE_LENGTH,
        use_vrf_leader: false,
        use_min_digest_fork: false,
        genesis_hash: kovanica_types::Hash::zero(),
        // Certified skips are exercised by their own tests; with 1-5 ms
        // rounds a 6-round T_skip would turn scheduling jitter into skips.
        skip_timeout_rounds: 1_000_000,
    }
}

/// A single unit of gossip between validators.
#[derive(Clone)]
enum Wire {
    /// A proposed statement block.
    Block(StatementBlock),
    /// A vote for the leader of `leader_round`.
    Vote {
        leader_round: Round,
        voter: AuthorityIndex,
        leader_hash: Hash,
    },
}

/// One in-process validator: its consensus engine plus the commits it has
/// published to the execution consumer.
struct Node {
    engine: ConsensusEngine<MockDag, MockBlockManager>,
    rx: mpsc::UnboundedReceiver<CommittedSubDag>,
    commits: Vec<CommittedSubDag>,
}

impl Node {
    fn new(authority: AuthorityIndex) -> Self {
        let (engine, _dag, _manager) =
            make_engine(authority, committee(NODES as u16), engine_config());
        let (tx, rx) = mpsc::unbounded_channel();
        engine.set_commit_sender(tx);
        Self {
            engine,
            rx,
            commits: Vec::new(),
        }
    }

    /// Move every queued committed sub-DAG into `commits` (in delivery order).
    fn drain(&mut self) {
        while let Ok(subdag) = self.rx.try_recv() {
            self.commits.push(subdag);
        }
    }
}

fn cluster() -> Vec<Node> {
    (0..NODES as u16).map(Node::new).collect()
}

/// Deliver one event to each target node.
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
            } => match nodes[target].engine.process_vote(&common::signed_vote(
                *leader_round,
                *voter,
                *leader_hash,
            )) {
                // Healing re-delivers votes a node already holds; the consensus
                // boundary rejects those as duplicates and counts them once.
                Ok(()) | Err(ConsensusError::VoteRejected(VoteRejection::Duplicate { .. })) => {}
                Err(e) => panic!("vote rejected: {e:?}"),
            },
        }
    }
}

/// Deliver one event to all nodes.
fn deliver_all(nodes: &mut [Node], wire: &Wire) {
    let targets: Vec<usize> = (0..nodes.len()).collect();
    deliver(nodes, &targets, wire);
}

fn drain_all(nodes: &mut [Node]) {
    for node in nodes.iter_mut() {
        node.drain();
    }
}

/// Build a canonical chain of blocks from round 0 through `max_round`.
///
/// Each round is authored by the committee's scheduled leader, so the engine
/// registers the leader slot of every leader round (`round % WAVE_LENGTH == 0`,
/// `WAVE_LENGTH == 3`) exactly as it does in production. The author comes from
/// `CommitteeInfo::leader` — the same function the engine consults — so the
/// chain builder can never drift from the leader rule again. Each block
/// references the previous one, producing fully connected causal history.
fn canonical_chain(max_round: Round) -> Vec<StatementBlock> {
    let members = committee(NODES as u16);
    let mut chain = vec![genesis()]; // round 0, author 0
    for round in 1..=max_round {
        let author = members.leader(round);
        let parent = block_ref(chain.last().expect("previous block exists"));
        let block = make_block(author, round, vec![parent], &format!("r{round}"));
        chain.push(block);
    }
    chain
}

/// A comparison key for a committed sub-DAG that captures everything the test
/// asserts on: the leader identity and the exact ordered block sequence.
fn fingerprint(subdag: &CommittedSubDag) -> (Round, AuthorityIndex, Hash, Vec<Hash>) {
    (
        subdag.leader_round,
        subdag.leader_author,
        subdag.leader.digest,
        subdag.blocks.iter().map(|b| b.digest).collect(),
    )
}

fn committed_rounds(node: &Node) -> Vec<Round> {
    node.commits.iter().map(|s| s.leader_round).collect()
}

fn fingerprints(node: &Node) -> Vec<(Round, AuthorityIndex, Hash, Vec<Hash>)> {
    node.commits.iter().map(fingerprint).collect()
}

/// Cast one quorum set of votes for every given leader round.
fn cast_votes(
    nodes: &mut [Node],
    targets: &[usize],
    voters: &[AuthorityIndex],
    chain: &[StatementBlock],
    leader_rounds: &[Round],
) {
    for &leader_round in leader_rounds {
        let leader_hash = chain[leader_round as usize].digest;
        for &voter in voters {
            deliver(
                nodes,
                targets,
                &Wire::Vote {
                    leader_round,
                    voter,
                    leader_hash,
                },
            );
        }
    }
}

/// The leader rounds committed by the canonical chain up to round 9. In a
/// 4-authority committee the scheduled leader of wave `w` is `w % 4`, so rounds
/// 3, 6, 9 (waves 1, 2, 3) are authored by 1, 2, 3.
const LEADER_ROUNDS: [Round; 3] = [3, 6, 9];

/// Requirement 1: four fully-connected nodes converge on the same
/// committed-leader sequence and the same `CommittedSubDag` ordering.
#[test]
fn four_nodes_converge_on_identical_commit_sequence() {
    let chain = canonical_chain(9);
    let mut nodes = cluster();

    // Phase 1: every block propagates to every node.
    for block in &chain {
        deliver_all(&mut nodes, &Wire::Block(block.clone()));
    }
    // Phase 2: every validator votes for every leader slot.
    let all_voters: Vec<AuthorityIndex> = (0..NODES as u16).collect();
    let all_targets: Vec<usize> = (0..NODES).collect();
    cast_votes(
        &mut nodes,
        &all_targets,
        &all_voters,
        &chain,
        &LEADER_ROUNDS,
    );
    drain_all(&mut nodes);

    // Each node commits exactly the leader rounds, in order.
    for (i, node) in nodes.iter().enumerate() {
        assert_eq!(
            committed_rounds(node),
            LEADER_ROUNDS.to_vec(),
            "node {i} committed an unexpected leader sequence"
        );
    }

    // And every node's committed sub-DAG ordering is byte-identical.
    let baseline = fingerprints(&nodes[0]);
    assert_eq!(baseline.len(), LEADER_ROUNDS.len());
    for (i, node) in nodes.iter().enumerate() {
        assert_eq!(
            fingerprints(node),
            baseline,
            "node {i} diverged from node 0 on committed sub-DAG ordering"
        );
    }

    // Sanity: the leader authored each sub-DAG and appears last (topological).
    for (subdag, &expected_round) in nodes[0].commits.iter().zip(LEADER_ROUNDS.iter()) {
        assert_eq!(subdag.leader_round, expected_round);
        assert_eq!(
            subdag.leader_author,
            ((expected_round / kovanica_types::WAVE_LENGTH) as usize % NODES) as AuthorityIndex
        );
        assert_eq!(
            subdag.blocks.last().map(|b| b.digest),
            Some(subdag.leader.digest)
        );
    }
}

/// Requirement 2a: a 3+1 partition. The three-node majority reaches quorum and
/// keeps committing; the isolated minority stalls. After the partition heals
/// the minority catches up to the identical state.
#[test]
fn three_one_partition_majority_commits_and_minority_catches_up() {
    let chain = canonical_chain(9);
    let mut nodes = cluster();

    // Blocks propagate to everyone before the partition begins.
    for block in &chain {
        deliver_all(&mut nodes, &Wire::Block(block.clone()));
    }

    let majority = [0usize, 1, 2];
    let minority = [3usize];
    let majority_voters: [AuthorityIndex; 3] = [0, 1, 2];

    // Partition: votes are only visible within each side.
    cast_votes(
        &mut nodes,
        &majority,
        &majority_voters,
        &chain,
        &LEADER_ROUNDS,
    );
    cast_votes(&mut nodes, &minority, &[3], &chain, &LEADER_ROUNDS);
    drain_all(&mut nodes);

    // Majority (stake 3 >= quorum 3) commits every leader.
    for &i in &majority {
        assert_eq!(
            committed_rounds(&nodes[i]),
            LEADER_ROUNDS.to_vec(),
            "majority node {i} should keep committing"
        );
    }
    // Minority (stake 1 < quorum 3) makes no progress.
    assert!(
        nodes[3].commits.is_empty(),
        "isolated minority must not commit while partitioned"
    );

    // Heal: the majority's withheld votes now reach the minority node.
    cast_votes(
        &mut nodes,
        &minority,
        &majority_voters,
        &chain,
        &LEADER_ROUNDS,
    );
    drain_all(&mut nodes);

    // All four nodes now agree exactly (leader sequence and ordering).
    let baseline = fingerprints(&nodes[0]);
    assert_eq!(baseline.len(), LEADER_ROUNDS.len());
    for (i, node) in nodes.iter().enumerate() {
        assert_eq!(
            fingerprints(node),
            baseline,
            "node {i} failed to converge after healing"
        );
    }
}

/// Requirement 2b: a symmetric 2+2 partition. Neither side holds quorum, so
/// neither side can commit — the safety side of a partition. Healing restores
/// progress and a single agreed state.
#[test]
fn two_two_partition_neither_side_reaches_quorum() {
    let chain = canonical_chain(6);
    let mut nodes = cluster();

    for block in &chain {
        deliver_all(&mut nodes, &Wire::Block(block.clone()));
    }

    let side_a = [0usize, 1];
    let side_b = [2usize, 3];

    // Two votes on each side: below the quorum threshold of 3.
    cast_votes(&mut nodes, &side_a, &[0, 1], &chain, &[3, 6]);
    cast_votes(&mut nodes, &side_b, &[2, 3], &chain, &[3, 6]);
    drain_all(&mut nodes);

    for (i, node) in nodes.iter().enumerate() {
        assert!(
            node.commits.is_empty(),
            "node {i} must not commit with only a 2-of-4 vote set"
        );
    }

    // Heal: everyone sees every vote, quorum is reached, all four converge.
    let all_targets: Vec<usize> = (0..NODES).collect();
    let all_voters: Vec<AuthorityIndex> = (0..NODES as u16).collect();
    cast_votes(&mut nodes, &all_targets, &all_voters, &chain, &[3, 6]);
    drain_all(&mut nodes);

    let baseline = fingerprints(&nodes[0]);
    assert_eq!(baseline.len(), 2);
    for (i, node) in nodes.iter().enumerate() {
        assert_eq!(
            fingerprints(node),
            baseline,
            "node {i} failed to converge after healing"
        );
    }
}

// ---------------------------------------------------------------------
// PRO-40 (b): quorum-certified skips
// ---------------------------------------------------------------------

fn signed_timeout(round: Round, voter: AuthorityIndex) -> kovanica_types::Timeout {
    let mut timeout = kovanica_types::Timeout {
        round,
        voter,
        signature: kovanica_types::Signature([0; 64]),
    };
    timeout.signature = kovanica_crypto::sign(
        &common::validator_signing_key(voter),
        &timeout.signature_data(
            kovanica_types::signing::chain_id::LOCAL,
            &engine_config().genesis_hash,
        ),
    );
    timeout
}

/// I2 (in-process): nobody votes for leader slot 3 (its block is too late
/// everywhere), three of four validators time out. Nodes 0, 2, 3 assemble the
/// certificate from individual timeouts, node 1 only receives the finished
/// certificate. All four skip slot 3, commit 6 and 9, and the slot-3 block is
/// ordered into the slot-6 sub-DAG identically on every node.
#[test]
fn certified_skip_is_identical_on_every_node_and_the_chain_continues() {
    let chain = canonical_chain(9);
    let mut nodes = cluster();
    for block in &chain {
        deliver_all(&mut nodes, &Wire::Block(block.clone()));
    }

    let signers: [AuthorityIndex; 3] = [0, 2, 3];
    for node in [0usize, 2, 3] {
        for voter in signers {
            nodes[node]
                .engine
                .process_timeout(&signed_timeout(3, voter))
                .expect("timeout accepted");
        }
    }
    let cert = kovanica_types::SkipCert {
        round: 3,
        timeouts: signers.iter().map(|v| signed_timeout(3, *v)).collect(),
    };
    nodes[1]
        .engine
        .process_skip_cert(&cert)
        .expect("cert accepted");

    let all_voters: Vec<AuthorityIndex> = (0..NODES as u16).collect();
    let all_targets: Vec<usize> = (0..NODES).collect();
    cast_votes(&mut nodes, &all_targets, &all_voters, &chain, &[6, 9]);
    drain_all(&mut nodes);

    let baseline = fingerprints(&nodes[0]);
    assert_eq!(committed_rounds(&nodes[0]), vec![6, 9]);
    for (i, node) in nodes.iter().enumerate() {
        assert_eq!(fingerprints(node), baseline, "node {i} diverged");
    }
    let slot3 = chain[3].digest;
    assert!(
        nodes[0].commits[0].blocks.iter().any(|b| b.digest == slot3),
        "the skipped leader block is ordered into the next sub-DAG"
    );
}

/// I3 / C3 (in-process): an even split, two votes and two timeouts for slot
/// 3. Neither a vote quorum nor a skip certificate exists, so no node commits
/// or skips anything: a safe stall, never a fork.
#[test]
fn a_vote_timeout_split_stalls_safely_on_every_node() {
    let chain = canonical_chain(9);
    let mut nodes = cluster();
    for block in &chain {
        deliver_all(&mut nodes, &Wire::Block(block.clone()));
    }
    let all_targets: Vec<usize> = (0..NODES).collect();
    cast_votes(&mut nodes, &all_targets, &[0, 1], &chain, &[3]);
    for node in nodes.iter() {
        for voter in [2u16, 3] {
            node.engine
                .process_timeout(&signed_timeout(3, voter))
                .expect("timeout accepted");
        }
    }
    cast_votes(&mut nodes, &all_targets, &[0, 1, 2, 3], &chain, &[6, 9]);
    drain_all(&mut nodes);
    for (i, node) in nodes.iter().enumerate() {
        assert!(node.commits.is_empty(), "node {i} moved past a split slot");
        assert_eq!(node.engine.last_decided_round(), 0);
    }
}
