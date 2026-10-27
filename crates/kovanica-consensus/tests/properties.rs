//! Property / invariant tests for kovanica-consensus.
//!
//! All generators are proptest strategies: every case is reproducible from
//! the printed seed on failure (deterministic RNG with shrinking).
//!
//! Invariants under test (see each property for the exact statement):
//!
//! 1. **Safety** — a leader round's decided status never changes once
//!    observed, and a round is never both committed and skipped.
//! 2. **Determinism** — identical inputs produce identical
//!    [`CommittedSubDag`] sequences (divergent nodes would fork the chain).
//! 3. **Monotonicity** — committed rounds strictly increase, each round is
//!    committed at most once, and `last_decided_round` tracks the highest
//!    decided round.
//! 4. **Threshold soundness** — a commit implies >= quorum (2f+1) stake
//!    voting *for the committed leader block*, which must exist in the store.
//! 5. **Linearizer idempotence / totality** — replay yields no duplicates and
//!    the same block set; output is a topological order with the leader last.
//! 6. **Faulty-vote robustness** — vote targets (foreign hashes), double
//!    votes, and arrival order never change the decision for a registered
//!    leader block.
//!
//! Two further properties (equivocation soundness and conflicting committed
//! views) are known-failing BUG properties (BUG-1: `try_direct_decide`
//! counts voters without checking the vote hash) and live at the bottom,
//! disabled with `#[ignore]`.

mod common;

use common::{
    block_ref, committee_with_stakes, drive_try_commit, genesis, leader_info, make_block, MockDag,
};
use kovanica_consensus::{
    CommittedSubDag, CommitteeInfo, LeaderInfo, LeaderStatus, Linearizer, UniversalCommitter,
};
use kovanica_types::block::{BlockReference, StatementBlock};
use kovanica_types::hash::Hash;
use kovanica_types::{AuthorityIndex, Round, Stake};
use proptest::prelude::*;
use std::collections::{HashMap, HashSet};

// ===========================================================================
// Strategies: committer scenarios
// ===========================================================================

fn arb_stakes() -> impl Strategy<Value = Vec<Stake>> {
    (1usize..=8).prop_flat_map(|n| proptest::collection::vec(1u64..=4, n))
}

/// One round's configuration in a generated committer scenario.
#[derive(Debug, Clone)]
struct Row {
    /// Whether a leader is registered for this round at all.
    register: bool,
    /// Per-voter participation (votes are cast for the leader block).
    votes: Vec<bool>,
    /// Whether the leader block is actually present in the store.
    has_block: bool,
    /// Leader registered without a block hash (quorum can never build a
    /// sub-DAG — must stall the walk, deterministically).
    block_hash_missing: bool,
}

#[derive(Debug, Clone)]
struct Scenario {
    stakes: Vec<Stake>,
    rows: Vec<Row>,
}

fn arb_scenario() -> impl Strategy<Value = Scenario> {
    arb_stakes().prop_flat_map(|stakes| {
        let n = stakes.len();
        let rows = proptest::collection::vec(
            (
                any::<bool>(),
                proptest::collection::vec(any::<bool>(), n),
                any::<bool>(),
                any::<bool>(),
            ),
            1..=10,
        );
        rows.prop_map(move |raw| Scenario {
            stakes: stakes.clone(),
            rows: raw
                .into_iter()
                .map(|(register, votes, has_block, block_hash_missing)| Row {
                    register,
                    votes,
                    has_block,
                    block_hash_missing,
                })
                .collect(),
        })
    })
}

/// How votes are cast when replaying the same scenario.
#[derive(Clone, Copy, PartialEq)]
enum VoteMode {
    /// Every voter votes for the leader block (baseline).
    Baseline,
    /// Every voter votes for some other hash (equivocation-style content).
    ForeignHashes,
    /// The baseline votes, but delivered in reverse voter order.
    ReversedOrder,
}

fn foreign_hash(round: Round, voter: AuthorityIndex) -> Hash {
    let mut bytes = b"kovanica-test/foreign".to_vec();
    bytes.extend_from_slice(&round.to_le_bytes());
    bytes.extend_from_slice(&voter.to_le_bytes());
    Hash::new(&bytes)
}

/// Build a fresh committer + DAG for a scenario. Rows become rounds 1..=k in
/// a single chain hanging off genesis; only stored blocks are referenced as
/// parents (a missing block therefore poisons ancestry — a realistic stall).
fn build_scenario(s: &Scenario, mode: VoteMode) -> (UniversalCommitter, MockDag, CommitteeInfo) {
    let committee = committee_with_stakes(&s.stakes);
    let n = committee.size() as AuthorityIndex;
    let g = genesis();
    let dag = MockDag::with_blocks([g.clone()]);
    let mut last_stored_parent = block_ref(&g);
    let committer = UniversalCommitter::new(committee.clone(), false, 100);

    for (i, row) in s.rows.iter().enumerate() {
        let round = i as u64 + 1;
        if !row.register {
            continue;
        }
        let block = make_block(
            (round % n as u64) as AuthorityIndex,
            round,
            vec![last_stored_parent],
            &format!("sc/{round}"),
        );
        let block_hash = if row.block_hash_missing {
            None
        } else {
            Some(block.digest)
        };
        committer.update_leader(leader_info(
            round,
            block.author,
            block_hash,
            LeaderStatus::Undecided,
            &[],
        ));
        if row.has_block {
            dag.put(block.clone());
            last_stored_parent = block_ref(&block);
        }

        let active: Vec<AuthorityIndex> = row
            .votes
            .iter()
            .enumerate()
            .filter(|(_, &v)| v)
            .map(|(idx, _)| idx as AuthorityIndex)
            .collect();
        let ordered: Vec<AuthorityIndex> = match mode {
            VoteMode::ReversedOrder => active.iter().copied().rev().collect(),
            _ => active,
        };
        for voter in ordered {
            match mode {
                VoteMode::Baseline | VoteMode::ReversedOrder => {
                    committer.add_vote(round, voter, block.digest);
                }
                VoteMode::ForeignHashes => {
                    committer.add_vote(round, voter, foreign_hash(round, voter));
                }
            }
        }
    }

    (committer, dag, committee)
}

/// Result of driving one scenario to quiescence.
struct Run {
    commits: Vec<CommittedSubDag>,
    /// Status of every decided round, observed after every `try_commit` call
    /// (in order) — used to detect status flips.
    status_observations: Vec<(Round, LeaderStatus)>,
    last_decided: Round,
    decided: HashMap<Round, LeaderInfo>,
}

fn run_scenario(s: &Scenario, mode: VoteMode) -> Run {
    let (committer, dag, _committee) = build_scenario(s, mode);
    let mut commits = Vec::new();
    let mut status_observations = Vec::new();

    for _ in 0..100 {
        let step = committer
            .try_commit_and_mark_durable(&dag)
            .expect("persist committed decision");
        for (round, info) in committer.get_all_decided_leaders() {
            status_observations.push((round, info.status));
        }
        match step {
            Some(subdag) => commits.push(subdag),
            None => break,
        }
    }

    Run {
        last_decided: committer.last_decided_round(),
        decided: committer.get_all_decided_leaders(),
        commits,
        status_observations,
    }
}

/// Canonical signature of a commit sequence: (leader round, ordered digests).
fn commit_signature(commits: &[CommittedSubDag]) -> Vec<(Round, Vec<Hash>)> {
    commits
        .iter()
        .map(|s| {
            (
                s.leader_round,
                s.blocks.iter().map(|b| b.digest).collect::<Vec<_>>(),
            )
        })
        .collect()
}

// ===========================================================================
// Invariant 1: safety — decided status never flips; no round both committed
// and skipped.
// ===========================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    #[test]
    fn prop_safety_no_conflicting_or_flipping_leader_status(s in arb_scenario()) {
        let run = run_scenario(&s, VoteMode::Baseline);

        // A round's decided status must be identical across every observation.
        let mut first_seen: HashMap<Round, LeaderStatus> = HashMap::new();
        for (round, status) in &run.status_observations {
            match first_seen.get(round) {
                None => {
                    first_seen.insert(*round, *status);
                }
                Some(prev) => prop_assert_eq!(
                    prev,
                    status,
                    "round {round} changed decided status {prev:?} -> {status:?}",
                    round = round,
                    prev = prev,
                    status = status
                ),
            }
        }

        // Committed rounds are tracked exactly once and appear as Commit.
        let committed: HashSet<Round> = run.commits.iter().map(|c| c.leader_round).collect();
        prop_assert_eq!(
            committed.len(),
            run.commits.len(),
            "the same round was committed more than once: {:?}",
            run.commits.iter().map(|c| c.leader_round).collect::<Vec<_>>()
        );
        for round in &committed {
            let info = run.decided.get(round);
            prop_assert!(info.is_some(), "committed round {round} not tracked as decided");
            prop_assert_eq!(
                info.map(|l| l.status),
                Some(LeaderStatus::Commit),
                "committed round {round} not marked Commit",
                round = round
            );
        }
    }
}

// ===========================================================================
// Invariant 3: monotonicity — committed rounds strictly increase, no repeat,
// watermark = highest decided round.
// ===========================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    #[test]
    fn prop_committed_rounds_strictly_increase(s in arb_scenario()) {
        let run = run_scenario(&s, VoteMode::Baseline);

        for pair in run.commits.windows(2) {
            prop_assert!(
                pair[0].leader_round < pair[1].leader_round,
                "committed rounds must strictly increase: {:?}",
                run.commits.iter().map(|c| c.leader_round).collect::<Vec<_>>()
            );
        }

        // The watermark equals the maximum decided round (skips included).
        let max_decided = run.decided.keys().copied().max().unwrap_or(0);
        prop_assert_eq!(
            run.last_decided, max_decided,
            "last_decided_round must equal the highest decided round"
        );

        // The watermark is never below the last committed round.
        if let Some(last_commit) = run.commits.last() {
            prop_assert!(
                run.last_decided >= last_commit.leader_round,
                "last_decided {} fell below committed round {}",
                run.last_decided,
                last_commit.leader_round
            );
        }
    }
}

// ===========================================================================
// Invariant 4: threshold soundness — commits imply quorum stake voting for
// the committed leader block, which exists in the store.
// ===========================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    #[test]
    fn prop_commit_requires_quorum_stake(s in arb_scenario()) {
        let (committer, dag, committee) = build_scenario(&s, VoteMode::Baseline);
        let mut commits = Vec::new();
        for _ in 0..100 {
            match committer
                .try_commit_and_mark_durable(&dag)
                .expect("persist committed decision")
            {
                Some(subdag) => {
                    commits.push(subdag);
                }
                None => break,
            }
        }

        for subdag in &commits {
            let round = subdag.leader_round;
            let info = committer
                .get_leader(round)
                .expect("a committed round must have leader info");

            // Stake of the votes cast *for this exact leader block*.
            let stake_for_leader: Stake = info
                .votes
                .iter()
                .filter(|(_, h)| **h == subdag.leader.digest)
                .map(|(voter, _)| committee.stake_of(*voter).unwrap_or(0))
                .sum();
            prop_assert!(
                stake_for_leader >= committee.quorum_threshold(),
                "round {round} committed with only {stake_for_leader} stake voting for the \
                 leader block (quorum {})",
                committee.quorum_threshold()
            );

            prop_assert!(
                dag.contains(&subdag.leader.digest),
                "committed leader block must exist in the store"
            );
            prop_assert_eq!(subdag.leader_author, info.author);
            // The leader is the unique sink of an ancestor-closed history:
            // it must be the last block of the committed sequence.
            prop_assert_eq!(
                subdag.blocks.last().map(|b| b.digest),
                Some(subdag.leader.digest),
                "leader must be last in round {round}",
                round = round
            );
            // No duplicates in the committed sequence.
            let mut seen = HashSet::new();
            for b in &subdag.blocks {
                prop_assert!(
                    seen.insert(b.digest),
                    "duplicate block in commit of round {round}"
                );
            }
        }
    }
}

// ===========================================================================
// Invariant 2: determinism — identical scenarios yield identical commit
// sequences across independent committers.
// ===========================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    #[test]
    fn prop_committer_determinism_identical_inputs(s in arb_scenario()) {
        let run1 = run_scenario(&s, VoteMode::Baseline);
        let run2 = run_scenario(&s, VoteMode::Baseline);

        prop_assert_eq!(
            commit_signature(&run1.commits),
            commit_signature(&run2.commits),
            "identical inputs produced different committed sub-DAG sequences"
        );
        prop_assert_eq!(run1.last_decided, run2.last_decided);

        let mut decided1: Vec<(Round, LeaderStatus)> =
            run1.decided.iter().map(|(r, l)| (*r, l.status)).collect();
        let mut decided2: Vec<(Round, LeaderStatus)> =
            run2.decided.iter().map(|(r, l)| (*r, l.status)).collect();
        decided1.sort_by_key(|(r, _)| *r);
        decided2.sort_by_key(|(r, _)| *r);
        prop_assert_eq!(decided1, decided2, "decided-leader state diverged");
    }
}

// ===========================================================================
// Invariant 6: decisions depend only on the set of votes *for the leader
// block*. Reordering the same vote content changes nothing; votes for other
// hashes never contribute quorum, so they can never ADD a commit.
// ===========================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    #[test]
    fn prop_decision_independent_of_vote_hashes_and_order(s in arb_scenario()) {
        let baseline = run_scenario(&s, VoteMode::Baseline);
        let reordered = run_scenario(&s, VoteMode::ReversedOrder);
        let foreign = run_scenario(&s, VoteMode::ForeignHashes);

        // (1) Same vote content, reversed arrival order → identical decisions.
        prop_assert_eq!(
            commit_signature(&baseline.commits),
            commit_signature(&reordered.commits),
            "reordering the same votes changed the decision"
        );
        prop_assert_eq!(baseline.last_decided, reordered.last_decided);
        let mut decided1: Vec<(Round, LeaderStatus)> =
            baseline.decided.iter().map(|(r, l)| (*r, l.status)).collect();
        let mut decided2: Vec<(Round, LeaderStatus)> =
            reordered.decided.iter().map(|(r, l)| (*r, l.status)).collect();
        decided1.sort_by_key(|(r, _)| *r);
        decided2.sort_by_key(|(r, _)| *r);
        prop_assert_eq!(decided1, decided2, "reordered decided-leader state diverged");

        // (2) Votes for other hashes are worthless: with every vote foreign,
        // nothing can ever be directly committed (and therefore nothing
        // indirectly either), so the foreign run commits nothing.
        prop_assert!(
            foreign.commits.is_empty(),
            "votes for foreign blocks committed a leader ({:?})",
            commit_signature(&foreign.commits)
        );
    }
}

// ===========================================================================
// Linearizer properties: total order, single-root determinism, leader-last,
// idempotent replay.
// ===========================================================================

/// A generated layered DAG. Layer 0's width controls the number of roots;
/// every later block takes a non-empty subset of the previous layer as
/// parents (empty masks get a deterministic fallback parent).
#[derive(Debug, Clone)]
struct LayeredDag {
    /// Block widths per layer; `masks[r - 1][i]` is block `i` of layer `r`'s
    /// parent mask over layer `r - 1`.
    widths: Vec<usize>,
    masks: Vec<Vec<Vec<bool>>>,
}

fn arb_layered_dag(max_root_width: usize) -> impl Strategy<Value = LayeredDag> {
    (
        1usize..=max_root_width,
        proptest::collection::vec(1usize..=3, 0..=4),
    )
        .prop_flat_map(|(root_width, rest)| {
            let widths = {
                let mut w = vec![root_width];
                w.extend(rest);
                w
            };
            let total_bits: usize = (1..widths.len()).map(|r| widths[r] * widths[r - 1]).sum();
            proptest::collection::vec(any::<bool>(), total_bits..=total_bits)
                .prop_map(move |bits| LayeredDag::from_bits(widths.clone(), &bits))
        })
}

impl LayeredDag {
    /// Consume `widths[r] * widths[r - 1]` bits per layer as parent masks,
    /// forcing at least one parent per non-root block.
    fn from_bits(widths: Vec<usize>, bits: &[bool]) -> Self {
        let mut masks: Vec<Vec<Vec<bool>>> = Vec::new();
        let mut off = 0;
        for r in 1..widths.len() {
            let prev = widths[r - 1];
            let mut layer = Vec::with_capacity(widths[r]);
            for i in 0..widths[r] {
                let mut mask = bits[off..off + prev].to_vec();
                off += prev;
                if !mask.iter().any(|&on| on) {
                    let pick = (r * 31 + i * 7 + 13) % prev;
                    mask[pick] = true;
                }
                layer.push(mask);
            }
            masks.push(layer);
        }
        Self { widths, masks }
    }
}

/// Materialize a layered shape as blocks; the leader hangs off the final
/// layer with every last-layer block as a parent.
fn build_layered(shape: &LayeredDag) -> (Vec<Vec<StatementBlock>>, StatementBlock) {
    let mut layers: Vec<Vec<StatementBlock>> = Vec::new();
    for r in 0..shape.widths.len() {
        let mut layer = Vec::with_capacity(shape.widths[r]);
        for i in 0..shape.widths[r] {
            let parents: Vec<BlockReference> = if r == 0 {
                Vec::new()
            } else {
                shape.masks[r - 1][i]
                    .iter()
                    .enumerate()
                    .filter(|(_, &on)| on)
                    .map(|(pi, _)| block_ref(&layers[r - 1][pi]))
                    .collect()
            };
            layer.push(make_block(
                i as AuthorityIndex,
                r as Round,
                parents,
                &format!("p/{r}/{i}"),
            ));
        }
        layers.push(layer);
    }
    let last = layers.last().expect("at least one layer");
    let leader = make_block(
        0,
        shape.widths.len() as Round,
        last.iter().map(block_ref).collect(),
        "p/leader",
    );
    (layers, leader)
}

fn flatten(layers: &[Vec<StatementBlock>]) -> Vec<StatementBlock> {
    layers.iter().flatten().cloned().collect()
}

/// Transitive ancestors of `leader` (excludes the leader itself).
fn ancestor_set(all: &[StatementBlock], leader: &StatementBlock) -> Vec<StatementBlock> {
    let by_digest: HashMap<Hash, &StatementBlock> = all.iter().map(|b| (b.digest, b)).collect();
    let mut stack: Vec<Hash> = leader.parents.iter().map(|p| p.digest).collect();
    let mut seen: HashSet<Hash> = HashSet::new();
    let mut out = Vec::new();
    while let Some(h) = stack.pop() {
        if !seen.insert(h) {
            continue;
        }
        if let Some(b) = by_digest.get(&h) {
            out.push((*b).clone());
            for p in &b.parents {
                stack.push(p.digest);
            }
        }
    }
    out
}

/// Violations of "topological order with unique blocks" (parents that are
/// absent from the sequence are ignored, matching production semantics).
fn topo_violations(blocks: &[StatementBlock]) -> Vec<String> {
    let mut violations = Vec::new();
    let mut pos: HashMap<Hash, usize> = HashMap::new();
    for (i, b) in blocks.iter().enumerate() {
        if let Some(prev) = pos.insert(b.digest, i) {
            violations.push(format!("duplicate {:?} at {prev} and {i}", b.digest));
        }
        for p in &b.parents {
            if let Some(&pp) = pos.get(&p.digest) {
                if pp >= i {
                    violations.push(format!(
                        "parent {:?} ({pp}) not before child {:?} ({i})",
                        p.digest, b.digest
                    ));
                }
            }
        }
    }
    violations
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    /// Arbitrary (possibly multi-root) histories still come back as a unique
    /// topological order with the leader as the unique sink, last.
    #[test]
    fn prop_linearizer_topological_unique_leader_last(shape in arb_layered_dag(2)) {
        let (layers, leader) = build_layered(&shape);
        let history = flatten(&layers);
        let subdag = Linearizer::new().linearize(leader.clone(), history.clone());

        let violations = topo_violations(&subdag.blocks);
        prop_assert!(violations.is_empty(), "{violations:?}");
        prop_assert_eq!(
            subdag.blocks.len(),
            history.len() + 1,
            "output must contain every history block plus the leader exactly once"
        );
        prop_assert_eq!(
            subdag.blocks.last().map(|b| b.digest),
            Some(leader.digest),
            "leader must be the last block (every block in the history is its ancestor)"
        );
    }

    /// Single-root histories are deterministic: two runs agree block-for-block.
    #[test]
    fn prop_linearizer_determinism_single_root(shape in arb_layered_dag(1)) {
        let (layers, leader) = build_layered(&shape);
        let history = flatten(&layers);
        let first = Linearizer::new().linearize(leader.clone(), history.clone());
        let second = Linearizer::new().linearize(leader.clone(), history.clone());

        prop_assert_eq!(
            first.blocks.iter().map(|b| b.digest).collect::<Vec<_>>(),
            second.blocks.iter().map(|b| b.digest).collect::<Vec<_>>(),
            "identical single-root input produced different orderings"
        );
    }

    /// Linearizing exactly the leader's ancestor set: covers precisely that
    /// set plus the leader, topologically ordered, leader last.
    #[test]
    fn prop_linearizer_ancestor_closed_history(shape in arb_layered_dag(2)) {
        let (layers, leader) = build_layered(&shape);
        let all = flatten(&layers);
        let history = ancestor_set(&all, &leader);
        let subdag = Linearizer::new().linearize(leader.clone(), history.clone());

        let mut expected: HashSet<Hash> = history.iter().map(|b| b.digest).collect();
        expected.insert(leader.digest);
        let got: HashSet<Hash> = subdag.blocks.iter().map(|b| b.digest).collect();
        prop_assert_eq!(got, expected, "output must be exactly ancestors + leader");

        let violations = topo_violations(&subdag.blocks);
        prop_assert!(violations.is_empty(), "{violations:?}");
        prop_assert_eq!(
            subdag.blocks.last().map(|b| b.digest),
            Some(leader.digest),
            "leader must be last in an ancestor-closed history"
        );
    }

    /// Idempotent replay: feeding a committed sequence back in yields the
    /// same block set with no duplicates, leader still last.
    #[test]
    fn prop_linearizer_idempotent_replay(shape in arb_layered_dag(1)) {
        let (layers, leader) = build_layered(&shape);
        let history = flatten(&layers);
        let first = Linearizer::new().linearize(leader.clone(), history.clone());
        let second = Linearizer::new().linearize(leader.clone(), first.blocks.clone());

        let set_a: HashSet<Hash> = first.blocks.iter().map(|b| b.digest).collect();
        let set_b: HashSet<Hash> = second.blocks.iter().map(|b| b.digest).collect();
        prop_assert_eq!(set_a, set_b, "replay changed the block set");
        prop_assert_eq!(
            first.blocks.len(),
            second.blocks.len(),
            "replay introduced or dropped blocks"
        );

        let violations = topo_violations(&second.blocks);
        prop_assert!(violations.is_empty(), "{violations:?}");
        prop_assert_eq!(
            second.blocks.last().map(|b| b.digest),
            Some(leader.digest),
            "leader must remain last on replay"
        );
    }
}

// ===========================================================================
// BUG properties — known-failing (BUG-1: `try_direct_decide` /
// `has_quorum` count voters without checking the vote hash, so a quorum of
// votes *for some other block* commits the registered leader).
// Disabled with #[ignore]; run with `cargo test -p kovanica-consensus -- --ignored`
// to reproduce. Each one fails today.
// ===========================================================================

/// Split voters into "voted for the leader block" and "voted for something
/// else".
fn arb_vote_split() -> impl Strategy<Value = (Vec<Stake>, Vec<bool>)> {
    arb_stakes().prop_flat_map(|stakes| {
        let n = stakes.len();
        let split = proptest::collection::vec(any::<bool>(), n..=n);
        (Just(stakes.clone()), split)
    })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    /// Quorum must be counted over votes *for the leader block*, not over any
    /// votes at all.
    // Regression: previously `try_direct_decide` -> `has_quorum` counted
    // voters regardless of hash, so mixed vote content could commit a leader
    // block nobody voted for. Now `has_quorum`/`has_validity` only count
    // votes whose hash equals the leader block's hash.
    #[test]
    fn prop_equivocation_quorum_must_count_votes_for_leader_block(
        (stakes, split) in arb_vote_split(),
    ) {
        let committee = committee_with_stakes(&stakes);
        let g = genesis();
        let dag = MockDag::with_blocks([g.clone()]);
        let block = make_block(0, 1, vec![block_ref(&g)], "eq/leader");
        dag.put(block.clone());

        let committer = UniversalCommitter::new(committee.clone(), false, 100);
        committer.update_leader(leader_info(
            1,
            block.author,
            Some(block.digest),
            LeaderStatus::Undecided,
            &[],
        ));
        for (i, &vote_for_leader) in split.iter().enumerate() {
            let voter = i as AuthorityIndex;
            let hash = if vote_for_leader {
                block.digest
            } else {
                foreign_hash(1, voter)
            };
            committer.add_vote(1, voter, hash);
        }

        let commits = drive_try_commit(&committer, &dag);
        if let Some(subdag) = commits.first() {
            let info = committer.get_leader(1).expect("leader registered");
            let stake_for_leader: Stake = info
                .votes
                .iter()
                .filter(|(_, h)| **h == subdag.leader.digest)
                .map(|(voter, _)| committee.stake_of(*voter).unwrap_or(0))
                .sum();
            prop_assert!(
                stake_for_leader >= committee.quorum_threshold(),
                "committed the leader block with only {stake_for_leader} stake voting for it \
                 (quorum {}); votes: {:?}",
                committee.quorum_threshold(),
                info.votes
            );
        }
    }

    /// Two views of the same leader slot — identical incoming votes, but the
    /// registered leader block differs (leader equivocation). At most one
    /// view may commit: the same vote messages must never justify two
    /// different committed leader blocks for round 1.
    // Regression: previously, because votes were counted without hash
    // checking, both views could reach quorum and commit different leader
    // blocks for the same slot. Vote hashes now match the registered leader
    // block, so a view can only commit a block the voters actually voted for.
    #[test]
    fn prop_no_conflicting_committed_views_under_leader_equivocation(
        (stakes, split) in arb_vote_split(),
    ) {
        let g = genesis();

        // View A: leader block X; voters in `split` vote for X.
        let committee = committee_with_stakes(&stakes);
        let dag_a = MockDag::with_blocks([g.clone()]);
        let block_x = make_block(0, 1, vec![block_ref(&g)], "eq/view-x");
        dag_a.put(block_x.clone());
        let view_a = UniversalCommitter::new(committee.clone(), false, 100);
        view_a.update_leader(leader_info(
            1,
            block_x.author,
            Some(block_x.digest),
            LeaderStatus::Undecided,
            &[],
        ));

        // View B: same round and author, but the registered leader block is
        // Y (equivocated). It receives *exactly the same vote messages* as
        // view A — votes for X (and the same foreign hashes).
        let dag_b = MockDag::with_blocks([g.clone()]);
        let block_y = make_block(0, 1, vec![block_ref(&g)], "eq/view-y");
        dag_b.put(block_y.clone());
        let view_b = UniversalCommitter::new(committee.clone(), false, 100);
        view_b.update_leader(leader_info(
            1,
            block_y.author,
            Some(block_y.digest),
            LeaderStatus::Undecided,
            &[],
        ));

        for (i, &vote_for_leader) in split.iter().enumerate() {
            let voter = i as AuthorityIndex;
            let hash = if vote_for_leader {
                block_x.digest
            } else {
                foreign_hash(1, voter)
            };
            view_a.add_vote(1, voter, hash);
            view_b.add_vote(1, voter, hash);
        }

        let commits_a = drive_try_commit(&view_a, &dag_a);
        let commits_b = drive_try_commit(&view_b, &dag_b);
        if let (Some(a), Some(b)) = (commits_a.first(), commits_b.first()) {
            prop_assert_eq!(
                a.leader.digest,
                b.leader.digest,
                "conflicting committed views for leader round 1: {:?} vs {:?}",
                a.leader.digest,
                b.leader.digest
            );
        }
    }
}
