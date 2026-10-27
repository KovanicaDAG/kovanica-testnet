//! Unit tests for the `Linearizer`: topological ordering, deduplication,
//! leader placement, and determinism.

mod common;

use common::{block_ref, genesis, make_block};
use kovanica_consensus::Linearizer;
use kovanica_types::block::StatementBlock;
use kovanica_types::hash::Hash;

/// Assert that `blocks` is a valid topological order over the block set:
/// every in-set parent appears before its child, and no digest repeats.
fn assert_topological(blocks: &[StatementBlock]) {
    let mut positions: std::collections::HashMap<Hash, usize> = std::collections::HashMap::new();
    for (i, b) in blocks.iter().enumerate() {
        assert!(
            !positions.contains_key(&b.digest),
            "duplicate block {:?} at position {i}",
            b.digest
        );
        for p in &b.parents {
            if let Some(&ppos) = positions.get(&p.digest) {
                assert!(
                    ppos < i,
                    "parent {} appears after its child {}",
                    p.digest,
                    b.digest
                );
            }
        }
        positions.insert(b.digest, i);
    }
}

fn digests(blocks: &[StatementBlock]) -> Vec<Hash> {
    blocks.iter().map(|b| b.digest).collect()
}

#[test]
fn test_linearize_leader_only() {
    let linearizer = Linearizer::new();
    let leader = make_block(1, 3, vec![block_ref(&genesis())], "leader");
    let subdag = linearizer.linearize(leader.clone(), Vec::new());

    assert_eq!(subdag.leader.digest, leader.digest);
    assert_eq!(subdag.leader_round, 3);
    assert_eq!(subdag.leader_author, 1);
    assert_eq!(digests(&subdag.blocks), vec![leader.digest]);
    assert_topological(&subdag.blocks);
}

/// History excluded + leader must produce exactly the two blocks, parents first.
#[test]
fn test_linearize_chain_of_three() {
    let linearizer = Linearizer::new();
    let g = genesis();
    let mid = make_block(1, 1, vec![block_ref(&g)], "mid");
    let leader = make_block(2, 3, vec![block_ref(&mid)], "leader");

    let subdag = linearizer.linearize(leader.clone(), vec![g.clone(), mid.clone()]);
    assert_eq!(
        digests(&subdag.blocks),
        vec![g.digest, mid.digest, leader.digest]
    );
    assert_topological(&subdag.blocks);
    assert_eq!(subdag.blocks.last().unwrap().digest, leader.digest);
}

/// Multiple children of one parent: all ordering constraints hold and the
/// leader (the unique sink) comes last.
#[test]
fn test_linearize_branching_dag() {
    let linearizer = Linearizer::new();
    let g = genesis();
    let a = make_block(1, 1, vec![block_ref(&g)], "a");
    let b = make_block(2, 1, vec![block_ref(&g)], "b");
    let c = make_block(3, 2, vec![block_ref(&a), block_ref(&b)], "c");
    let leader = make_block(0, 3, vec![block_ref(&c)], "leader");

    let subdag = linearizer.linearize(
        leader.clone(),
        vec![g.clone(), a.clone(), b.clone(), c.clone()],
    );
    assert_topological(&subdag.blocks);
    assert_eq!(subdag.blocks.len(), 5);
    assert_eq!(
        subdag.blocks.last().unwrap().digest,
        leader.digest,
        "leader is the unique sink and must be last"
    );
    // Both branches must precede the merge block.
    let pos = |h: Hash| {
        subdag
            .blocks
            .iter()
            .position(|b| b.digest == h)
            .expect("block present")
    };
    assert!(pos(a.digest) < pos(c.digest));
    assert!(pos(b.digest) < pos(c.digest));
    assert!(pos(c.digest) < pos(leader.digest));
}

/// A block reachable through two paths appears exactly once.
#[test]
fn test_linearize_dedups_diamond_history() {
    let linearizer = Linearizer::new();
    let g = genesis();
    let left = make_block(1, 1, vec![block_ref(&g)], "left");
    let right = make_block(2, 1, vec![block_ref(&g)], "right");
    let join = make_block(3, 2, vec![block_ref(&left), block_ref(&right)], "join");
    let leader = make_block(0, 3, vec![block_ref(&join)], "leader");

    // `get_ancestors` on a diamond pushes `g` twice (once per branch); the
    // linearizer must collapse that.
    let history = vec![
        g.clone(),
        g.clone(),
        left.clone(),
        right.clone(),
        join.clone(),
        g.clone(),
        left.clone(),
    ];
    let subdag = linearizer.linearize(leader.clone(), history);

    let mut seen = std::collections::HashSet::new();
    for b in &subdag.blocks {
        assert!(seen.insert(b.digest), "duplicate block {:?}", b.digest);
    }
    assert_eq!(subdag.blocks.len(), 5, "g/left/right/join/leader");
    assert_topological(&subdag.blocks);
    assert_eq!(subdag.blocks.last().unwrap().digest, leader.digest);
}

/// Feeding the output of one linearization back in (already-committed blocks)
/// must not introduce duplicates, and must cover the same block set.
#[test]
fn test_linearize_idempotent_on_replayed_output() {
    let linearizer = Linearizer::new();
    let g = genesis();
    let a = make_block(1, 1, vec![block_ref(&g)], "a");
    let leader = make_block(2, 2, vec![block_ref(&a)], "leader");

    let first = linearizer.linearize(leader.clone(), vec![g.clone(), a.clone()]);
    // Second round: history is the previous output, which already contains
    // the leader itself.
    let second = linearizer.linearize(leader, first.blocks.clone());

    let mut seen = std::collections::HashSet::new();
    for b in &second.blocks {
        assert!(seen.insert(b.digest), "duplicate block {:?}", b.digest);
    }
    assert_eq!(seen.len(), first.blocks.len(), "same block set");
    assert_topological(&second.blocks);
}

/// Identical inputs must produce identical output *within a run* — and the
/// single-root shape used by the committer (ancestor-closed history from one
/// genesis) must be deterministic across repeated calls.
#[test]
fn test_linearize_deterministic_single_root_repeated_calls() {
    let linearizer = Linearizer::new();
    let build = || {
        let g = genesis();
        let a = make_block(1, 1, vec![block_ref(&g)], "a");
        let b = make_block(2, 1, vec![block_ref(&g)], "b");
        let c = make_block(3, 2, vec![block_ref(&a)], "c");
        let leader = make_block(0, 3, vec![block_ref(&c), block_ref(&b)], "leader");
        (g, a, b, c, leader)
    };

    let (g, a, b, c, leader) = build();
    let reference = digests(
        &linearizer
            .linearize(leader.clone(), vec![g, a, b, c])
            .blocks,
    );
    for attempt in 0..32 {
        let (g, a, b, c, leader) = build();
        let out = digests(&linearizer.linearize(leader, vec![g, a, b, c]).blocks);
        assert_eq!(out, reference, "attempt {attempt} diverged");
    }
}

/// Ancestors outside the set (parents not in `history`) simply do not create
/// edges — every block that IS in the set still respects its in-set parents.
#[test]
fn test_linearize_parents_outside_history_ignored() {
    let linearizer = Linearizer::new();
    let g = genesis();
    let a = make_block(1, 1, vec![block_ref(&g)], "a");
    // Leader references a block that is not in the history.
    let outsider = make_block(2, 2, vec![block_ref(&a)], "outsider");
    let leader = make_block(3, 3, vec![block_ref(&outsider)], "leader");

    let subdag = linearizer.linearize(leader.clone(), vec![g, a]);
    assert_topological(&subdag.blocks);
    // The outsider is absent: not part of this sub-DAG.
    assert!(!digests(&subdag.blocks).contains(&outsider.digest));
    assert!(digests(&subdag.blocks).contains(&leader.digest));
}

/// Empty history and an empty-committee-shaped input must not panic.
#[test]
fn test_linearize_leader_with_no_parents_no_history() {
    let linearizer = Linearizer::new();
    let leader = make_block(0, 0, Vec::new(), "lone");
    let subdag = linearizer.linearize(leader.clone(), Vec::new());
    assert_eq!(digests(&subdag.blocks), vec![leader.digest]);
}

/// The leader's parent edges are applied even when the parent is the only
/// history entry (committer always passes the full ancestor list).
#[test]
fn test_linearize_leader_parent_edges_applied() {
    let linearizer = Linearizer::new();
    let g = genesis();
    let leader = make_block(1, 3, vec![block_ref(&g)], "leader");
    let subdag = linearizer.linearize(leader.clone(), vec![g.clone()]);
    assert_eq!(digests(&subdag.blocks), vec![g.digest, leader.digest]);
    // And with the leader duplicated in history too (defensive: no dupes).
    let subdag = linearizer.linearize(leader.clone(), vec![g.clone(), leader.clone()]);
    assert_eq!(
        subdag.blocks.len(),
        2,
        "no duplicates when leader is in history"
    );
    assert_eq!(subdag.blocks.last().unwrap().digest, leader.digest);
    assert_topological(&subdag.blocks);
}

/// Duplicate parents in the parent list must not corrupt the ordering.
#[test]
fn test_linearize_duplicate_parent_refs() {
    let linearizer = Linearizer::new();
    let g = genesis();
    let leader = make_block(
        1,
        3,
        vec![block_ref(&g), block_ref(&g)],
        "leader-dup-parents",
    );
    let subdag = linearizer.linearize(leader.clone(), vec![g.clone()]);
    assert_eq!(digests(&subdag.blocks), vec![g.digest, leader.digest]);
    assert_topological(&subdag.blocks);
}

// ---------------------------------------------------------------------------
// BUG (disabled): multi-root histories linearize non-deterministically
// ---------------------------------------------------------------------------

/// Regression: multi-root histories must linearize deterministically.
///
/// `Linearizer::linearize` seeds Kahn's queue from a sorted list of
/// zero-degree blocks and expands children in sorted (digest) order, so the
/// output depends only on the graph structure — never on HashMap iteration
/// order or the input `history` slice order (the historical BUG: seeds were
/// taken from `in_degree` HashMap iteration, so identical inputs could order
/// differently; on a real chain divergent linearization = divergent execution
/// = fork).
#[test]
fn test_linearizer_multi_root_input_is_deterministic() {
    let linearizer = Linearizer::new();
    let root_a = make_block(0, 0, Vec::new(), "root-a");
    let root_b = make_block(1, 0, Vec::new(), "root-b");
    let leader = make_block(2, 1, vec![block_ref(&root_a), block_ref(&root_b)], "leader");

    let reference = digests(
        &linearizer
            .linearize(leader.clone(), vec![root_a.clone(), root_b.clone()])
            .blocks,
    );
    for attempt in 0..64 {
        let out = digests(
            &linearizer
                .linearize(leader.clone(), vec![root_a.clone(), root_b.clone()])
                .blocks,
        );
        assert_eq!(
            out,
            reference,
            "attempt {attempt}: multi-root input produced a different ordering \
             ({:?} vs {reference:?})",
            out.iter().map(|h| h.to_hex()).collect::<Vec<_>>()
        );
    }
}
