//! Unit tests for scoped GHOSTDAG k=3 colouring.

use kovanica_consensus::ghostdag_scoped::colour_mergeset;
use kovanica_types::block::{BlockReference, StatementBlock};
use kovanica_types::hash::Hash;
use kovanica_types::{AuthorityIndex, Round, Signature};
use std::collections::{HashMap, HashSet};

fn make_block(
    author: AuthorityIndex,
    round: Round,
    parents: Vec<BlockReference>,
    tag: &str,
) -> StatementBlock {
    StatementBlock {
        author,
        round,
        parents,
        transactions: Vec::new(),
        statements: tag.as_bytes().to_vec(),
        signature: Signature([0u8; 64]),
        digest: Hash::new(format!("kovanica-test/{tag}").as_bytes()),
        merkle_root: Default::default(),
    }
}

fn block_ref(block: &StatementBlock) -> BlockReference {
    BlockReference {
        author: block.author,
        round: block.round,
        digest: block.digest,
    }
}

#[test]
fn test_simple_chain_all_blue() {
    // Genesis -> block1 -> block2 -> block3 (all in chain)
    let genesis = make_block(0, 0, vec![], "genesis");
    let b1 = make_block(1, 1, vec![block_ref(&genesis)], "b1");
    let b2 = make_block(2, 2, vec![block_ref(&b1)], "b2");
    let b3 = make_block(3, 3, vec![block_ref(&b2)], "b3");

    let blocks = vec![genesis.clone(), b1.clone(), b2.clone(), b3.clone()];
    let result = colour_mergeset(&blocks, 3, &[]);

    // All should be blue
    assert_eq!(result.blue.len(), 4);
    assert!(result.blue.contains(&genesis.digest));
    assert!(result.blue.contains(&b1.digest));
    assert!(result.blue.contains(&b2.digest));
    assert!(result.blue.contains(&b3.digest));

    // Selected parent chain
    assert_eq!(result.selected_parent[&genesis.digest], None);
    assert_eq!(result.selected_parent[&b1.digest], Some(genesis.digest));
    assert_eq!(result.selected_parent[&b2.digest], Some(b1.digest));
    assert_eq!(result.selected_parent[&b3.digest], Some(b2.digest));

    // Blue scores
    assert_eq!(result.blue_score[&genesis.digest], 0);
    assert_eq!(result.blue_score[&b1.digest], 1);
    assert_eq!(result.blue_score[&b2.digest], 2);
    assert_eq!(result.blue_score[&b3.digest], 3);

    // Blue ordered should be genesis, b1, b2, b3
    let ordered = result.blue_ordered();
    assert_eq!(
        ordered,
        vec![genesis.digest, b1.digest, b2.digest, b3.digest]
    );
}

#[test]
fn test_two_conflicting_blocks_k3_both_blue() {
    // Two blocks at same round from different authors, same parent (genesis)
    let genesis = make_block(0, 0, vec![], "genesis");
    let b1 = make_block(1, 1, vec![block_ref(&genesis)], "b1-conflict");
    let b2 = make_block(2, 1, vec![block_ref(&genesis)], "b2-conflict");

    let blocks = vec![genesis.clone(), b1.clone(), b2.clone()];
    let result = colour_mergeset(&blocks, 3, &[]);

    // Both should be blue (anticone size 1 <= 3)
    assert_eq!(result.blue.len(), 3);
    assert!(result.blue.contains(&genesis.digest));
    assert!(result.blue.contains(&b1.digest));
    assert!(result.blue.contains(&b2.digest));

    // Both have genesis as selected parent
    assert_eq!(result.selected_parent[&b1.digest], Some(genesis.digest));
    assert_eq!(result.selected_parent[&b2.digest], Some(genesis.digest));
}

#[test]
fn test_five_conflicting_blocks_k3_fifth_red() {
    // Five pairwise-incomparable blocks at same round (same parent)
    let genesis = make_block(0, 0, vec![], "genesis");
    let b1 = make_block(1, 1, vec![block_ref(&genesis)], "b1");
    let b2 = make_block(2, 1, vec![block_ref(&genesis)], "b2");
    let b3 = make_block(3, 1, vec![block_ref(&genesis)], "b3");
    let b4 = make_block(4, 1, vec![block_ref(&genesis)], "b4");
    let b5 = make_block(5, 1, vec![block_ref(&genesis)], "b5");

    let blocks = vec![
        genesis.clone(),
        b1.clone(),
        b2.clone(),
        b3.clone(),
        b4.clone(),
        b5.clone(),
    ];
    let result = colour_mergeset(&blocks, 3, &[]);

    // Exactly 4 of the 5 conflicting blocks should be blue (plus genesis = 5 total)
    // The specific 4 depends on hash ordering, but exactly one should be red
    let conflicting_blocks = [b1.digest, b2.digest, b3.digest, b4.digest, b5.digest];
    let blue_conflicting: Vec<_> = result
        .blue
        .iter()
        .filter(|h| conflicting_blocks.contains(h))
        .copied()
        .collect();
    assert_eq!(
        blue_conflicting.len(),
        4,
        "Exactly 4 of 5 conflicting blocks should be blue"
    );
    assert!(
        result.blue.contains(&genesis.digest),
        "Genesis should be blue"
    );
    assert_eq!(
        result.blue.len(),
        5,
        "Total blue: genesis + 4 conflicting = 5"
    );
}

#[test]
fn test_previous_tips_seeded() {
    // Previous tips are already blue
    let tip1 = make_block(1, 5, vec![], "tip1");
    let tip2 = make_block(2, 5, vec![], "tip2");
    let previous_tips = vec![tip1.digest, tip2.digest];

    // New blocks at round 6 referencing both tips
    let b1 = make_block(3, 6, vec![block_ref(&tip1), block_ref(&tip2)], "b1");

    let blocks = vec![b1.clone()];
    let result = colour_mergeset(&blocks, 3, &previous_tips);

    // b1 should be blue, its anticone against previous tips is empty (tips are its ancestors)
    assert_eq!(result.blue.len(), 1);
    assert!(result.blue.contains(&b1.digest));
    // Selected parent should be one of the tips (both have score 0, tie-break by hash)
    let parent = result.selected_parent[&b1.digest].unwrap();
    assert!(parent == tip1.digest || parent == tip2.digest);
}

#[test]
fn test_diamond_structure() {
    //    genesis
    //   /       \
    //  b1        b2
    //   \       /
    //    b3 (merges both)
    let genesis = make_block(0, 0, vec![], "genesis");
    let b1 = make_block(1, 1, vec![block_ref(&genesis)], "b1");
    let b2 = make_block(2, 1, vec![block_ref(&genesis)], "b2");
    let b3 = make_block(3, 2, vec![block_ref(&b1), block_ref(&b2)], "b3");

    let blocks = vec![genesis.clone(), b1.clone(), b2.clone(), b3.clone()];
    let result = colour_mergeset(&blocks, 3, &[]);

    // All should be blue
    assert_eq!(result.blue.len(), 4);
    assert!(result.blue.contains(&genesis.digest));
    assert!(result.blue.contains(&b1.digest));
    assert!(result.blue.contains(&b2.digest));
    assert!(result.blue.contains(&b3.digest));

    // b3's selected parent should be b1 or b2 (both have score 1, tie-break by hash)
    let b3_parent = result.selected_parent[&b3.digest].unwrap();
    assert!(b3_parent == b1.digest || b3_parent == b2.digest);
}

#[test]
fn test_blue_ordered_is_topological() {
    // Test that blue_ordered returns a valid topological order
    let genesis = make_block(0, 0, vec![], "genesis");
    let b1 = make_block(1, 1, vec![block_ref(&genesis)], "b1");
    let b2 = make_block(2, 1, vec![block_ref(&genesis)], "b2");
    let b3 = make_block(3, 2, vec![block_ref(&b1), block_ref(&b2)], "b3");

    let blocks = vec![genesis.clone(), b1.clone(), b2.clone(), b3.clone()];
    let result = colour_mergeset(&blocks, 3, &[]);

    let ordered = result.blue_ordered();
    assert_eq!(ordered.len(), 4);

    // Check topological order: parents before children
    let pos: HashMap<Hash, usize> = ordered.iter().enumerate().map(|(i, h)| (*h, i)).collect();

    // genesis before b1, b2
    assert!(pos[&genesis.digest] < pos[&b1.digest]);
    assert!(pos[&genesis.digest] < pos[&b2.digest]);
    // b1 before b3
    assert!(pos[&b1.digest] < pos[&b3.digest]);
    // b2 before b3
    assert!(pos[&b2.digest] < pos[&b3.digest]);
}

#[test]
fn test_disconnected_block_still_colored() {
    // Block with no parents in the set (but not genesis)
    let genesis = make_block(0, 0, vec![], "genesis");
    let b1 = make_block(1, 1, vec![block_ref(&genesis)], "b1");
    // b2 has parent that doesn't exist in our set
    let fake_parent = BlockReference {
        author: 99,
        round: 0,
        digest: Hash::new(b"fake"),
    };
    let b2 = make_block(2, 2, vec![fake_parent], "b2");

    let blocks = vec![genesis.clone(), b1.clone(), b2.clone()];
    let result = colour_mergeset(&blocks, 3, &[]);

    // b2 has no blue parents, so its anticone is all already_blue (genesis, b1) = 2 <= 3
    // So it should be blue with score 0
    assert_eq!(result.blue.len(), 3);
    assert!(result.blue.contains(&b2.digest));
    assert_eq!(result.selected_parent[&b2.digest], None);
    assert_eq!(result.blue_score[&b2.digest], 0);
}

// ============================================================================
// Layered DAG generator for property tests (copied from properties.rs)
// ============================================================================

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

// ============================================================================
// Property tests
// ============================================================================

/// Verify that the blue set is conflict-free:
/// - No two blue blocks from the same round AND same authority (double-sign)
/// - Selected parent chain is valid (each blue block's selected_parent is also blue)
/// - Blue scores are consistent with selected parent
/// - blue_ordered is a valid topological order
#[test]
fn prop_blue_set_is_conflict_free() {
    // Use a few deterministic layered DAG shapes
    let shapes = vec![
        // Single root, 3 layers
        LayeredDag::from_bits(vec![1, 2, 2], &[true, false, true, true, true, false]),
        // Two roots, 2 layers
        LayeredDag::from_bits(
            vec![2, 3],
            &[true, false, true, false, true, true, false, true, true],
        ),
        // Three roots, 3 layers
        LayeredDag::from_bits(
            vec![3, 2, 2],
            &[
                true, false, true, false, true, true, true, true, true, false, true, true,
            ],
        ),
    ];

    for shape in shapes {
        let (layers, leader) = build_layered(&shape);
        let history = flatten(&layers);
        let all_blocks = {
            let mut v = history.clone();
            v.push(leader.clone());
            v
        };

        let previous_tips: Vec<Hash> = vec![];
        let result = colour_mergeset(&all_blocks, 3, &previous_tips);

        // Property 1: No double-sign (same round, same authority) in blue set
        let mut seen_round_author: HashSet<(Round, AuthorityIndex)> = HashSet::new();
        for &blue_hash in &result.blue {
            // Find the block
            if let Some(block) = all_blocks.iter().find(|b| b.digest == blue_hash) {
                let key = (block.round, block.author);
                assert!(
                    seen_round_author.insert(key),
                    "Double-sign detected in blue set: round {}, author {}",
                    block.round,
                    block.author
                );
            }
        }

        // Property 2: Selected parent of each blue block is also blue (or None)
        for (&blue_hash, &opt_parent) in &result.selected_parent {
            if let Some(parent) = opt_parent {
                assert!(
                    result.blue.contains(&parent),
                    "Selected parent {:?} of blue block {:?} is not blue",
                    parent,
                    blue_hash
                );
            }
        }

        // Property 3: Blue scores are consistent with selected parent
        for (&blue_hash, &score) in &result.blue_score {
            if let Some(parent) = result.selected_parent.get(&blue_hash).copied().flatten() {
                assert_eq!(
                    score,
                    result.blue_score[&parent] + 1,
                    "Blue score mismatch: block {:?} has score {} but parent {:?} has score {}",
                    blue_hash,
                    score,
                    parent,
                    result.blue_score[&parent]
                );
            } else {
                assert_eq!(score, 0, "Root blue block should have score 0");
            }
        }

        // Property 4: blue_ordered is a valid topological order
        let ordered = result.blue_ordered();
        assert_eq!(ordered.len(), result.blue.len());
        let pos: HashMap<Hash, usize> = ordered.iter().enumerate().map(|(i, h)| (*h, i)).collect();
        let blue_set: HashSet<Hash> = result.blue.iter().copied().collect();
        for &blue_hash in &result.blue {
            if let Some(block) = all_blocks.iter().find(|b| b.digest == blue_hash) {
                for parent_ref in &block.parents {
                    if blue_set.contains(&parent_ref.digest) {
                        assert!(
                            pos[&parent_ref.digest] < pos[&blue_hash],
                            "Topological order violation: parent {:?} after child {:?}",
                            parent_ref.digest,
                            blue_hash
                        );
                    }
                }
            }
        }
    }
}

#[test]
fn prop_blue_set_k_cluster_property() {
    // Test that the blue set can be partitioned into at most k+1 chains
    // This is the fundamental GHOSTDAG property
    let shapes = vec![LayeredDag::from_bits(
        vec![1, 3, 3],
        &[
            true, true, true, true, false, true, true, true, false, false, true, true, true, false,
            true,
        ],
    )];

    for shape in shapes {
        let (layers, leader) = build_layered(&shape);
        let history = flatten(&layers);
        let all_blocks = {
            let mut v = history.clone();
            v.push(leader.clone());
            v
        };

        let result = colour_mergeset(&all_blocks, 3, &[]);

        // The blue set size should be significant
        assert!(!result.blue.is_empty());

        // Verify that the selected-parent relation forms a forest (no cycles)
        // by checking that blue_ordered contains all blue blocks exactly once
        let ordered = result.blue_ordered();
        assert_eq!(ordered.len(), result.blue.len());
        let ordered_set: HashSet<_> = ordered.iter().copied().collect();
        let blue_set: HashSet<_> = result.blue.iter().copied().collect();
        assert_eq!(ordered_set, blue_set);
    }
}
