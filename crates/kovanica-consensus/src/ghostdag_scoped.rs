//! Scoped GHOSTDAG k=3 colouring.
//!
//! Runs classic GHOSTDAG only on the mergeset of a newly committed leader.
//! This keeps CPU and memory cost proportional to wave size, not full history.

use kovanica_types::block::StatementBlock;
use kovanica_types::hash::Hash;
use std::collections::HashMap;

/// Output of a scoped colouring run.
#[derive(Debug, Clone)]
pub struct ColouringResult {
    /// Blocks that were coloured blue (conflict-free set).
    pub blue: Vec<Hash>,
    /// Selected-parent relation for the blue blocks.
    pub selected_parent: HashMap<Hash, Option<Hash>>,
    /// Blue score of each blue block (useful for metrics / debugging).
    pub blue_score: HashMap<Hash, u64>,
}

impl ColouringResult {
    /// Returns the blue blocks in a deterministic topological order
    /// induced by the selected-parent relation.
    ///
    /// Delegates to [`kovanica_types::colouring::ColouringResult::blue_ordered`]
    /// so the committer and a light client share one order.
    pub fn blue_ordered(&self) -> Vec<Hash> {
        kovanica_types::colouring::ColouringResult {
            blue: self.blue.clone(),
            selected_parent: self.selected_parent.clone(),
            blue_score: self.blue_score.clone(),
        }
        .blue_ordered()
    }
}

/// Colour the given mergeset with GHOSTDAG parameter `k`.
///
/// `blocks` – the mergeset (and optionally previous tips already included)
/// `k`      – must be 3 for the current safety claims
/// `previous_tips` – tips of prior committed sub-dags (treated as already blue)
///
/// The algorithm is [`kovanica_types::colouring::colour_mergeset`]. This wrapper
/// only adapts [`StatementBlock`] headers onto that function. `k != 3`
/// panics, as the previous in-crate implementation did.
pub fn colour_mergeset(
    blocks: &[StatementBlock],
    k: usize,
    previous_tips: &[Hash],
) -> ColouringResult {
    let views: Vec<kovanica_types::colouring::ColourBlock> = blocks
        .iter()
        .map(|block| kovanica_types::colouring::ColourBlock {
            digest: block.digest,
            round: block.round,
            parents: block.parents.iter().map(|parent| parent.digest).collect(),
        })
        .collect();
    let result = kovanica_types::colouring::colour_mergeset(&views, k, previous_tips)
        .expect("MysticGhost currently requires k = 3");
    ColouringResult {
        blue: result.blue,
        selected_parent: result.selected_parent,
        blue_score: result.blue_score,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kovanica_types::block::{BlockReference, StatementBlock};
    use kovanica_types::hash::Hash;
    use kovanica_types::{AuthorityIndex, Round, Signature};

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
}
