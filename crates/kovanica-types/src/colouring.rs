//! Scoped GHOSTDAG colouring for MysticGhost (`k = 3`).
//!
//! This is the same colouring the consensus committer runs when
//! `use_mysticghost` is on. It lives here so a light client can re-run it
//! on block headers (digest, round, parent digests) without the DAG store.
//! Consensus keeps its own wrapper and must not grow a second algorithm.

use crate::hash::Hash;
use crate::merkle;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};

/// Header fields the colouring algorithm reads.
///
/// Transaction bytes are not required. Parent digests that fall outside
/// the mergeset and the previous-tip list are ignored, matching the
/// consensus wrapper.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ColourBlock {
    /// Block digest.
    pub digest: Hash,
    /// Block round. Sorting is `(round, digest)`.
    pub round: u64,
    /// Parent digests, in the order stored on the block.
    pub parents: Vec<Hash>,
}

/// Output of one scoped colouring run.
#[derive(Debug, Clone)]
pub struct ColouringResult {
    /// Mergeset blocks coloured blue. Previous tips are not included.
    pub blue: Vec<Hash>,
    /// Selected parent of each blue block, including seeded previous tips.
    pub selected_parent: HashMap<Hash, Option<Hash>>,
    /// Blue score of each blue block and each seeded tip.
    pub blue_score: HashMap<Hash, u64>,
}

impl ColouringResult {
    /// Blue blocks in selected-parent topological order.
    ///
    /// Roots and children are sorted by digest, so the order depends only
    /// on the colouring, not on map iteration.
    pub fn blue_ordered(&self) -> Vec<Hash> {
        let mut in_degree: HashMap<Hash, usize> = HashMap::new();
        let mut children: HashMap<Hash, Vec<Hash>> = HashMap::new();

        for &blue_hash in &self.blue {
            in_degree.insert(blue_hash, 0);
            children.insert(blue_hash, Vec::new());
        }

        for (&blue_hash, &opt_parent) in &self.selected_parent {
            if let Some(parent) = opt_parent {
                if self.blue.iter().any(|h| h == &parent) {
                    *in_degree.get_mut(&blue_hash).unwrap() += 1;
                    children.get_mut(&parent).unwrap().push(blue_hash);
                }
            }
        }

        let mut roots: Vec<Hash> = in_degree
            .iter()
            .filter(|(_, &deg)| deg == 0)
            .map(|(h, _)| *h)
            .collect();
        roots.sort_by_key(|h| h.0);
        for child_list in children.values_mut() {
            child_list.sort_by_key(|h| h.0);
        }

        let mut queue: VecDeque<Hash> = roots.into();
        let mut ordered = Vec::new();
        while let Some(hash) = queue.pop_front() {
            ordered.push(hash);
            if let Some(child_list) = children.get(&hash) {
                for child in child_list {
                    let deg = in_degree.get_mut(child).unwrap();
                    *deg -= 1;
                    if *deg == 0 {
                        queue.push_back(*child);
                    }
                }
            }
        }
        ordered
    }
}

/// Why a MysticGhost commitment could not be built or checked.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ColourError {
    /// Two headers in the mergeset share a digest.
    DuplicateDigest,
    /// The claimed leader digest is not in the mergeset.
    LeaderMissing,
    /// `k` was not 3. MysticGhost refuses any other parameter.
    UnsupportedK,
    /// Re-colouring did not reproduce the header's blue or non-blue root.
    RootMismatch,
    /// The certificate leader is not the header's leader.
    LeaderMismatch,
    /// The header was not produced on the MysticGhost path.
    NotGhost,
}

/// Blue-set and red-set commitments for one committed leader.
///
/// `executed` follows the committer: blue blocks in [`ColouringResult::blue_ordered`]
/// order, with the leader appended when colouring left it out. Red blocks are
/// every other mergeset digest, ordered by `(round, digest)`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GhostCommitment {
    /// Pure blue order. Does not force-include the leader.
    pub blue_ordered: Vec<Hash>,
    /// Block digests execution walks. Leader is last if colouring omitted it.
    pub executed: Vec<Hash>,
    /// Red mergeset digests. The leader is never red.
    pub non_blue: Vec<Hash>,
    /// Merkle root of [`Self::blue_ordered`].
    pub blue_root: Hash,
    /// Merkle root of [`Self::non_blue`]. Zero when there are no red blocks.
    pub non_blue_root: Hash,
}

/// Colour `blocks` with GHOSTDAG parameter `k`.
///
/// `k` must be 3. `previous_tips` are seeded as already-blue and are not
/// added to [`ColouringResult::blue`].
pub fn colour_mergeset(
    blocks: &[ColourBlock],
    k: usize,
    previous_tips: &[Hash],
) -> Result<ColouringResult, ColourError> {
    if k != 3 {
        return Err(ColourError::UnsupportedK);
    }

    let mut block_hashes = HashSet::with_capacity(blocks.len());
    for block in blocks {
        block_hashes.insert(block.digest);
    }

    let mut parents_in_subgraph: HashMap<Hash, Vec<Hash>> = HashMap::with_capacity(blocks.len());
    for block in blocks {
        let mut parent_hashes = Vec::new();
        for parent in &block.parents {
            if block_hashes.contains(parent) || previous_tips.contains(parent) {
                parent_hashes.push(*parent);
            }
        }
        parents_in_subgraph.insert(block.digest, parent_hashes);
    }

    let mut sorted_blocks = blocks.to_vec();
    sorted_blocks.sort_by_key(|b| (b.round, b.digest.0));

    let mut already_blue: HashSet<Hash> = HashSet::new();
    let mut past_cone: HashMap<Hash, HashSet<Hash>> = HashMap::new();
    let mut blue_score: HashMap<Hash, u64> = HashMap::new();
    let mut selected_parent: HashMap<Hash, Option<Hash>> = HashMap::new();
    let mut blue: Vec<Hash> = Vec::new();

    for tip in previous_tips {
        already_blue.insert(*tip);
        let mut cone = HashSet::new();
        cone.insert(*tip);
        past_cone.insert(*tip, cone);
        blue_score.insert(*tip, 0);
        selected_parent.insert(*tip, None);
    }

    for block in &sorted_blocks {
        let block_hash = block.digest;
        let parent_hashes = parents_in_subgraph
            .get(&block_hash)
            .cloned()
            .unwrap_or_default();
        let blue_parents: Vec<Hash> = parent_hashes
            .iter()
            .filter(|h| already_blue.contains(*h))
            .copied()
            .collect();

        let mut ancestors = HashSet::new();
        for parent in &blue_parents {
            if let Some(parent_cone) = past_cone.get(parent) {
                ancestors.extend(parent_cone.iter().copied());
            }
        }

        let mut blue_anticone = Vec::new();
        for &blue_hash in &already_blue {
            if !ancestors.contains(&blue_hash) {
                blue_anticone.push(blue_hash);
            }
        }

        if blue_anticone.len() <= k {
            already_blue.insert(block_hash);
            blue.push(block_hash);

            let mut cone = HashSet::new();
            cone.insert(block_hash);
            for parent in &blue_parents {
                if let Some(parent_cone) = past_cone.get(parent) {
                    cone.extend(parent_cone.iter().copied());
                }
            }
            past_cone.insert(block_hash, cone);

            let best_parent = if blue_parents.is_empty() {
                None
            } else {
                let mut best = blue_parents[0];
                let mut best_score = blue_score[&best];
                for parent in &blue_parents[1..] {
                    let score = blue_score[parent];
                    if score > best_score || (score == best_score && parent.0 < best.0) {
                        best = *parent;
                        best_score = score;
                    }
                }
                Some(best)
            };
            selected_parent.insert(block_hash, best_parent);

            let score = best_parent.map(|p| blue_score[&p] + 1).unwrap_or(0);
            blue_score.insert(block_hash, score);
        }
    }

    Ok(ColouringResult {
        blue,
        selected_parent,
        blue_score,
    })
}

/// Commitments the committer publishes for a MysticGhost wave.
///
/// Duplicate digests are rejected so a light client and a full node cannot
/// disagree about which header a digest names. The leader must be one of
/// `blocks`.
pub fn mysticghost_commitment(
    blocks: &[ColourBlock],
    previous_tips: &[Hash],
    leader: Hash,
) -> Result<GhostCommitment, ColourError> {
    let mut seen = HashSet::with_capacity(blocks.len());
    for block in blocks {
        if !seen.insert(block.digest) {
            return Err(ColourError::DuplicateDigest);
        }
    }
    if !seen.contains(&leader) {
        return Err(ColourError::LeaderMissing);
    }

    let colouring = colour_mergeset(blocks, 3, previous_tips)?;
    let blue_ordered = colouring.blue_ordered();
    let blue_set: HashSet<Hash> = colouring.blue.iter().copied().collect();

    let mut non_blue: Vec<ColourBlock> = blocks
        .iter()
        .filter(|b| b.digest != leader && !blue_set.contains(&b.digest))
        .cloned()
        .collect();
    non_blue.sort_by_key(|b| (b.round, b.digest.0));
    non_blue.dedup_by(|a, b| a.digest == b.digest);
    let non_blue: Vec<Hash> = non_blue.into_iter().map(|b| b.digest).collect();

    let mut executed = blue_ordered.clone();
    if !executed.contains(&leader) {
        executed.push(leader);
    }

    Ok(GhostCommitment {
        blue_root: merkle::root(&blue_ordered),
        non_blue_root: merkle::root(&non_blue),
        blue_ordered,
        executed,
        non_blue,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn block(round: u64, tag: u8, parents: &[Hash]) -> ColourBlock {
        ColourBlock {
            digest: Hash::new([tag]),
            round,
            parents: parents.to_vec(),
        }
    }

    #[test]
    fn chain_is_all_blue_in_parent_order() {
        let genesis = block(0, 1, &[]);
        let b1 = block(1, 2, &[genesis.digest]);
        let b2 = block(2, 3, &[b1.digest]);
        let result = colour_mergeset(&[genesis.clone(), b1.clone(), b2.clone()], 3, &[]).unwrap();
        assert_eq!(
            result.blue_ordered(),
            vec![genesis.digest, b1.digest, b2.digest]
        );
        assert_eq!(result.selected_parent[&b2.digest], Some(b1.digest));
    }

    #[test]
    fn fifth_incomparable_block_is_red_and_leader_stays_executed() {
        let genesis = block(0, 1, &[]);
        let mut blocks = vec![genesis.clone()];
        for tag in 2..7 {
            blocks.push(block(1, tag, &[genesis.digest]));
        }
        let leader = genesis.digest;
        let commitment = mysticghost_commitment(&blocks, &[], leader).unwrap();
        assert_eq!(commitment.non_blue.len(), 1);
        assert!(commitment.executed.contains(&leader));
        assert_ne!(commitment.blue_root, Hash::zero());
        assert_ne!(commitment.non_blue_root, Hash::zero());
    }

    #[test]
    fn k_other_than_3_is_rejected() {
        let genesis = block(0, 1, &[]);
        assert_eq!(
            colour_mergeset(&[genesis], 2, &[]).unwrap_err(),
            ColourError::UnsupportedK
        );
    }

    #[test]
    fn duplicate_digest_is_rejected_by_the_commitment() {
        let genesis = block(0, 1, &[]);
        let err = mysticghost_commitment(&[genesis.clone(), genesis.clone()], &[], genesis.digest)
            .unwrap_err();
        assert_eq!(err, ColourError::DuplicateDigest);
    }
}
