//! Binary Merkle tree used by transaction roots and light-client proofs.
//!
//! Pairing matches [`crate::block::StatementBlock::compute_merkle_root`]:
//! an odd trailing node is promoted unchanged, and every pair is
//! `BLAKE3` keyed by [`crate::hash::Hash::DOMAIN_MERKLE`]. An empty leaf
//! list hashes to [`crate::hash::Hash::zero`].

use crate::hash::Hash;
use serde::{Deserialize, Serialize};

/// One step on a path from a leaf to the root.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum MerkleStep {
    /// This node had no sibling and was promoted to the next level.
    Promote,
    /// Combine with `hash`. `is_left` means the sibling is the left child.
    Sibling {
        /// Sibling hash at this level.
        hash: Hash,
        /// Whether the sibling sits to the left of the current node.
        is_left: bool,
    },
}

/// Inclusion path for one leaf.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MerkleProof {
    /// Steps from the leaf up to, but not including, the root.
    pub steps: Vec<MerkleStep>,
}

/// Merkle root of `leaves`. Empty input is the zero hash.
pub fn root(leaves: &[Hash]) -> Hash {
    if leaves.is_empty() {
        return Hash::zero();
    }
    let mut current = leaves.to_vec();
    while current.len() > 1 {
        current = parent_level(&current);
    }
    current[0]
}

/// Build an inclusion proof for `leaves[index]`.
///
/// Returns `None` when the list is empty or `index` is out of range.
pub fn proof(leaves: &[Hash], index: usize) -> Option<MerkleProof> {
    if leaves.is_empty() || index >= leaves.len() {
        return None;
    }
    if leaves.len() == 1 {
        return Some(MerkleProof { steps: Vec::new() });
    }

    let mut levels = Vec::new();
    levels.push(leaves.to_vec());
    while levels.last().map(|l| l.len()).unwrap_or(0) > 1 {
        let next = parent_level(levels.last().expect("level pushed above"));
        levels.push(next);
    }

    let mut steps = Vec::new();
    let mut idx = index;
    for level in &levels[..levels.len() - 1] {
        if level.len() % 2 == 1 && idx == level.len() - 1 {
            steps.push(MerkleStep::Promote);
        } else {
            let sibling_idx = if idx.is_multiple_of(2) {
                idx + 1
            } else {
                idx - 1
            };
            steps.push(MerkleStep::Sibling {
                hash: level[sibling_idx],
                is_left: sibling_idx < idx,
            });
        }
        idx /= 2;
    }
    Some(MerkleProof { steps })
}

/// Recompute the root from `leaf` and `proof` and compare it to `expected`.
pub fn verify(leaf: &Hash, proof: &MerkleProof, expected: &Hash) -> bool {
    let mut acc = *leaf;
    for step in &proof.steps {
        match step {
            MerkleStep::Promote => {}
            MerkleStep::Sibling { hash, is_left } => {
                acc = if *is_left {
                    pair(*hash, acc)
                } else {
                    pair(acc, *hash)
                };
            }
        }
    }
    acc == *expected
}

fn parent_level(current: &[Hash]) -> Vec<Hash> {
    let mut next = Vec::with_capacity(current.len().div_ceil(2));
    for chunk in current.chunks(2) {
        if chunk.len() == 2 {
            next.push(pair(chunk[0], chunk[1]));
        } else {
            next.push(chunk[0]);
        }
    }
    next
}

fn pair(left: Hash, right: Hash) -> Hash {
    let mut data = [0u8; 64];
    data[..32].copy_from_slice(left.as_ref());
    data[32..].copy_from_slice(right.as_ref());
    Hash::new_keyed(Hash::DOMAIN_MERKLE, data)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn leaf(n: u8) -> Hash {
        Hash::new([n])
    }

    #[test]
    fn empty_root_is_zero() {
        assert_eq!(root(&[]), Hash::zero());
        assert!(proof(&[], 0).is_none());
    }

    #[test]
    fn single_leaf_proof_is_empty() {
        let leaves = [leaf(1)];
        let proof = proof(&leaves, 0).unwrap();
        assert!(proof.steps.is_empty());
        assert!(verify(&leaves[0], &proof, &root(&leaves)));
    }

    #[test]
    fn odd_list_proves_every_index() {
        let leaves = [leaf(1), leaf(2), leaf(3), leaf(4), leaf(5)];
        let expected = root(&leaves);
        for (i, leaf) in leaves.iter().enumerate() {
            let path = proof(&leaves, i).unwrap();
            assert!(verify(leaf, &path, &expected), "index {i}");
            assert!(!verify(&Hash::new([9]), &path, &expected));
        }
    }

    #[test]
    fn out_of_range_index_has_no_proof() {
        let leaves = [leaf(1), leaf(2)];
        assert!(proof(&leaves, 2).is_none());
    }
}
