//! Mergeset extraction helper for MysticGhost.
//!
//! The mergeset of a committed leader is the set of all blocks that are
//! reachable from the leader and have not yet been included in any previous
//! CommittedSubDag.
//!
//! This module provides a clean API; the real implementation should reuse
//! the existing reachability / ancestor indexes of the DAG store.

use crate::dag_store::DagStore;
use kovanica_types::hash::Hash;
use std::collections::{HashSet, VecDeque};

/// Trait that the DAG store should implement for mergeset computation.
pub trait DagReachability {
    /// Returns true if `ancestor` is in the past cone of `block` (or equal).
    fn is_ancestor(&self, ancestor: &Hash, block: &Hash) -> bool;

    /// Direct parents of a block.
    fn parents(&self, block: &Hash) -> Vec<Hash>;

    /// All blocks already committed by previous sub-dags, i.e. by decided
    /// leaders of rounds strictly below `leader`'s round (and their histories).
    fn already_committed(&self, leader: &Hash) -> Result<HashSet<Hash>, crate::DagStoreError>;

    /// Get a block by hash (for reading round info).
    fn get_block(
        &self,
        hash: &Hash,
    ) -> Result<kovanica_types::block::StatementBlock, crate::DagStoreError>;

    /// Get the last committed leader's round, if any.
    fn committed_leader_round(&self) -> Result<Option<u64>, crate::DagStoreError>;
}

/// Compute the mergeset of `leader`.
///
/// Simple BFS / DFS implementation. For production, replace with an
/// indexed version that uses the reachability oracle.
pub fn compute_mergeset<D: DagReachability>(
    dag: &D,
    leader: &Hash,
) -> Result<Vec<Hash>, crate::DagStoreError> {
    let mut result = Vec::new();
    let mut visited = HashSet::new();
    let mut queue = VecDeque::new();

    // Cutoff is the actual committed set, not the last leader's round, so a
    // late lower-round block that no earlier leader referenced is included.
    let committed = dag.already_committed(leader)?;

    queue.push_back(*leader);
    visited.insert(*leader);

    while let Some(current) = queue.pop_front() {
        if current != *leader && committed.contains(&current) {
            continue;
        }
        dag.get_block(&current)?;

        result.push(current);

        for parent in dag.parents(&current) {
            if visited.insert(parent) {
                queue.push_back(parent);
            }
        }
    }

    // The classic mergeset also includes blocks that point *to* the leader
    // but are not yet committed. Depending on your exact DAG store API you
    // may need a second pass over children / tips. Adjust accordingly.
    Ok(result)
}

impl DagReachability for DagStore {
    fn is_ancestor(&self, ancestor: &Hash, block: &Hash) -> bool {
        // Use get_ancestors with min_round = 0 to check reachability
        self.get_ancestors(block, 0)
            .map(|ancestors| ancestors.contains(ancestor))
            .unwrap_or(false)
    }

    fn parents(&self, block: &Hash) -> Vec<Hash> {
        self.get_parents(block).unwrap_or_default()
    }

    fn already_committed(&self, leader: &Hash) -> Result<HashSet<Hash>, crate::DagStoreError> {
        let round = DagStore::get_block(self, leader)?.round;
        self.committed_before(round)
    }

    fn get_block(
        &self,
        hash: &Hash,
    ) -> Result<kovanica_types::block::StatementBlock, crate::DagStoreError> {
        DagStore::get_block(self, hash)
    }

    fn committed_leader_round(&self) -> Result<Option<u64>, crate::DagStoreError> {
        match self.get_last_committed()? {
            Some(last_committed_hash) => match DagStore::get_block(self, &last_committed_hash) {
                Ok(block) => Ok(Some(block.round)),
                // Last committed block pruned: its round is unknown.
                Err(crate::DagStoreError::NotFound(_)) => Ok(None),
                Err(e) => Err(e),
            },
            None => Ok(None), // No committed leaders yet - don't stop
        }
    }
}

#[cfg(test)]
mod tests {
    // Add synthetic DAG tests here once the real store is available.
}
