//! Red (non-blue) mergeset blocks of a MysticGhost commit (#13, variant A).
//!
//! Red blocks are not executed as blocks (they are never part of
//! [`CommittedSubDag::blocks`]), but their transactions must not be lost:
//! the committed sub-DAG lists them in [`CommittedSubDag::non_blue`] and
//! [`non_blue_transactions`] returns their transactions so the node can hand
//! them back to the mempool. Red blocks stay in the DAG until ordinary round
//! pruning (`prune_waves_before`); `prune_non_blue` is no longer called.
//!
//! Both helpers are pure functions of the DAG contents, so the live commit
//! path and the node's recovery path produce identical results when they call
//! them over the same DAG.

use crate::engine::{ConsensusError, DagStoreTrait};
use kovanica_types::block::{BlockReference, StatementBlock};
use kovanica_types::hash::Hash;
use kovanica_types::transaction::Transaction;
use kovanica_types::CommittedSubDag;
use std::collections::HashSet;

/// Red blocks of a coloured mergeset: every mergeset block that is neither
/// blue nor the leader.
///
/// Order: topological by round (a parent always has a lower round than its
/// child), ties broken by block digest. Deterministic for a given mergeset
/// and blue set, independent of the input order.
pub fn non_blue_refs(
    mergeset_blocks: &[StatementBlock],
    blue: &[Hash],
    leader: &Hash,
) -> Vec<BlockReference> {
    let blue: HashSet<&Hash> = blue.iter().collect();
    let mut refs: Vec<BlockReference> = mergeset_blocks
        .iter()
        .filter(|b| b.digest != *leader && !blue.contains(&b.digest))
        .map(|b| BlockReference {
            author: b.author,
            round: b.round,
            digest: b.digest,
        })
        .collect();
    refs.sort_by_key(|r| (r.round, r.digest.0));
    refs.dedup_by(|a, b| a.digest == b.digest);
    // The canonical genesis block is never red: it is an ancestor of every
    // block, so GHOSTDAG always colours it blue. State sync relies on it being
    // in `CommittedSubDag::blocks` (see `is_genesis_subdag`).
    debug_assert!(
        !refs
            .iter()
            .any(|r| crate::genesis::is_canonical_genesis(r.round, &r.digest)),
        "canonical genesis block must never be in non_blue"
    );
    refs
}

/// Transactions of the red blocks of `subdag` that are not already executed
/// through its blue blocks.
///
/// Order: `subdag.non_blue` order, then in-block order. Deduplicated by
/// transaction hash (first occurrence wins); any transaction whose hash also
/// appears in a blue block of the same sub-DAG (`subdag.blocks` or the
/// leader) is excluded. Deterministic: same DAG and sub-DAG, same result.
///
/// Errors if a red block is missing from the DAG (red blocks are only removed
/// by round pruning, which keeps far more than one commit's history).
pub fn non_blue_transactions<D: DagStoreTrait + ?Sized>(
    dag: &D,
    subdag: &CommittedSubDag,
) -> Result<Vec<Transaction>, ConsensusError> {
    let mut seen: HashSet<Hash> = subdag
        .blocks
        .iter()
        .chain(std::iter::once(&subdag.leader))
        .flat_map(|b| b.transactions.iter().map(|t| t.hash))
        .collect();
    let mut out = Vec::new();
    for r in &subdag.non_blue {
        let block = dag.get_block(&r.digest)?;
        for tx in block.transactions {
            if seen.insert(tx.hash) {
                out.push(tx);
            }
        }
    }
    Ok(out)
}
