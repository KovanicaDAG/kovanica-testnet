//! State sync support: recognise the genesis committed sub-DAG.

use kovanica_types::block::StatementBlock;
use kovanica_types::hash::Hash;
use kovanica_types::{CommittedSubDag, GENESIS_ROUND};

/// Digest of the canonical genesis block (author 0, round 0, no parents,
/// no transactions, no statements). The same value the node writes at
/// genesis and `BlockManager::validate_canonical_genesis` enforces.
fn canonical_genesis_digest() -> Hash {
    StatementBlock::compute_digest(0, GENESIS_ROUND, &[], &[])
}

/// True iff `(round, digest)` identifies the canonical genesis block.
pub(crate) fn is_canonical_genesis(round: kovanica_types::Round, digest: &Hash) -> bool {
    round == GENESIS_ROUND && *digest == canonical_genesis_digest()
}

/// True iff `subdag` is the genesis sub-DAG: the committed sub-DAG whose
/// **executed** blocks include the canonical genesis block.
///
/// Pure function of the sub-DAG content (no DAG access, no I/O), so the answer
/// is the same live and on restart replay of a stored sub-DAG, even after the
/// DAG was pruned.
///
/// The check: `blocks ∪ {leader}` contains a block with round
/// [`GENESIS_ROUND`] (0) **and** the canonical genesis digest
/// (`StatementBlock::compute_digest(0, 0, &[], &[])`). Checking the digest as
/// well as the round means a forged round-0 block can't qualify (and
/// `validate_block` already rejects any non-canonical round-0 block).
///
/// - `non_blue` is **not** considered: execution only executes `blocks`.
///   Genesis is never red anyway (debug-asserted where `non_blue` is built,
///   in `non_blue_refs`).
/// - If the first leader is skipped, the genesis block is delivered by the
///   first sub-DAG committed at a later round, and that one returns `true`.
/// - Later sub-DAGs never contain genesis again (committed blocks are never
///   re-delivered), so they return `false`.
///
/// Used as the per-call `is_genesis_subdag` input of Execution's state sync
/// gate (`StartupSyncState::allows`).
pub fn is_genesis_subdag(subdag: &CommittedSubDag) -> bool {
    is_canonical_genesis(subdag.leader.round, &subdag.leader.digest)
        || subdag
            .blocks
            .iter()
            .any(|b| is_canonical_genesis(b.round, &b.digest))
}
