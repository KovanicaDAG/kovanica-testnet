//! Example wrapper for MysticGhost ordering. Not called by the engine.
//!
//! The flag that changes commit output is [`crate::UniversalCommitter`]'s
//! `use_mysticghost` (from [`crate::ConsensusConfig`], default on,
//! `KOVANICA_MYSTICGHOST` on the node). This module is a sketch of that seam.
//! Nothing here runs unless a caller invokes
//! [`commit_with_optional_mysticghost`] directly. The live committer reads
//! the flag itself.

use crate::ghostdag_scoped::ColouringResult;
use crate::linearizer::Linearizer;
use crate::mysticghost::{order_committed_wave, MysticGhostConfig, MysticGhostOrder};
use kovanica_types::block::StatementBlock;
use kovanica_types::hash::Hash;
use kovanica_types::CommittedSubDag;

/// Result of running the optional-MysticGhost commit wrapper for one wave.
#[derive(Debug)]
pub enum CommitOutcome {
    /// Scoped GHOSTDAG produced the blue-set order (hashes only; the wave is
    /// not yet linearized into a [`CommittedSubDag`]).
    Ghost { order: Vec<Hash> },
    /// Pure Mysticeti path — output of the regular [`Linearizer`], identical
    /// to what the existing committer would produce.
    Linearized(CommittedSubDag),
}

/// Example of how the commit path should look after integration.
///
/// Scaffold — the real UniversalCommitter wiring comes in a later phase.
pub fn commit_with_optional_mysticghost(
    cfg: &MysticGhostConfig,
    leader: StatementBlock,
    // the DAG store that can answer mergeset()
    dag: &impl MergesetProvider,
    // the original linearizer (kept for fallback)
    linearizer: &impl LinearizerTrait,
    previous_tips: &[Hash],
) -> CommitOutcome {
    // 1. Always compute the mergeset (cheap if the DAG store is indexed)
    let mergeset_hashes = dag.mergeset(&leader.digest);
    let mergeset_blocks = dag.get_blocks(&mergeset_hashes);

    // 2. Ask MysticGhost whether it wants to order this wave
    match order_committed_wave(cfg, &mergeset_blocks, previous_tips) {
        MysticGhostOrder::Ghost { colouring } => {
            // Use the blue-set order
            CommitOutcome::Ghost {
                order: colouring.blue_ordered(),
            }
        }
        MysticGhostOrder::Fallback => {
            // Pure Mysticeti path – bit-identical to today
            let subdag = linearizer.linearize(leader, mergeset_blocks);
            CommitOutcome::Linearized(subdag)
        }
    }
}

// ---------------------------------------------------------------------------
// Traits the wrapper needs from the DAG store and the linearizer.
// ---------------------------------------------------------------------------

/// Trait that the DAG store should implement (or already partially implements).
pub trait MergesetProvider {
    /// Hashes of the blocks in the mergeset of `leader`.
    fn mergeset(&self, leader: &Hash) -> Vec<Hash>;
    /// Full blocks for the given hashes (missing hashes are skipped).
    fn get_blocks(&self, hashes: &[Hash]) -> Vec<StatementBlock>;
}

/// Mirrors the real [`Linearizer::linearize`] signature so the production
/// linearizer can be passed straight to [`commit_with_optional_mysticghost`].
pub trait LinearizerTrait {
    /// Topologically order `leader` + `history` into a committed sub-DAG.
    fn linearize(&self, leader: StatementBlock, history: Vec<StatementBlock>) -> CommittedSubDag;
}

impl LinearizerTrait for Linearizer {
    fn linearize(&self, leader: StatementBlock, history: Vec<StatementBlock>) -> CommittedSubDag {
        // Delegate to the inherent implementation. (Verified: inherent
        // associated items take precedence over trait items in path
        // resolution, so this does not recurse into this impl.)
        Linearizer::linearize(self, leader, history)
    }
}
