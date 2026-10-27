//! MysticGhost glue module for kovanica-consensus.
//!
//! This module sits between the existing wave engine / UniversalCommitter
//! and the scoped GHOSTDAG colouring.
//!
//! Feature flag: `ConsensusConfig::use_mysticghost` (env `KOVANICA_MYSTICGHOST`)

use crate::ghostdag_scoped::{colour_mergeset, ColouringResult};
use kovanica_types::block::StatementBlock;
use kovanica_types::hash::Hash;

/// Configuration for the MysticGhost path.
#[derive(Clone, Debug)]
pub struct MysticGhostConfig {
    /// When false, the original linearizer is used (pure Mysticeti).
    pub enabled: bool,
    /// GHOSTDAG parameter k (must be 3 for the current safety argument).
    pub k: usize,
    /// Maximum number of blocks allowed in a mergeset before we refuse to
    /// colour (the safety valve returns `MysticGhostOrder::Fallback`, it does
    /// not error).
    ///
    /// The production cap is **2_000** blocks: both `Default` and the
    /// committer's own config use that value. (This comment said "1_000" while
    /// the code has always used 2_000; the code is the contract.)
    pub max_mergeset_blocks: usize,
}

impl Default for MysticGhostConfig {
    fn default() -> Self {
        Self {
            enabled: false, // start disabled – pure Mysticeti
            k: 3,
            max_mergeset_blocks: 2_000,
        }
    }
}

/// Result of attempting a MysticGhost ordering.
#[derive(Debug)]
pub enum MysticGhostOrder {
    /// Scoped GHOSTDAG produced a blue-set order.
    Ghost { colouring: ColouringResult },
    /// Fell back to the original linearizer (feature disabled or mergeset too large).
    Fallback,
}

/// Entry point called from the committer after a leader is committed.
///
/// `mergeset_blocks` – blocks returned by the DAG store’s mergeset() method
/// `previous_tips`   – tips of already committed sub-dags (needed for correct colouring)
pub fn order_committed_wave(
    cfg: &MysticGhostConfig,
    mergeset_blocks: &[StatementBlock],
    previous_tips: &[Hash],
) -> MysticGhostOrder {
    if !cfg.enabled {
        return MysticGhostOrder::Fallback;
    }

    if mergeset_blocks.len() > cfg.max_mergeset_blocks {
        // Safety valve – do not blow the resource budget.
        // In production you may want to log + metric this event.
        return MysticGhostOrder::Fallback;
    }

    let colouring = colour_mergeset(mergeset_blocks, cfg.k, previous_tips);
    MysticGhostOrder::Ghost { colouring }
}
