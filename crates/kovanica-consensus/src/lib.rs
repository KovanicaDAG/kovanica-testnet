//! Mysticeti-style DAG consensus for Kovanica.
//!
//! Implements wave-based uncertified DAG with direct/indirect commit rules.

#![deny(unsafe_code)]
#![allow(missing_docs)]
#![allow(clippy::result_large_err)]
#![allow(clippy::large_enum_variant)]
#![allow(unused_mut)]
#![allow(dead_code)]
#![allow(unused_imports)]
#![allow(unused_variables)]

pub mod committer;
pub mod committer_mysticghost;
pub mod engine;
pub mod genesis;
pub mod ghostdag_scoped;
pub mod linearizer;
pub mod metrics;
pub mod mysticghost;
pub mod non_blue;
pub mod skip;
pub mod types;

pub use committer::{uncommitted_history, BaseCommitter, UniversalCommitter};
pub use engine::{
    BlockBroadcaster, ConsensusConfig, ConsensusEngine, ConsensusError, TimeoutBroadcaster,
    ValidatorState, VoteBroadcaster, VoteRejection,
};
pub use genesis::is_genesis_subdag;
pub use kovanica_types::Vote;
pub use linearizer::Linearizer;
pub use metrics::{
    metrics_text, observe_finality_latency, record_active_validators, record_block_height,
    record_colouring_duration_ms, record_commit_latency, record_committed_leader,
    record_connected_peers, record_current_round, record_mempool_size, record_mergeset_size,
    record_mergeset_size_metric, record_peer_count, record_pruned_blocks, record_pruned_waves,
    record_rss_bytes, record_rss_proxy, record_skipped_leader, record_sync_error,
    record_timeout_signed, record_vote_timeout_equivocation, registry, SkipReason, SyncErrorKind,
};
pub use non_blue::{non_blue_refs, non_blue_transactions};
pub use types::{
    AuthorityInfo, CommitResult, CommittedSubDag, CommitteeInfo, CommitteeInfoError, LeaderInfo,
    LeaderStatus,
};

use kovanica_types::{Round, WAVE_LENGTH};

/// Returns the wave number for a given round.
#[inline]
pub fn wave_of(round: Round) -> u64 {
    round / WAVE_LENGTH
}

/// Returns the offset inside the wave (0 = leader, 1 = vote, 2 = decide).
#[inline]
pub fn offset_in_wave(round: Round) -> u64 {
    round % WAVE_LENGTH
}

/// True if this round is a leader round.
#[inline]
pub fn is_leader_round(round: Round) -> bool {
    offset_in_wave(round) == 0
}

/// True if this round is a vote round.
#[inline]
pub fn is_vote_round(round: Round) -> bool {
    offset_in_wave(round) == 1
}
