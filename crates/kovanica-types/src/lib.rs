//! Core types for the Kovanica (KUNA) blockchain.
//!
//! This crate contains all fundamental data structures used across the system:
//! blocks, transactions, addresses, rounds, committee, etc.

#![deny(unsafe_code)]
#![warn(missing_docs)]

pub mod account_tree;
pub mod address;
pub mod block;
pub mod colouring;
pub mod commit;
pub mod committee;
pub mod crypto;
pub mod error;
pub mod evidence;
pub mod hash;
pub mod light_client;
pub mod merkle;
pub mod signing;
pub mod timeout;
pub mod transaction;
pub mod vote;

pub use account_tree::{
    account_leaf_hash, account_root, verify_account_proof, AccountProof, AccountSmt,
};
pub use address::Address;
pub use block::{Block, BlockReference, StatementBlock};
pub use colouring::{
    colour_mergeset, mysticghost_commitment, ColourBlock, ColourError, ColouringResult,
    GhostCommitment,
};
pub use commit::CommittedSubDag;
pub use committee::{Authority, Committee, Stake};
pub use crypto::{PublicKey, Signature, SigningKey};
pub use error::TypesError;
pub use evidence::{
    EquivocationEvidence, EvidenceError, SignedBlockHeader, EVIDENCE_MAX_AGE_ROUNDS,
};
pub use hash::Hash;
pub use light_client::{
    committee_seal_hash, decode_with_version, encode_with_version, executed_tx_hashes,
    leader_header, light_vrf_input, light_vrf_priority, snapshot_seal_members, verify_colouring,
    vrf_hash_prefix, vrf_priority_cmp, ColouringCertificate, CommitSeal, LeaderHeader,
    LightClientCheckpoint, SealAnnouncement, SealCommitteeMember, SealCommitteeSnapshotMember,
    SealError, StateProof, WaveCommitCertificate, EPOCH_COMMITTEE_VERSION, LIGHT_VRF_DOMAIN,
    SNAPSHOT_MAGIC, STAKING_STATE_VERSION, STAKING_STATE_VERSION_PREVIOUS,
};
pub use merkle::{MerkleProof, MerkleStep};
pub use signing::SigningContext;
pub use timeout::{SkipCert, Timeout};
pub use transaction::{Transaction, TransactionKind};
pub use vote::Vote;

/// Logical round number in the DAG.
pub type Round = u64;

/// Unique authority index within the current committee.
pub type AuthorityIndex = u16;

/// Wave length used by the consensus (Mysticeti-style = 3).
pub const WAVE_LENGTH: u64 = 3;

/// Epoch length in **DAG rounds**: 7 200 rounds × 4 s ≈ **8 h**.
///
/// Toni's decision of 2026-10-23 (option a): an epoch is 7 200 DAG rounds,
/// which is what consensus has always computed (`leader_round / 7_200`), so
/// the vote/seal signing context and the committee snapshots are unchanged.
/// The earlier "7 200 committed leaders ≈ 1 day" wording is retired.
///
/// There are two epoch counters with the **same length**:
///
/// * [`epoch_for_round`]: consensus (vote/seal signing context, committee
///   snapshots `EPOCH_COMMITTEE`, RPC `getCommittee`/`signingContext`),
///   derived from the DAG round of the leader.
/// * [`epoch_for_height`]: staking-side state keyed by committed leader
///   height (light set registration/exit, beacon, escrow settlement,
///   `StakingState::current_epoch`). One leader slot per wave, so an epoch is
///   [`EPOCH_LEADER_HEIGHTS`] = `EPOCH_ROUNDS / WAVE_LENGTH` = 2 400 heights.
///
/// The counters agree only while every leader slot is committed. Each leader
/// slot that is skipped (today none are: the commit walk stalls instead,
/// PRO-35/PRO-40; after the PRO-40 quorum-certified skip, each certified
/// skip) advances the round by `WAVE_LENGTH` without advancing the height, so
/// the height-based epoch lags the round-based one by
/// `skipped_slots / EPOCH_LEADER_HEIGHTS` epochs. The two are used by
/// independent subsystems and never compared, so the lag is not a safety
/// problem: a height-based epoch is never shorter than 8 h of wall-clock
/// time, but it is longer when leader slots are skipped.
/// `kovanica_staking` re-exports this constant for backward-compatible paths.
pub const EPOCH_ROUNDS: u64 = 7_200;

/// Epoch length in committed leader heights: `EPOCH_ROUNDS / WAVE_LENGTH` =
/// 2 400 (one leader per wave, 12 s per leader ≈ 8 h).
pub const EPOCH_LEADER_HEIGHTS: u64 = EPOCH_ROUNDS / WAVE_LENGTH;

/// Consensus epoch of a DAG round: `round / EPOCH_ROUNDS`.
///
/// A pure function of the round, decoupled from wall-clock time, committed
/// height and boot time, so every node derives the same value and it cannot
/// drift across a restart. The consensus signing context, the network
/// vote/seal edge, the committee builder and the RPC committee paths must all
/// use it. Never pass a committed height here; use [`epoch_for_height`].
#[must_use]
pub fn epoch_for_round(round: Round) -> u64 {
    round / EPOCH_ROUNDS
}

/// Staking-side epoch of a committed leader height:
/// `height / EPOCH_LEADER_HEIGHTS`.
///
/// Used by everything that is keyed by committed height (light set, beacon,
/// escrow settlement, `StakingState::current_epoch`). Same 8 h length as
/// [`epoch_for_round`]; see [`EPOCH_ROUNDS`] for why the two counters can
/// drift apart once leader slots are skipped.
#[must_use]
pub fn epoch_for_height(height: u64) -> u64 {
    height / EPOCH_LEADER_HEIGHTS
}

/// True if `height` is the first committed height of a staking epoch.
#[must_use]
pub fn is_epoch_start_height(height: u64) -> bool {
    height.is_multiple_of(EPOCH_LEADER_HEIGHTS)
}

/// Maximum allowed gap, in rounds, between a block and any of its parents.
///
/// Parent selection walks backwards from `round - 1` until it finds the most
/// recent populated round; validation rejects any parent further back than
/// this, keeping the DAG causally connected without unbounded edges.
pub const MAX_PARENT_ROUND_GAP: u64 = 300;

/// Maximum number of transactions per block (tunable).
pub const MAX_TXS_PER_BLOCK: usize = 10_000;

/// Canonical per-transaction gas cap for `Call` transactions.
///
/// `Call.gas_limit` is charged as interpreter (wasmi) fuel, so an uncapped
/// value is unbounded per-transaction work. This is the **single source of
/// truth**: `kovanica-runtime` re-exports it, `kovanica-dag`'s block manager
/// enforces it on the consensus path, and the mempool's default
/// `MempoolConfig::max_gas_limit` is derived from it. Change it here only.
pub const MAX_TX_GAS_LIMIT: u64 = 10_000_000;

/// Round from which the gas-hardening consensus rules take effect.
///
/// Three new rules are gated on `block.round >= GAS_HARDENING_ACTIVE_FROM_ROUND`
/// (below it every block validates and executes exactly as before):
///
/// 1. per-transaction `Call` gas cap ([`MAX_TX_GAS_LIMIT`]) in block-manager
///    `validate_transaction`;
/// 2. per-block gas budget in block-manager `validate_block_content`;
/// 3. per-call module-size gas floor in the execution layer (`Call` gas must be
///    at least `bytecode_len * kovanica_runtime::GAS_PER_MODULE_BYTE`).
///
/// Defaults to `u64::MAX` so the rules are **inert** on the currently running
/// testnet: activating them on a live chain without a coordinated upgrade would
/// fork it, because a node that has not yet been updated would still accept an
/// over-cap block that an updated node rejects. Set to `0` at the next genesis /
/// testnet reset, after every validator runs a build containing the hardening.
pub const GAS_HARDENING_ACTIVE_FROM_ROUND: u64 = u64::MAX;

/// Whether the gas-hardening consensus rules apply to a block/leader at
/// `round`.
///
/// Equivalent to `round >= GAS_HARDENING_ACTIVE_FROM_ROUND`. This is the single
/// predicate every gate uses (block-manager proposal truncation and block
/// validation, execution-time module-size floor), so the activation rule has
/// exactly one definition.
///
/// The lint is allowed because the default activation round is `u64::MAX` (so
/// the rules are inert on the running testnet); the comparison is deliberate,
/// not an accident, and would move here should the constant ever be redefined.
#[allow(clippy::absurd_extreme_comparisons)]
pub fn gas_hardening_active_from(round: Round) -> bool {
    round >= GAS_HARDENING_ACTIVE_FROM_ROUND
}

/// Round from which the contract-hardening consensus rules take effect.
///
/// Three new rules are gated on `block.round >= CONTRACT_HARDENING_ACTIVE_FROM_ROUND`
/// (below it every `Deploy`/`Call` validates and executes exactly as before,
/// so an un-updated node never diverges):
///
/// 1. `Deploy` bytecode validation — a deploy whose `code` is not a valid wasm
///    module (compiled with the same wasmi engine the interpreter uses,
///    hosted in `kovanica-execution`) is rejected **before** any account/code
///    row is written; fee and nonce are still charged, matching the existing
///    failure accounting;
/// 2. `Deploy` overwrite guard — a deploy that would replace the code of an
///    account that already holds non-empty code is rejected;
/// 3. wasm entry-point gating — a `Call` whose `method` is not one of the 16
///    canonical `kovanica_execution::ENTRY_POINTS` is rejected before the
///    interpreter runs (the native `dispatch_entry` path already gated these).
///
/// Defaults to `u64::MAX` so the rules are **inert** on the currently running
/// testnet: activating them on a live chain without a coordinated upgrade would
/// fork it, because a node that has not yet been updated would still accept a
/// deploy/call that an updated node rejects. Set to `0` at the next genesis /
/// testnet reset, after every validator runs a build containing the hardening.
pub const CONTRACT_HARDENING_ACTIVE_FROM_ROUND: u64 = u64::MAX;

/// Whether the contract-hardening consensus rules apply to a block/leader at
/// `round`.
///
/// Equivalent to `round >= CONTRACT_HARDENING_ACTIVE_FROM_ROUND`. This is the
/// single predicate the execution layer uses for deploy bytecode validation,
/// the deploy overwrite guard, and wasm entry-point gating, so the activation
/// rule has exactly one definition.
///
/// The lint is allowed because the default activation round is `u64::MAX` (so
/// the rules are inert on the running testnet); the comparison is deliberate,
/// not an accident, and would move here should the constant ever be redefined.
#[allow(clippy::absurd_extreme_comparisons)]
pub fn contract_hardening_active_from(round: Round) -> bool {
    round >= CONTRACT_HARDENING_ACTIVE_FROM_ROUND
}

/// Round from which production slashing takes effect.
///
/// Gates [`TransactionKind::Evidence`](crate::TransactionKind::Evidence) —
/// the transaction that carries a self-contained [`EquivocationEvidence`]
/// proof (see `docs/rfcs/RFC-010-PRODUCTION-SLASHING.md`). Below this round
/// every such transaction fails deterministically with "slashing not
/// active", so a node that has not been updated never diverges: it simply
/// keeps the transaction in the block and records a failed receipt, exactly
/// like any other failing transaction.
///
/// A new transaction kind changes the wire enum, so the rule cannot be
/// activated on a running chain without a coordinated upgrade. Defaults to
/// `u64::MAX`; set to `0` at the next genesis / testnet reset, after every
/// validator runs a build containing the slashing implementation.
pub const SLASHING_ACTIVE_FROM_ROUND: u64 = u64::MAX;

/// Whether production slashing applies to a block/leader at `round`.
///
/// Equivalent to `round >= SLASHING_ACTIVE_FROM_ROUND`. Single predicate for
/// both the execution gate and the engine's evidence-reporting trigger, so
/// the activation rule has exactly one definition.
#[allow(clippy::absurd_extreme_comparisons)]
pub fn slashing_active_from(round: Round) -> bool {
    round >= SLASHING_ACTIVE_FROM_ROUND
}

/// Round from which the sealed `LeaderHeader::state_root` also commits to
/// the contract code, contract storage and staking tables.
///
/// Before this round the header root is the account sparse Merkle root over
/// balance and nonce only, so a commit-seal quorum authenticates accounts and
/// nothing else. A state-sync snapshot additionally carries staking and
/// contract rows that no seal covers, and the importer therefore cannot trust
/// them. From this round the account tree carries one reserved leaf that
/// holds a digest of those tables (see
/// `kovanica_storage::state_store::AUX_STATE_LEAF_ADDRESS`), so the same seal
/// quorum authenticates the full state and `import_verified_snapshot` can
/// reject forged staking or contract rows.
///
/// Changing the header root is a consensus change: a node without it would
/// compute a different root and its seals would not match. It therefore
/// defaults to `u64::MAX` (inert; state sync refuses every snapshot because
/// none can be authenticated) and is set to `0` at the next genesis / testnet
/// reset, after every validator runs a build containing it. Do not activate it
/// on a running chain without the owner's approval.
pub const STATE_COMMITMENT_ACTIVE_FROM_ROUND: u64 = u64::MAX;

/// Whether the leader header at `round` commits to the full state.
///
/// Equivalent to `round >= STATE_COMMITMENT_ACTIVE_FROM_ROUND`; the single
/// predicate execution uses when it computes the sealed state root.
#[allow(clippy::absurd_extreme_comparisons)]
pub fn state_commitment_active_from(round: Round) -> bool {
    round >= STATE_COMMITMENT_ACTIVE_FROM_ROUND
}

/// Maximum serialized size of a single transaction, in bytes (512 KiB).
///
/// Measured on the bincode encoding, which is what storage and the network
/// use, so every node computes the same size for the same transaction. The
/// cap keeps a hostile or buggy sender from forcing peers to buffer, relay
/// and store arbitrarily large payloads; a wasm `Deploy` is the only kind
/// that can realistically approach it.
pub const MAX_TX_BYTES: usize = 512 * 1024;

/// Maximum serialized size of a block, in bytes (960 KiB).
///
/// Must stay comfortably below the network frame cap (`MAX_TRANSMIT_SIZE`,
/// 1 MiB) so a block that passes consensus validation always fits in one
/// message; `kovanica-network` asserts that relationship in a test.
pub const MAX_BLOCK_BYTES: usize = 960 * 1024;

/// Round from which the consensus size limits take effect.
///
/// Two block-validity rejections are gated on
/// `block.round >= SIZE_LIMITS_ACTIVE_FROM_ROUND` (below it every block
/// validates exactly as before):
///
/// 1. a transaction whose bincode encoding exceeds [`MAX_TX_BYTES`];
/// 2. a block whose bincode encoding exceeds [`MAX_BLOCK_BYTES`].
///
/// Defaults to `u64::MAX` so the rules are **inert** on the currently running
/// testnet: activating them on a live chain without a coordinated upgrade
/// would fork it, because a node that has not yet been updated would still
/// accept an oversized block that an updated node rejects. Set to `0` at the
/// next genesis / testnet reset, after every validator runs a build containing
/// the limits.
pub const SIZE_LIMITS_ACTIVE_FROM_ROUND: u64 = u64::MAX;

/// Whether the consensus size limits apply to a block at `round`.
///
/// Equivalent to `round >= SIZE_LIMITS_ACTIVE_FROM_ROUND`. This is the single
/// predicate the block manager uses, so the activation rule has exactly one
/// definition.
///
/// The lint is allowed because the default activation round is `u64::MAX` (so
/// the rules are inert on the running testnet); the comparison is deliberate,
/// not an accident, and would move here should the constant ever be redefined.
#[allow(clippy::absurd_extreme_comparisons)]
pub fn size_limits_active_from(round: Round) -> bool {
    round >= SIZE_LIMITS_ACTIVE_FROM_ROUND
}

/// Genesis round.
pub const GENESIS_ROUND: Round = 0;

#[cfg(test)]
mod epoch_tests {
    use super::{
        epoch_for_height, epoch_for_round, is_epoch_start_height, EPOCH_LEADER_HEIGHTS,
        EPOCH_ROUNDS, WAVE_LENGTH,
    };

    /// The epoch unit is frozen at 7_200 rounds. Every crate that derives an
    /// epoch from a round must agree on this value; changing it is a consensus
    /// change (it would fork the signing context at every boundary).
    #[test]
    fn epoch_rounds_is_the_frozen_unit() {
        assert_eq!(EPOCH_ROUNDS, 7_200);
    }

    /// `epoch_for_round` is the one shared epoch function. It must be a pure
    /// floor-division of the round so consensus, the network edge, the
    /// committee builder, and the RPC paths all compute the same epoch.
    #[test]
    fn epoch_for_round_is_floor_division_of_the_round() {
        assert_eq!(epoch_for_round(0), 0);
        assert_eq!(epoch_for_round(EPOCH_ROUNDS - 1), 0);
        assert_eq!(epoch_for_round(EPOCH_ROUNDS), 1);
        assert_eq!(epoch_for_round(EPOCH_ROUNDS + 1), 1);
        assert_eq!(epoch_for_round(5 * EPOCH_ROUNDS), 5);
    }

    /// Toni 2026-10-23: one epoch is 7 200 DAG rounds ≈ 8 h, and the
    /// height-based staking epoch has the same length (2 400 leaders).
    #[test]
    fn consensus_and_staking_epochs_are_both_eight_hours() {
        const ROUND_SECS: u64 = 4;
        assert_eq!(EPOCH_ROUNDS, 7_200);
        assert_eq!(EPOCH_ROUNDS * ROUND_SECS, 8 * 3_600);
        assert_eq!(EPOCH_LEADER_HEIGHTS, 2_400);
        assert_eq!(EPOCH_LEADER_HEIGHTS * WAVE_LENGTH * ROUND_SECS, 8 * 3_600);
        // With no skipped slots the counters advance together: height h and
        // round h * WAVE_LENGTH name the same epoch. (The leader at height h
        // is at round (h + 1) * WAVE_LENGTH, so at a boundary the two can
        // differ by that one slot.)
        for height in [0, 1, EPOCH_LEADER_HEIGHTS - 2, EPOCH_LEADER_HEIGHTS * 3 + 7] {
            let round = height * WAVE_LENGTH;
            assert_eq!(epoch_for_height(height), epoch_for_round(round));
        }
    }

    #[test]
    fn epoch_for_height_boundary() {
        assert_eq!(epoch_for_height(0), 0);
        assert_eq!(epoch_for_height(EPOCH_LEADER_HEIGHTS - 1), 0);
        assert_eq!(epoch_for_height(EPOCH_LEADER_HEIGHTS), 1);
        assert_eq!(epoch_for_height(EPOCH_LEADER_HEIGHTS + 1), 1);
        assert_eq!(epoch_for_height(3 * EPOCH_LEADER_HEIGHTS), 3);
        assert!(is_epoch_start_height(0));
        assert!(!is_epoch_start_height(EPOCH_LEADER_HEIGHTS - 1));
        assert!(is_epoch_start_height(EPOCH_LEADER_HEIGHTS));
        assert!(!is_epoch_start_height(EPOCH_LEADER_HEIGHTS + 1));
    }
}
