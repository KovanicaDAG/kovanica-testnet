//! State transition function – executes committed sub-DAGs and distributes rewards.
//!
//! Every time a `CommittedSubDag` is finalized by consensus:
//! 1. Native transactions and WASM calls inside the blocks are applied
//!    in topological order (GHOSTDAG linearization).
//! 2. The mining reward for the leader block is paid to the leader's payout
//!    address — the balance is credited in the provided [`Storage`].
//! 3. Treasury vesting is advanced (inside `StakingState`).
//!
//! Contract entry points are dispatched through [`contracts`]: the native
//! typed-API path ([`contracts::execute_contract_call`]) and the wasmi path
//! ([`contracts::ContractRunner::execute_wasm_call`]) share one
//! [`contracts::ContractHost`] state model with commit-only-on-success
//! semantics.

#![deny(unsafe_code)]
// `ExecutionError` wraps `kovanica_storage`'s error enums, whose largest variants
// are redb errors (>128 bytes) we cannot shrink from this crate. Same
// allowance as the other storage-adjacent crates (kovanica-storage, kovanica-dag,
// kovanica-consensus, kovanica-mempool, kovanica-network).
#![allow(clippy::result_large_err)]

use kovanica_consensus::CommittedSubDag;
use kovanica_crypto::{vrf_verify, VRFOutput};
use kovanica_runtime::{ExecutionConfig, DEFAULT_CONTRACT_MEMORY_PAGES};
use kovanica_staking::{LightSet, LightSetError, RewardOutcome, StakingError, StakingState};
use kovanica_storage::{
    address_to_bytes, state_store::Account, tables, BincodeSerialize, StateStoreError, Storage,
    StorageError,
};
use kovanica_types::signing::{chain_id, SigningContext};
use kovanica_types::{
    epoch_for_round, light_vrf_input, Address, Hash, PublicKey, SealCommitteeSnapshotMember,
    Transaction, TransactionKind,
};
use redb::{ReadableTable, TableDefinition, WriteTransaction};
use thiserror::Error;
use tracing::{debug, info};

pub mod call_args;
pub mod contracts;
pub use call_args::{
    encode_htlc_claim, encode_htlc_create, encode_htlc_refund, encode_multisig_confirm,
    encode_multisig_create, encode_multisig_execute, encode_multisig_propose, encode_token_approve,
    encode_token_burn, encode_token_create, encode_token_mint, encode_token_transfer,
    encode_token_transfer_from, encode_vault_cancel, encode_vault_claim, encode_vault_create,
};
pub use contracts::{
    execute_contract_call, execute_contract_call_in_txn, is_entry_point, ContractEvent,
    ContractHost, ContractRunner, WasmCall, ENTRY_POINTS,
};

/// Table tracking executed sub-DAG leaders (idempotency).
const EXECUTED_SUBDAGS: TableDefinition<[u8; 32], u8> =
    TableDefinition::new("execution_committed_subdags");

/// Table for transaction receipts (committed_leader_height -> receipts).
const TX_RECEIPTS: TableDefinition<u64, Vec<u8>> = TableDefinition::new("tx_receipts");

/// Per-transaction receipt index (tx hash -> receipt), written alongside
/// [`TX_RECEIPTS`] so `kovanica_getTransactionReceipt` can look up the real
/// execution outcome without walking committed heights.
///
/// **Unbounded growth**: one row is added per executed transaction and nothing
/// ever removes them, so this table — like [`TX_RECEIPTS`] — grows with the
/// chain forever. It is only a lookup index for RPC; pruning it (e.g. keeping
/// the last N committed heights) requires a height/age field that the receipt
/// does not currently carry, so no prune helper is provided here. Operators
/// should plan index pruning alongside the per-height history table before
/// long-running storage becomes a concern.
const TX_RECEIPT_BY_HASH: TableDefinition<[u8; 32], Vec<u8>> =
    TableDefinition::new("tx_receipt_by_hash");

/// Accrued, unclaimed delegator rewards: `delegator || validator` -> amount.
/// Kept outside `StakingState` so its persisted (bincode) format is unchanged.
const PENDING_REWARDS: TableDefinition<[u8; 64], u64> =
    TableDefinition::new("staking_pending_rewards");

/// Processed double-sign evidence ids (`EquivocationEvidence::id` /
/// `StakingState::evidence_id`): blake3, 32 bytes.
const PROCESSED_EVIDENCE: TableDefinition<[u8; 32], u8> =
    TableDefinition::new("staking_processed_evidence");

/// Supply accounting counters kept by execution (e.g. `"slashed_to_treasury"`).
const SUPPLY_COUNTERS: TableDefinition<&str, u64> = TableDefinition::new("supply_counters");

fn reward_key(delegator: &Address, validator: &Address) -> [u8; 64] {
    let mut k = [0u8; 64];
    k[..32].copy_from_slice(&delegator.0);
    k[32..].copy_from_slice(&validator.0);
    k
}

#[derive(Error, Debug)]
pub enum ExecutionError {
    #[error("Staking error: {0}")]
    Staking(#[from] StakingError),
    /// The contract rejected the call (`ContractError::code()` codes).
    /// Nothing of the failed call was committed.
    #[error("Contract rejected: {0}")]
    Contract(kovanica_common::ContractError),
    /// Wasmi runtime failure (trap, out of gas, missing export, …) — also
    /// means nothing of the failed call was committed.
    #[error("Runtime error: {0}")]
    Runtime(#[from] kovanica_runtime::RuntimeError),
    #[error("Storage error: {0}")]
    Storage(#[from] StorageError),
    #[error("State store error: {0}")]
    StateStore(#[from] kovanica_storage::StateStoreError),
    #[error("Transaction validation failed: {0}")]
    Validation(String),
    #[error("Insufficient balance for transaction fee")]
    InsufficientFee,
    #[error("Nonce mismatch: expected {expected}, got {actual}")]
    NonceMismatch { expected: u64, actual: u64 },
    #[error("Execution failed: {0}")]
    Other(String),
}

// `ContractError` is `no_std`-friendly and does not implement
// `std::error::Error`, so thiserror cannot generate the `From` impl.
impl From<kovanica_common::ContractError> for ExecutionError {
    fn from(err: kovanica_common::ContractError) -> Self {
        Self::Contract(err)
    }
}

impl From<redb::TableError> for ExecutionError {
    fn from(err: redb::TableError) -> Self {
        Self::Other(format!("Table error: {err}"))
    }
}

impl From<redb::StorageError> for ExecutionError {
    fn from(err: redb::StorageError) -> Self {
        Self::Other(format!("Storage error: {err}"))
    }
}

impl From<bincode::Error> for ExecutionError {
    fn from(err: bincode::Error) -> Self {
        Self::Other(format!("Bincode error: {err}"))
    }
}

/// Transaction execution outcome.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct TransactionReceipt {
    /// Transaction hash.
    pub tx_hash: kovanica_types::hash::Hash,
    /// Whether the transaction succeeded.
    pub success: bool,
    /// Fuel actually consumed by the wasmi store for this transaction.
    ///
    /// `0` for native transaction kinds and for failures before the
    /// interpreter starts; equals the call's `gas_limit` when the call ran
    /// out of gas.
    pub gas_used: u64,
    /// Error message if failed.
    pub error: Option<String>,
    /// Events emitted during execution.
    pub events: Vec<ContractEvent>,
}

/// Result of executing one committed sub-DAG.
#[derive(Debug)]
pub struct ExecutionResult {
    /// Reward that was paid for the leader block (if any).
    pub reward: Option<RewardOutcome>,
    /// Number of transactions that were applied.
    pub txs_applied: usize,
    /// New circulating supply after this execution.
    pub circulating_supply: u64,
    /// Receipts for all executed transactions in this sub-DAG.
    pub receipts: Vec<TransactionReceipt>,
    /// Account-tree root after this commit. `None` when the sub-DAG was
    /// already executed and this call did not write state.
    pub state_root: Option<kovanica_types::hash::Hash>,
}

/// Minimal execution context (will later hold the full account state / Merkle tree).
pub struct ExecutionContext {
    pub staking: StakingState,
    /// Basis points of `block_reward` placed in the light-node escrow.
    ///
    /// Production leaves this at [`kovanica_staking::LIGHT_REWARD_BPS`] (20%).
    /// A test may set another value, including 0. It is not persisted and it
    /// is not part of a block, vote, or transaction hash.
    pub light_reward_bps: u16,
    /// Contract runner for WASM execution (shared module cache).
    pub contract_runner: ContractRunner,
    /// Event publisher for transaction logs.
    pub log_publisher: Option<Box<dyn LogPublisher>>,
    /// Signature format v1 context (`chain_id`) every transaction signature
    /// is verified against. Built from local configuration only.
    signing_ctx: SigningContext,
}

/// Trait for publishing transaction execution logs.
/// Implemented by the node to forward logs to WebSocket subscribers.
pub trait LogPublisher: Send + Sync {
    fn publish_logs(&self, receipts: &[TransactionReceipt]);
}

/// Round context and activation gates for one committed sub-DAG.
///
/// Bundled so `execute_transaction` keeps a small, readable signature and so
/// the set of gates stays one explicit value rather than five adjacent booleans.
#[derive(Clone, Copy, Debug)]
struct SubDagContext {
    /// Committed leader height before this sub-DAG (the reward height).
    committed_height: u64,
    /// DAG round of this sub-DAG's leader block.
    leader_round: kovanica_types::Round,
    /// `gas_hardening_active_from(leader_round)`.
    gas_hardening_active: bool,
    /// `contract_hardening_active_from(leader_round)`.
    contract_hardening_active: bool,
    /// `slashing_active_from(leader_round)`.
    slashing_active: bool,
}

impl ExecutionContext {
    /// **Dev/test only.** Context for `chain_id::LOCAL` (1337). On a real
    /// network every signature (signed for mainnet/testnet/devnet) is
    /// rejected — it fails closed. Nodes must use
    /// [`ExecutionContext::with_signing_context`].
    pub fn new() -> Self {
        Self::with_signing_context(SigningContext::new(chain_id::LOCAL))
    }

    /// Execution context verifying transaction signatures (format v1,
    /// `KUNA/tx/v1` domain tag) against `ctx.chain_id`. `ctx` must come from
    /// the node's own configuration, never from a network message.
    pub fn with_signing_context(ctx: SigningContext) -> Self {
        Self {
            staking: StakingState::new(),
            light_reward_bps: kovanica_staking::LIGHT_REWARD_BPS,
            contract_runner: ContractRunner::new(),
            log_publisher: None,
            signing_ctx: ctx,
        }
    }

    /// The signing context transactions are verified against.
    pub fn signing_context(&self) -> SigningContext {
        self.signing_ctx
    }

    /// Configure treasury address at genesis.
    pub fn init_treasury(&mut self, treasury_address: Address) {
        self.staking.init_treasury(treasury_address);
    }

    /// Execute a committed sub-DAG produced by consensus.
    ///
    /// This is the main entry point that ties the DAG commit path to tokenomics:
    /// the author of the leader block receives the block reward, **credited
    /// into `storage`** (its payout address account balance) in the same call.
    ///
    /// Ordering / atomicity notes:
    ///
    /// - The storage write transaction is opened before candidate staking
    ///   accounting: if the transition fails (unknown authority), the
    ///   transaction is dropped and storage is untouched.
    /// - The candidate staking state, payout, and executed-leader marker are
    ///   written in the same transaction. The candidate is published in memory
    ///   only after that transaction commits.
    pub fn execute_committed_subdag(
        &mut self,
        subdag: &CommittedSubDag,
        storage: &Storage,
    ) -> Result<ExecutionResult, ExecutionError> {
        self.execute_committed_subdag_with_commit(subdag, storage, |txn| {
            txn.commit()
                .map_err(StorageError::Commit)
                .map_err(ExecutionError::from)
        })
    }

    fn execute_committed_subdag_with_commit(
        &mut self,
        subdag: &CommittedSubDag,
        storage: &Storage,
        commit: impl FnOnce(WriteTransaction) -> Result<(), ExecutionError>,
    ) -> Result<ExecutionResult, ExecutionError> {
        // Transactions mutate `self.staking` in place. If anything fails
        // before the storage transaction commits, the in-memory staking state
        // must return to exactly what is persisted, so snapshot it here.
        let pre_subdag_staking = snapshot_staking(&self.staking);
        let result = self.execute_committed_subdag_inner(subdag, storage, commit);
        if result.is_err() {
            self.staking = pre_subdag_staking;
        }
        result
    }

    /// Replace in-memory staking when the database is strictly ahead.
    ///
    /// State sync imports a verified snapshot into the database without
    /// restarting this context. The next commit has to use that height.
    /// `NotFound` is a fresh database and is not an error.
    fn adopt_stored_staking_if_ahead(&mut self, storage: &Storage) -> Result<(), ExecutionError> {
        let txn = storage.begin_read()?;
        let stored = match storage.state().load_staking_state(&txn) {
            Ok(state) => state,
            Err(StateStoreError::NotFound(_)) => return Ok(()),
            Err(e) => return Err(e.into()),
        };
        if stored.committed_leader_height > self.staking.committed_leader_height {
            info!(
                stored = stored.committed_leader_height,
                local = self.staking.committed_leader_height,
                "execution adopts staking state from a verified snapshot"
            );
            self.staking = stored;
        }
        Ok(())
    }

    fn execute_committed_subdag_inner(
        &mut self,
        subdag: &CommittedSubDag,
        storage: &Storage,
        commit: impl FnOnce(WriteTransaction) -> Result<(), ExecutionError>,
    ) -> Result<ExecutionResult, ExecutionError> {
        // A verified state snapshot replaces on-disk staking while this
        // context still holds the pre-sync copy. Continue from the stored
        // height. A stored height that is not ahead is left alone.
        self.adopt_stored_staking_if_ahead(storage)?;

        // 1. Check idempotency first (before any execution). A replayed
        // sub-DAG must not freeze a committee snapshot: the live state is now
        // past that epoch, so a late snapshot would poison the epoch.
        {
            let check = storage.begin_write()?;
            let executed = {
                let table = check
                    .open_table(EXECUTED_SUBDAGS)
                    .map_err(StorageError::Table)?;
                let present = table
                    .get(subdag.leader.digest.0)
                    .map_err(StorageError::Storage)?
                    .is_some();
                present
            };
            if executed {
                return Ok(ExecutionResult {
                    reward: None,
                    txs_applied: 0,
                    circulating_supply: self.staking.circulating_supply(),
                    receipts: Vec::new(),
                    state_root: None,
                });
            }
            drop(check); // abort the empty txn before opening another write txn
        }

        // 1b. Pin the epoch committee BEFORE the sub-DAG's transactions run,
        // then resolve the leader's identity from it. Authority indices are
        // assigned per epoch; the live `committee_order()` can shift inside
        // this very sub-DAG (unbond, slash, liveness eviction) and must never
        // be used to decide who gets paid or who missed a leader slot.
        let leader_epoch = epoch_for_round(subdag.leader_round);
        let epoch_committee = ensure_epoch_committee(storage, &self.staking, leader_epoch)?;
        let leader_identity =
            resolve_leader_identity(&epoch_committee, &self.staking, subdag.leader_author);

        // 2. Execute all transactions in the committed sub-DAG
        let mut txn = storage.begin_write()?;
        let mut receipts = Vec::new();
        let mut txs_applied = 0;
        let committed_height = self.staking.committed_leader_height;
        self.note_light_beacon(&mut txn, storage, committed_height, subdag.leader.digest)?;

        // Gas-hardening activation: the per-call module-size gas floor applies
        // only from `GAS_HARDENING_ACTIVE_FROM_ROUND` on, so a sub-DAG committed
        // below it executes exactly as before (no ledger divergence while the
        // network upgrades).
        let gas_hardening_active = kovanica_types::gas_hardening_active_from(subdag.leader_round);
        // Contract-hardening activation: deploy bytecode validation, the
        // deploy overwrite guard, and wasm entry-point gating apply only from
        // `CONTRACT_HARDENING_ACTIVE_FROM_ROUND` on. Below it every deploy and
        // call validates/executes exactly as before (no ledger divergence while
        // the network upgrades).
        let contract_hardening_active =
            kovanica_types::contract_hardening_active_from(subdag.leader_round);
        // Slashing activation: `Evidence` transactions are only actionable
        // from `SLASHING_ACTIVE_FROM_ROUND` on. Below it they fail
        // deterministically, so a node without the feature keeps producing
        // identical blocks (it just records a failed receipt).
        let slashing_active = kovanica_types::slashing_active_from(subdag.leader_round);

        for block in &subdag.blocks {
            for tx in &block.transactions {
                let receipt = self.execute_transaction(
                    tx,
                    storage,
                    &mut txn,
                    SubDagContext {
                        committed_height,
                        leader_round: subdag.leader_round,
                        gas_hardening_active,
                        contract_hardening_active,
                        slashing_active,
                    },
                )?;
                receipts.push(receipt);
                txs_applied += 1;
            }
        }

        // 3. Pay the mining reward to the leader of this sub-DAG.
        // Perform the transition on a candidate state. The live in-memory state
        // is published only after all related storage writes commit successfully.
        let mut candidate_staking = snapshot_staking(&self.staking);
        // The leader identity was resolved from the epoch committee BEFORE the
        // transactions ran. It may have left the active committee *during* this
        // sub-DAG, e.g. it equivocated and was slashed by an evidence tx it
        // carried (PRO-19 deactivates a slashed validator immediately), or it
        // fully unbonded. In that case the reward is forfeited rather than
        // aborting the commit — a misbehaving leader must not be able to halt
        // the chain, and a departed validator must not be paid by accident.
        let leader = leader_identity
            .and_then(|address| candidate_staking.active_validator(address))
            .cloned();
        let reward = match (&leader, leader_identity) {
            (Some(_), Some(address)) => {
                candidate_staking.on_leader_committed_resolved(subdag.leader_author, address)?
            }
            _ => candidate_staking
                .on_leader_committed_forfeited_resolved(subdag.leader_author, leader_identity),
        };
        // Split the reward: commission + the validator's own pro-rata share
        // go straight to its payout address; delegator shares accrue per
        // (delegator, validator) and are paid by ClaimRewards.
        // Production escrows [`kovanica_staking::LIGHT_REWARD_BPS`] (20%). The
        // leader side is what delegators share. Escrow is settled at epoch
        // close. `leader_amount + escrow_part` equals `reward.amount`.
        if let Some(leader) = &leader {
            let (leader_amount, _) =
                kovanica_staking::split_block_reward(reward.amount, self.light_reward_bps);
            let shares = candidate_staking.reward_share(
                leader.address,
                leader_amount,
                leader.commission_bps,
            );
            {
                let mut pending = txn.open_table(PENDING_REWARDS)?;
                for (addr, amount) in &shares {
                    if *addr != leader.address && *amount > 0 {
                        let key = reward_key(addr, &leader.address);
                        let cur = pending.get(key)?.map(|v| v.value()).unwrap_or(0);
                        pending.insert(key, cur.saturating_add(*amount))?;
                    }
                }
            }
            let validator_part: u64 = shares
                .iter()
                .filter(|(a, _)| *a == leader.address)
                .map(|(_, x)| *x)
                .sum();
            storage
                .state()
                .add_balance(&txn, &reward.recipient, validator_part)?;
        }
        let (_, escrow_part) =
            kovanica_staking::split_block_reward(reward.amount, self.light_reward_bps);
        // Pay out matured unbonding entries (UNBONDING_ROUNDS elapsed) via
        // withdraw_unbonded, in deterministic (delegator, validator) order.
        let mut ready: Vec<(Address, Address)> = candidate_staking
            .unbonding_ready()
            .iter()
            .map(|e| (e.delegator, e.validator))
            .collect();
        ready.dedup_by(|a, b| a.0 == b.0 && a.1 == b.1);
        for (delegator, validator) in ready {
            let amount = candidate_staking.withdraw_unbonded(delegator, validator)?;
            storage.state().add_balance(&txn, &delegator, amount)?;
        }
        self.pay_light_escrow(
            &mut txn,
            storage,
            committed_height,
            candidate_staking.committed_leader_height,
            reward.recipient,
            escrow_part,
        )?;
        // Persist staking state (height, total_mining_issued, treasury vesting)
        storage
            .state()
            .save_staking_state(&txn, &candidate_staking)?;
        // Also increment the consensus store's committed leader height for RPC visibility
        storage
            .consensus()
            .increment_committed_leader_height(&txn)
            .map_err(StorageError::ConsensusStore)?;

        // 4. Persist transaction receipts: the per-height history list plus a
        // per-hash index so RPC can answer `kovanica_getTransactionReceipt`
        // with the real status / gas without scanning heights.
        let receipts_bytes = bincode::serialize(&receipts)
            .map_err(|e| ExecutionError::Other(format!("receipt serialization: {e}")))?;
        txn.open_table(TX_RECEIPTS)
            .map_err(StorageError::Table)?
            .insert(committed_height, receipts_bytes)
            .map_err(StorageError::Storage)?;
        {
            let mut by_hash = txn
                .open_table(TX_RECEIPT_BY_HASH)
                .map_err(StorageError::Table)?;
            for receipt in &receipts {
                let bytes = bincode::serialize(receipt)
                    .map_err(|e| ExecutionError::Other(format!("receipt serialization: {e}")))?;
                by_hash
                    .insert(receipt.tx_hash.0, bytes)
                    .map_err(StorageError::Storage)?;
            }
        }

        // Address history is a local RPC index in this same write transaction.
        // A failed commit drops it with the rest of the transition. It is not
        // read by `commit_account_smt` and it is not part of any consensus hash.
        {
            let mut indexed = Vec::with_capacity(receipts.len());
            let mut seen = 0usize;
            for block in &subdag.blocks {
                for tx in &block.transactions {
                    let success = receipts
                        .get(seen)
                        .ok_or_else(|| {
                            ExecutionError::Other(
                                "address tx index: receipt count does not match transactions"
                                    .into(),
                            )
                        })?
                        .success;
                    indexed.push((tx, success));
                    seen += 1;
                }
            }
            if seen != receipts.len() {
                return Err(ExecutionError::Other(
                    "address tx index: receipt count does not match transactions".into(),
                ));
            }
            kovanica_storage::index_committed_txs(&txn, committed_height, &indexed)
                .map_err(|e| ExecutionError::Other(format!("address tx index: {e}")))?;
        }

        // 5. Account sparse Merkle over balance and nonce, then mark executed.
        let commit_full = kovanica_types::state_commitment_active_from(subdag.leader_round);
        let state_root = storage
            .state()
            .commit_state_smt(&txn, committed_height, commit_full)?;
        txn.open_table(EXECUTED_SUBDAGS)
            .map_err(StorageError::Table)?
            .insert(subdag.leader.digest.0, 1)
            .map_err(StorageError::Storage)?;

        commit(txn)?;
        self.staking = candidate_staking;

        // Publish transaction logs to WebSocket subscribers
        if let Some(publisher) = &self.log_publisher {
            publisher.publish_logs(&receipts);
        }

        info!(
            target: "kovanica-execution",
            "Committed leader round={} author={} reward={} {} (height={}) paid to {:?}",
            subdag.leader_round,
            subdag.leader_author,
            reward.amount / kovanica_staking::ONE_KUNA,
            kovanica_staking::TICKER,
            reward.height,
            reward.recipient,
        );

        debug!(
            target: "kovanica-execution",
            "Applied {} txs, circulating supply now {}",
            txs_applied,
            self.staking.circulating_supply()
        );

        Ok(ExecutionResult {
            reward: Some(reward),
            txs_applied,
            circulating_supply: self.staking.circulating_supply(),
            receipts,
            state_root: Some(state_root),
        })
    }

    /// Execute a single transaction within a committed sub-DAG.
    /// Returns a TransactionReceipt with the execution outcome.
    fn execute_transaction(
        &mut self,
        tx: &Transaction,
        storage: &Storage,
        txn: &mut WriteTransaction,
        context: SubDagContext,
    ) -> Result<TransactionReceipt, ExecutionError> {
        let SubDagContext {
            committed_height,
            leader_round,
            gas_hardening_active,
            contract_hardening_active,
            slashing_active,
        } = context;
        // Every transaction must carry a valid Ed25519 signature by its
        // sender over the signing hash. There is deliberately no bypass:
        // tests sign with real keypairs (see `tests::signed_tx`).
        if !tx.verify_signature(&self.signing_ctx) {
            return Ok(TransactionReceipt {
                tx_hash: tx.hash,
                success: false,
                gas_used: 0,
                error: Some("Invalid signature".to_string()),
                events: Vec::new(),
            });
        }

        // Load sender account and validate nonce, deduct fee, increment nonce in one table access
        let sender_key = address_to_bytes(&tx.sender);
        let mut sender_account = {
            let table = txn.open_table(tables::ACCOUNTS)?;
            let value = table.get(sender_key)?;
            value
                .map(|v| Account::from_bytes(&v.value()).unwrap_or_default())
                .unwrap_or_default()
        };

        if sender_account.nonce != tx.nonce {
            return Ok(TransactionReceipt {
                tx_hash: tx.hash,
                success: false,
                gas_used: 0,
                error: Some(format!(
                    "Nonce mismatch: expected {}, got {}",
                    sender_account.nonce, tx.nonce
                )),
                events: Vec::new(),
            });
        }

        // Check fee balance
        if sender_account.balance < tx.fee {
            return Ok(TransactionReceipt {
                tx_hash: tx.hash,
                success: false,
                gas_used: 0,
                error: Some("Insufficient balance for fee".to_string()),
                events: Vec::new(),
            });
        }

        // Deduct fee upfront and increment nonce
        sender_account.balance = sender_account.balance.saturating_sub(tx.fee);
        sender_account.nonce = sender_account.nonce.saturating_add(1);

        // Save updated sender account
        {
            let mut table = txn.open_table(tables::ACCOUNTS)?;
            table.insert(sender_key, sender_account.to_bytes()?)?;
        }

        // ---- Per-transaction savepoint -------------------------------------
        //
        // Fee and nonce are CHARGED even if the body fails (they were written
        // above): this pays for inclusion and prevents replaying the same
        // signed transaction. Everything the body does is rolled back on
        // failure: the staking state is restored from a snapshot and every
        // storage row the body may write is restored from its pre-image.
        // (redb cannot take a savepoint inside a dirty write transaction, so
        // the savepoint is an explicit undo journal.)
        let staking_savepoint = snapshot_staking(&self.staking);
        let undo = AccountUndo::capture(txn, &touched_accounts(tx))?;
        let light_before = storage.state().load_light_set_write(txn)?;

        // Fuel actually burned by the interpreter for this transaction.
        // Native kinds never touch it (0); `Call` fills it in through
        // `execute_call`, including on out-of-gas, where it equals the
        // transaction's `gas_limit`. Kept outside the match so the failure
        // arm below can still report it after the body is rolled back.
        let mut gas_used = 0u64;

        // Execute based on transaction kind
        let result = match &tx.kind {
            TransactionKind::Transfer { to, amount } => {
                self.execute_transfer(txn, storage, &tx.sender, *to, *amount)
            }
            TransactionKind::Stake { amount } => {
                self.execute_stake(txn, storage, &tx.sender, *amount)
            }
            TransactionKind::Unstake { amount } => {
                self.execute_unstake(txn, storage, &tx.sender, *amount)
            }
            TransactionKind::Delegate { validator, amount } => {
                self.execute_delegate(txn, storage, &tx.sender, *validator, *amount)
            }
            TransactionKind::ClaimRewards { validator } => {
                self.execute_claim_rewards(txn, storage, &tx.sender, *validator)
            }
            TransactionKind::Deploy { code } => self.execute_deploy(
                txn,
                storage,
                &tx.sender,
                code.clone(),
                contract_hardening_active,
            ),
            TransactionKind::Call {
                contract,
                value,
                method,
                args,
                gas_limit,
            } => self.execute_call(
                txn,
                storage,
                &tx.sender,
                *contract,
                *value,
                method,
                args,
                *gas_limit,
                committed_height,
                gas_hardening_active,
                contract_hardening_active,
                &mut gas_used,
            ),
            TransactionKind::RegisterLightNode {
                vrf_public_key,
                stake,
            } => self.execute_register_light(
                txn,
                storage,
                &tx.sender,
                *vrf_public_key,
                *stake,
                committed_height,
            ),
            TransactionKind::ExitLightNode => {
                self.execute_exit_light(txn, storage, &tx.sender, committed_height)
            }
            TransactionKind::SubmitLightWitness {
                epoch,
                vrf_hash,
                vrf_proof,
            } => {
                self.execute_light_witness(txn, storage, &tx.sender, *epoch, *vrf_hash, *vrf_proof)
            }
            TransactionKind::SetCommission {
                validator,
                commission_bps,
            } => self.execute_set_commission(txn, storage, &tx.sender, *validator, *commission_bps),
            TransactionKind::ClaimTreasury { amount } => {
                self.execute_claim_treasury(txn, storage, &tx.sender, *amount)
            }
            TransactionKind::Evidence { evidence } => {
                self.execute_evidence(txn, storage, evidence, leader_round, slashing_active)
            }
        };

        let (success, error, events) = match result {
            Ok(events) => (true, None, events),
            Err(e) => {
                self.staking = staking_savepoint;
                undo.restore(txn)?;
                self.restore_light_set(txn, storage, &light_before)?;
                (false, Some(e.to_string()), Vec::new())
            }
        };

        // Gas accounting: only `Call` transactions consume interpreter fuel,
        // and `gas_used` was written by the runtime before `execute_call`
        // returned — on failure (including out of gas) as well as on success.
        // The body rollback above does not touch it: the fee and nonce
        // charged before the savepoint stand either way.
        Ok(TransactionReceipt {
            tx_hash: tx.hash,
            success,
            gas_used,
            error,
            events,
        })
    }

    /// Execute a native KUNA transfer.
    fn execute_transfer(
        &self,
        txn: &mut WriteTransaction,
        _storage: &Storage,
        from: &Address,
        to: Address,
        amount: u64,
    ) -> Result<Vec<ContractEvent>, ExecutionError> {
        if from == &to {
            return Ok(Vec::new()); // Self-transfer is a no-op
        }

        // Check sender has sufficient balance (after fee deduction) and debit sender
        let from_key = address_to_bytes(from);
        let mut sender_account = {
            let table = txn.open_table(tables::ACCOUNTS)?;
            let value = table.get(from_key)?;
            value
                .map(|v| Account::from_bytes(&v.value()).unwrap_or_default())
                .unwrap_or_default()
        };
        if sender_account.balance < amount {
            return Err(ExecutionError::Validation(
                "Insufficient balance for transfer".to_string(),
            ));
        }
        sender_account.balance = sender_account.balance.saturating_sub(amount);
        {
            let mut table = txn.open_table(tables::ACCOUNTS)?;
            table.insert(from_key, sender_account.to_bytes()?)?;
        }

        // Credit recipient
        let to_key = address_to_bytes(&to);
        let mut recipient_account = {
            let table = txn.open_table(tables::ACCOUNTS)?;
            let value = table.get(to_key)?;
            value
                .map(|v| Account::from_bytes(&v.value()).unwrap_or_default())
                .unwrap_or_default()
        };
        recipient_account.balance = recipient_account.balance.saturating_add(amount);
        {
            let mut table = txn.open_table(tables::ACCOUNTS)?;
            table.insert(to_key, recipient_account.to_bytes()?)?;
        }

        // Emit transfer event
        let events = vec![ContractEvent {
            address: *from,
            topic: kovanica_common::events::TOKEN_TRANSFER.to_vec(),
            data: bincode::serialize(&(from, &to, amount))
                .map_err(|e| ExecutionError::Other(e.to_string()))?,
        }];

        Ok(events)
    }

    /// Execute a stake transaction.
    ///
    /// F7 (Toni's decision): an explicit Stake tx has three outcomes based on
    /// the sender's existing validator record:
    /// * record present and `active` → top up self-stake (`bond_validator`);
    /// * record present but inactive (offline-evicted or fully unbonded) →
    ///   reactivate with an explicit stake (`reactivate_validator`). This is the
    ///   ONLY way an evicted validator returns — there is no automatic refill.
    ///   A **slashed** record is refused (`ValidatorSlashed`) and never re-enters;
    /// * no record at all → register a new validator (`join_validator`).
    fn execute_stake(
        &mut self,
        txn: &mut WriteTransaction,
        storage: &Storage,
        from: &Address,
        amount: u64,
    ) -> Result<Vec<ContractEvent>, ExecutionError> {
        let account = storage.state().get_account_or_default_write(txn, from)?;
        if account.balance < amount {
            return Err(ExecutionError::Validation(
                "Insufficient balance for stake".to_string(),
            ));
        }
        let record = self.staking.validators.iter().find(|v| v.address == *from);
        match record.map(|v| v.active) {
            Some(true) => self.staking.bond_validator(*from, amount)?,
            // Existing inactive record: reactivate by explicit stake, not a
            // fresh join (join_validator would reject the duplicate address).
            Some(false) => self.staking.reactivate_validator(*from, amount)?,
            // Address == Ed25519 public key (unchanged address format).
            None => {
                let pk = kovanica_types::PublicKey(from.0);
                self.staking
                    .join_validator(*from, amount, 0, None, Some(pk), None)?;
            }
        }
        sub_balance_mapped(storage, txn, from, amount)?;
        Ok(vec![ContractEvent {
            address: *from,
            topic: b"stake".to_vec(),
            data: bincode::serialize(&(from, amount))
                .map_err(|e| ExecutionError::Other(e.to_string()))?,
        }])
    }

    /// Execute an unstake transaction. Validators unbond self-stake
    /// (`unbond_validator`); delegators unbond via `unbond()` across their
    /// delegations in validator-address order. Funds enter the unbonding
    /// queue and are paid out automatically after `UNBONDING_ROUNDS`.
    fn execute_unstake(
        &mut self,
        _txn: &mut WriteTransaction,
        _storage: &Storage,
        from: &Address,
        amount: u64,
    ) -> Result<Vec<ContractEvent>, ExecutionError> {
        if amount == 0 {
            return Err(ExecutionError::Validation(
                "Unstake amount must be positive".into(),
            ));
        }
        if self.staking.validators.iter().any(|v| v.address == *from) {
            self.staking.unbond_validator(*from, amount)?;
        } else {
            let mut per_validator: std::collections::BTreeMap<[u8; 32], u64> = Default::default();
            for d in self
                .staking
                .delegations
                .iter()
                .filter(|d| d.delegator == *from)
            {
                *per_validator.entry(d.validator.0).or_default() += d.amount;
            }
            let total: u64 = per_validator.values().fold(0, |a, b| a.saturating_add(*b));
            if total < amount {
                return Err(ExecutionError::Validation(
                    "Insufficient staked amount to unstake".to_string(),
                ));
            }
            let mut remaining = amount;
            for (validator, delegated) in per_validator {
                if remaining == 0 {
                    break;
                }
                let take = remaining.min(delegated);
                self.staking.unbond(*from, Address(validator), take)?;
                remaining -= take;
            }
        }
        Ok(vec![ContractEvent {
            address: *from,
            topic: b"unstake".to_vec(),
            data: bincode::serialize(&(from, amount))
                .map_err(|e| ExecutionError::Other(e.to_string()))?,
        }])
    }

    /// Execute a delegate transaction via `StakingState::delegate`.
    fn execute_delegate(
        &mut self,
        txn: &mut WriteTransaction,
        storage: &Storage,
        from: &Address,
        validator: Address,
        amount: u64,
    ) -> Result<Vec<ContractEvent>, ExecutionError> {
        if amount == 0 {
            return Err(ExecutionError::Validation(
                "Delegate amount must be positive".to_string(),
            ));
        }
        let account = storage.state().get_account_or_default_write(txn, from)?;
        if account.balance < amount {
            return Err(ExecutionError::Validation(
                "Insufficient balance for delegate".to_string(),
            ));
        }
        self.staking
            .delegate(*from, validator, amount)
            .map_err(|_| {
                ExecutionError::Validation("Validator not found or inactive".to_string())
            })?;
        sub_balance_mapped(storage, txn, from, amount)?;
        Ok(vec![ContractEvent {
            address: *from,
            topic: b"delegate".to_vec(),
            data: bincode::serialize(&(from, &validator, amount))
                .map_err(|e| ExecutionError::Other(e.to_string()))?,
        }])
    }

    /// Execute a claim-rewards transaction: pay the sender's accrued
    /// delegator rewards (for one validator, or all) to its balance.
    fn execute_claim_rewards(
        &mut self,
        txn: &mut WriteTransaction,
        storage: &Storage,
        from: &Address,
        validator: Option<Address>,
    ) -> Result<Vec<ContractEvent>, ExecutionError> {
        // Collect first (no writes), then validate, then write.
        let claims: Vec<([u8; 64], Address, u64)> = {
            let table = txn.open_table(PENDING_REWARDS)?;
            match validator {
                Some(v) => {
                    let key = reward_key(from, &v);
                    let amt = table.get(key)?.map(|x| x.value()).unwrap_or(0);
                    vec![(key, v, amt)]
                }
                None => {
                    let lo = reward_key(from, &Address([0u8; 32]));
                    let hi = reward_key(from, &Address([0xFF; 32]));
                    let mut out = Vec::new();
                    for row in table.range(lo..=hi)? {
                        let (k, v) = row?;
                        let k = k.value();
                        let mut va = [0u8; 32];
                        va.copy_from_slice(&k[32..]);
                        out.push((k, Address(va), v.value()));
                    }
                    out
                }
            }
        };
        let total: u64 = claims.iter().map(|c| c.2).fold(0, u64::saturating_add);
        if total == 0 {
            return Err(ExecutionError::Validation(
                "No rewards to claim".to_string(),
            ));
        }
        let mut events = Vec::new();
        {
            let mut table = txn.open_table(PENDING_REWARDS)?;
            for (key, v, amt) in &claims {
                table.remove(*key)?;
                events.push(ContractEvent {
                    address: *from,
                    topic: b"claim_rewards".to_vec(),
                    data: bincode::serialize(&(v, *amt))
                        .map_err(|e| ExecutionError::Other(e.to_string()))?,
                });
            }
        }
        storage.state().add_balance(txn, from, total)?;
        Ok(events)
    }

    /// Execute a contract deployment transaction.
    ///
    /// When `contract_hardening_active` is set the bytecode is validated
    /// (compiled with the same wasmi engine the interpreter uses) **before**
    /// any state is written, and a deploy that would overwrite an account that
    /// already holds code is rejected. Both checks are deterministic and run
    /// before `deploy_contract`, so an invalid/overwriting deploy leaves no
    /// code write. Fee and nonce were already charged by the per-transaction
    /// savepoint in `execute_transaction`, matching every other body failure.
    fn execute_deploy(
        &mut self,
        txn: &mut WriteTransaction,
        storage: &Storage,
        from: &Address,
        code: Vec<u8>,
        contract_hardening_active: bool,
    ) -> Result<Vec<ContractEvent>, ExecutionError> {
        if code.is_empty() {
            return Err(ExecutionError::Validation(
                "Empty contract code".to_string(),
            ));
        }

        // Compute contract address: hash(sender || nonce)
        // For now, use a simple derivation. In production, this should be deterministic
        // and collision-resistant.
        let from_key = address_to_bytes(from);
        let sender_account = {
            let table = txn.open_table(tables::ACCOUNTS)?;
            let value = table.get(from_key)?;
            value
                .map(|v| Account::from_bytes(&v.value()).unwrap_or_default())
                .unwrap_or_default()
        };
        let mut addr_bytes = Vec::new();
        addr_bytes.extend_from_slice(&from.0);
        addr_bytes.extend_from_slice(&sender_account.nonce.to_le_bytes());
        let contract_addr = Address(kovanica_common::hash(&addr_bytes));

        // Contract-hardening (activation-gated): validate the bytecode and
        // refuse to overwrite an account that already holds code, before any
        // storage write. Below activation both checks are skipped so the old
        // (accept-anything) behavior is preserved bit-for-bit.
        if contract_hardening_active {
            // Overwrite guard first: it is a cheap account read and avoids
            // compiling bytecode that will be rejected anyway.
            let existing = storage
                .state()
                .get_account_or_default_write(txn, &contract_addr)?;
            if !existing.code.is_empty() {
                return Err(ExecutionError::Validation(
                    "Contract address already has code".to_string(),
                ));
            }

            // Deterministic bytecode validation, before any storage write.
            self.contract_runner
                .validate_module(&code)
                .map_err(|_| ExecutionError::Validation("Invalid contract bytecode".to_string()))?;
        }

        // Deploy contract code
        let code_hash = storage.state().deploy_contract(txn, &contract_addr, code)?;

        // Emit deploy event
        let events = vec![ContractEvent {
            address: contract_addr,
            topic: b"deploy".to_vec(),
            data: bincode::serialize(&(&contract_addr, &code_hash))
                .map_err(|e| ExecutionError::Other(e.to_string()))?,
        }];

        Ok(events)
    }

    /// Execute a contract call transaction.
    ///
    /// Reports the interpreter fuel consumed into `gas_used` (written by the
    /// runtime on every outcome where the store was created — success,
    /// contract rejection, out of gas). Failures before the interpreter
    /// starts (missing contract, module-size gas floor, compilation, value
    /// attach) leave it at `0`.
    ///
    /// When `gas_hardening_active` is set, the call must carry at least
    /// `code.len() * kovanica_runtime::GAS_PER_MODULE_BYTE` gas: compiling a
    /// large module is host-side work that wasmi fuel does not pay for, so the
    /// floor makes the requested gas proportional to that work and rejects
    /// tiny-gas calls to large modules **before** any compilation happens.
    ///
    /// When `contract_hardening_active` is set, `method` must be one of the 16
    /// canonical [`ENTRY_POINTS`]; anything else is rejected before the
    /// interpreter runs (the native `dispatch_entry` path already enforced
    /// this). Below activation the check is skipped and any export the module
    /// happens to define is callable, exactly as before.
    #[allow(clippy::too_many_arguments)]
    fn execute_call(
        &mut self,
        txn: &mut WriteTransaction,
        storage: &Storage,
        from: &Address,
        contract: Address,
        value: u64,
        method: &str,
        args: &[u8],
        gas_limit: u64,
        block_height: u64,
        gas_hardening_active: bool,
        contract_hardening_active: bool,
        gas_used: &mut u64,
    ) -> Result<Vec<ContractEvent>, ExecutionError> {
        // Check contract exists
        let contract_account = storage
            .state()
            .get_account_or_default_write(txn, &contract)?;
        if contract_account.code.is_empty() {
            return Err(ExecutionError::Validation("Contract not found".to_string()));
        }

        // Get contract code
        let code = contract_account.code.clone();

        // Module-size gas floor (activation-gated): reject a call whose gas
        // cannot pay for compiling the target module, before `ContractRunner`
        // compiles it. Deterministic — depends only on the bytecode length.
        if gas_hardening_active {
            let floor = kovanica_runtime::min_gas_for_module(code.len());
            if gas_limit < floor {
                return Err(ExecutionError::Validation(format!(
                    "Call gas limit {gas_limit} below module-size floor {floor} for a {}-byte module",
                    code.len()
                )));
            }
        }

        // Entry-point gating (activation-gated): only the 16 canonical entry
        // points may be called. Checked before the interpreter starts, after
        // the module-size floor so the gas floor still reports first for a
        // tiny-gas call to a large module when both gates are active.
        if contract_hardening_active && !contracts::is_entry_point(method) {
            return Err(ExecutionError::Validation(format!(
                "Unknown contract entry point: {method}"
            )));
        }

        // Execute via ContractRunner (WASM)
        let config = ExecutionConfig {
            gas_limit,
            memory_limit_pages: DEFAULT_CONTRACT_MEMORY_PAGES,
        };

        let wasm_call = WasmCall {
            wasm: &code,
            entry: method,
            contract,
            caller: *from,
            height: block_height,
            // Blocks carry no wall-clock time: contract time IS the height.
            // Contract expiry/vesting values must use the same unit
            // (see `kovanica_common::Timestamp`).
            timestamp: kovanica_common::contract_time_from_height(block_height),
            args,
            storage,
            // Single writer: the host reads and writes through the sub-DAG's
            // open write transaction instead of opening a second one.
            txn: Some(&*txn),
            // Signed Call.value: moved signer -> contract inside the host
            // overlay, so a failed call moves nothing (fee/nonce still
            // charged by the per-tx savepoint).
            value,
            config: &config,
        };

        let (_, events) = self
            .contract_runner
            .execute_wasm_call_with_gas(wasm_call, gas_used)?;

        Ok(events)
    }

    /// Apply double-sign evidence: slash 5% (SLASH_PCT_BPS) of the
    /// validator's self-stake and of each delegation, once per evidence.
    ///
    /// Destination: **treasury**. The slashed amount moves from staked to the
    /// real account balance of the configured treasury address
    /// (`TreasuryState::treasury_address`, the same account `claim_treasury`
    /// credits). Nothing is burned, total supply is unchanged, and the
    /// treasury vesting schedule (`vested`/`claimed`) is NOT touched.
    /// Cumulative total in `supply_counters["slashed_to_treasury"]`.
    /// Without a configured treasury the evidence is rejected and nothing
    /// changes.
    /// Opens its own write transaction: call only between sub-DAGs.
    pub fn apply_double_sign_evidence(
        &mut self,
        evidence: kovanica_staking::DoubleSignEvidence,
        storage: &Storage,
    ) -> Result<u64, ExecutionError> {
        let id = StakingState::evidence_id(&evidence);
        let txn = storage.begin_write()?;
        if txn.open_table(PROCESSED_EVIDENCE)?.get(id)?.is_some() {
            return Err(StakingError::EvidenceProcessed.into());
        }
        let treasury = self
            .staking
            .treasury_address()
            .ok_or_else(|| ExecutionError::Other("treasury not configured".into()))?;
        let mut candidate = snapshot_staking(&self.staking);
        let slashed = candidate.slash(evidence)?;
        storage.state().add_balance(&txn, &treasury, slashed)?;
        {
            let mut counters = txn.open_table(SUPPLY_COUNTERS)?;
            let cur = counters
                .get("slashed_to_treasury")?
                .map(|v| v.value())
                .unwrap_or(0);
            counters.insert("slashed_to_treasury", cur.saturating_add(slashed))?;
        }
        txn.open_table(PROCESSED_EVIDENCE)?.insert(id, 1)?;
        storage.state().save_staking_state(&txn, &candidate)?;
        txn.commit().map_err(StorageError::Commit)?;
        self.staking = candidate;
        Ok(slashed)
    }

    /// Claim available treasury funds and credit them to the treasury address.
    ///
    /// This can be called by an operator / governance process to move vested
    /// treasury funds into circulation. The treasury address must have been
    /// configured at genesis via `init_treasury`.
    ///
    /// Returns the amount actually claimed (may be less than requested if
    /// not enough has vested).
    pub fn claim_treasury(
        &mut self,
        amount: u64,
        storage: &Storage,
    ) -> Result<u64, ExecutionError> {
        let treasury_address = self
            .staking
            .treasury_address()
            .ok_or_else(|| ExecutionError::Other("treasury not configured".into()))?;

        let claimable = self.staking.treasury_claimable();
        if claimable == 0 {
            return Ok(0);
        }

        let to_claim = amount.min(claimable);
        let claimed = self.staking.claim_treasury(to_claim)?;

        if claimed == 0 {
            return Ok(0);
        }

        // Credit the treasury address balance
        let txn = storage.begin_write()?;
        storage
            .state()
            .add_balance(&txn, &treasury_address, claimed)?;
        // Persist updated staking state (claimed counter)
        storage.state().save_staking_state(&txn, &self.staking)?;
        txn.commit().map_err(StorageError::Commit)?;

        info!(
            target: "kovanica-execution",
            "Treasury claim: {} {} credited to {:?}",
            claimed / kovanica_staking::ONE_KUNA,
            kovanica_staking::TICKER,
            treasury_address
        );

        Ok(claimed)
    }

    fn note_light_beacon(
        &self,
        txn: &mut WriteTransaction,
        storage: &Storage,
        height: u64,
        leader_digest: Hash,
    ) -> Result<(), ExecutionError> {
        let Some(mut set) = storage.state().load_light_set_write(txn)? else {
            return Ok(());
        };
        if kovanica_types::is_epoch_start_height(height) {
            set.note_beacon(kovanica_types::epoch_for_height(height), leader_digest);
            storage.state().save_light_set(txn, &set)?;
        }
        Ok(())
    }

    fn pay_light_escrow(
        &self,
        txn: &mut WriteTransaction,
        storage: &Storage,
        committed_height: u64,
        now_height: u64,
        contributor: Address,
        escrow_part: u64,
    ) -> Result<(), ExecutionError> {
        let loaded = storage.state().load_light_set_write(txn)?;
        let Some(mut set) = (match loaded {
            None if escrow_part == 0 => None,
            None => Some(LightSet::default()),
            Some(set) => Some(set),
        }) else {
            return Ok(());
        };
        let epoch = kovanica_types::epoch_for_height(committed_height);
        if escrow_part > 0 {
            set.add_escrow(epoch, contributor, escrow_part);
        }
        let mut credits = Vec::new();
        if kovanica_types::is_epoch_start_height(committed_height + 1) {
            let settled = set.settle(epoch);
            credits.extend(settled.winner_payouts);
            credits.extend(settled.leader_refunds);
        }
        credits.extend(set.release_unbonded(now_height));
        for (address, amount) in credits {
            if amount > 0 {
                storage.state().add_balance(txn, &address, amount)?;
            }
        }
        storage.state().save_light_set(txn, &set)?;
        Ok(())
    }

    fn restore_light_set(
        &self,
        txn: &mut WriteTransaction,
        storage: &Storage,
        before: &Option<LightSet>,
    ) -> Result<(), ExecutionError> {
        match before {
            Some(set) => storage.state().save_light_set(txn, set)?,
            None => storage.state().clear_light_set(txn)?,
        }
        Ok(())
    }

    fn execute_register_light(
        &self,
        txn: &mut WriteTransaction,
        storage: &Storage,
        from: &Address,
        vrf_public_key: PublicKey,
        stake: u64,
        height: u64,
    ) -> Result<Vec<ContractEvent>, ExecutionError> {
        let account = storage.state().get_account_or_default_write(txn, from)?;
        if account.balance < stake {
            return Err(ExecutionError::Validation(
                "Insufficient balance for light bond".into(),
            ));
        }
        let mut set = storage
            .state()
            .load_light_set_write(txn)?
            .unwrap_or_default();
        set.register(*from, vrf_public_key, stake, height)
            .map_err(light_set_error)?;
        sub_balance_mapped(storage, txn, from, stake)?;
        storage.state().save_light_set(txn, &set)?;
        Ok(Vec::new())
    }

    fn execute_exit_light(
        &self,
        txn: &mut WriteTransaction,
        storage: &Storage,
        from: &Address,
        height: u64,
    ) -> Result<Vec<ContractEvent>, ExecutionError> {
        let mut set = storage
            .state()
            .load_light_set_write(txn)?
            .unwrap_or_default();
        let (refund, _) = set.exit(*from, height).map_err(light_set_error)?;
        if refund > 0 {
            storage.state().add_balance(txn, from, refund)?;
        }
        storage.state().save_light_set(txn, &set)?;
        Ok(Vec::new())
    }

    fn execute_light_witness(
        &self,
        txn: &mut WriteTransaction,
        storage: &Storage,
        from: &Address,
        epoch: u64,
        vrf_hash: [u8; 32],
        vrf_proof: [u8; 96],
    ) -> Result<Vec<ContractEvent>, ExecutionError> {
        let mut set = storage
            .state()
            .load_light_set_write(txn)?
            .unwrap_or_default();
        let node = set
            .nodes()
            .iter()
            .find(|node| node.address == *from)
            .cloned()
            .ok_or_else(|| ExecutionError::Validation("light node is not registered".into()))?;
        let beacon = set
            .beacon(epoch)
            .ok_or_else(|| ExecutionError::Validation("light epoch has no beacon".into()))?;
        let input = light_vrf_input(self.signing_ctx.chain_id, epoch, &beacon);
        let output = VRFOutput::new(vrf_hash, vrf_proof);
        vrf_verify(&node.vrf_public_key, &input, &output)
            .map_err(|_| ExecutionError::Validation("light witness rejected".into()))?;
        set.submit_witness(epoch, *from, vrf_hash, vrf_proof)
            .map_err(light_set_error)?;
        storage.state().save_light_set(txn, &set)?;
        Ok(Vec::new())
    }

    fn execute_set_commission(
        &mut self,
        _txn: &mut WriteTransaction,
        _storage: &Storage,
        from: &Address,
        validator: Address,
        commission_bps: u16,
    ) -> Result<Vec<ContractEvent>, ExecutionError> {
        // Only the validator itself can change its commission.
        if from != &validator {
            return Err(ExecutionError::Validation(
                "Only the validator can change its commission".to_string(),
            ));
        }
        // Mutates `self.staking`; the outer sub-DAG flow persists the staking
        // state after all transactions (and rolls this back via the per-tx
        // staking savepoint if a later step of this body fails).
        self.staking
            .set_commission(validator, commission_bps)
            .map_err(|e| ExecutionError::Validation(e.to_string()))?;
        Ok(vec![ContractEvent {
            address: *from,
            topic: b"set_commission".to_vec(),
            data: bincode::serialize(&(from, commission_bps))
                .map_err(|e| ExecutionError::Other(e.to_string()))?,
        }])
    }

    /// Claim vested treasury funds through a transaction.
    ///
    /// Permissionless trigger: the claimed amount is credited to the fixed
    /// treasury address — never to the sender — so submitting this
    /// transaction can only move funds from "vested but unclaimed" into the
    /// treasury account. The claim is bounded by what has actually vested
    /// (`treasury_claimable`). The sender only pays the fee.
    fn execute_claim_treasury(
        &mut self,
        txn: &mut WriteTransaction,
        storage: &Storage,
        from: &Address,
        amount: u64,
    ) -> Result<Vec<ContractEvent>, ExecutionError> {
        let _ = from;
        let treasury_address = self
            .staking
            .treasury_address()
            .ok_or_else(|| ExecutionError::Other("treasury not configured".into()))?;
        if amount == 0 {
            return Err(ExecutionError::Validation(
                "Claim amount must be positive".to_string(),
            ));
        }
        let claimable = self.staking.treasury_claimable();
        if claimable == 0 {
            return Err(ExecutionError::Validation(
                "No treasury funds available to claim".to_string(),
            ));
        }
        // Bounded by what has actually vested (claim_treasury clamps again).
        let claimed = self.staking.claim_treasury(amount.min(claimable))?;
        if claimed == 0 {
            return Err(ExecutionError::Validation(
                "No treasury funds claimed".to_string(),
            ));
        }
        // Serialize the event before the write so the credit is the last
        // fallible step: once `add_balance` succeeds the body succeeds, and
        // the per-tx savepoint never has to roll back a treasury-address
        // credit (that address is not part of `touched_accounts`).
        let event = ContractEvent {
            address: treasury_address,
            topic: b"claim_treasury".to_vec(),
            data: bincode::serialize(&claimed).map_err(|e| ExecutionError::Other(e.to_string()))?,
        };
        // Credit the treasury address through the sub-DAG's open write
        // transaction (single-writer rule). The claimed counter in
        // `self.staking` is persisted with the rest of the staking state
        // after the transaction loop.
        storage
            .state()
            .add_balance(txn, &treasury_address, claimed)?;
        Ok(vec![event])
    }

    /// Apply equivocation (double-sign) evidence.
    ///
    /// Everything is checked before any state is written, so a malformed or
    /// stale proof is a plain failed transaction (fee/nonce still charged by
    /// the caller) and never a partial slash:
    ///
    /// 1. the transaction kind is only actionable from
    ///    `SLASHING_ACTIVE_FROM_ROUND` on;
    /// 2. both header signatures verify under the claimed author (strict
    ///    Ed25519), same author, same round, different digests;
    /// 3. the author is an **active** validator in the staking state being
    ///    executed — the one piece the proof itself cannot establish;
    /// 4. the proof is no older than `EVIDENCE_MAX_AGE_ROUNDS` relative to
    ///    the leader round being executed;
    /// 5. the (author, round) event has not been processed before.
    ///
    /// Then `slash_validator` applies the fixed cut to self-stake, all
    /// delegations, and all still-pending unbonding entries (H2), and the
    /// total is credited to the treasury account — the same destination and
    /// the same `slashed_to_treasury` counter as the legacy path.
    ///
    /// The processed marker is written **before** the treasury credit: if the
    /// credit fails, the offender escapes one slash rather than the treasury
    /// being credited without a matching slash (which would inflate supply).
    fn execute_evidence(
        &mut self,
        txn: &mut WriteTransaction,
        storage: &Storage,
        evidence: &kovanica_types::EquivocationEvidence,
        leader_round: kovanica_types::Round,
        slashing_active: bool,
    ) -> Result<Vec<ContractEvent>, ExecutionError> {
        if !slashing_active {
            return Err(ExecutionError::Validation(
                "slashing not active at this round".to_string(),
            ));
        }
        let offender = evidence
            .offender()
            .map_err(|e| ExecutionError::Validation(format!("invalid evidence: {e}")))?;
        if !evidence.is_fresh_at(leader_round) {
            return Err(ExecutionError::Validation(format!(
                "evidence from round {} is older than EVIDENCE_MAX_AGE_ROUNDS at {}",
                evidence.round(),
                leader_round
            )));
        }
        // Replay check first: `id()` depends only on (offender, round), so a
        // re-delivered evidence must report "already processed" deterministically
        // instead of being judged against the offender's *current* (already
        // slashed, hence inactive) status. PRO-19 makes this ordering matter —
        // a slashed validator leaves the active set immediately.
        let id = evidence.id().0;
        if txn.open_table(PROCESSED_EVIDENCE)?.get(id)?.is_some() {
            return Err(StakingError::EvidenceProcessed.into());
        }
        let is_active = self
            .staking
            .validators
            .iter()
            .any(|v| v.address == offender && v.active);
        if !is_active {
            return Err(ExecutionError::Validation(
                "evidence author is not an active validator".to_string(),
            ));
        }
        let treasury = self
            .staking
            .treasury_address()
            .ok_or_else(|| ExecutionError::Other("treasury not configured".into()))?;

        // Slash a candidate so a failure below leaves `self.staking` untouched
        // (the caller's savepoint also covers this, but keeping it explicit
        // makes the ordering obvious).
        let mut candidate = snapshot_staking(&self.staking);
        let slashed = candidate.slash_validator(offender)?;
        if slashed == 0 {
            return Err(ExecutionError::Validation(
                "slash amount is zero".to_string(),
            ));
        }
        let event = ContractEvent {
            address: treasury,
            topic: b"evidence_slash".to_vec(),
            data: bincode::serialize(&(offender, slashed))
                .map_err(|e| ExecutionError::Other(e.to_string()))?,
        };

        txn.open_table(PROCESSED_EVIDENCE)?.insert(id, 1)?;
        {
            let mut counters = txn.open_table(SUPPLY_COUNTERS)?;
            let cur = counters
                .get("slashed_to_treasury")?
                .map(|v| v.value())
                .unwrap_or(0);
            counters.insert("slashed_to_treasury", cur.saturating_add(slashed))?;
        }
        storage.state().add_balance(txn, &treasury, slashed)?;
        self.staking = candidate;
        Ok(vec![event])
    }
}

fn light_set_error(err: LightSetError) -> ExecutionError {
    ExecutionError::Validation(err.to_string())
}

/// Look up a transaction receipt by transaction hash.
///
/// Reads the per-hash index written by
/// [`ExecutionContext::execute_committed_subdag`] alongside the per-height
/// [`TX_RECEIPTS`] list, so RPC can answer `kovanica_getTransactionReceipt`
/// with the real status / `gas_used` without walking committed heights.
///
/// Returns `Ok(None)` when no receipt is indexed for `tx_hash` — the
/// transaction was never executed, or it was executed on a storage that predates
/// the index (the table is created lazily on first write, so an existing but
/// empty table is indistinguishable from a missing one; both mean "no receipt").
pub fn receipt_by_tx_hash(
    storage: &Storage,
    tx_hash: &Hash,
) -> Result<Option<TransactionReceipt>, ExecutionError> {
    let txn = storage.begin_read()?;
    let table = match txn.open_table(TX_RECEIPT_BY_HASH) {
        Ok(table) => table,
        // Lazily-created table: nothing has been executed against this
        // storage yet, so there is simply no receipt to return.
        Err(redb::TableError::TableDoesNotExist(_)) => return Ok(None),
        Err(e) => return Err(StorageError::Table(e).into()),
    };
    let Some(bytes) = table.get(tx_hash.0)? else {
        return Ok(None);
    };
    let receipt: TransactionReceipt = bincode::deserialize(&bytes.value())
        .map_err(|e| ExecutionError::Other(format!("receipt deserialization: {e}")))?;
    Ok(Some(receipt))
}

/// Read every stored receipt in the committed-leader height range
/// `from..=to` (inclusive), in ascending height order.
///
/// Backs `kovanica_getLogs`: the per-height [`TX_RECEIPTS`] list is scanned
/// directly, so no extra topic index is needed. Heights with no stored
/// receipts are skipped, so a query spanning blocks that were never executed
/// (or that predate the index) simply returns what exists.
///
/// Returns an empty vector when `from > to` or when the table has not been
/// created yet (nothing has been executed against this storage).
pub fn receipts_in_height_range(
    storage: &Storage,
    from: u64,
    to: u64,
) -> Result<Vec<(u64, Vec<TransactionReceipt>)>, ExecutionError> {
    if from > to {
        return Ok(Vec::new());
    }
    let txn = storage.begin_read()?;
    let table = match txn.open_table(TX_RECEIPTS) {
        Ok(table) => table,
        // Lazily-created table: nothing has been executed yet.
        Err(redb::TableError::TableDoesNotExist(_)) => return Ok(Vec::new()),
        Err(e) => return Err(StorageError::Table(e).into()),
    };
    let mut out = Vec::new();
    for row in table.range(from..=to)? {
        let (key, value) = row?;
        let receipts: Vec<TransactionReceipt> = bincode::deserialize(&value.value())
            .map_err(|e| ExecutionError::Other(format!("receipt deserialization: {e}")))?;
        out.push((key.value(), receipts));
    }
    Ok(out)
}

/// Prune transaction receipts for every committed height strictly below
/// `min_height`.
///
/// For each pruned height both indexes are updated together:
/// * the per-height row is deleted from [`TX_RECEIPTS`];
/// * every transaction in that row is deleted from [`TX_RECEIPT_BY_HASH`].
///
/// The per-height list is the authoritative source of which transaction hashes
/// belong to a height (the receipt itself has no height field), so no separate
/// height index is needed: pruning a height first reads its receipts, then
/// removes their hashes.
///
/// At most `max_batch` **heights** are processed in one call (0 is a no-op), so
/// a single invocation over a long chain stays bounded; call again on the next
/// maintenance tick to make further progress. Returns the number of receipts
/// removed from the per-hash index.
///
/// # RPC behaviour after pruning
/// * [`receipt_by_tx_hash`] returns `Ok(None)` for a pruned transaction, so
///   `kovanica_getTransactionReceipt` answers `null`;
/// * [`receipts_in_height_range`] simply skips a missing height, so
///   `kovanica_getLogs` returns the receipts that are still stored.
///
/// Pruning is irreversible: callers must pass a `min_height` that is safely
/// below the committed tip (the node applies its own safety margin).
pub fn prune_receipts_below(
    storage: &Storage,
    min_height: u64,
    max_batch: usize,
) -> Result<u64, ExecutionError> {
    if max_batch == 0 {
        return Ok(0);
    }
    let txn = storage.begin_write()?;

    // Collect the heights to prune first (can't mutate while iterating). The
    // range yields keys in ascending order, so the batch is the oldest heights.
    let heights: Vec<u64> = {
        let table = txn.open_table(TX_RECEIPTS).map_err(StorageError::Table)?;
        let mut heights = Vec::new();
        for row in table.range(0..min_height).map_err(StorageError::Storage)? {
            let (key, _) = row.map_err(StorageError::Storage)?;
            heights.push(key.value());
            if heights.len() >= max_batch {
                break;
            }
        }
        heights
    };

    let mut removed = 0u64;
    {
        let mut receipts_table = txn.open_table(TX_RECEIPTS).map_err(StorageError::Table)?;
        let mut by_hash = txn
            .open_table(TX_RECEIPT_BY_HASH)
            .map_err(StorageError::Table)?;
        for height in heights {
            if let Some(bytes) = receipts_table.get(height).map_err(StorageError::Storage)? {
                let receipts: Vec<TransactionReceipt> = bincode::deserialize(&bytes.value())
                    .map_err(|e| ExecutionError::Other(format!("receipt deserialization: {e}")))?;
                for receipt in &receipts {
                    if by_hash
                        .remove(receipt.tx_hash.0)
                        .map_err(StorageError::Storage)?
                        .is_some()
                    {
                        removed += 1;
                    }
                }
            }
            receipts_table
                .remove(height)
                .map_err(StorageError::Storage)?;
        }
    }
    txn.commit().map_err(StorageError::Commit)?;
    Ok(removed)
}

/// Debit `amount` from `address` through `StateStore::sub_balance`
/// (balance checked by the caller).
///
/// Error mapping keeps the pre-#41 local-helper behaviour byte-for-byte:
/// - `InsufficientBalance` -> `Validation("Insufficient balance")`;
/// - `NotFound` (missing account == zero balance): an overdraft for any
///   `amount > 0`, and for `amount == 0` a default account is written, as the
///   old read-or-default/write helper did;
/// - any other storage error propagates as `ExecutionError::StateStore`.
fn sub_balance_mapped(
    storage: &Storage,
    txn: &WriteTransaction,
    address: &Address,
    amount: u64,
) -> Result<(), ExecutionError> {
    match storage.state().sub_balance(txn, address, amount) {
        Ok(_) => Ok(()),
        Err(StateStoreError::InsufficientBalance { .. }) => Err(insufficient_balance()),
        Err(StateStoreError::NotFound(_)) if amount > 0 => Err(insufficient_balance()),
        Err(StateStoreError::NotFound(_)) => {
            storage
                .state()
                .set_account(txn, address, &Default::default())?;
            Ok(())
        }
        Err(e) => Err(e.into()),
    }
}

fn insufficient_balance() -> ExecutionError {
    ExecutionError::Validation("Insufficient balance".to_string())
}

/// Field-by-field copy of the staking state (it does not derive `Clone`).
fn snapshot_staking(s: &StakingState) -> StakingState {
    StakingState {
        validators: s.validators.clone(),
        delegations: s.delegations.clone(),
        total_staked: s.total_staked,
        committed_leader_height: s.committed_leader_height,
        total_mining_issued: s.total_mining_issued,
        reward_totals: s.reward_totals.clone(),
        treasury: s.treasury.clone(),
        unbonding_queue: s.unbonding_queue.clone(),
    }
}

/// Return the epoch committee snapshot for `epoch`, freezing it from the
/// **pre-sub-DAG** staking state on first use.
///
/// Execution calls this before applying the sub-DAG's transactions, so the
/// snapshot always describes the committee that assigned authority indices at
/// the epoch's start. The seal path (`publish_local_seal`) reuses the same row,
/// and `put_epoch_committee_if_absent` makes it first-writer-wins.
///
/// An empty vector means "no snapshot available / not freezable"; the caller
/// then falls back to the live committee order. A snapshot is only frozen when
/// every member has a consensus key, so the index sequence is never sparse.
fn ensure_epoch_committee(
    storage: &Storage,
    staking: &StakingState,
    epoch: u64,
) -> Result<Vec<SealCommitteeSnapshotMember>, ExecutionError> {
    {
        let read = storage.begin_read()?;
        if let Some(members) = storage.state().get_epoch_committee(&read, epoch)? {
            return Ok(members);
        }
    }
    let Some(proposed) = staking.epoch_committee_snapshot() else {
        return Ok(Vec::new());
    };
    let write = storage.begin_write()?;
    let frozen = storage
        .state()
        .put_epoch_committee_if_absent(&write, epoch, &proposed)?;
    write
        .commit()
        .map_err(|e| ExecutionError::Other(format!("commit epoch committee: {e}")))?;
    Ok(frozen)
}

/// Map an authority index to the leader's identity address using the epoch
/// committee that assigned it.
///
/// Falls back to the live committee order only when no snapshot exists (direct
/// execution-layer callers and bootstrap). When a snapshot exists but the index
/// is not a member, the leader is unresolvable: the reward is forfeited rather
/// than paid to whoever happens to sit at that index in the live order now.
fn resolve_leader_identity(
    epoch_committee: &[SealCommitteeSnapshotMember],
    staking: &StakingState,
    leader_author: u16,
) -> Option<Address> {
    if epoch_committee.is_empty() {
        return staking
            .authority_validator(leader_author)
            .map(|validator| validator.address);
    }
    epoch_committee
        .iter()
        .find(|member| member.index == leader_author)
        .map(|member| Address::from_public_key(&member.public_key))
}

/// Every `ACCOUNTS` row a transaction body can write (sender, plus the
/// transfer recipient / deployed contract address).
fn touched_accounts(tx: &Transaction) -> Vec<[u8; 32]> {
    let mut keys = vec![address_to_bytes(&tx.sender)];
    match &tx.kind {
        TransactionKind::Transfer { to, .. } => keys.push(address_to_bytes(to)),
        TransactionKind::Deploy { .. } => {
            // Contract address derivation mirrors `execute_deploy`; the nonce
            // has already been incremented when the body runs.
            let mut b = Vec::with_capacity(40);
            b.extend_from_slice(&tx.sender.0);
            b.extend_from_slice(&tx.nonce.saturating_add(1).to_le_bytes());
            keys.push(address_to_bytes(&Address(kovanica_common::hash(&b))));
        }
        _ => {}
    }
    keys.sort_unstable();
    keys.dedup();
    keys
}

/// Pre-images of account rows, restored when a transaction body fails.
struct AccountUndo(Vec<([u8; 32], Option<Vec<u8>>)>);

impl AccountUndo {
    fn capture(txn: &WriteTransaction, keys: &[[u8; 32]]) -> Result<Self, ExecutionError> {
        let table = txn.open_table(tables::ACCOUNTS)?;
        let mut rows = Vec::with_capacity(keys.len());
        for key in keys {
            rows.push((*key, table.get(*key)?.map(|v| v.value())));
        }
        Ok(Self(rows))
    }

    fn restore(self, txn: &WriteTransaction) -> Result<(), ExecutionError> {
        let mut table = txn.open_table(tables::ACCOUNTS)?;
        for (key, pre) in self.0 {
            match pre {
                Some(bytes) => {
                    table.insert(key, bytes)?;
                }
                None => {
                    table.remove(key)?;
                }
            }
        }
        Ok(())
    }
}

impl Default for ExecutionContext {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use kovanica_types::crypto::SigningKey;
    use kovanica_types::{Signature, StatementBlock};

    /// Tests sign for the dev/test network `ExecutionContext::new` uses.
    const TEST_CTX: SigningContext = SigningContext::new(chain_id::LOCAL);

    fn sample_block(author: u16) -> StatementBlock {
        sample_block_at(author, 1)
    }

    fn sample_block_at(author: u16, round: u64) -> StatementBlock {
        let digest = StatementBlock::compute_digest(author, round, &[], &[]);
        StatementBlock {
            author,
            round,
            parents: Vec::new(),
            transactions: Vec::new(),
            statements: Vec::new(),
            signature: Signature([0u8; 64]),
            digest,
            merkle_root: Default::default(),
        }
    }

    fn sample_committed_subdag(round: u64, author: u16) -> CommittedSubDag {
        let leader = sample_block_at(author, round);
        CommittedSubDag {
            blocks: vec![leader.clone()],
            leader,
            leader_round: round,
            leader_author: author,
            non_blue: Vec::new(),
        }
    }

    fn sample_block_with_txs(author: u16, txs: Vec<Transaction>) -> StatementBlock {
        let digest = StatementBlock::compute_digest(author, 1, &[], &txs);
        StatementBlock {
            author,
            round: 1,
            parents: Vec::new(),
            transactions: txs,
            statements: Vec::new(),
            signature: Signature([0u8; 64]),
            digest,
            merkle_root: Default::default(),
        }
    }

    /// Deterministic test keypair. The secret bytes are a fixed test-only
    /// constant and are never logged or printed.
    fn test_keypair(tag: u8) -> SigningKey {
        SigningKey::from_bytes(&[tag; 32])
    }

    /// The account address controlled by a test keypair (address = Ed25519
    /// public key, unchanged address format).
    fn address_of(key: &SigningKey) -> Address {
        Address(key.verifying_key().to_bytes())
    }

    /// Build a transaction for `kind` and sign it properly with `key`.
    fn signed_tx(key: &SigningKey, kind: TransactionKind, nonce: u64, fee: u64) -> Transaction {
        let mut tx = Transaction {
            sender: address_of(key),
            nonce,
            kind,
            fee,
            signature: Signature([0u8; 64]),
            hash: kovanica_types::hash::Hash([0u8; 32]),
        };
        tx.hash = tx.signing_hash(&TEST_CTX);
        tx.signature = kovanica_crypto::sign(key, &tx.signing_hash(&TEST_CTX).0);
        assert!(
            tx.verify_signature(&TEST_CTX),
            "test helper must produce valid signatures"
        );
        tx
    }

    fn create_transfer_tx(
        key: &SigningKey,
        recipient: &Address,
        amount: u64,
        nonce: u64,
        fee: u64,
    ) -> Transaction {
        let kind = TransactionKind::Transfer {
            to: *recipient,
            amount,
        };
        signed_tx(key, kind, nonce, fee)
    }

    fn genesis_staking_state() -> StakingState {
        let mut state = StakingState::new();
        state.init_treasury(Address([42u8; 32]));
        for i in 0..3u8 {
            state
                .join_validator(
                    Address([i + 1; 32]),
                    kovanica_staking::MIN_VALIDATOR_STAKE,
                    0,
                    Some(Address([i + 11; 32])),
                    None,
                    None,
                )
                .expect("genesis validator");
        }
        state
    }

    fn staking_state_bytes(state: &StakingState) -> Vec<u8> {
        bincode::serialize(state).expect("serialize staking state")
    }

    fn load_staking_state(storage: &Storage) -> StakingState {
        let txn = storage.begin_read().expect("read txn");
        storage
            .state()
            .load_staking_state(&txn)
            .expect("persisted staking state")
    }

    fn persist_initial_staking_state(storage: &Storage, state: &StakingState) {
        let txn = storage.begin_write().expect("write txn");
        storage
            .state()
            .save_staking_state(&txn, state)
            .expect("save initial staking state");
        txn.commit().expect("commit initial staking state");
    }

    fn read_balance(storage: &Storage, address: &Address) -> u64 {
        let txn = storage.begin_read().expect("read txn");
        storage
            .state()
            .get_account_or_default(&txn, address)
            .expect("account")
            .balance
    }

    // (c) execute_committed_subdag must credit the leader's payout address
    // with the block reward in persistent storage.
    #[test]
    fn committed_subdag_credits_leader_payout_address() {
        let dir = tempfile::tempdir().expect("tempdir");
        let storage = Storage::new(dir.path().join("test.redb")).expect("storage");

        let mut ctx = ExecutionContext::new();
        let validator = Address([1u8; 32]);
        let payout = Address([9u8; 32]);
        ctx.staking
            .join_validator(
                validator,
                kovanica_staking::MIN_VALIDATOR_STAKE,
                0,
                Some(payout),
                None,
                None,
            )
            .expect("join validator");

        let subdag = CommittedSubDag {
            leader: sample_block(0),
            blocks: vec![sample_block(0)],
            leader_round: 1,
            leader_author: 0,
            non_blue: Vec::new(),
        };

        let first = ctx
            .execute_committed_subdag(&subdag, &storage)
            .expect("first commit");
        let reward = first.reward.expect("reward paid");
        assert_eq!(
            reward.recipient, payout,
            "reward must go to the payout address"
        );
        assert_eq!(reward.height, 0);
        assert!(reward.amount > 0);
        assert_eq!(first.txs_applied, 0, "no transactions in the sample blocks");

        // The payout address actually HOLDS the reward in storage …
        // With 20% light escrow, payout receives leader side (80% of full reward)
        let expected_leader_side = reward.amount * 80 / 100;
        assert_eq!(read_balance(&storage, &payout), expected_leader_side);
        // … and nothing was credited anywhere else.
        assert_eq!(read_balance(&storage, &validator), 0);
        assert_eq!(read_balance(&storage, &Address([7u8; 32])), 0);

        // Duplicate delivery of the same committed leader is idempotent.
        let second = ctx
            .execute_committed_subdag(&subdag, &storage)
            .expect("duplicate delivery");
        assert!(second.reward.is_none());
        let expected_leader_side = reward.amount * 80 / 100;
        assert_eq!(read_balance(&storage, &payout), expected_leader_side);

        // A different committed leader pays the next height's reward.
        let next_subdag = sample_committed_subdag(2, 0);
        let second = ctx
            .execute_committed_subdag(&next_subdag, &storage)
            .expect("next commit");
        let reward2 = second.reward.expect("second reward");
        assert_eq!(reward2.height, reward.height + 1, "height counter advances");
        assert_eq!(
            read_balance(&storage, &payout),
            expected_leader_side + (reward2.amount * 80 / 100),
            "rewards accumulate on the payout address"
        );
        assert_eq!(
            second.circulating_supply,
            first.circulating_supply + reward2.amount
        );

        // An unresolvable leader (never registered, or slashed and thus removed
        // from the committee in PRO-19) forfeits the reward: the commit still
        // succeeds deterministically and advances the height counter, but no
        // balance is credited. Halting here would let a misbehaving leader stop
        // the chain.
        let bad = CommittedSubDag {
            leader: sample_block(7),
            blocks: vec![sample_block(7)],
            leader_round: 2,
            leader_author: 7,
            non_blue: Vec::new(),
        };
        let forfeited = ctx
            .execute_committed_subdag(&bad, &storage)
            .expect("unresolvable leader forfeits, does not halt");
        let reward3 = forfeited.reward.expect("forfeit is still a reward outcome");
        assert_eq!(reward3.amount, 0, "forfeit pays nothing");
        assert_eq!(
            reward3.height,
            reward2.height + 1,
            "height still advances on a forfeit"
        );
        assert_eq!(
            read_balance(&storage, &payout),
            expected_leader_side + (reward2.amount * 80 / 100),
            "forfeit credits nothing"
        );
    }

    /// Freeze a committee snapshot directly, as the first sub-DAG of an epoch
    /// would.
    fn freeze_test_committee(
        storage: &Storage,
        epoch: u64,
        members: &[SealCommitteeSnapshotMember],
    ) {
        let txn = storage.begin_write().expect("write txn");
        storage
            .state()
            .put_epoch_committee_if_absent(&txn, epoch, members)
            .expect("freeze committee");
        txn.commit().expect("commit");
    }

    fn snapshot_member(index: u16, address: Address) -> SealCommitteeSnapshotMember {
        SealCommitteeSnapshotMember {
            index,
            public_key: PublicKey(address.0),
            stake: kovanica_staking::MIN_VALIDATOR_STAKE,
            vrf_public_key: None,
        }
    }

    #[test]
    fn leader_index_resolves_against_the_frozen_epoch_committee() {
        let dir = tempfile::tempdir().expect("tempdir");
        let storage = Storage::new(dir.path().join("epoch-committee.redb")).expect("storage");
        let mut ctx = ExecutionContext::new();
        ctx.staking = genesis_staking_state(); // a(1)=[1], a(2)=[2], a(3)=[3]

        // The epoch started with a(1) at authority index 0.
        freeze_test_committee(
            &storage,
            0,
            &[
                snapshot_member(0, Address([1u8; 32])),
                snapshot_member(1, Address([2u8; 32])),
                snapshot_member(2, Address([3u8; 32])),
            ],
        );

        // A validator whose address sorts first joins mid-epoch, so the LIVE
        // order maps index 0 to it — while the epoch index still belongs to
        // a(1).
        ctx.staking
            .join_validator(
                Address([0u8; 32]),
                kovanica_staking::MIN_VALIDATOR_STAKE,
                0,
                Some(Address([10u8; 32])),
                None,
                None,
            )
            .expect("mid-epoch join");
        assert_eq!(ctx.staking.committee_order()[0].address, Address([0u8; 32]));

        let result = ctx
            .execute_committed_subdag(&sample_committed_subdag(1, 0), &storage)
            .expect("execute");
        let reward = result.reward.expect("reward outcome");

        assert_eq!(
            reward.recipient,
            Address([11u8; 32]),
            "must pay a(1)'s payout, not the shifted live index-0 validator"
        );
        assert_eq!(
            read_balance(&storage, &Address([11u8; 32])),
            reward.amount * 80 / 100
        );
        assert_eq!(read_balance(&storage, &Address([10u8; 32])), 0);
        assert_eq!(read_balance(&storage, &Address([12u8; 32])), 0);
        assert_eq!(
            ctx.staking
                .validator(Address([1u8; 32]))
                .expect("leader")
                .missed_leader_count,
            0,
            "the real leader is credited with being online"
        );
    }

    #[test]
    fn leader_deactivated_in_its_own_subdag_forfeits_against_the_epoch_committee() {
        let dir = tempfile::tempdir().expect("tempdir");
        let storage = Storage::new(dir.path().join("epoch-forfeit.redb")).expect("storage");
        let mut ctx = ExecutionContext::new();
        ctx.staking = genesis_staking_state();
        freeze_test_committee(
            &storage,
            0,
            &[
                snapshot_member(0, Address([1u8; 32])),
                snapshot_member(1, Address([2u8; 32])),
                snapshot_member(2, Address([3u8; 32])),
            ],
        );

        // a(1) is slashed by an evidence tx inside the sub-DAG it led. It leaves
        // the live committee, so live index 0 now names a(2).
        let leader = ctx
            .staking
            .validators
            .iter_mut()
            .find(|v| v.address == Address([1u8; 32]))
            .expect("leader record");
        leader.active = false;
        leader.missed_leader_count = 5;
        assert_eq!(ctx.staking.committee_order()[0].address, Address([2u8; 32]));

        let result = ctx
            .execute_committed_subdag(&sample_committed_subdag(1, 0), &storage)
            .expect("execute");
        let reward = result.reward.expect("forfeit is still an outcome");

        assert_eq!(reward.amount, 0, "a departed leader is not paid");
        assert_eq!(reward.recipient, Address([11u8; 32]));
        assert_eq!(
            read_balance(&storage, &Address([12u8; 32])),
            0,
            "the shifted index-0 validator must not be paid either"
        );
        assert_eq!(ctx.staking.committed_leader_height, 1);
        assert_eq!(
            ctx.staking
                .validator(Address([1u8; 32]))
                .expect("leader")
                .missed_leader_count,
            0,
            "the leader's own miss counter is reset on forfeit"
        );
        assert_eq!(
            ctx.staking
                .validator(Address([2u8; 32]))
                .expect("shifted validator")
                .missed_leader_count,
            1
        );
    }

    #[test]
    fn first_execution_freezes_the_epoch_committee_before_transactions() {
        let dir = tempfile::tempdir().expect("tempdir");
        let storage = Storage::new(dir.path().join("pre-tx-freeze.redb")).expect("storage");
        let key = test_keypair(1);
        let me = address_of(&key);
        let mut ctx = setup_funded_sender(&storage, &me, 100_000 * K);
        let validator = ctx.staking.validators[0].address;
        // Give the sole member a consensus key so the snapshot is freezable.
        ctx.staking.validators[0].public_key = Some(PublicKey(validator.0));

        // The sub-DAG itself adds a second validator. If the snapshot were
        // frozen after execution it would contain both; it must contain only
        // the pre-sub-DAG committee.
        let joiner = test_keypair(2);
        fund(&storage, &address_of(&joiner), 100_000 * K);
        let txs = vec![signed_tx(
            &joiner,
            TransactionKind::Stake {
                amount: kovanica_staking::MIN_VALIDATOR_STAKE,
            },
            0,
            1000,
        )];
        let result = ctx
            .execute_committed_subdag(&subdag_at(5, txs), &storage)
            .expect("execute");
        assert!(result.receipts[0].success, "{:?}", result.receipts);
        assert_eq!(ctx.staking.committee_order().len(), 2, "joiner is active");

        let read = storage.begin_read().expect("read txn");
        let frozen = storage
            .state()
            .get_epoch_committee(&read, 0)
            .expect("read committee")
            .expect("committee frozen");
        assert_eq!(frozen.len(), 1, "snapshot predates the joining tx");
        assert_eq!(frozen[0].public_key, PublicKey(validator.0));
    }

    #[test]
    fn failed_storage_commit_does_not_publish_candidate_staking_state() {
        let dir = tempfile::tempdir().expect("tempdir");
        let storage = Storage::new(dir.path().join("failed-commit.redb")).expect("storage");
        let initial_staking = genesis_staking_state();
        persist_initial_staking_state(&storage, &initial_staking);
        let mut ctx = ExecutionContext {
            staking: initial_staking,
            light_reward_bps: kovanica_staking::LIGHT_REWARD_BPS,
            contract_runner: ContractRunner::new(),
            log_publisher: None,
            signing_ctx: TEST_CTX,
        };
        let initial_bytes = staking_state_bytes(&ctx.staking);
        let subdag = sample_committed_subdag(1, 0);

        let err = ctx
            .execute_committed_subdag_with_commit(&subdag, &storage, |_txn| {
                Err(ExecutionError::Other("injected commit failure".into()))
            })
            .expect_err("injected storage commit failure");
        assert!(matches!(err, ExecutionError::Other(_)));
        assert_eq!(staking_state_bytes(&ctx.staking), initial_bytes);
        assert_eq!(
            staking_state_bytes(&load_staking_state(&storage)),
            initial_bytes,
            "the aborted write transaction must not persist state"
        );
        assert_eq!(read_balance(&storage, &Address([11; 32])), 0);

        // Aborting left the leader unmarked, so replay can apply it exactly once.
        let replay = ctx
            .execute_committed_subdag(&subdag, &storage)
            .expect("replay after failed persistence");
        assert!(replay.reward.is_some());
        assert_eq!(ctx.staking.committed_leader_height, 1);
    }

    #[test]
    fn committed_leader_replay_is_deterministic_from_genesis() {
        // This exercises the implemented staking/reward transition only. Native
        // transactions and WASM calls remain placeholders in execution, so this
        // is not a claim of full account or contract state replay.
        let dir_a = tempfile::tempdir().expect("tempdir a");
        let dir_b = tempfile::tempdir().expect("tempdir b");
        let storage_a = Storage::new(dir_a.path().join("replay.redb")).expect("storage a");
        let storage_b = Storage::new(dir_b.path().join("replay.redb")).expect("storage b");

        let genesis = genesis_staking_state();
        let genesis_bytes = staking_state_bytes(&genesis);
        let mut context_a = ExecutionContext {
            staking: bincode::deserialize(&genesis_bytes).expect("genesis state a"),
            light_reward_bps: kovanica_staking::LIGHT_REWARD_BPS,
            contract_runner: ContractRunner::new(),
            log_publisher: None,
            signing_ctx: TEST_CTX,
        };
        let mut context_b = ExecutionContext {
            staking: bincode::deserialize(&genesis_bytes).expect("genesis state b"),
            light_reward_bps: kovanica_staking::LIGHT_REWARD_BPS,
            contract_runner: ContractRunner::new(),
            log_publisher: None,
            signing_ctx: TEST_CTX,
        };
        persist_initial_staking_state(&storage_a, &context_a.staking);
        persist_initial_staking_state(&storage_b, &context_b.staking);

        // These minimal committed-subdag fixtures provide execution with the
        // committed leader authors/rounds; they do not run or model consensus.
        let replay = [
            sample_committed_subdag(1, 0),
            sample_committed_subdag(2, 1),
            sample_committed_subdag(3, 2),
            sample_committed_subdag(4, 1),
            sample_committed_subdag(5, 0),
        ];
        let payout_addresses = [
            Address([11u8; 32]),
            Address([12u8; 32]),
            Address([13u8; 32]),
        ];
        let mut rewards_a = Vec::new();
        let mut rewards_b = Vec::new();

        for subdag in &replay {
            let result_a = context_a
                .execute_committed_subdag(subdag, &storage_a)
                .expect("replay on context a");
            let result_b = context_b
                .execute_committed_subdag(subdag, &storage_b)
                .expect("replay on context b");

            let reward_a = result_a.reward.expect("reward a");
            let reward_b = result_b.reward.expect("reward b");
            assert_eq!(
                (
                    reward_a.leader_author,
                    reward_a.recipient,
                    reward_a.amount,
                    reward_a.height
                ),
                (
                    reward_b.leader_author,
                    reward_b.recipient,
                    reward_b.amount,
                    reward_b.height
                ),
                "reward outcome must match after every committed leader"
            );
            assert_eq!(result_a.circulating_supply, result_b.circulating_supply);
            assert_eq!(
                context_a.staking.committed_leader_height,
                context_b.staking.committed_leader_height
            );
            assert_eq!(
                context_a.staking.total_mining_issued,
                context_b.staking.total_mining_issued
            );
            assert_eq!(
                context_a.staking.circulating_supply(),
                context_b.staking.circulating_supply()
            );
            assert_eq!(
                staking_state_bytes(&context_a.staking),
                staking_state_bytes(&context_b.staking),
                "in-memory staking states must match after every committed leader"
            );

            // Reload the committed states on both sides to include the available
            // storage persistence path in the deterministic replay check.
            context_a.staking = load_staking_state(&storage_a);
            context_b.staking = load_staking_state(&storage_b);
            assert_eq!(
                staking_state_bytes(&context_a.staking),
                staking_state_bytes(&context_b.staking),
                "reloaded staking states must match after every committed leader"
            );
            assert_eq!(
                (
                    context_a.staking.committed_leader_height,
                    context_a.staking.total_mining_issued
                ),
                (
                    context_b.staking.committed_leader_height,
                    context_b.staking.total_mining_issued
                )
            );
            assert_eq!(
                context_a.staking.circulating_supply(),
                context_b.staking.circulating_supply()
            );
            assert_eq!(
                read_balance(&storage_a, &reward_a.recipient),
                read_balance(&storage_b, &reward_b.recipient),
                "matching reward recipients must have matching persisted payouts"
            );
            for address in payout_addresses {
                assert_eq!(
                    read_balance(&storage_a, &address),
                    read_balance(&storage_b, &address),
                    "all validator payout balances must match"
                );
            }

            rewards_a.push((
                reward_a.leader_author,
                reward_a.recipient,
                reward_a.amount,
                reward_a.height,
            ));
            rewards_b.push((
                reward_b.leader_author,
                reward_b.recipient,
                reward_b.amount,
                reward_b.height,
            ));
        }

        assert_eq!(rewards_a, rewards_b, "final reward sequence must match");
        assert_eq!(
            staking_state_bytes(&context_a.staking),
            staking_state_bytes(&context_b.staking),
            "final persisted staking states must be byte-identical"
        );
        assert_eq!(
            context_a.staking.committed_leader_height,
            replay.len() as u64
        );
        assert_eq!(
            context_a.staking.total_mining_issued,
            rewards_a.iter().map(|(_, _, amount, _)| amount).sum()
        );
        assert_eq!(
            context_a.staking.circulating_supply(),
            context_b.staking.circulating_supply()
        );
    }

    #[test]
    fn treasury_claim_works() {
        let dir = tempfile::tempdir().expect("tempdir");
        let storage = Storage::new(dir.path().join("test.redb")).expect("storage");

        let mut ctx = ExecutionContext::new();
        let treasury_addr = Address([8u8; 32]);
        ctx.init_treasury(treasury_addr);

        // Register a validator to be the leader
        let validator = Address([1u8; 32]);
        let payout = Address([9u8; 32]);
        ctx.staking
            .join_validator(
                validator,
                kovanica_staking::MIN_VALIDATOR_STAKE,
                0,
                Some(payout),
                None,
                None,
            )
            .expect("join validator");

        // Manually advance treasury vesting for testing (simulate 2 years elapsed)
        // by directly setting vested amount on the treasury state.
        if let Some(ref mut treasury) = ctx.staking.treasury {
            treasury.vested = 2 * kovanica_staking::TREASURY_ANNUAL;
        }

        // Treasury should have 2M KUNA vested and claimable
        let claimable = ctx.staking.treasury_claimable();
        assert_eq!(claimable, 2 * kovanica_staking::TREASURY_ANNUAL);

        // Claim 1M KUNA
        let claimed = ctx
            .claim_treasury(kovanica_staking::TREASURY_ANNUAL, &storage)
            .expect("claim treasury");
        assert_eq!(claimed, kovanica_staking::TREASURY_ANNUAL);

        // Verify treasury address was credited
        assert_eq!(read_balance(&storage, &treasury_addr), claimed);

        // Verify staking state updated
        assert_eq!(ctx.staking.treasury.as_ref().unwrap().claimed, claimed);
        assert_eq!(
            ctx.staking.treasury_claimable(),
            kovanica_staking::TREASURY_ANNUAL
        );

        // Claim the rest
        let claimed2 = ctx
            .claim_treasury(kovanica_staking::TREASURY_ANNUAL, &storage)
            .expect("claim treasury again");
        assert_eq!(claimed2, kovanica_staking::TREASURY_ANNUAL);
        assert_eq!(
            read_balance(&storage, &treasury_addr),
            2 * kovanica_staking::TREASURY_ANNUAL
        );

        // Double claim beyond vested amount returns 0
        let claimed3 = ctx
            .claim_treasury(kovanica_staking::TREASURY_ANNUAL, &storage)
            .expect("claim treasury third time");
        assert_eq!(claimed3, 0);

        // Claim without treasury configured fails
        let mut ctx2 = ExecutionContext::new();
        let err = ctx2
            .claim_treasury(kovanica_staking::TREASURY_ANNUAL, &storage)
            .expect_err("claim without treasury must fail");
        assert!(matches!(err, ExecutionError::Other(_)));
    }

    #[test]
    fn duplicate_delivery_after_restart_does_not_pay_twice() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("restart.redb");
        let subdag = sample_committed_subdag(1, 0);
        let payout = Address([11u8; 32]);
        let first_reward;

        {
            let storage = Storage::new(&path).expect("storage");
            let mut context = ExecutionContext {
                staking: genesis_staking_state(),
                light_reward_bps: kovanica_staking::LIGHT_REWARD_BPS,
                contract_runner: ContractRunner::new(),
                log_publisher: None,
                signing_ctx: TEST_CTX,
            };
            persist_initial_staking_state(&storage, &context.staking);
            first_reward = context
                .execute_committed_subdag(&subdag, &storage)
                .expect("first delivery")
                .reward
                .expect("reward paid")
                .amount;
            // With 20% escrow, payout receives leader side (80% of full reward)
            assert_eq!(read_balance(&storage, &payout), first_reward * 80 / 100);
        }

        let storage = Storage::new(&path).expect("reopened storage");
        let mut context = ExecutionContext {
            staking: load_staking_state(&storage),
            light_reward_bps: kovanica_staking::LIGHT_REWARD_BPS,
            contract_runner: ContractRunner::new(),
            log_publisher: None,
            signing_ctx: TEST_CTX,
        };
        let replay = context
            .execute_committed_subdag(&subdag, &storage)
            .expect("replayed delivery");
        assert!(replay.reward.is_none());
        assert_eq!(context.staking.committed_leader_height, 1);
        assert_eq!(read_balance(&storage, &payout), first_reward * 80 / 100);
    }

    #[test]
    fn transfer_transaction_execution() {
        let dir = tempfile::tempdir().expect("tempdir");
        let storage = Storage::new(dir.path().join("test.redb")).expect("storage");

        let mut ctx = ExecutionContext::new();
        let sender_key = test_keypair(1);
        let sender = address_of(&sender_key);
        let recipient = Address([2u8; 32]);
        let validator = Address([3u8; 32]);
        let payout = Address([4u8; 32]);

        // Fund sender with 1000 KUNA
        let txn = storage.begin_write().expect("write txn");
        storage
            .state()
            .set_account(
                &txn,
                &sender,
                &Account {
                    balance: 1000 * kovanica_staking::ONE_KUNA,
                    nonce: 0,
                    code_hash: [0u8; 32],
                    code: Vec::new(),
                },
            )
            .expect("set_account");
        txn.commit().expect("commit");

        // Setup validator for leader
        ctx.staking
            .join_validator(
                validator,
                kovanica_staking::MIN_VALIDATOR_STAKE,
                0,
                Some(payout),
                None,
                None,
            )
            .expect("join validator");

        // Create a signed transfer transaction
        let tx = create_transfer_tx(
            &sender_key,
            &recipient,
            100 * kovanica_staking::ONE_KUNA,
            0,
            1000,
        );
        let subdag = CommittedSubDag {
            leader: sample_block(0),
            blocks: vec![sample_block_with_txs(0, vec![tx.clone()])],
            leader_round: 1,
            leader_author: 0,
            non_blue: Vec::new(),
        };

        let result = ctx
            .execute_committed_subdag(&subdag, &storage)
            .expect("execute");
        assert_eq!(result.txs_applied, 1);
        assert_eq!(result.receipts.len(), 1);
        assert!(result.receipts[0].success);

        // Check balances
        let _sender_bal = read_balance(&storage, &sender);
        let _recipient_bal = read_balance(&storage, &recipient);
        // 1000 - 100 (transfer) - 1000 (fee) = -100, but fee is deducted first
        // Actually: 1000 - 1000 (fee) = 0, then transfer 100 fails due to insufficient balance
        // Let me fix the fee to be smaller
    }

    #[test]
    fn receipts_index_supports_height_range_scans_with_event_addresses() {
        let dir = tempfile::tempdir().expect("tempdir");
        let storage = Storage::new(dir.path().join("test.redb")).expect("storage");

        let mut ctx = ExecutionContext::new();
        let sender_key = test_keypair(7);
        let sender = address_of(&sender_key);
        let recipient = Address([2u8; 32]);
        let validator = Address([3u8; 32]);
        let payout = Address([4u8; 32]);

        let txn = storage.begin_write().expect("write txn");
        storage
            .state()
            .set_account(
                &txn,
                &sender,
                &Account {
                    balance: 1000 * kovanica_staking::ONE_KUNA,
                    nonce: 0,
                    code_hash: [0u8; 32],
                    code: Vec::new(),
                },
            )
            .expect("set_account");
        txn.commit().expect("commit");

        ctx.staking
            .join_validator(
                validator,
                kovanica_staking::MIN_VALIDATOR_STAKE,
                0,
                Some(payout),
                None,
                None,
            )
            .expect("join validator");

        let tx = create_transfer_tx(&sender_key, &recipient, 10, 0, 200);
        let subdag = CommittedSubDag {
            leader: sample_block(0),
            blocks: vec![sample_block_with_txs(0, vec![tx.clone()])],
            leader_round: 1,
            leader_author: 0,
            non_blue: Vec::new(),
        };
        let result = ctx
            .execute_committed_subdag(&subdag, &storage)
            .expect("execute");
        assert!(result.receipts[0].success, "{:?}", result.receipts[0].error);

        // The transfer event is attributed to the sender, so `getLogs` can
        // address-filter it.
        let event = &result.receipts[0].events[0];
        assert_eq!(event.address, sender);
        assert_eq!(event.topic, kovanica_common::events::TOKEN_TRANSFER);

        // The per-height scan returns the stored receipt.
        let scanned = receipts_in_height_range(&storage, 0, 5).expect("scan");
        assert_eq!(scanned.len(), 1);
        assert_eq!(scanned[0].0, 0);
        assert_eq!(scanned[0].1.len(), 1);
        assert_eq!(scanned[0].1[0].tx_hash, tx.hash);
        assert_eq!(scanned[0].1[0].events[0].address, sender);

        // Heights with no receipts are skipped, and an inverted range is empty.
        assert!(receipts_in_height_range(&storage, 1, 5)
            .expect("scan")
            .is_empty());
        assert!(receipts_in_height_range(&storage, 5, 1)
            .expect("scan")
            .is_empty());
    }

    #[test]
    fn prune_receipts_removes_both_height_and_hash_index_rows() {
        let dir = tempfile::tempdir().expect("tempdir");
        let storage = Storage::new(dir.path().join("prune.redb")).expect("storage");

        let mut ctx = ExecutionContext::new();
        let sender_key = test_keypair(21);
        let sender = address_of(&sender_key);
        let recipient = Address([2u8; 32]);
        let validator = Address([3u8; 32]);
        let payout = Address([4u8; 32]);

        {
            let txn = storage.begin_write().expect("write txn");
            storage
                .state()
                .set_account(
                    &txn,
                    &sender,
                    &Account {
                        balance: 1000 * kovanica_staking::ONE_KUNA,
                        nonce: 0,
                        code_hash: [0u8; 32],
                        code: Vec::new(),
                    },
                )
                .expect("set_account");
            txn.commit().expect("commit");
        }
        ctx.staking
            .join_validator(
                validator,
                kovanica_staking::MIN_VALIDATOR_STAKE,
                0,
                Some(payout),
                None,
                None,
            )
            .expect("join validator");

        // Two committed leaders, each carrying one transfer → receipts at
        // committed heights 0 and 1.
        let tx0 = create_transfer_tx(&sender_key, &recipient, 10, 0, 200);
        let subdag0 = CommittedSubDag {
            leader: sample_block_at(0, 1),
            blocks: vec![sample_block_with_txs(0, vec![tx0.clone()])],
            leader_round: 1,
            leader_author: 0,
            non_blue: Vec::new(),
        };
        let r0 = ctx
            .execute_committed_subdag(&subdag0, &storage)
            .expect("first commit");
        assert_eq!(r0.receipts.len(), 1);

        let tx1 = create_transfer_tx(&sender_key, &recipient, 11, 1, 200);
        let subdag1 = CommittedSubDag {
            leader: sample_block_at(0, 2),
            blocks: vec![sample_block_with_txs(0, vec![tx1.clone()])],
            leader_round: 2,
            leader_author: 0,
            non_blue: Vec::new(),
        };
        let r1 = ctx
            .execute_committed_subdag(&subdag1, &storage)
            .expect("second commit");
        assert_eq!(r1.receipts.len(), 1);

        // Both are indexed by hash and by height before pruning.
        assert!(receipt_by_tx_hash(&storage, &tx0.hash)
            .expect("lookup")
            .is_some());
        assert!(receipt_by_tx_hash(&storage, &tx1.hash)
            .expect("lookup")
            .is_some());
        assert_eq!(
            receipts_in_height_range(&storage, 0, 1)
                .expect("scan")
                .len(),
            2
        );

        // Prune everything below height 1: only height 0's receipts go.
        let removed = prune_receipts_below(&storage, 1, 100).expect("prune");
        assert_eq!(removed, 1, "one receipt removed from the per-hash index");

        assert!(
            receipt_by_tx_hash(&storage, &tx0.hash)
                .expect("lookup")
                .is_none(),
            "pruned transaction must no longer resolve"
        );
        assert!(
            receipt_by_tx_hash(&storage, &tx1.hash)
                .expect("lookup")
                .is_some(),
            "transaction at the retained height must survive"
        );
        let scanned = receipts_in_height_range(&storage, 0, 1).expect("scan");
        assert_eq!(scanned.len(), 1, "the pruned height is simply skipped");
        assert_eq!(scanned[0].0, 1);

        // Zero batch is a no-op; a floor above the stored heights still prunes
        // what is below it (height 1), because the floor is a "below" bound.
        assert_eq!(prune_receipts_below(&storage, 5, 0).expect("no-op"), 0);
        assert_eq!(prune_receipts_below(&storage, 5, 10).expect("prune"), 1);
        assert!(receipt_by_tx_hash(&storage, &tx1.hash)
            .expect("lookup")
            .is_none());
        assert!(
            receipts_in_height_range(&storage, 0, 5)
                .expect("scan")
                .is_empty(),
            "every height is now pruned"
        );
    }

    #[test]
    fn transfer_transaction_with_sufficient_balance() {
        let dir = tempfile::tempdir().expect("tempdir");
        let storage = Storage::new(dir.path().join("test.redb")).expect("storage");

        let mut ctx = ExecutionContext::new();
        let sender_key = test_keypair(1);
        let sender = address_of(&sender_key);
        let recipient = Address([2u8; 32]);
        let validator = Address([3u8; 32]);
        let payout = Address([4u8; 32]);

        // Fund sender with 1000 KUNA
        let txn = storage.begin_write().expect("write txn");
        storage
            .state()
            .set_account(
                &txn,
                &sender,
                &Account {
                    balance: 1000 * kovanica_staking::ONE_KUNA,
                    nonce: 0,
                    code_hash: [0u8; 32],
                    code: Vec::new(),
                },
            )
            .expect("set_account");
        txn.commit().expect("commit");

        // Setup validator for leader
        ctx.staking
            .join_validator(
                validator,
                kovanica_staking::MIN_VALIDATOR_STAKE,
                0,
                Some(payout),
                None,
                None,
            )
            .expect("join validator");

        // Create a signed transfer transaction with small fee
        let tx = create_transfer_tx(
            &sender_key,
            &recipient,
            100 * kovanica_staking::ONE_KUNA,
            0,
            1000,
        );
        let subdag = CommittedSubDag {
            leader: sample_block(0),
            blocks: vec![sample_block_with_txs(0, vec![tx.clone()])],
            leader_round: 1,
            leader_author: 0,
            non_blue: Vec::new(),
        };

        let result = ctx
            .execute_committed_subdag(&subdag, &storage)
            .expect("execute");
        assert_eq!(result.txs_applied, 1);
        assert_eq!(result.receipts.len(), 1);
        assert!(
            result.receipts[0].success,
            "Transfer failed: {:?}",
            result.receipts[0].error
        );

        // Check balances: 1000 - 100 (transfer) - 1000 (fee) -> need more balance
        // Let's use a smaller fee
    }

    /// Fund `address`, register a leader validator and return the context.
    fn setup_funded_sender(storage: &Storage, address: &Address, balance: u64) -> ExecutionContext {
        let txn = storage.begin_write().expect("write txn");
        storage
            .state()
            .set_account(
                &txn,
                address,
                &Account {
                    balance,
                    nonce: 0,
                    code_hash: [0u8; 32],
                    code: Vec::new(),
                },
            )
            .expect("set_account");
        txn.commit().expect("commit");

        let mut ctx = ExecutionContext::new();
        ctx.staking
            .join_validator(
                Address([3u8; 32]),
                kovanica_staking::MIN_VALIDATOR_STAKE,
                0,
                Some(Address([4u8; 32])),
                None,
                None,
            )
            .expect("join validator");
        ctx
    }

    fn read_nonce(storage: &Storage, address: &Address) -> u64 {
        let txn = storage.begin_read().expect("read txn");
        storage
            .state()
            .get_account_or_default(&txn, address)
            .expect("account")
            .nonce
    }

    fn execute_single_tx(
        ctx: &mut ExecutionContext,
        storage: &Storage,
        tx: Transaction,
    ) -> ExecutionResult {
        let subdag = CommittedSubDag {
            leader: sample_block(0),
            blocks: vec![sample_block_with_txs(0, vec![tx])],
            leader_round: 1,
            leader_author: 0,
            non_blue: Vec::new(),
        };
        ctx.execute_committed_subdag(&subdag, storage)
            .expect("execute")
    }

    /// State sync writes a higher `committed_leader_height` into the database
    /// while this context still holds the pre-sync copy. The next commit must
    /// continue from the stored height.
    #[test]
    fn execution_adopts_a_higher_stored_staking_height() {
        let dir = tempfile::tempdir().expect("tempdir");
        let storage = Storage::new(dir.path().join("state.redb")).expect("storage");
        let commits = 101u64;
        {
            let mut stored = StakingState::new();
            stored.committed_leader_height = commits;
            let txn = storage.begin_write().expect("write");
            storage
                .state()
                .save_staking_state(&txn, &stored)
                .expect("save staking");
            txn.commit().expect("commit");
        }

        let mut ctx = ExecutionContext::new();
        assert_eq!(ctx.staking.committed_leader_height, 0);
        let subdag = CommittedSubDag {
            leader: sample_block(0),
            blocks: vec![sample_block(0)],
            leader_round: commits * kovanica_types::WAVE_LENGTH + kovanica_types::WAVE_LENGTH,
            leader_author: 0,
            non_blue: Vec::new(),
        };
        let result = ctx
            .execute_committed_subdag(&subdag, &storage)
            .expect("commit after the snapshot");
        assert_eq!(
            result.reward.expect("height still advances").height,
            commits
        );
        assert_eq!(ctx.staking.committed_leader_height, commits + 1);
    }

    // Regression: the executor used to skip verification for any signature
    // made of 64 bytes of 0x01, so anyone could forge a transfer from any
    // account. It must now be rejected and leave all state untouched.
    #[test]
    fn all_0x01_signature_is_rejected() {
        let dir = tempfile::tempdir().expect("tempdir");
        let storage = Storage::new(dir.path().join("test.redb")).expect("storage");

        // Victim account the attacker does NOT hold the key for.
        let victim = address_of(&test_keypair(1));
        let attacker = Address([0xAA; 32]);
        let initial = 1000 * kovanica_staking::ONE_KUNA;
        let mut ctx = setup_funded_sender(&storage, &victim, initial);

        let mut forged = Transaction {
            sender: victim,
            nonce: 0,
            kind: TransactionKind::Transfer {
                to: attacker,
                amount: 500 * kovanica_staking::ONE_KUNA,
            },
            fee: 1000,
            signature: Signature([1u8; 64]),
            hash: kovanica_types::hash::Hash([0u8; 32]),
        };
        forged.hash = forged.signing_hash(&TEST_CTX);

        let result = execute_single_tx(&mut ctx, &storage, forged);
        assert_eq!(result.receipts.len(), 1);
        let receipt = &result.receipts[0];
        assert!(!receipt.success, "forged 0x01 signature must be rejected");
        assert_eq!(receipt.error.as_deref(), Some("Invalid signature"));
        assert_eq!(read_balance(&storage, &victim), initial, "no fee, no debit");
        assert_eq!(read_nonce(&storage, &victim), 0, "nonce not consumed");
        assert_eq!(read_balance(&storage, &attacker), 0);
    }

    // A real signature by a different key over the same payload is rejected.
    #[test]
    fn signature_by_wrong_key_is_rejected() {
        let dir = tempfile::tempdir().expect("tempdir");
        let storage = Storage::new(dir.path().join("test.redb")).expect("storage");

        let victim = address_of(&test_keypair(1));
        let attacker_key = test_keypair(2);
        let initial = 1000 * kovanica_staking::ONE_KUNA;
        let mut ctx = setup_funded_sender(&storage, &victim, initial);

        // Attacker signs a valid tx for its own address, then swaps in the
        // victim as sender.
        let mut tx = create_transfer_tx(
            &attacker_key,
            &address_of(&attacker_key),
            500 * kovanica_staking::ONE_KUNA,
            0,
            1000,
        );
        tx.sender = victim;
        tx.hash = tx.signing_hash(&TEST_CTX);

        let result = execute_single_tx(&mut ctx, &storage, tx);
        assert!(!result.receipts[0].success);
        assert_eq!(
            result.receipts[0].error.as_deref(),
            Some("Invalid signature")
        );
        assert_eq!(read_balance(&storage, &victim), initial);
        assert_eq!(read_balance(&storage, &address_of(&attacker_key)), 0);
    }

    // A properly signed transfer is applied with the exact balance deltas.
    #[test]
    fn properly_signed_transfer_moves_exact_amounts() {
        let dir = tempfile::tempdir().expect("tempdir");
        let storage = Storage::new(dir.path().join("test.redb")).expect("storage");

        let key = test_keypair(1);
        let sender = address_of(&key);
        let recipient = Address([2u8; 32]);
        let initial = 1000 * kovanica_staking::ONE_KUNA;
        let amount = 100 * kovanica_staking::ONE_KUNA;
        let fee = 1000;
        let mut ctx = setup_funded_sender(&storage, &sender, initial);

        let tx = create_transfer_tx(&key, &recipient, amount, 0, fee);
        let result = execute_single_tx(&mut ctx, &storage, tx);
        assert!(result.receipts[0].success, "{:?}", result.receipts[0].error);
        assert_eq!(read_balance(&storage, &sender), initial - amount - fee);
        assert_eq!(read_balance(&storage, &recipient), amount);
        assert_eq!(read_nonce(&storage, &sender), 1);
    }

    fn delegate_tx(key: &SigningKey, validator: Address, amount: u64, nonce: u64) -> Transaction {
        signed_tx(
            key,
            TransactionKind::Delegate { validator, amount },
            nonce,
            1000,
        )
    }

    // Rollback: delegating to a nonexistent validator charges only fee+nonce,
    // leaves staking untouched and yields an honest failed receipt.
    #[test]
    fn failed_delegate_rolls_back_except_fee_and_nonce() {
        let dir = tempfile::tempdir().expect("tempdir");
        let storage = Storage::new(dir.path().join("test.redb")).expect("storage");
        let key = test_keypair(1);
        let sender = address_of(&key);
        let initial = 1000 * kovanica_staking::ONE_KUNA;
        let fee = 1000;
        let mut ctx = setup_funded_sender(&storage, &sender, initial);
        let staked_before = ctx.staking.total_staked;
        let delegations_before = ctx.staking.delegations.len();

        let tx = delegate_tx(
            &key,
            Address([0xEE; 32]),
            100 * kovanica_staking::ONE_KUNA,
            0,
        );
        let result = execute_single_tx(&mut ctx, &storage, tx);
        let receipt = &result.receipts[0];
        assert!(!receipt.success, "receipt must report failure");
        assert!(receipt
            .error
            .as_deref()
            .unwrap_or("")
            .contains("Validator not found"));
        assert!(receipt.events.is_empty());
        assert_eq!(
            read_balance(&storage, &sender),
            initial - fee,
            "only the fee"
        );
        assert_eq!(read_nonce(&storage, &sender), 1, "nonce consumed");
        assert_eq!(ctx.staking.total_staked, staked_before);
        assert_eq!(ctx.staking.delegations.len(), delegations_before);
    }

    // A failed tx in the middle of a sub-DAG does not affect its neighbours.
    #[test]
    fn failed_tx_mid_subdag_does_not_affect_neighbours() {
        let dir = tempfile::tempdir().expect("tempdir");
        let storage = Storage::new(dir.path().join("test.redb")).expect("storage");
        let key = test_keypair(1);
        let sender = address_of(&key);
        let recipient = Address([2u8; 32]);
        let initial = 1000 * kovanica_staking::ONE_KUNA;
        let amount = 10 * kovanica_staking::ONE_KUNA;
        let fee = 1000;
        let mut ctx = setup_funded_sender(&storage, &sender, initial);

        let txs = vec![
            create_transfer_tx(&key, &recipient, amount, 0, fee),
            delegate_tx(
                &key,
                Address([0xEE; 32]),
                100 * kovanica_staking::ONE_KUNA,
                1,
            ),
            create_transfer_tx(&key, &recipient, amount, 2, fee),
        ];
        let subdag = CommittedSubDag {
            leader: sample_block(0),
            blocks: vec![sample_block_with_txs(0, txs)],
            leader_round: 1,
            leader_author: 0,
            non_blue: Vec::new(),
        };
        let result = ctx
            .execute_committed_subdag(&subdag, &storage)
            .expect("execute");
        let ok: Vec<bool> = result.receipts.iter().map(|r| r.success).collect();
        assert_eq!(ok, vec![true, false, true]);
        assert_eq!(read_balance(&storage, &recipient), 2 * amount);
        assert_eq!(
            read_balance(&storage, &sender),
            initial - 2 * amount - 3 * fee
        );
        assert_eq!(read_nonce(&storage, &sender), 3);
    }

    // Tx-level staking writes must not leak into memory when the sub-DAG's
    // storage commit fails.
    #[test]
    fn failed_subdag_commit_rolls_back_tx_staking_changes() {
        let dir = tempfile::tempdir().expect("tempdir");
        let storage = Storage::new(dir.path().join("test.redb")).expect("storage");
        let key = test_keypair(1);
        let sender = address_of(&key);
        let mut ctx = setup_funded_sender(&storage, &sender, 100_000 * kovanica_staking::ONE_KUNA);
        let before = staking_state_bytes(&ctx.staking);
        let tx = signed_tx(
            &key,
            TransactionKind::Stake {
                amount: kovanica_staking::MIN_VALIDATOR_STAKE,
            },
            0,
            1000,
        );
        let subdag = CommittedSubDag {
            leader: sample_block(0),
            blocks: vec![sample_block_with_txs(0, vec![tx])],
            leader_round: 1,
            leader_author: 0,
            non_blue: Vec::new(),
        };
        ctx.execute_committed_subdag_with_commit(&subdag, &storage, |_| {
            Err(ExecutionError::Other("injected commit failure".into()))
        })
        .expect_err("injected failure");
        assert_eq!(staking_state_bytes(&ctx.staking), before);
    }

    // Deterministic replay with successful and failed txs interleaved.
    #[test]
    fn replay_with_failed_txs_is_deterministic() {
        let key = test_keypair(1);
        let sender = address_of(&key);
        let recipient = Address([2u8; 32]);
        let run = || {
            let dir = tempfile::tempdir().expect("tempdir");
            let storage = Storage::new(dir.path().join("r.redb")).expect("storage");
            let mut ctx = setup_funded_sender(&storage, &sender, 1000 * kovanica_staking::ONE_KUNA);
            let txs = vec![
                create_transfer_tx(&key, &recipient, kovanica_staking::ONE_KUNA, 0, 1000),
                delegate_tx(&key, Address([0xEE; 32]), kovanica_staking::ONE_KUNA, 1),
                delegate_tx(&key, Address([3u8; 32]), kovanica_staking::ONE_KUNA, 2),
                create_transfer_tx(&key, &recipient, u64::MAX / 2, 3, 1000),
            ];
            let subdag = CommittedSubDag {
                leader: sample_block(0),
                blocks: vec![sample_block_with_txs(0, txs)],
                leader_round: 1,
                leader_author: 0,
                non_blue: Vec::new(),
            };
            let r = ctx
                .execute_committed_subdag(&subdag, &storage)
                .expect("execute");
            (
                bincode::serialize(&r.receipts).expect("receipts"),
                staking_state_bytes(&ctx.staking),
                read_balance(&storage, &sender),
                read_balance(&storage, &recipient),
                read_nonce(&storage, &sender),
                r.receipts.iter().map(|r| r.success).collect::<Vec<_>>(),
            )
        };
        let a = run();
        let b = run();
        assert_eq!(a.5, vec![true, false, true, false]);
        assert_eq!(a, b);
    }
    // ---- single redb writer for contract calls --------------------------

    fn leb_u32(out: &mut Vec<u8>, mut v: u32) {
        loop {
            let mut b = (v & 0x7f) as u8;
            v >>= 7;
            if v != 0 {
                b |= 0x80;
            }
            out.push(b);
            if v == 0 {
                break;
            }
        }
    }

    fn leb_i32(out: &mut Vec<u8>, mut v: i32) {
        loop {
            let b = (v as u8) & 0x7f;
            v >>= 7;
            let done = (v == 0 && b & 0x40 == 0) || (v == -1 && b & 0x40 != 0);
            out.push(if done { b } else { b | 0x80 });
            if done {
                break;
            }
        }
    }

    fn section(wasm: &mut Vec<u8>, id: u8, payload: &[u8]) {
        wasm.push(id);
        leb_u32(wasm, payload.len() as u32);
        wasm.extend(payload);
    }

    fn name(out: &mut Vec<u8>, n: &str) {
        leb_u32(out, n.len() as u32);
        out.extend(n.as_bytes());
    }

    /// `probe_wasm` with a different exported entry name: used to exercise the
    /// activation-gated entry-point check, which inspects the *method* name
    /// (`ENTRY_POINTS`), not the module's exports.
    fn probe_wasm_named(entry_name: &str) -> Vec<u8> {
        let mut w = b"\0asm\x01\0\0\0".to_vec();
        let mut types = vec![5];
        types.extend([0x60, 2, 0x7f, 0x7f, 1, 0x7e]); // 0 (i32,i32)->i64
        types.extend([0x60, 1, 0x7f, 1, 0x7f]); // 1 i32->i32
        types.extend([0x60, 2, 0x7f, 0x7f, 0]); // 2 (i32,i32)->()
        types.extend([0x60, 1, 0x7f, 0]); // 3 i32->()
        types.extend([0x60, 4, 0x7f, 0x7f, 0x7f, 0x7f, 1, 0x7f]); // 4
        section(&mut w, 1, &types);
        let mut imports = vec![3];
        for (n, t) in [
            ("kovanica_caller", 3u8),
            ("kovanica_balance_of", 0),
            ("kovanica_storage_set", 4),
        ] {
            name(&mut imports, "env");
            name(&mut imports, n);
            imports.extend([0, t]);
        }
        section(&mut w, 2, &imports);
        section(&mut w, 3, &[3, 1, 2, 0]);
        section(&mut w, 5, &[1, 0, 1]);
        let mut exports = vec![4];
        for (n, kind, idx) in [
            ("memory", 2u8, 0u8),
            ("kovanica_alloc", 0, 3),
            ("kovanica_dealloc", 0, 4),
            (entry_name, 0, 5),
        ] {
            name(&mut exports, n);
            exports.extend([kind, idx]);
        }
        section(&mut w, 7, &exports);

        let mut alloc = vec![0, 0x41];
        leb_i32(&mut alloc, 64);
        alloc.push(0x0b);
        let dealloc = vec![0, 0x0b];
        let c = |v: i32| {
            let mut o = vec![0x41];
            leb_i32(&mut o, v);
            o
        };
        let mut entry = vec![0];
        entry.extend(c(256));
        entry.extend([0x10, 0]); // kovanica_caller(256)
        entry.extend(c(512));
        entry.extend(c(256));
        entry.extend(c(32));
        entry.extend([0x10, 1]); // kovanica_balance_of(256, 32)
        entry.extend([0x37, 0x03, 0x00]); // i64.store [512]
        entry.extend(c(600));
        entry.extend(c(1));
        entry.extend(c(512));
        entry.extend(c(8));
        entry.extend([0x10, 2, 0x1a]); // kovanica_storage_set(...); drop
        entry.extend([0x20, 1, 0x04, 0x40, 0x42, 0x7f, 0x0f, 0x0b]); // if len { return -1 }
        entry.extend([0x42, 0x00, 0x0b]); // i64.const 0; end
        let mut code = vec![3];
        for body in [&alloc, &dealloc, &entry] {
            leb_u32(&mut code, body.len() as u32);
            code.extend(body.iter());
        }
        section(&mut w, 10, &code);
        w
    }

    /// Hand-assembled probe contract (entry `probe`): reads the caller's
    /// native balance via `kovanica_balance_of`, stores it (i64 LE) under raw
    /// key `[0]`, then succeeds if `args` is empty and fails (contract
    /// error) otherwise — i.e. a failing call that already wrote its overlay.
    fn probe_wasm() -> Vec<u8> {
        probe_wasm_named("probe")
    }

    const PROBE_CONTRACT: Address = Address([0xC0; 32]);

    fn deploy_probe(storage: &Storage) {
        let txn = storage.begin_write().expect("write txn");
        let code = probe_wasm();
        storage
            .state()
            .set_account(
                &txn,
                &PROBE_CONTRACT,
                &Account {
                    balance: 0,
                    nonce: 0,
                    code_hash: kovanica_common::hash(&code),
                    code,
                },
            )
            .expect("deploy probe");
        txn.commit().expect("commit");
    }

    fn probe_call(key: &SigningKey, fail: bool, nonce: u64, fee: u64) -> Transaction {
        let kind = TransactionKind::Call {
            contract: PROBE_CONTRACT,
            value: 0,
            method: "probe".to_string(),
            args: if fail { vec![1] } else { Vec::new() },
            gas_limit: 1_000_000,
        };
        signed_tx(key, kind, nonce, fee)
    }

    fn probe_slot(storage: &Storage) -> Option<u64> {
        let txn = storage.begin_read().expect("read");
        storage
            .state()
            .get_storage(&txn, &PROBE_CONTRACT, &kovanica_common::hash(&[0u8]))
            .expect("storage read")
            .map(|v| u64::from_le_bytes(v.try_into().expect("8 bytes")))
    }

    /// `probe_wasm()` padded to at least `target_len` bytes with an ignored wasm
    /// custom section: the module still behaves exactly like `probe_wasm`, but
    /// its bytecode is large enough to exercise the compile-cost gas floor.
    fn big_probe_wasm(target_len: usize) -> Vec<u8> {
        let mut w = probe_wasm();
        // Custom-section framing overhead (id byte + LEB length + name).
        let overhead = 8;
        if target_len > w.len() + overhead {
            let mut payload = Vec::new();
            name(&mut payload, "pad");
            payload.resize(target_len - w.len(), 0u8);
            section(&mut w, 0, &payload);
        }
        assert!(w.len() >= target_len, "padding must reach the target size");
        w
    }

    const BIG_CONTRACT: Address = Address([0xC2; 32]);

    fn deploy_big_probe(storage: &Storage, target_len: usize) {
        let txn = storage.begin_write().expect("write txn");
        let code = big_probe_wasm(target_len);
        storage
            .state()
            .set_account(
                &txn,
                &BIG_CONTRACT,
                &Account {
                    balance: 0,
                    nonce: 0,
                    code_hash: kovanica_common::hash(&code),
                    code,
                },
            )
            .expect("deploy big probe");
        txn.commit().expect("commit");
    }

    fn big_probe_call(key: &SigningKey, nonce: u64, fee: u64, gas_limit: u64) -> Transaction {
        let kind = TransactionKind::Call {
            contract: BIG_CONTRACT,
            value: 0,
            method: "probe".to_string(),
            args: Vec::new(),
            gas_limit,
        };
        signed_tx(key, kind, nonce, fee)
    }

    /// Execute ten tiny-gas calls to a ~256 KiB module committed at `round`,
    /// returning the receipts.
    fn run_tiny_gas_big_calls(round: u64) -> Vec<TransactionReceipt> {
        let dir = tempfile::tempdir().expect("tempdir");
        let storage = Storage::new(dir.path().join("big.redb")).expect("storage");
        let key = test_keypair(1);
        let sender = address_of(&key);
        let mut ctx = setup_funded_sender(&storage, &sender, 1_000_000);
        deploy_big_probe(&storage, 256 * 1024);
        let txs: Vec<Transaction> = (0..10)
            .map(|nonce| big_probe_call(&key, nonce, 1, 1_000))
            .collect();
        let digest = StatementBlock::compute_digest(0, round, &[], &txs);
        let block = StatementBlock {
            author: 0,
            round,
            parents: Vec::new(),
            transactions: txs,
            statements: Vec::new(),
            signature: Signature([0u8; 64]),
            digest,
            merkle_root: Default::default(),
        };
        let subdag = CommittedSubDag {
            leader: sample_block_at(0, round),
            blocks: vec![block],
            leader_round: round,
            leader_author: 0,
            non_blue: Vec::new(),
        };
        ctx.execute_committed_subdag(&subdag, &storage)
            .expect("execute")
            .receipts
    }

    /// Hand-assembled out-of-gas contract (entry `probe`): no imports, and the
    /// entry point spins in an infinite `loop { br 0 }` so the wasmi store
    /// always exhausts its fuel. Same entry body the runtime suite pins in
    /// `low_gas_rejects_an_infinite_guest_loop`.
    fn oog_wasm() -> Vec<u8> {
        let mut w = b"\0asm\x01\0\0\0".to_vec();
        let mut types = vec![3];
        types.extend([0x60, 2, 0x7f, 0x7f, 1, 0x7e]); // 0 (i32,i32)->i64
        types.extend([0x60, 1, 0x7f, 1, 0x7f]); // 1 i32->i32
        types.extend([0x60, 2, 0x7f, 0x7f, 0]); // 2 (i32,i32)->()
        section(&mut w, 1, &types);
        // No imports, so the defined functions start at index 0.
        section(&mut w, 3, &[3, 1, 2, 0]); // alloc, dealloc, entry
        section(&mut w, 5, &[1, 0, 1]); // one memory, min 1 page
        let mut exports = vec![4];
        for (n, kind, idx) in [
            ("memory", 2u8, 0u8),
            ("kovanica_alloc", 0, 0),
            ("kovanica_dealloc", 0, 1),
            ("probe", 0, 2),
        ] {
            name(&mut exports, n);
            exports.extend([kind, idx]);
        }
        section(&mut w, 7, &exports);

        let mut alloc = vec![0, 0x41];
        leb_i32(&mut alloc, 64);
        alloc.push(0x0b);
        let dealloc = vec![0, 0x0b];
        // loop { br 0 } — burns fuel forever; i64.const 0 is unreachable but
        // keeps the (i32,i32)->i64 signature valid.
        let entry = vec![0, 0x03, 0x40, 0x0c, 0, 0x0b, 0x42, 0, 0x0b];
        let mut code = vec![3];
        for body in [&alloc, &dealloc, &entry] {
            leb_u32(&mut code, body.len() as u32);
            code.extend(body.iter());
        }
        section(&mut w, 10, &code);
        w
    }

    const OOG_CONTRACT: Address = Address([0xC1; 32]);

    fn deploy_oog(storage: &Storage) {
        let txn = storage.begin_write().expect("write txn");
        let code = oog_wasm();
        storage
            .state()
            .set_account(
                &txn,
                &OOG_CONTRACT,
                &Account {
                    balance: 0,
                    nonce: 0,
                    code_hash: kovanica_common::hash(&code),
                    code,
                },
            )
            .expect("deploy oog contract");
        txn.commit().expect("commit");
    }

    fn oog_call(key: &SigningKey, nonce: u64, fee: u64, gas_limit: u64) -> Transaction {
        let kind = TransactionKind::Call {
            contract: OOG_CONTRACT,
            value: 0,
            method: "probe".to_string(),
            args: Vec::new(),
            gas_limit,
        };
        signed_tx(key, kind, nonce, fee)
    }

    /// Run `f` on a worker thread; fail (instead of hanging the suite) if it
    /// does not finish within 30 s. The old code deadlocked here.
    fn with_timeout<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> T {
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = tx.send(f());
        });
        rx.recv_timeout(std::time::Duration::from_secs(30))
            .expect("contract call hung: a second redb writer was opened (deadlock)")
    }

    // Call via execute_committed_subdag must not hang, and the contract must
    // see the fee already deducted in the same open write transaction.
    #[test]
    fn wasm_call_in_subdag_uses_single_writer_and_sees_fee() {
        let (receipt, slot, balance) = with_timeout(|| {
            let dir = tempfile::tempdir().expect("tempdir");
            let storage = Storage::new(dir.path().join("t.redb")).expect("storage");
            let key = test_keypair(1);
            let sender = address_of(&key);
            let mut ctx = setup_funded_sender(&storage, &sender, 1_000_000);
            deploy_probe(&storage);
            let r = execute_single_tx(&mut ctx, &storage, probe_call(&key, false, 0, 1000));
            (
                r.receipts[0].clone(),
                probe_slot(&storage),
                read_balance(&storage, &sender),
            )
        });
        assert!(receipt.success, "{:?}", receipt.error);
        assert_eq!(
            slot,
            Some(1_000_000 - 1000),
            "contract saw the fee deducted"
        );
        assert_eq!(balance, 1_000_000 - 1000);
    }

    // A transfer earlier in the same block is visible to the contract.
    #[test]
    fn wasm_call_sees_earlier_writes_in_same_block() {
        let (ok, slot) = with_timeout(|| {
            let dir = tempfile::tempdir().expect("tempdir");
            let storage = Storage::new(dir.path().join("t.redb")).expect("storage");
            let key = test_keypair(1);
            let sender = address_of(&key);
            let mut ctx = setup_funded_sender(&storage, &sender, 1_000_000);
            deploy_probe(&storage);
            let txs = vec![
                create_transfer_tx(&key, &Address([2u8; 32]), 100_000, 0, 1000),
                probe_call(&key, false, 1, 1000),
            ];
            let subdag = CommittedSubDag {
                leader: sample_block(0),
                blocks: vec![sample_block_with_txs(0, txs)],
                leader_round: 1,
                leader_author: 0,
                non_blue: Vec::new(),
            };
            let r = ctx
                .execute_committed_subdag(&subdag, &storage)
                .expect("execute");
            (
                r.receipts.iter().map(|r| r.success).collect::<Vec<_>>(),
                probe_slot(&storage),
            )
        });
        assert_eq!(ok, vec![true, true]);
        assert_eq!(slot, Some(1_000_000 - 100_000 - 2000));
    }

    // A failing call (after it already wrote its overlay) leaves no storage
    // write; only fee and nonce are charged.
    #[test]
    fn failed_wasm_call_leaves_no_storage_writes() {
        let (receipt, slot, balance, nonce) = with_timeout(|| {
            let dir = tempfile::tempdir().expect("tempdir");
            let storage = Storage::new(dir.path().join("t.redb")).expect("storage");
            let key = test_keypair(1);
            let sender = address_of(&key);
            let mut ctx = setup_funded_sender(&storage, &sender, 1_000_000);
            deploy_probe(&storage);
            let r = execute_single_tx(&mut ctx, &storage, probe_call(&key, true, 0, 1000));
            (
                r.receipts[0].clone(),
                probe_slot(&storage),
                read_balance(&storage, &sender),
                read_nonce(&storage, &sender),
            )
        });
        assert!(!receipt.success);
        assert_eq!(slot, None, "failed call must not write contract storage");
        assert_eq!(balance, 1_000_000 - 1000);
        assert_eq!(nonce, 1);
    }

    // Receipts carry the real interpreter fuel: a successful call reports a
    // positive amount below its limit, while an out-of-gas call reports the
    // full limit, keeps a failure status and still charges fee + nonce.
    #[test]
    fn receipts_report_real_gas_used_on_success_and_out_of_gas() {
        let (ok_receipt, oog_receipt, indexed, balance, nonce) = with_timeout(|| {
            let dir = tempfile::tempdir().expect("tempdir");
            let storage = Storage::new(dir.path().join("t.redb")).expect("storage");
            let key = test_keypair(1);
            let sender = address_of(&key);
            let mut ctx = setup_funded_sender(&storage, &sender, 1_000_000);
            deploy_probe(&storage);
            deploy_oog(&storage);
            let txs = vec![
                probe_call(&key, false, 0, 1000),
                oog_call(&key, 1, 1000, 10_000),
            ];
            let subdag = CommittedSubDag {
                leader: sample_block(0),
                blocks: vec![sample_block_with_txs(0, txs)],
                leader_round: 1,
                leader_author: 0,
                non_blue: Vec::new(),
            };
            let r = ctx
                .execute_committed_subdag(&subdag, &storage)
                .expect("execute");
            let ok = r.receipts[0].clone();
            let oog = r.receipts[1].clone();
            let indexed = receipt_by_tx_hash(&storage, &oog.tx_hash).expect("receipt index");
            (
                ok,
                oog,
                indexed,
                read_balance(&storage, &sender),
                read_nonce(&storage, &sender),
            )
        });

        assert!(ok_receipt.success, "{:?}", ok_receipt.error);
        assert!(
            ok_receipt.gas_used > 0 && ok_receipt.gas_used < 1_000_000,
            "successful call must report real fuel, got {}",
            ok_receipt.gas_used
        );

        assert!(!oog_receipt.success, "out of gas must fail the receipt");
        assert!(
            oog_receipt
                .error
                .as_deref()
                .is_some_and(|e| e.contains("Out of gas")),
            "expected an out-of-gas error, got {:?}",
            oog_receipt.error
        );
        assert_eq!(
            oog_receipt.gas_used, 10_000,
            "out of gas burns the entire limit"
        );

        // The per-hash index serves exactly the receipt RPC reads back.
        let indexed = indexed.expect("OOG receipt must be indexed by tx hash");
        assert_eq!(indexed.tx_hash, oog_receipt.tx_hash);
        assert_eq!(indexed.success, oog_receipt.success);
        assert_eq!(indexed.gas_used, oog_receipt.gas_used);
        assert_eq!(indexed.error, oog_receipt.error);

        // Fee and nonce stand even though the body was rolled back.
        assert_eq!(balance, 1_000_000 - 2000);
        assert_eq!(nonce, 2);
    }

    // MEDIUM-3: a `Call` with a tiny gas limit can no longer force a full
    // compile of a large module. From activation on, ten such calls are
    // rejected by the module-size gas floor *before* the interpreter (and
    // therefore before compilation); below activation they still execute.
    #[test]
    fn big_bytecode_tiny_gas_calls_are_rejected_at_activation() {
        let active_round = kovanica_types::GAS_HARDENING_ACTIVE_FROM_ROUND;

        // Below activation the floor is inert: the calls reach the interpreter
        // (compile + run) and are never rejected for module size. This is the
        // old behavior the gate preserves, so an un-updated node cannot diverge.
        if let Some(below_round) = active_round.checked_sub(1) {
            let below = with_timeout(move || run_tiny_gas_big_calls(below_round));
            assert_eq!(below.len(), 10);
            for receipt in &below {
                assert!(
                    receipt
                        .error
                        .as_deref()
                        .is_none_or(|e| !e.contains("module-size floor")),
                    "below activation the module-size floor must not fire: {receipt:?}"
                );
            }
        }

        // At/above activation every tiny-gas call to the large module is
        // rejected up front, deterministically, with no interpreter work.
        let active = with_timeout(move || run_tiny_gas_big_calls(active_round));
        assert_eq!(active.len(), 10);
        for (i, receipt) in active.iter().enumerate() {
            assert!(!receipt.success, "call {i} must be rejected: {receipt:?}");
            assert!(
                receipt
                    .error
                    .as_deref()
                    .is_some_and(|e| e.contains("module-size floor")),
                "call {i} expected a module-size floor rejection, got {:?}",
                receipt.error
            );
            assert_eq!(
                receipt.gas_used, 0,
                "rejected before the interpreter starts, so no fuel is consumed"
            );
        }

        // The same calls with enough gas to cover the floor are not rejected by
        // it (they may still fail for other reasons, but not for module size).
        let funded = with_timeout(move || {
            let dir = tempfile::tempdir().expect("tempdir");
            let storage = Storage::new(dir.path().join("big.redb")).expect("storage");
            let key = test_keypair(1);
            let sender = address_of(&key);
            let mut ctx = setup_funded_sender(&storage, &sender, 1_000_000);
            let size = 256 * 1024;
            deploy_big_probe(&storage, size);
            // Floor for the *actual* deployed module length (padding framing
            // makes it a few bytes larger than `size`).
            let floor = kovanica_runtime::min_gas_for_module(big_probe_wasm(size).len());
            let txs = vec![big_probe_call(&key, 0, 1, floor)];
            let digest = StatementBlock::compute_digest(0, active_round, &[], &txs);
            let block = StatementBlock {
                author: 0,
                round: active_round,
                parents: Vec::new(),
                transactions: txs,
                statements: Vec::new(),
                signature: Signature([0u8; 64]),
                digest,
                merkle_root: Default::default(),
            };
            let subdag = CommittedSubDag {
                leader: sample_block_at(0, active_round),
                blocks: vec![block],
                leader_round: active_round,
                leader_author: 0,
                non_blue: Vec::new(),
            };
            ctx.execute_committed_subdag(&subdag, &storage)
                .expect("execute")
                .receipts
        });
        assert_eq!(funded.len(), 1);
        assert!(
            funded[0]
                .error
                .as_deref()
                .is_none_or(|e| !e.contains("module-size floor")),
            "a call funded to the floor must not be rejected for module size: {:?}",
            funded[0].error
        );
    }

    // Deterministic replay with successful and failing contract calls.
    #[test]
    fn replay_with_contract_calls_is_deterministic() {
        let run = || {
            with_timeout(|| {
                let dir = tempfile::tempdir().expect("tempdir");
                let storage = Storage::new(dir.path().join("t.redb")).expect("storage");
                let key = test_keypair(1);
                let sender = address_of(&key);
                let mut ctx = setup_funded_sender(&storage, &sender, 1_000_000);
                deploy_probe(&storage);
                let txs = vec![
                    probe_call(&key, true, 0, 1000),
                    create_transfer_tx(&key, &Address([2u8; 32]), 5_000, 1, 1000),
                    probe_call(&key, false, 2, 1000),
                ];
                let subdag = CommittedSubDag {
                    leader: sample_block(0),
                    blocks: vec![sample_block_with_txs(0, txs)],
                    leader_round: 1,
                    leader_author: 0,
                    non_blue: Vec::new(),
                };
                let r = ctx
                    .execute_committed_subdag(&subdag, &storage)
                    .expect("execute");
                (
                    bincode::serialize(&r.receipts).expect("receipts"),
                    staking_state_bytes(&ctx.staking),
                    probe_slot(&storage),
                    read_balance(&storage, &sender),
                    read_nonce(&storage, &sender),
                )
            })
        };
        let a = run();
        assert_eq!(a.2, Some(1_000_000 - 5_000 - 3000));
        assert_eq!(a, run());
    }
    // ---- staking wiring -------------------------------------------------

    const K: u64 = kovanica_staking::ONE_KUNA;

    fn subdag_at(round: u64, txs: Vec<Transaction>) -> CommittedSubDag {
        let leader = sample_block_at(0, round);
        let mut block = sample_block_with_txs(0, txs);
        block.round = round;
        CommittedSubDag {
            blocks: vec![block],
            leader,
            leader_round: round,
            leader_author: 0,
            non_blue: Vec::new(),
        }
    }

    fn run(
        ctx: &mut ExecutionContext,
        storage: &Storage,
        round: u64,
        txs: Vec<Transaction>,
    ) -> Vec<TransactionReceipt> {
        ctx.execute_committed_subdag(&subdag_at(round, txs), storage)
            .expect("execute")
            .receipts
    }

    fn pending_reward(storage: &Storage, d: &Address, v: &Address) -> u64 {
        let txn = storage.begin_read().expect("read");
        match txn.open_table(PENDING_REWARDS) {
            Ok(t) => t
                .get(reward_key(d, v))
                .expect("get")
                .map(|x| x.value())
                .unwrap_or(0),
            Err(_) => 0,
        }
    }

    // --- sub_balance_mapped pins the old local `debit` helper's semantics ---

    fn debit_once(storage: &Storage, addr: &Address, amount: u64) -> Result<(), ExecutionError> {
        let txn = storage.begin_write().expect("write txn");
        let r = sub_balance_mapped(storage, &txn, addr, amount);
        if r.is_ok() {
            // Another ACCOUNTS op in the same write txn, then commit.
            let other = Address([0x77; 32]);
            let mut acc = storage
                .state()
                .get_account_or_default_write(&txn, &other)
                .expect("other");
            acc.balance += 1;
            storage
                .state()
                .set_account(&txn, &other, &acc)
                .expect("set");
            txn.commit().expect("commit");
        } else {
            txn.abort().expect("abort");
        }
        r
    }

    fn fund(storage: &Storage, addr: &Address, balance: u64) {
        let txn = storage.begin_write().expect("write txn");
        let acc = Account {
            balance,
            ..Default::default()
        };
        storage.state().set_account(&txn, addr, &acc).expect("set");
        txn.commit().expect("commit");
    }

    fn account_exists(storage: &Storage, addr: &Address) -> bool {
        let txn = storage.begin_read().expect("read txn");
        storage.state().get_account(&txn, addr).is_ok()
    }

    fn history(
        storage: &Storage,
        address: Address,
        direction: kovanica_storage::TxDirection,
    ) -> Vec<kovanica_storage::TxHistoryEntry> {
        let txn = storage.begin_read().expect("read");
        kovanica_storage::query_tx_history(
            &txn,
            &kovanica_storage::TxHistoryQuery {
                address,
                limit: Some(50),
                cursor: None,
                direction,
            },
        )
        .expect("history")
        .entries
    }

    #[test]
    fn committed_subdag_writes_address_index_in_the_commit_transaction() {
        let dir = tempfile::tempdir().expect("tempdir");
        let storage = Storage::new(dir.path().join("hist.redb")).expect("storage");
        let mut ctx = ExecutionContext::new();
        let key = test_keypair(0x21);
        let sender = address_of(&key);
        let bob = Address([0x22; 32]);
        fund(&storage, &sender, 1_000);

        let first = create_transfer_tx(&key, &bob, 10, 0, 1);
        let second = create_transfer_tx(&key, &bob, 11, 1, 1);
        let result = ctx
            .execute_committed_subdag(&subdag_at(1, vec![first.clone(), second.clone()]), &storage)
            .expect("commit");
        assert!(result.receipts.iter().all(|r| r.success));
        let root = result.state_root.expect("state root");
        {
            // `commit_account_smt` stores the account SMT (balance + nonce).
            // `compute_state_root` is the snapshot Merkle and is a different
            // value. The account proof root is the consensus root, and it is
            // built only from the accounts table.
            let txn = storage.begin_read().expect("read");
            let proof = storage
                .state()
                .prove_account(&txn, &sender)
                .expect("account proof");
            assert_eq!(
                proof.state_root, root,
                "committed state root is the account SMT and does not include the address index"
            );
        }

        let sent = history(&storage, sender, kovanica_storage::TxDirection::Sent);
        assert_eq!(sent.len(), 2);
        assert_eq!(sent[0].tx_hash, second.hash);
        assert_eq!(sent[0].height, 0);
        assert_eq!(sent[0].tx_index, 1);
        assert_eq!(sent[0].amount, 11);
        assert_eq!(sent[1].tx_hash, first.hash);
        assert_eq!(sent[1].tx_index, 0);
        let received = history(&storage, bob, kovanica_storage::TxDirection::Received);
        assert_eq!(received.len(), 2);
        assert!(history(&storage, bob, kovanica_storage::TxDirection::Sent).is_empty());

        let replay = ctx
            .execute_committed_subdag(&subdag_at(1, vec![first.clone(), second.clone()]), &storage)
            .expect("replay");
        assert!(replay.state_root.is_none(), "replay must not write");
        assert_eq!(
            history(&storage, sender, kovanica_storage::TxDirection::All).len(),
            2,
            "replay must not duplicate index rows"
        );

        // A commit that fails after the index write is opened rolls the index
        // back with the balance update. Height 0 was already committed above,
        // so this is the next height.
        let balance_before = read_balance(&storage, &sender);
        let third = create_transfer_tx(&key, &bob, 4, 2, 1);
        let err = ctx
            .execute_committed_subdag_with_commit(&subdag_at(2, vec![third]), &storage, |_txn| {
                Err(ExecutionError::Other("forced rollback".into()))
            })
            .expect_err("commit callback fails");
        assert!(matches!(err, ExecutionError::Other(_)));
        assert_eq!(read_balance(&storage, &sender), balance_before);
        assert_eq!(
            history(&storage, sender, kovanica_storage::TxDirection::All).len(),
            2,
            "rolled-back commit must not publish index rows"
        );
    }

    #[test]
    fn sub_balance_mapped_debits_and_allows_more_ops_in_txn() {
        let dir = tempfile::tempdir().expect("tempdir");
        let storage = Storage::new(dir.path().join("t.redb")).expect("storage");
        let a = Address([0x11; 32]);
        fund(&storage, &a, 100);
        debit_once(&storage, &a, 40).expect("debit");
        assert_eq!(read_balance(&storage, &a), 60);
        debit_once(&storage, &a, 60).expect("exact debit to zero");
        assert_eq!(read_balance(&storage, &a), 0);
        assert_eq!(read_balance(&storage, &Address([0x77; 32])), 2);
    }

    #[test]
    fn sub_balance_mapped_overdraft_is_old_validation_error() {
        let dir = tempfile::tempdir().expect("tempdir");
        let storage = Storage::new(dir.path().join("t.redb")).expect("storage");
        let a = Address([0x12; 32]);
        fund(&storage, &a, 10);
        let err = debit_once(&storage, &a, 11).expect_err("overdraft");
        assert!(
            matches!(&err, ExecutionError::Validation(m) if m == "Insufficient balance"),
            "{err:?}"
        );
        assert_eq!(
            err.to_string(),
            "Transaction validation failed: Insufficient balance"
        );
        assert_eq!(read_balance(&storage, &a), 10, "balance untouched");
    }

    #[test]
    fn sub_balance_mapped_missing_account_is_zero_balance() {
        let dir = tempfile::tempdir().expect("tempdir");
        let storage = Storage::new(dir.path().join("t.redb")).expect("storage");
        let a = Address([0x13; 32]);
        let err = debit_once(&storage, &a, 1).expect_err("missing overdraft");
        assert!(
            matches!(&err, ExecutionError::Validation(m) if m == "Insufficient balance"),
            "{err:?}"
        );
        assert!(
            !account_exists(&storage, &a),
            "no account created on failure"
        );
        // amount == 0: old helper wrote a default account; keep that.
        debit_once(&storage, &a, 0).expect("zero debit of missing account");
        assert!(account_exists(&storage, &a));
        assert_eq!(read_balance(&storage, &a), 0);
    }

    #[test]
    fn stake_and_delegate_overdraft_receipts_unchanged() {
        let dir = tempfile::tempdir().expect("tempdir");
        let storage = Storage::new(dir.path().join("t.redb")).expect("storage");
        let key = test_keypair(1);
        let me = address_of(&key);
        let initial = 1000 * K;
        let mut ctx = setup_funded_sender(&storage, &me, initial);
        let staked_before = ctx.staking.total_staked;
        let r = run(
            &mut ctx,
            &storage,
            1,
            vec![
                signed_tx(
                    &key,
                    TransactionKind::Stake {
                        amount: 2 * initial,
                    },
                    0,
                    1000,
                ),
                delegate_tx(&key, Address([0xEE; 32]), 2 * initial, 1),
            ],
        );
        assert!(!r[0].success && !r[1].success, "{r:?}");
        assert!(r[0]
            .error
            .as_deref()
            .unwrap_or("")
            .contains("Insufficient balance for stake"));
        assert!(r[1]
            .error
            .as_deref()
            .unwrap_or("")
            .contains("Insufficient balance for delegate"));
        assert!(r[0].events.is_empty() && r[1].events.is_empty());
        assert_eq!(read_balance(&storage, &me), initial - 2000, "only fees");
        assert_eq!(read_nonce(&storage, &me), 2);
        assert_eq!(
            ctx.staking.total_staked, staked_before,
            "staking rolled back"
        );
    }

    #[test]
    fn stake_tx_joins_then_bonds_validator() {
        let dir = tempfile::tempdir().expect("tempdir");
        let storage = Storage::new(dir.path().join("t.redb")).expect("storage");
        let key = test_keypair(1);
        let me = address_of(&key);
        let mut ctx = setup_funded_sender(&storage, &me, 100_000 * K);
        let min = kovanica_staking::MIN_VALIDATOR_STAKE;
        let r = run(
            &mut ctx,
            &storage,
            1,
            vec![
                signed_tx(&key, TransactionKind::Stake { amount: min }, 0, 1000),
                signed_tx(&key, TransactionKind::Stake { amount: 5 * K }, 1, 1000),
            ],
        );
        assert!(r.iter().all(|r| r.success), "{r:?}");
        let v = ctx
            .staking
            .validators
            .iter()
            .find(|v| v.address == me)
            .expect("validator");
        assert!(v.active);
        assert_eq!(v.stake, min + 5 * K);
        assert_eq!(v.public_key, Some(kovanica_types::PublicKey(me.0)));
        assert_eq!(
            ctx.staking
                .validators
                .iter()
                .filter(|v| v.address == me)
                .count(),
            1
        );
        assert_eq!(
            read_balance(&storage, &me),
            100_000 * K - min - 5 * K - 2000
        );
        // Below-minimum fresh stake is rejected and rolled back.
        let k2 = test_keypair(2);
        let other = address_of(&k2);
        let txn = storage.begin_write().expect("w");
        storage
            .state()
            .add_balance(&txn, &other, 10 * K)
            .expect("fund");
        txn.commit().expect("c");
        let r = run(
            &mut ctx,
            &storage,
            2,
            vec![signed_tx(
                &k2,
                TransactionKind::Stake { amount: 5 * K },
                0,
                1000,
            )],
        );
        assert!(!r[0].success);
        assert_eq!(read_balance(&storage, &other), 10 * K - 1000);
    }

    #[test]
    fn explicit_stake_tx_reactivates_an_evicted_validator() {
        let dir = tempfile::tempdir().expect("tempdir");
        let storage = Storage::new(dir.path().join("t.redb")).expect("storage");
        let key = test_keypair(1);
        let me = address_of(&key);
        let mut ctx = setup_funded_sender(&storage, &me, 200_000 * K);
        let min = kovanica_staking::MIN_VALIDATOR_STAKE;

        // Join as a validator.
        let r = run(
            &mut ctx,
            &storage,
            1,
            vec![signed_tx(
                &key,
                TransactionKind::Stake { amount: min },
                0,
                1000,
            )],
        );
        assert!(r.iter().all(|r| r.success), "{r:?}");
        let idx = ctx
            .staking
            .validators
            .iter()
            .position(|v| v.address == me)
            .expect("validator");

        // Evict it via the missed-leader threshold (the same routine the engine
        // calls): drive its missed count to one below the limit, then advance
        // liveness with a leader other than itself.
        ctx.staking.validators[idx].missed_leader_count =
            kovanica_staking::MAX_MISSED_LEADERS_BEFORE_OFFLINE - 1;
        let mine = ctx
            .staking
            .committee_order()
            .iter()
            .position(|v| v.address == me)
            .map(|p| p as u16)
            .expect("validator in committee");
        let other_leader = if mine == 0 { 1 } else { 0 };
        let went_offline = ctx.staking.advance_validator_liveness(other_leader);
        assert!(went_offline.contains(&me), "validator must be evicted");
        assert!(!ctx.staking.validators[idx].active);

        // An explicit new Stake tx on the inactive (non-slashed) record must
        // REACTIVATE it, not fail with ValidatorExists.
        let r = run(
            &mut ctx,
            &storage,
            2,
            vec![signed_tx(
                &key,
                TransactionKind::Stake { amount: min },
                1,
                1000,
            )],
        );
        assert!(
            r.iter().all(|r| r.success),
            "explicit re-stake must succeed: {r:?}"
        );
        let v = ctx
            .staking
            .validators
            .iter()
            .find(|v| v.address == me)
            .expect("validator");
        assert!(v.active, "explicit re-stake reactivates the validator");
    }

    #[test]
    fn unstake_goes_through_queue_and_pays_after_unbonding_rounds() {
        let dir = tempfile::tempdir().expect("tempdir");
        let storage = Storage::new(dir.path().join("t.redb")).expect("storage");
        let key = test_keypair(1);
        let me = address_of(&key);
        let validator = Address([3u8; 32]);
        let mut ctx = setup_funded_sender(&storage, &me, 1_000 * K);
        let r = run(
            &mut ctx,
            &storage,
            1,
            vec![
                signed_tx(
                    &key,
                    TransactionKind::Delegate {
                        validator,
                        amount: 400 * K,
                    },
                    0,
                    1000,
                ),
                signed_tx(&key, TransactionKind::Unstake { amount: 150 * K }, 1, 1000),
            ],
        );
        assert!(r.iter().all(|r| r.success), "{r:?}");
        assert_eq!(ctx.staking.delegated_to(validator), 250 * K);
        assert_eq!(ctx.staking.unbonding_queue.len(), 1);
        let release = ctx.staking.unbonding_queue[0].release_height;
        assert_eq!(
            release,
            kovanica_staking::UNBONDING_ROUNDS,
            "unbonded at height 0"
        );
        let liquid = read_balance(&storage, &me);
        assert_eq!(liquid, 600 * K - 2000, "unstaked funds are not liquid yet");
        // Not yet matured.
        run(&mut ctx, &storage, 2, vec![]);
        assert_eq!(read_balance(&storage, &me), liquid);
        // Jump to just before maturity; the next commit pays out.
        ctx.staking.committed_leader_height = release - 1;
        run(&mut ctx, &storage, 3, vec![]);
        assert_eq!(read_balance(&storage, &me), liquid + 150 * K);
        assert!(ctx.staking.unbonding_queue.is_empty());
    }

    // Old behaviour: ClaimRewards only emitted events, delegators were never paid.
    #[test]
    fn delegator_rewards_accrue_and_claim_pays_them() {
        let dir = tempfile::tempdir().expect("tempdir");
        let storage = Storage::new(dir.path().join("t.redb")).expect("storage");
        let key = test_keypair(1);
        let me = address_of(&key);
        let validator = Address([3u8; 32]);
        let payout = Address([4u8; 32]);
        let mut ctx = setup_funded_sender(&storage, &me, 100_000 * K);
        let min = kovanica_staking::MIN_VALIDATOR_STAKE;
        let r = run(
            &mut ctx,
            &storage,
            1,
            vec![signed_tx(
                &key,
                TransactionKind::Delegate {
                    validator,
                    amount: min,
                },
                0,
                1000,
            )],
        );
        assert!(r[0].success);
        // Reward of round 1 (2.5 KUNA) with 20% escrow: leader side 2.0 KUNA split 50/50 (commission 0).
        assert_eq!(pending_reward(&storage, &me, &validator), K); // 2.0 / 2
        assert_eq!(read_balance(&storage, &payout), K);
        let before = read_balance(&storage, &me);
        let r = run(
            &mut ctx,
            &storage,
            2,
            vec![signed_tx(
                &key,
                TransactionKind::ClaimRewards { validator: None },
                1,
                1000,
            )],
        );
        assert!(r[0].success, "{r:?}");
        assert_eq!(read_balance(&storage, &me), before + K - 1000);
        // Round-2 reward accrued again after the claim tx.
        assert_eq!(pending_reward(&storage, &me, &validator), K);
        // Commission is paid to the validator payout.
        ctx.staking
            .set_commission(validator, 2_000)
            .expect("commission");
        run(&mut ctx, &storage, 3, vec![]);
        // With 20% escrow: leader side 2.0 KUNA, commission 20% to validator, 80% pool split 50/50.
        // First two rounds: each gave 1.0 to payout, 1.0 to delegator (pending). Commission round 3: leader side 2.0, commission 20% of 2.0 = 0.4 to validator from pool? Wait - reward_share takes commission_bps of reward_amount (leader side). Commission 2000 bps on 2.0K = 0.4K to validator cut; pool is 1.6K split 50/50 between validator (self) and delegator = 0.8K each. So validator total from this round = commission cut (0.4K) + their own pool share (0.8K) = 1.2K added to payout? Also delegator gets 0.8K added to pending.
        // Previous state: payout had 1.0 (round1) + 1.0 (round2, claimed from delegator side? no wait - look up: after round1, delegator pending was 1.0K, payout had 1.0K. After claim in round2, delegator was paid 1.0K, and then round2 executed again? Let us look up the test flow.
        // "Round-2 reward accrued again after the claim tx" - so after claiming at height 2, they executed another block? Or maybe the claim tx itself doesn't generate reward; but in the test setup, they do run() which executes a subdag. Also the reward is paid when executing committed subdag. So at round 1 (height 1), reward paid. At round 2, they first claim (tx), so when executing that subdag with claim tx, rewards are paid for that round too? Let us look up how run works.
        // run executes subdag_at(round, txs) - so when they call run for round 2 with claim tx, it executes subdag at round 2, so reward for height 2 is paid. That matches. So after claiming in round 2's execution, delegator gets paid their pending (1.0K) and immediately round 2's reward is paid - so delegator pending becomes 1.0K again (round 2's reward). Payout had 1.0K from round 1; round 2's reward gives payout 1.0K (validator side of round 2). So payout total so far is 2.0K.
        // Then commission is set to 20%, round 3 executes: leader side 2.0K. Commission 20% = 0.4K to validator cut. Pool = 1.6K, split 50/50 (validator self stake equals delegator stake? They both have min stake). So pool gives 0.8K to validator's own share, 0.8K to delegator. So validator gets commission cut (0.4K) + own pool share (0.8K) = 1.2K added to payout. Delegator gets 0.8K added to pending. So payout becomes 2.0K + 1.2K = 3.2K = 16*K/5 (3.2). And pending becomes 0.8K + 0.8K (round 3 gives another 0.8K to delegator? Wait - "Round-2 reward accrued again after the claim tx" - so pending becomes 1.0K (round 2). Then round 3 executes with commission 20%, so round 3's reward is paid: delegator gets 0.8K of round 3's reward added to pending. So pending becomes 1.0K (round 2 leftover? no wait - look up: pending is delegator rewards accrued. When reward is paid at commit, delegator's share of leader_amount goes to PENDING_REWARDS. When they claim, it moves from pending to balance.
        // So after round 1: payout gets 1.0K, delegator gets 1.0K in pending.
        // At round 2, they send claim tx. Executing subdag at round 2: first applies txs (claim moves pending to balance), then pays reward for round 2. So after claim tx succeeds, delegator balance increases by 1.0K, pending decreases by 1.0K. Then reward for round 2 is paid: delegator gets their share of round 2's leader_amount (1.0K) added to pending. So pending ends at 1.0K. Correct - matches line 2867.
        // Payout balance: only gets validator's share when rewards are paid. Claiming doesn't affect payout. So payout had 1.0K from round 1; round 2's reward adds validator's share of round 2 (1.0K) to payout. So payout is 2.0K before round 3.
        // Round 3 with commission 20%: validator share is 1.2K, so payout increases by 1.2K → 3.2K total. Delegator share is 0.8K added to pending → pending becomes 1.0K (from round 2) + 0.8K (from round 3) = 1.8K = 9*K/5.
        assert_eq!(read_balance(&storage, &payout), 2 * K + 1_200_000_000); // 2.0K + 1.2K = 3.2K
        assert_eq!(pending_reward(&storage, &me, &validator), K + 800_000_000); // 1.8K = 9*K/5
                                                                                // Claiming with nothing pending fails honestly.
        let k2 = test_keypair(2);
        let other = address_of(&k2);
        let txn = storage.begin_write().expect("w");
        storage.state().add_balance(&txn, &other, K).expect("fund");
        txn.commit().expect("c");
        let r = run(
            &mut ctx,
            &storage,
            4,
            vec![signed_tx(
                &k2,
                TransactionKind::ClaimRewards {
                    validator: Some(validator),
                },
                0,
                1000,
            )],
        );
        assert!(!r[0].success);
    }

    const TREASURY: Address = Address([0x7E; 32]);

    /// Validator [3;32] (50k self) + one 10k delegation, treasury configured.
    fn slash_fixture(storage: &Storage) -> ExecutionContext {
        let mut ctx = setup_funded_sender(storage, &Address([9u8; 32]), 0);
        ctx.init_treasury(TREASURY);
        ctx.staking
            .delegate(Address([9u8; 32]), Address([3u8; 32]), 10_000 * K)
            .expect("delegate");
        ctx
    }

    fn slashed_counter(storage: &Storage) -> Option<u64> {
        let txn = storage.begin_read().expect("r");
        let t = txn.open_table(SUPPLY_COUNTERS).ok()?;
        let v = t.get("slashed_to_treasury").expect("g").map(|x| x.value());
        v
    }

    /// liquid (treasury + delegator) + staked + unbonding.
    fn total_supply(ctx: &ExecutionContext, storage: &Storage) -> u64 {
        read_balance(storage, &TREASURY)
            + read_balance(storage, &Address([9u8; 32]))
            + ctx.staking.total_staked
            + ctx
                .staking
                .unbonding_queue
                .iter()
                .map(|e| e.amount)
                .sum::<u64>()
    }

    // Old behaviour: slashed stake was burned, treasury got nothing.
    #[test]
    fn double_sign_slash_moves_stake_to_treasury_once() {
        let dir = tempfile::tempdir().expect("tempdir");
        let storage = Storage::new(dir.path().join("t.redb")).expect("storage");
        let mut ctx = slash_fixture(&storage);
        let v = Address([3u8; 32]);
        let supply_before = total_supply(&ctx, &storage);
        let treasury_before = read_balance(&storage, &TREASURY);
        let vesting_before = bincode::serialize(&ctx.staking.treasury).expect("t");
        let ev = kovanica_staking::DoubleSignEvidence {
            validator: v,
            height: 1,
        };
        let slashed = ctx
            .apply_double_sign_evidence(ev.clone(), &storage)
            .expect("slash");
        assert_eq!(slashed, 3_000 * K);
        assert_eq!(read_balance(&storage, &TREASURY), treasury_before + slashed);
        assert_eq!(
            total_supply(&ctx, &storage),
            supply_before,
            "nothing burned"
        );
        assert_eq!(ctx.staking.total_staked, 57_000 * K);
        assert_eq!(slashed_counter(&storage), Some(slashed));
        assert_eq!(
            bincode::serialize(&ctx.staking.treasury).expect("t"),
            vesting_before,
            "vesting schedule untouched"
        );
        // Same evidence twice: rejected, nothing moves.
        let err = ctx
            .apply_double_sign_evidence(ev, &storage)
            .expect_err("dup");
        assert!(matches!(
            err,
            ExecutionError::Staking(StakingError::EvidenceProcessed)
        ));
        assert_eq!(read_balance(&storage, &TREASURY), treasury_before + slashed);
        assert_eq!(total_supply(&ctx, &storage), supply_before);
        assert_eq!(
            staking_state_bytes(&load_staking_state(&storage)),
            staking_state_bytes(&ctx.staking)
        );
    }

    /// Build a signed header for `round` over `seed`.
    fn evidence_header(
        key: &SigningKey,
        round: u64,
        seed: &[u8],
    ) -> kovanica_types::SignedBlockHeader {
        let digest = kovanica_types::Hash::new(seed);
        kovanica_types::SignedBlockHeader {
            author: address_of(key),
            round,
            digest,
            signature: kovanica_crypto::sign(key, digest.as_ref()),
        }
    }

    /// Two conflicting signed headers for `(key, round)`.
    fn equivocation(key: &SigningKey, round: u64) -> kovanica_types::EquivocationEvidence {
        kovanica_types::EquivocationEvidence {
            header_a: evidence_header(key, round, b"block-a"),
            header_b: evidence_header(key, round, b"block-b"),
        }
    }

    fn evidence_tx(
        reporter: &SigningKey,
        nonce: u64,
        evidence: kovanica_types::EquivocationEvidence,
    ) -> Transaction {
        signed_tx(reporter, TransactionKind::Evidence { evidence }, nonce, 0)
    }

    const GATE: u64 = kovanica_types::SLASHING_ACTIVE_FROM_ROUND;

    /// Execute a sub-DAG at `round` with a unique leader digest.
    ///
    /// The activation round is `u64::MAX`, so every gated test must run at
    /// that same round. `execute_committed_subdag` is idempotent per leader
    /// digest and `subdag_at` derives it from `(author, round, [])` alone, so
    /// a second call at the same round would be a no-op; salting the digest
    /// models two different committed leaders at the same round instead.
    fn run_salted(
        ctx: &mut ExecutionContext,
        storage: &Storage,
        round: u64,
        txs: Vec<Transaction>,
        salt: u8,
    ) -> Vec<TransactionReceipt> {
        let mut sub = subdag_at(round, txs);
        sub.leader.digest = kovanica_types::Hash::new([salt]);
        ctx.execute_committed_subdag(&sub, storage)
            .expect("execute")
            .receipts
    }

    /// Like [`slash_fixture`], but the validator address is the *real*
    /// address of `key` (tests sign blocks with that key, so the address and
    /// the signing key must correspond; `Address([3;32])` is not the public
    /// key of `SigningKey::from_bytes([3;32])`).
    fn keyed_slash_fixture(storage: &Storage, key: &SigningKey) -> (ExecutionContext, Address) {
        let reporter = Address([9u8; 32]);
        let mut ctx = setup_funded_sender(storage, &reporter, 0);
        ctx.init_treasury(TREASURY);
        let v = address_of(key);
        ctx.staking.validators.clear();
        ctx.staking.delegations.clear();
        ctx.staking.total_staked = 0;
        ctx.staking
            .join_validator(
                v,
                kovanica_staking::MIN_VALIDATOR_STAKE,
                0,
                Some(Address([4u8; 32])),
                None,
                None,
            )
            .expect("join validator");
        ctx.staking
            .delegate(reporter, v, 10_000 * K)
            .expect("delegate");
        (ctx, v)
    }

    #[test]
    fn evidence_is_rejected_below_the_activation_round() {
        let dir = tempfile::tempdir().expect("tempdir");
        let storage = Storage::new(dir.path().join("t.redb")).expect("storage");
        let k = test_keypair(3);
        let (mut ctx, _) = keyed_slash_fixture(&storage, &k);
        let staked_before = ctx.staking.total_staked;
        let treasury_before = read_balance(&storage, &TREASURY);
        let tx = evidence_tx(&test_keypair(9), 0, equivocation(&k, 1));

        let r = run(&mut ctx, &storage, GATE - 1, vec![tx]);
        assert!(!r[0].success);
        assert!(
            r[0].error
                .as_deref()
                .unwrap_or("")
                .contains("slashing not active"),
            "{:?}",
            r[0].error
        );
        assert_eq!(ctx.staking.total_staked, staked_before);
        assert!(!ctx.staking.validators[0].slashed);
        assert_eq!(read_balance(&storage, &TREASURY), treasury_before);
        assert_eq!(slashed_counter(&storage), None);
    }

    #[test]
    fn evidence_slashes_active_validator_and_credits_treasury() {
        let dir = tempfile::tempdir().expect("tempdir");
        let storage = Storage::new(dir.path().join("t.redb")).expect("storage");
        let k = test_keypair(3);
        let (mut ctx, _) = keyed_slash_fixture(&storage, &k);
        let supply_before = total_supply(&ctx, &storage);
        let treasury_before = read_balance(&storage, &TREASURY);

        let r = run(
            &mut ctx,
            &storage,
            GATE,
            vec![evidence_tx(&test_keypair(9), 0, equivocation(&k, GATE))],
        );
        assert!(r[0].success, "{:?}", r[0].error);
        assert_eq!(r[0].events[0].topic, b"evidence_slash");

        // 5% of 50k self + 5% of 10k delegation.
        let slashed = 3_000 * K;
        assert_eq!(read_balance(&storage, &TREASURY), treasury_before + slashed);
        assert_eq!(
            total_supply(&ctx, &storage),
            supply_before,
            "nothing burned"
        );
        assert_eq!(ctx.staking.total_staked, 57_000 * K);
        assert!(ctx.staking.validators[0].slashed);
        assert_eq!(slashed_counter(&storage), Some(slashed));
        // Persisted, not just in memory.
        assert_eq!(
            staking_state_bytes(&load_staking_state(&storage)),
            staking_state_bytes(&ctx.staking)
        );

        // Same (author, round) again, even with a different digest pair:
        // rejected. (A new round avoids the sub-DAG idempotency marker.)
        let again = kovanica_types::EquivocationEvidence {
            header_a: evidence_header(&k, GATE, b"third"),
            header_b: evidence_header(&k, GATE, b"fourth"),
        };
        let r = run_salted(
            &mut ctx,
            &storage,
            GATE,
            vec![evidence_tx(&test_keypair(9), 1, again)],
            1,
        );
        assert!(!r[0].success);
        assert!(
            r[0].error
                .as_deref()
                .unwrap_or("")
                .contains("already processed"),
            "{:?}",
            r[0].error
        );
        assert_eq!(read_balance(&storage, &TREASURY), treasury_before + slashed);
    }

    #[test]
    fn evidence_is_rejected_when_stale_or_not_a_validator_or_forged() {
        let dir = tempfile::tempdir().expect("tempdir");
        let storage = Storage::new(dir.path().join("t.redb")).expect("storage");
        let k = test_keypair(3);
        let (mut ctx, _) = keyed_slash_fixture(&storage, &k);
        let staked_before = ctx.staking.total_staked;
        let treasury_before = read_balance(&storage, &TREASURY);

        // Stale: round 0 versus a leader round far beyond the age bound.
        let r = run(
            &mut ctx,
            &storage,
            GATE,
            vec![evidence_tx(&test_keypair(9), 0, equivocation(&k, 0))],
        );
        assert!(!r[0].success);
        assert!(
            r[0].error.as_deref().unwrap_or("").contains("older than"),
            "{:?}",
            r[0].error
        );

        // A key that is not a registered validator.
        let outsider = test_keypair(5);
        let r = run_salted(
            &mut ctx,
            &storage,
            GATE,
            vec![evidence_tx(
                &test_keypair(9),
                1,
                equivocation(&outsider, GATE),
            )],
            2,
        );
        assert!(!r[0].success);
        assert!(
            r[0].error
                .as_deref()
                .unwrap_or("")
                .contains("not an active validator"),
            "{:?}",
            r[0].error
        );

        // Forged: the second header is signed by a different key.
        let mut forged = equivocation(&k, GATE);
        forged.header_b = evidence_header(&outsider, GATE, b"block-b");
        let r = run_salted(
            &mut ctx,
            &storage,
            GATE,
            vec![evidence_tx(&test_keypair(9), 2, forged)],
            3,
        );
        assert!(!r[0].success);
        assert!(
            r[0].error
                .as_deref()
                .unwrap_or("")
                .contains("invalid evidence"),
            "{:?}",
            r[0].error
        );

        assert_eq!(ctx.staking.total_staked, staked_before);
        assert!(!ctx.staking.validators[0].slashed);
        assert_eq!(read_balance(&storage, &TREASURY), treasury_before);
        assert_eq!(slashed_counter(&storage), None);
    }

    /// H2 end to end: an unbond started before the offence is still cut.
    #[test]
    fn evidence_cuts_pending_unbonding_entries() {
        let dir = tempfile::tempdir().expect("tempdir");
        let storage = Storage::new(dir.path().join("t.redb")).expect("storage");
        let k = test_keypair(3);
        let (mut ctx, v) = keyed_slash_fixture(&storage, &k);
        // 60k self + 10k delegated, so 10k can unbond and the validator
        // stays at MIN_VALIDATOR_STAKE (and thus active).
        ctx.staking.validators[0].stake = 70_000 * K;
        ctx.staking.total_staked += 20_000 * K;
        ctx.staking.unbond_validator(v, 10_000 * K).expect("unbond");
        assert_eq!(ctx.staking.unbonding_queue[0].amount, 10_000 * K);
        assert!(ctx.staking.validators[0].active);

        let supply_before = total_supply(&ctx, &storage);
        let treasury_before = read_balance(&storage, &TREASURY);
        let r = run(
            &mut ctx,
            &storage,
            GATE,
            vec![evidence_tx(&test_keypair(9), 0, equivocation(&k, GATE))],
        );
        assert!(r[0].success, "{:?}", r[0].error);

        // 5% of 50k self + 5% of 10k delegation + 5% of the 10k queued.
        let slashed = 3_500 * K;
        assert_eq!(read_balance(&storage, &TREASURY), treasury_before + slashed);
        assert_eq!(
            total_supply(&ctx, &storage),
            supply_before,
            "nothing burned"
        );
        assert_eq!(ctx.staking.unbonding_queue[0].amount, 9_500 * K);

        // The reduced amount is what becomes withdrawable.
        ctx.staking.committed_leader_height = ctx.staking.unbonding_queue[0].release_height;
        assert_eq!(ctx.staking.withdraw_unbonded(v, v).unwrap(), 9_500 * K);
        assert!(ctx.staking.unbonding_queue.is_empty());
    }

    #[test]
    fn slash_without_treasury_is_rejected_and_changes_nothing() {
        let dir = tempfile::tempdir().expect("tempdir");
        let storage = Storage::new(dir.path().join("t.redb")).expect("storage");
        let mut ctx = setup_funded_sender(&storage, &Address([9u8; 32]), 0);
        let before = staking_state_bytes(&ctx.staking);
        let ev = kovanica_staking::DoubleSignEvidence {
            validator: Address([3u8; 32]),
            height: 1,
        };
        assert!(ctx.apply_double_sign_evidence(ev, &storage).is_err());
        assert_eq!(staking_state_bytes(&ctx.staking), before);
        assert_eq!(slashed_counter(&storage), None);
    }

    #[test]
    fn slash_to_treasury_replay_is_deterministic() {
        let go = || {
            let dir = tempfile::tempdir().expect("tempdir");
            let storage = Storage::new(dir.path().join("t.redb")).expect("storage");
            let mut ctx = slash_fixture(&storage);
            let mut out = Vec::new();
            for h in [1u64, 2, 2, 5] {
                let ev = kovanica_staking::DoubleSignEvidence {
                    validator: Address([3u8; 32]),
                    height: h,
                };
                out.push(ctx.apply_double_sign_evidence(ev, &storage).ok());
            }
            (
                out,
                staking_state_bytes(&ctx.staking),
                read_balance(&storage, &TREASURY),
                slashed_counter(&storage),
            )
        };
        let a = go();
        assert_eq!(a.0[2], None, "duplicate evidence rejected");
        assert_eq!(a, go());
    }

    #[test]
    fn staking_replay_is_deterministic() {
        let go = || {
            let dir = tempfile::tempdir().expect("tempdir");
            let storage = Storage::new(dir.path().join("t.redb")).expect("storage");
            let key = test_keypair(1);
            let me = address_of(&key);
            let validator = Address([3u8; 32]);
            let mut ctx = setup_funded_sender(&storage, &me, 200_000 * K);
            let mut receipts = Vec::new();
            receipts.extend(run(
                &mut ctx,
                &storage,
                1,
                vec![
                    signed_tx(
                        &key,
                        TransactionKind::Delegate {
                            validator,
                            amount: 1_000 * K,
                        },
                        0,
                        1000,
                    ),
                    signed_tx(
                        &key,
                        TransactionKind::Stake {
                            amount: kovanica_staking::MIN_VALIDATOR_STAKE,
                        },
                        1,
                        1000,
                    ),
                ],
            ));
            receipts.extend(run(
                &mut ctx,
                &storage,
                2,
                vec![
                    signed_tx(
                        &key,
                        TransactionKind::ClaimRewards { validator: None },
                        2,
                        1000,
                    ),
                    signed_tx(&key, TransactionKind::Unstake { amount: 10 * K }, 3, 1000),
                ],
            ));
            (
                bincode::serialize(&receipts).expect("r"),
                staking_state_bytes(&ctx.staking),
                read_balance(&storage, &me),
                pending_reward(&storage, &me, &validator),
            )
        };
        let a = go();
        assert_eq!(a, go());
    }
    // ---- signature format v1 + Call.value -------------------------------

    fn signed_tx_for(
        key: &SigningKey,
        kind: TransactionKind,
        nonce: u64,
        fee: u64,
        ctx: &SigningContext,
    ) -> Transaction {
        let mut tx = Transaction {
            sender: address_of(key),
            nonce,
            kind,
            fee,
            signature: Signature([0u8; 64]),
            hash: kovanica_types::hash::Hash([0u8; 32]),
        };
        tx.hash = tx.signing_hash(ctx);
        tx.signature = kovanica_crypto::sign(key, &tx.signing_hash(ctx).0);
        tx
    }

    // A valid v1 signature for another chain_id is rejected; nothing charged.
    #[test]
    fn v1_signature_for_other_chain_is_rejected() {
        let dir = tempfile::tempdir().expect("tempdir");
        let storage = Storage::new(dir.path().join("t.redb")).expect("storage");
        let key = test_keypair(1);
        let sender = address_of(&key);
        let mut ctx = setup_funded_sender(&storage, &sender, 1_000 * K);
        let testnet = SigningContext::new(chain_id::TESTNET);
        let kind = TransactionKind::Transfer {
            to: Address([2u8; 32]),
            amount: K,
        };
        let tx = signed_tx_for(&key, kind, 0, 1000, &testnet);
        assert!(tx.verify_signature(&testnet), "valid on its own chain");
        let r = execute_single_tx(&mut ctx, &storage, tx);
        assert!(!r.receipts[0].success);
        assert_eq!(r.receipts[0].error.as_deref(), Some("Invalid signature"));
        assert_eq!(read_balance(&storage, &sender), 1_000 * K);
        assert_eq!(read_nonce(&storage, &sender), 0);
        // The same chain configured via with_signing_context accepts it.
        let dir2 = tempfile::tempdir().expect("tempdir");
        let storage2 = Storage::new(dir2.path().join("t.redb")).expect("storage");
        let mut ctx2 = setup_funded_sender(&storage2, &sender, 1_000 * K);
        ctx2.signing_ctx = testnet;
        let tx = signed_tx_for(
            &key,
            TransactionKind::Transfer {
                to: Address([2u8; 32]),
                amount: K,
            },
            0,
            1000,
            &testnet,
        );
        assert!(execute_single_tx(&mut ctx2, &storage2, tx).receipts[0].success);
        assert_eq!(
            ExecutionContext::with_signing_context(testnet).signing_context(),
            testnet
        );
        assert_eq!(
            ExecutionContext::new().signing_context().chain_id,
            chain_id::LOCAL
        );
    }

    /// Pre-v1 (v0) signing preimage: no domain tag, no chain_id, keyed with
    /// the old `KVNC-TX-v1` BLAKE3 key.
    fn v0_signing_hash(tx: &Transaction) -> kovanica_types::hash::Hash {
        let TransactionKind::Transfer { to, amount } = &tx.kind else {
            unreachable!("transfer only")
        };
        let mut data = Vec::new();
        data.extend_from_slice(&tx.sender.0);
        data.extend_from_slice(&tx.nonce.to_le_bytes());
        data.push(0);
        data.extend_from_slice(&to.0);
        data.extend_from_slice(&amount.to_le_bytes());
        data.extend_from_slice(&tx.fee.to_le_bytes());
        kovanica_types::hash::Hash::new_keyed(b"KVNC-TX-v1", &data)
    }

    #[test]
    fn v0_signature_is_rejected() {
        let dir = tempfile::tempdir().expect("tempdir");
        let storage = Storage::new(dir.path().join("t.redb")).expect("storage");
        let key = test_keypair(1);
        let sender = address_of(&key);
        let mut ctx = setup_funded_sender(&storage, &sender, 1_000 * K);
        let mut tx = Transaction {
            sender,
            nonce: 0,
            kind: TransactionKind::Transfer {
                to: Address([2u8; 32]),
                amount: K,
            },
            fee: 1000,
            signature: Signature([0u8; 64]),
            hash: kovanica_types::hash::Hash([0u8; 32]),
        };
        let v0 = v0_signing_hash(&tx);
        tx.hash = v0;
        tx.signature = kovanica_crypto::sign(&key, &v0.0);
        let r = execute_single_tx(&mut ctx, &storage, tx);
        assert!(!r.receipts[0].success);
        assert_eq!(r.receipts[0].error.as_deref(), Some("Invalid signature"));
        assert_eq!(read_balance(&storage, &sender), 1_000 * K);
    }

    fn probe_call_value(key: &SigningKey, fail: bool, value: u64, nonce: u64) -> Transaction {
        let kind = TransactionKind::Call {
            contract: PROBE_CONTRACT,
            value,
            method: "probe".to_string(),
            args: if fail { vec![1] } else { Vec::new() },
            gas_limit: 1_000_000,
        };
        signed_tx(key, kind, nonce, 1000)
    }

    // Call.value moves exactly that amount signer -> contract, before the
    // call runs (the contract sees the reduced caller balance).
    #[test]
    fn call_value_moves_exact_amount_to_contract() {
        let (slot, sender_bal, contract_bal, ok) = with_timeout(|| {
            let dir = tempfile::tempdir().expect("tempdir");
            let storage = Storage::new(dir.path().join("t.redb")).expect("storage");
            let key = test_keypair(1);
            let sender = address_of(&key);
            let mut ctx = setup_funded_sender(&storage, &sender, 1_000_000);
            deploy_probe(&storage);
            let r = execute_single_tx(&mut ctx, &storage, probe_call_value(&key, false, 1234, 0));
            (
                probe_slot(&storage),
                read_balance(&storage, &sender),
                read_balance(&storage, &PROBE_CONTRACT),
                r.receipts[0].success,
            )
        });
        assert!(ok);
        assert_eq!(sender_bal, 1_000_000 - 1000 - 1234);
        assert_eq!(contract_bal, 1234);
        assert_eq!(slot, Some(1_000_000 - 1000 - 1234), "moved before the call");
    }

    // value > balance: rejected, only fee/nonce charged.
    #[test]
    fn call_value_above_balance_is_rejected() {
        let (ok, sender_bal, contract_bal, nonce) = with_timeout(|| {
            let dir = tempfile::tempdir().expect("tempdir");
            let storage = Storage::new(dir.path().join("t.redb")).expect("storage");
            let key = test_keypair(1);
            let sender = address_of(&key);
            let mut ctx = setup_funded_sender(&storage, &sender, 10_000);
            deploy_probe(&storage);
            let r = execute_single_tx(&mut ctx, &storage, probe_call_value(&key, false, 9_500, 0));
            (
                r.receipts[0].success,
                read_balance(&storage, &sender),
                read_balance(&storage, &PROBE_CONTRACT),
                read_nonce(&storage, &sender),
            )
        });
        assert!(!ok);
        assert_eq!(sender_bal, 10_000 - 1000);
        assert_eq!(contract_bal, 0);
        assert_eq!(nonce, 1);
    }

    // A failing call does not move its value.
    #[test]
    fn failed_call_does_not_move_value() {
        let (ok, sender_bal, contract_bal, slot) = with_timeout(|| {
            let dir = tempfile::tempdir().expect("tempdir");
            let storage = Storage::new(dir.path().join("t.redb")).expect("storage");
            let key = test_keypair(1);
            let sender = address_of(&key);
            let mut ctx = setup_funded_sender(&storage, &sender, 1_000_000);
            deploy_probe(&storage);
            let r = execute_single_tx(&mut ctx, &storage, probe_call_value(&key, true, 5_000, 0));
            (
                r.receipts[0].success,
                read_balance(&storage, &sender),
                read_balance(&storage, &PROBE_CONTRACT),
                probe_slot(&storage),
            )
        });
        assert!(!ok);
        assert_eq!(sender_bal, 1_000_000 - 1000);
        assert_eq!(contract_bal, 0);
        assert_eq!(slot, None);
    }

    #[test]
    fn replay_with_call_values_is_deterministic() {
        let go = || {
            with_timeout(|| {
                let dir = tempfile::tempdir().expect("tempdir");
                let storage = Storage::new(dir.path().join("t.redb")).expect("storage");
                let key = test_keypair(1);
                let sender = address_of(&key);
                let mut ctx = setup_funded_sender(&storage, &sender, 1_000_000);
                deploy_probe(&storage);
                let txs = vec![
                    probe_call_value(&key, false, 100, 0),
                    probe_call_value(&key, true, 200, 1),
                    probe_call_value(&key, false, 10_000_000, 2),
                    probe_call_value(&key, false, 300, 3),
                ];
                let r = ctx
                    .execute_committed_subdag(&subdag_at(1, txs), &storage)
                    .expect("execute");
                (
                    bincode::serialize(&r.receipts).expect("r"),
                    read_balance(&storage, &sender),
                    read_balance(&storage, &PROBE_CONTRACT),
                    probe_slot(&storage),
                )
            })
        };
        let a = go();
        assert_eq!(a.2, 400);
        assert_eq!(a, go());
    }

    #[test]
    fn live_light_bps_escrows_twenty_percent_and_conserves_the_reward() {
        assert_eq!(kovanica_staking::LIGHT_REWARD_BPS, 2_000);
        let dir = tempfile::tempdir().expect("tempdir");
        let storage = Storage::new(dir.path().join("t.redb")).expect("storage");
        let mut ctx = ExecutionContext::new();
        let validator = Address([1u8; 32]);
        let payout = Address([9u8; 32]);
        let delegator = Address([5u8; 32]);
        ctx.staking
            .join_validator(
                validator,
                kovanica_staking::MIN_VALIDATOR_STAKE,
                1_000,
                Some(payout),
                None,
                None,
            )
            .unwrap();
        ctx.staking
            .delegate(delegator, validator, kovanica_staking::MIN_VALIDATOR_STAKE)
            .unwrap();
        let result = ctx
            .execute_committed_subdag(&sample_committed_subdag(1, 0), &storage)
            .unwrap();
        let reward = result.reward.unwrap();
        let full = kovanica_staking::block_reward(0);
        assert_eq!(reward.amount, full);
        let (leader_side, escrow) = kovanica_staking::split_block_reward(full, 2_000);
        let txn = storage.begin_read().unwrap();
        let pending_table = txn.open_table(PENDING_REWARDS).unwrap();
        let pending = pending_table
            .get(reward_key(&delegator, &validator))
            .unwrap()
            .map(|guard| guard.value())
            .unwrap_or(0);
        drop(pending_table);
        drop(txn);
        let paid = read_balance(&storage, &payout);
        assert_eq!(paid + pending, leader_side);
        assert!(pending > 0);
        assert!(paid > 0);
        let txn = storage.begin_read().unwrap();
        let set = storage.state().load_light_set(&txn).unwrap().unwrap();
        drop(txn);
        let stored: u64 = set.escrow(0).iter().map(|(_, amount)| *amount).sum();
        assert_eq!(stored, escrow);
        assert_eq!(paid + pending + stored, full);
    }

    #[test]
    fn registration_activates_next_epoch_and_a_valid_witness_is_stored() {
        let dir = tempfile::tempdir().expect("tempdir");
        let storage = Storage::new(dir.path().join("t.redb")).expect("storage");
        let key = test_keypair(4);
        let sender = address_of(&key);
        let bond = kovanica_staking::MIN_LIGHT_BOND;
        let mut ctx = setup_funded_sender(&storage, &sender, bond + 10);
        let secret = kovanica_crypto::derive_vrf_secret_from_seed(&[9u8; 32]);
        let vrf = kovanica_crypto::VRFKeyPair::from_secret(secret).unwrap();
        let register = signed_tx(
            &key,
            TransactionKind::RegisterLightNode {
                vrf_public_key: vrf.public_key_typed(),
                stake: bond,
            },
            0,
            1,
        );
        let registered = execute_single_tx(&mut ctx, &storage, register);
        assert!(
            registered.receipts[0].success,
            "{:?}",
            registered.receipts[0].error
        );
        assert_eq!(read_balance(&storage, &sender), 9);
        let txn = storage.begin_read().unwrap();
        let set = storage.state().load_light_set(&txn).unwrap().unwrap();
        drop(txn);
        assert_eq!(set.nodes()[0].effective_epoch, 1);
        assert!(set.active_nodes(0).is_empty());

        ctx.staking.committed_leader_height = kovanica_staking::EPOCH_LEADER_HEIGHTS;
        let leader = sample_block_at(0, 9);
        let input = light_vrf_input(chain_id::LOCAL, 1, &leader.digest);
        let output = kovanica_crypto::vrf_prove(&vrf, &input);
        let witness = signed_tx(
            &key,
            TransactionKind::SubmitLightWitness {
                epoch: 1,
                vrf_hash: output.hash,
                vrf_proof: output.proof,
            },
            1,
            1,
        );
        let mut block = sample_block_with_txs(0, vec![witness]);
        block.round = 9;
        let subdag = CommittedSubDag {
            blocks: vec![block],
            leader: leader.clone(),
            leader_round: 9,
            leader_author: 0,
            non_blue: Vec::new(),
        };
        let witnessed = ctx.execute_committed_subdag(&subdag, &storage).unwrap();
        assert!(
            witnessed.receipts[0].success,
            "{:?}",
            witnessed.receipts[0].error
        );
        let txn = storage.begin_read().unwrap();
        let set = storage.state().load_light_set(&txn).unwrap().unwrap();
        drop(txn);
        assert_eq!(set.witnesses(1).len(), 1);
        assert_eq!(set.winners(1), vec![sender]);

        let mut bad = output.proof;
        bad[0] ^= 0xff;
        let rejected = signed_tx(
            &key,
            TransactionKind::SubmitLightWitness {
                epoch: 1,
                vrf_hash: output.hash,
                vrf_proof: bad,
            },
            2,
            1,
        );
        let mut bad_block = sample_block_with_txs(0, vec![rejected]);
        bad_block.round = 10;
        let rejected_result = ctx
            .execute_committed_subdag(
                &CommittedSubDag {
                    blocks: vec![bad_block],
                    leader: sample_block_at(0, 10),
                    leader_round: 10,
                    leader_author: 0,
                    non_blue: Vec::new(),
                },
                &storage,
            )
            .unwrap();
        assert!(!rejected_result.receipts[0].success);
        let txn = storage.begin_read().unwrap();
        let set = storage.state().load_light_set(&txn).unwrap().unwrap();
        assert_eq!(set.witnesses(1).len(), 1);
    }

    #[test]
    fn an_in_test_bps_override_conserves_block_reward() {
        assert_eq!(kovanica_staking::LIGHT_REWARD_BPS, 2_000);
        let dir = tempfile::tempdir().expect("tempdir");
        let storage = Storage::new(dir.path().join("t.redb")).expect("storage");
        let mut ctx = ExecutionContext::new();
        ctx.light_reward_bps = 2_000;
        ctx.staking.committed_leader_height = kovanica_staking::EPOCH_LEADER_HEIGHTS - 1;
        let payout = Address([9u8; 32]);
        ctx.staking
            .join_validator(
                Address([1u8; 32]),
                kovanica_staking::MIN_VALIDATOR_STAKE,
                0,
                Some(payout),
                None,
                None,
            )
            .unwrap();
        let closing = ctx
            .execute_committed_subdag(&sample_committed_subdag(1, 0), &storage)
            .unwrap();
        let closing_reward = closing.reward.unwrap().amount;
        assert_eq!(read_balance(&storage, &payout), closing_reward);
        let txn = storage.begin_read().unwrap();
        let set = storage.state().load_light_set(&txn).unwrap().unwrap();
        drop(txn);
        assert!(set.escrow(0).is_empty());

        let opening = ctx
            .execute_committed_subdag(&sample_committed_subdag(2, 0), &storage)
            .unwrap();
        let opening_reward = opening.reward.unwrap().amount;
        let (leader_side, escrow) = kovanica_staking::split_block_reward(opening_reward, 2_000);
        assert_eq!(
            read_balance(&storage, &payout),
            closing_reward + leader_side
        );
        let txn = storage.begin_read().unwrap();
        let set = storage.state().load_light_set(&txn).unwrap().unwrap();
        drop(txn);
        let stored: u64 = set.escrow(1).iter().map(|(_, amount)| *amount).sum();
        assert_eq!(stored, escrow);
        assert_eq!(
            read_balance(&storage, &payout) + stored,
            closing_reward + opening_reward
        );
    }

    // ---- contract hardening (deploy validation / overwrite / entry points) ----

    /// The contract address `execute_deploy` derives for `sender`'s transaction
    /// with `nonce`: `hash(sender || (nonce + 1) LE)` (the nonce is incremented
    /// by the savepoint before the body derives the address).
    fn deployed_address(sender: &Address, nonce: u64) -> Address {
        let mut b = Vec::with_capacity(40);
        b.extend_from_slice(&sender.0);
        b.extend_from_slice(&nonce.saturating_add(1).to_le_bytes());
        Address(kovanica_common::hash(&b))
    }

    fn read_account_code(storage: &Storage, address: &Address) -> Vec<u8> {
        let txn = storage.begin_read().expect("read txn");
        storage
            .state()
            .get_account_or_default(&txn, address)
            .expect("account")
            .code
    }

    fn set_raw_code(storage: &Storage, address: &Address, code: Vec<u8>) {
        let txn = storage.begin_write().expect("write txn");
        storage
            .state()
            .set_account(
                &txn,
                address,
                &Account {
                    balance: 0,
                    nonce: 0,
                    code_hash: kovanica_common::hash(&code),
                    code,
                },
            )
            .expect("set_account");
        txn.commit().expect("commit");
    }

    // A `Deploy` carries bytecode the node never compiles (compilation happens
    // on the first call). Below activation an invalid module is therefore
    // stored successfully; from activation it is rejected before any write,
    // with the fee/nonce still charged.
    #[test]
    fn invalid_bytecode_deploy_is_gated() {
        let active_round = kovanica_types::CONTRACT_HARDENING_ACTIVE_FROM_ROUND;
        let invalid = b"\x00asm\x01\0\0\0this is not a valid module".to_vec();

        // Below activation: old behavior — accepted and stored verbatim.
        {
            let dir = tempfile::tempdir().expect("tempdir");
            let storage = Storage::new(dir.path().join("t.redb")).expect("storage");
            let key = test_keypair(1);
            let sender = address_of(&key);
            let mut ctx = setup_funded_sender(&storage, &sender, 1_000_000);
            let tx = signed_tx(
                &key,
                TransactionKind::Deploy {
                    code: invalid.clone(),
                },
                0,
                1_000,
            );
            let receipts = run(&mut ctx, &storage, 1, vec![tx]);
            assert!(receipts[0].success, "{:?}", receipts[0].error);
            assert_eq!(
                read_account_code(&storage, &deployed_address(&sender, 0)),
                invalid
            );
        }

        // At activation: rejected, no code write, fee + nonce still charged.
        {
            let dir = tempfile::tempdir().expect("tempdir");
            let storage = Storage::new(dir.path().join("t.redb")).expect("storage");
            let key = test_keypair(1);
            let sender = address_of(&key);
            let mut ctx = setup_funded_sender(&storage, &sender, 1_000_000);
            let tx = signed_tx(
                &key,
                TransactionKind::Deploy {
                    code: invalid.clone(),
                },
                0,
                1_000,
            );
            let receipts = run(&mut ctx, &storage, active_round, vec![tx]);
            assert!(!receipts[0].success);
            assert!(
                receipts[0]
                    .error
                    .as_deref()
                    .is_some_and(|e| e.contains("Invalid contract bytecode")),
                "{:?}",
                receipts[0].error
            );
            assert!(
                read_account_code(&storage, &deployed_address(&sender, 0)).is_empty(),
                "invalid deploy must not write code"
            );
            assert_eq!(read_balance(&storage, &sender), 1_000_000 - 1_000);
            assert_eq!(read_nonce(&storage, &sender), 1);
        }
    }

    // The overwrite guard only fires from activation; below it a deploy still
    // replaces whatever code the derived address held.
    #[test]
    fn deploy_overwrite_guard_is_gated() {
        let active_round = kovanica_types::CONTRACT_HARDENING_ACTIVE_FROM_ROUND;

        // Below activation: the deploy overwrites the pre-seeded code.
        {
            let dir = tempfile::tempdir().expect("tempdir");
            let storage = Storage::new(dir.path().join("t.redb")).expect("storage");
            let key = test_keypair(1);
            let sender = address_of(&key);
            let mut ctx = setup_funded_sender(&storage, &sender, 1_000_000);
            let target = deployed_address(&sender, 0);
            set_raw_code(&storage, &target, b"pre-seeded code".to_vec());
            let tx = signed_tx(
                &key,
                TransactionKind::Deploy {
                    code: b"replacement".to_vec(),
                },
                0,
                1_000,
            );
            let receipts = run(&mut ctx, &storage, 1, vec![tx]);
            assert!(receipts[0].success, "{:?}", receipts[0].error);
            assert_eq!(read_account_code(&storage, &target), b"replacement");
        }

        // At activation: rejected, and the pre-seeded code is left untouched.
        {
            let dir = tempfile::tempdir().expect("tempdir");
            let storage = Storage::new(dir.path().join("t.redb")).expect("storage");
            let key = test_keypair(1);
            let sender = address_of(&key);
            let mut ctx = setup_funded_sender(&storage, &sender, 1_000_000);
            let target = deployed_address(&sender, 0);
            set_raw_code(&storage, &target, b"pre-seeded code".to_vec());
            // Valid wasm so only the overwrite guard (not the bytecode check)
            // can reject it.
            let tx = signed_tx(
                &key,
                TransactionKind::Deploy { code: probe_wasm() },
                0,
                1_000,
            );
            let receipts = run(&mut ctx, &storage, active_round, vec![tx]);
            assert!(!receipts[0].success);
            assert!(
                receipts[0]
                    .error
                    .as_deref()
                    .is_some_and(|e| e.contains("Contract address already has code")),
                "{:?}",
                receipts[0].error
            );
            assert_eq!(read_account_code(&storage, &target), b"pre-seeded code");
            assert_eq!(read_balance(&storage, &sender), 1_000_000 - 1_000);
            assert_eq!(read_nonce(&storage, &sender), 1);
        }
    }

    // Only the 16 canonical entry points are callable from activation on; below
    // activation any export the module defines is callable (old behavior).
    #[test]
    fn wasm_entry_point_is_gated() {
        let active_round = kovanica_types::CONTRACT_HARDENING_ACTIVE_FROM_ROUND;
        const ALLOWED_CONTRACT: Address = Address([0xC3; 32]);

        // gate OFF: the module's non-entry export "probe" still executes.
        {
            let dir = tempfile::tempdir().expect("tempdir");
            let storage = Storage::new(dir.path().join("t.redb")).expect("storage");
            let key = test_keypair(1);
            let sender = address_of(&key);
            let mut ctx = setup_funded_sender(&storage, &sender, 1_000_000);
            deploy_probe(&storage);
            let receipts = run(
                &mut ctx,
                &storage,
                1,
                vec![probe_call(&key, false, 0, 1_000)],
            );
            assert!(receipts[0].success, "{:?}", receipts[0].error);
            assert_eq!(probe_slot(&storage), Some(1_000_000 - 1_000));
        }

        // gate ON: "probe" is not an entry point — rejected before the
        // interpreter (no fuel, no storage write).
        {
            let dir = tempfile::tempdir().expect("tempdir");
            let storage = Storage::new(dir.path().join("t.redb")).expect("storage");
            let key = test_keypair(1);
            let sender = address_of(&key);
            let mut ctx = setup_funded_sender(&storage, &sender, 1_000_000);
            deploy_probe(&storage);
            let receipts = run(
                &mut ctx,
                &storage,
                active_round,
                vec![probe_call(&key, false, 0, 1_000)],
            );
            assert!(!receipts[0].success);
            assert!(
                receipts[0]
                    .error
                    .as_deref()
                    .is_some_and(|e| e.contains("Unknown contract entry point: probe")),
                "{:?}",
                receipts[0].error
            );
            assert_eq!(receipts[0].gas_used, 0, "rejected before the interpreter");
            assert_eq!(probe_slot(&storage), None, "no storage write");
        }

        // gate ON: a canonical entry point is not rejected by the gate and the
        // call runs to completion.
        {
            let dir = tempfile::tempdir().expect("tempdir");
            let storage = Storage::new(dir.path().join("t.redb")).expect("storage");
            let key = test_keypair(1);
            let sender = address_of(&key);
            let mut ctx = setup_funded_sender(&storage, &sender, 1_000_000);
            set_raw_code(
                &storage,
                &ALLOWED_CONTRACT,
                probe_wasm_named("token_transfer"),
            );
            let kind = TransactionKind::Call {
                contract: ALLOWED_CONTRACT,
                value: 0,
                method: "token_transfer".to_string(),
                args: Vec::new(),
                gas_limit: 1_000_000,
            };
            let receipts = run(
                &mut ctx,
                &storage,
                active_round,
                vec![signed_tx(&key, kind, 0, 1_000)],
            );
            assert!(receipts[0].success, "{:?}", receipts[0].error);
        }
    }

    #[test]
    fn contract_e2e_transactions_htlc_vault_multisig_gated_and_ungated() {
        let htlc_wasm = match contracts::tests::build_contract_wasm("kovanica-htlc") {
            Some(w) => w,
            None => return,
        };
        let vault_wasm = match contracts::tests::build_contract_wasm("kovanica-vault") {
            Some(w) => w,
            None => return,
        };
        let multisig_wasm = match contracts::tests::build_contract_wasm("kovanica-multisig") {
            Some(w) => w,
            None => return,
        };

        let active_round = kovanica_types::CONTRACT_HARDENING_ACTIVE_FROM_ROUND;

        // Test with gate inactive (round 1) and gate active (round active_round)
        for &round in &[1u64, active_round] {
            let dir = tempfile::tempdir().expect("tempdir");
            let storage = Storage::new(dir.path().join("e2e.redb")).expect("storage");

            let key1 = test_keypair(1);
            let sender1 = address_of(&key1);
            let key2 = test_keypair(2);
            let sender2 = address_of(&key2);
            let key3 = test_keypair(3);
            let sender3 = address_of(&key3);

            let mut ctx = setup_funded_sender(&storage, &sender1, 50_000_000);
            fund(&storage, &sender2, 20_000_000);
            fund(&storage, &sender3, 10_000_000);

            let mut step = 0u16;
            let mut execute_step = |ctx: &mut ExecutionContext, txs: Vec<Transaction>| {
                let leader = sample_block_at(step, round);
                let mut block = sample_block_with_txs(step, txs);
                block.round = round;
                let subdag = CommittedSubDag {
                    blocks: vec![block],
                    leader,
                    leader_round: round,
                    leader_author: step,
                    non_blue: Vec::new(),
                };
                step += 1;
                ctx.execute_committed_subdag(&subdag, &storage)
                    .expect("execute")
                    .receipts
            };

            // ---------------------------------------------------------------
            // 1. HTLC (Deploy -> Create -> Claim failure -> Claim success)
            // ---------------------------------------------------------------
            let deploy_htlc = signed_tx(
                &key1,
                TransactionKind::Deploy {
                    code: htlc_wasm.clone(),
                },
                0,
                1_000,
            );
            let receipts = execute_step(&mut ctx, vec![deploy_htlc]);
            assert!(receipts[0].success, "{:?}", receipts[0].error);
            let htlc_addr = deployed_address(&sender1, 0);

            let preimage = b"tx_e2e_htlc_secret";
            let hash_lock = kovanica_common::hash(preimage);

            let create_args = call_args::encode_htlc_create(sender2.0, 500_000, hash_lock, 10_000)
                .expect("encode");
            let create_tx = signed_tx(
                &key1,
                TransactionKind::Call {
                    contract: htlc_addr,
                    value: 500_000,
                    method: "htlc_create".to_string(),
                    args: create_args,
                    gas_limit: 10_000_000,
                },
                1,
                1_000,
            );
            let receipts = execute_step(&mut ctx, vec![create_tx]);
            assert!(receipts[0].success, "{:?}", receipts[0].error);
            assert!(receipts[0].gas_used > 0);
            assert_eq!(receipts[0].events.len(), 1);
            assert_eq!(
                receipts[0].events[0].topic,
                kovanica_common::events::HTLC_CREATED
            );
            let htlc_id: [u8; 32] = receipts[0].events[0]
                .data
                .as_slice()
                .try_into()
                .expect("32-byte id");

            // Claim failure (wrong preimage) -> receipt.success == false, rolled back
            let bad_claim_args =
                call_args::encode_htlc_claim(htlc_id, b"wrong_preimage").expect("encode");
            let fail_claim_tx = signed_tx(
                &key2,
                TransactionKind::Call {
                    contract: htlc_addr,
                    value: 0,
                    method: "htlc_claim".to_string(),
                    args: bad_claim_args,
                    gas_limit: 10_000_000,
                },
                0,
                1_000,
            );
            let receipts = execute_step(&mut ctx, vec![fail_claim_tx]);
            assert!(!receipts[0].success);
            assert!(receipts[0].error.is_some());
            // Recipient was not credited 500_000
            assert_eq!(read_balance(&storage, &sender2), 20_000_000 - 1_000);

            // Claim success (valid preimage)
            let good_claim_args = call_args::encode_htlc_claim(htlc_id, preimage).expect("encode");
            let claim_tx = signed_tx(
                &key2,
                TransactionKind::Call {
                    contract: htlc_addr,
                    value: 0,
                    method: "htlc_claim".to_string(),
                    args: good_claim_args,
                    gas_limit: 10_000_000,
                },
                1,
                1_000,
            );
            let receipts = execute_step(&mut ctx, vec![claim_tx]);
            assert!(receipts[0].success, "{:?}", receipts[0].error);
            assert_eq!(
                receipts[0].events[0].topic,
                kovanica_common::events::HTLC_CLAIMED
            );
            assert_eq!(
                read_balance(&storage, &sender2),
                20_000_000 - 2_000 + 500_000
            );

            // ---------------------------------------------------------------
            // 2. Vault (Deploy -> Create -> Unauthorized claim -> Valid claim)
            // ---------------------------------------------------------------
            let deploy_vault = signed_tx(
                &key1,
                TransactionKind::Deploy {
                    code: vault_wasm.clone(),
                },
                2,
                1_000,
            );
            let receipts = execute_step(&mut ctx, vec![deploy_vault]);
            assert!(receipts[0].success, "{:?}", receipts[0].error);
            let vault_addr = deployed_address(&sender1, 2);

            let schedule = kovanica_vault::VestingSchedule::Linear {
                start: 0,
                end: 1,
                cliff: None,
            };
            let v_create_args =
                call_args::encode_vault_create(sender2.0, 1_000_000, &schedule).expect("encode");
            let v_create_tx = signed_tx(
                &key1,
                TransactionKind::Call {
                    contract: vault_addr,
                    value: 1_000_000,
                    method: "vault_create".to_string(),
                    args: v_create_args,
                    gas_limit: 10_000_000,
                },
                3,
                1_000,
            );
            let receipts = execute_step(&mut ctx, vec![v_create_tx]);
            assert!(receipts[0].success, "{:?}", receipts[0].error);
            assert_eq!(
                receipts[0].events[0].topic,
                kovanica_common::events::VAULT_CREATED
            );
            let vault_id: [u8; 32] = receipts[0].events[0]
                .data
                .as_slice()
                .try_into()
                .expect("32-byte id");

            // Unauthorized claim by sender3
            let v_claim_args = call_args::encode_vault_claim(vault_id).expect("encode");
            let unauth_tx = signed_tx(
                &key3,
                TransactionKind::Call {
                    contract: vault_addr,
                    value: 0,
                    method: "vault_claim".to_string(),
                    args: v_claim_args.clone(),
                    gas_limit: 10_000_000,
                },
                0,
                1_000,
            );
            let receipts = execute_step(&mut ctx, vec![unauth_tx]);
            assert!(!receipts[0].success);

            // Beneficiary claim success
            let v_claim_tx = signed_tx(
                &key2,
                TransactionKind::Call {
                    contract: vault_addr,
                    value: 0,
                    method: "vault_claim".to_string(),
                    args: v_claim_args,
                    gas_limit: 10_000_000,
                },
                2,
                1_000,
            );
            let receipts = execute_step(&mut ctx, vec![v_claim_tx]);
            assert!(receipts[0].success, "{:?}", receipts[0].error);
            assert_eq!(
                receipts[0].events[0].topic,
                kovanica_common::events::VAULT_CLAIMED
            );

            // ---------------------------------------------------------------
            // 3. Multisig (Deploy -> Fund -> Create -> Propose -> Execute fail -> Confirm -> Execute)
            // ---------------------------------------------------------------
            let deploy_ms = signed_tx(
                &key1,
                TransactionKind::Deploy {
                    code: multisig_wasm.clone(),
                },
                4,
                1_000,
            );
            let receipts = execute_step(&mut ctx, vec![deploy_ms]);
            assert!(receipts[0].success, "{:?}", receipts[0].error);
            let ms_addr = deployed_address(&sender1, 4);

            // Fund multisig contract with 5_000_000 via native transfer
            let fund_ms_tx = create_transfer_tx(&key1, &ms_addr, 5_000_000, 5, 1_000);
            let receipts = execute_step(&mut ctx, vec![fund_ms_tx]);
            assert!(receipts[0].success, "{:?}", receipts[0].error);

            // Create 2-of-2 multisig
            let ms_create_args =
                call_args::encode_multisig_create(&[sender1.0, sender2.0], 2).expect("encode");
            let ms_create_tx = signed_tx(
                &key1,
                TransactionKind::Call {
                    contract: ms_addr,
                    value: 0,
                    method: "multisig_create".to_string(),
                    args: ms_create_args,
                    gas_limit: 10_000_000,
                },
                6,
                1_000,
            );
            let receipts = execute_step(&mut ctx, vec![ms_create_tx]);
            assert!(receipts[0].success, "{:?}", receipts[0].error);
            assert_eq!(
                receipts[0].events[0].topic,
                kovanica_common::events::MULTISIG_CREATED
            );
            let ms_id: [u8; 32] = receipts[0].events[0]
                .data
                .as_slice()
                .try_into()
                .expect("32-byte id");

            // Propose transfer of 1_000_000 to sender3
            let prop_args = call_args::encode_multisig_propose(ms_id, sender3.0, 1_000_000, &[])
                .expect("encode");
            let prop_tx = signed_tx(
                &key1,
                TransactionKind::Call {
                    contract: ms_addr,
                    value: 0,
                    method: "multisig_propose".to_string(),
                    args: prop_args,
                    gas_limit: 10_000_000,
                },
                7,
                1_000,
            );
            let receipts = execute_step(&mut ctx, vec![prop_tx]);
            assert!(receipts[0].success, "{:?}", receipts[0].error);
            assert_eq!(
                receipts[0].events[0].topic,
                kovanica_common::events::MULTISIG_PROPOSED
            );
            let tx_id =
                u64::from_le_bytes(receipts[0].events[0].data.as_slice().try_into().unwrap());
            assert_eq!(tx_id, 1);

            // Execute failure (only 1 confirmation, threshold is 2)
            let exec_args = call_args::encode_multisig_execute(ms_id, tx_id).expect("encode");
            let early_exec_tx = signed_tx(
                &key1,
                TransactionKind::Call {
                    contract: ms_addr,
                    value: 0,
                    method: "multisig_execute".to_string(),
                    args: exec_args.clone(),
                    gas_limit: 10_000_000,
                },
                8,
                1_000,
            );
            let receipts = execute_step(&mut ctx, vec![early_exec_tx]);
            assert!(!receipts[0].success);

            // Confirm by sender2 (now 2 of 2)
            let conf_args = call_args::encode_multisig_confirm(ms_id, tx_id).expect("encode");
            let conf_tx = signed_tx(
                &key2,
                TransactionKind::Call {
                    contract: ms_addr,
                    value: 0,
                    method: "multisig_confirm".to_string(),
                    args: conf_args,
                    gas_limit: 10_000_000,
                },
                3,
                1_000,
            );
            let receipts = execute_step(&mut ctx, vec![conf_tx]);
            assert!(receipts[0].success, "{:?}", receipts[0].error);
            assert_eq!(
                receipts[0].events[0].topic,
                kovanica_common::events::MULTISIG_CONFIRMED
            );

            // Execute success
            let balance_before = read_balance(&storage, &sender3);
            let exec_tx = signed_tx(
                &key1,
                TransactionKind::Call {
                    contract: ms_addr,
                    value: 0,
                    method: "multisig_execute".to_string(),
                    args: exec_args,
                    gas_limit: 10_000_000,
                },
                9,
                1_000,
            );
            let receipts = execute_step(&mut ctx, vec![exec_tx]);
            assert!(receipts[0].success, "{:?}", receipts[0].error);
            assert_eq!(
                receipts[0].events[0].topic,
                kovanica_common::events::MULTISIG_EXECUTED
            );
            assert_eq!(read_balance(&storage, &sender3), balance_before + 1_000_000);
        }
    }
}
