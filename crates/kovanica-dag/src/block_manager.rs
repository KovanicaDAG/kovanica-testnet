//! Block manager for Kovanica.
//!
#![allow(missing_docs)]
//! Handles block proposal, validation, and broadcast.

use crate::DagStore;
use kovanica_crypto::{self as crypto, CryptoError};
use kovanica_types::{
    block::{BlockReference, StatementBlock},
    crypto::PublicKey,
    hash::Hash,
    transaction::Transaction,
    AuthorityIndex, Round, Signature, SigningKey, MAX_TXS_PER_BLOCK, MAX_TX_GAS_LIMIT,
};
use parking_lot::RwLock;
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::watch;
use tracing::{debug, info, warn};

/// bincode is used for transaction hash verification
use bincode;

/// Per-block gas budget: the sum of the `gas_limit` of every `Call`
/// transaction in a block may not exceed this.
///
/// Chosen as `MAX_TX_GAS_LIMIT * 8` (= 80_000_000). `MAX_TXS_PER_BLOCK` alone
/// does not bound interpreter work, because each pooled transaction carries its
/// own `gas_limit`; this bounds the worst case a single block can force on every
/// validator to eight maximal calls per committed round, while leaving ample
/// room for the common case (native transactions consume no interpreter fuel).
/// The cap and this budget are enforced only from
/// [`kovanica_types::GAS_HARDENING_ACTIVE_FROM_ROUND`] on — see
/// `validate_block_content`.
const BLOCK_GAS_BUDGET: u64 = MAX_TX_GAS_LIMIT * 8;

/// The `gas_limit` a transaction asks the interpreter for, or `0` for native
/// kinds (they never touch wasmi fuel).
fn tx_gas_limit(tx: &kovanica_types::Transaction) -> u64 {
    match &tx.kind {
        kovanica_types::TransactionKind::Call { gas_limit, .. } => *gas_limit,
        _ => 0,
    }
}

/// Sum of the requested `Call` gas limits over `txs`, saturating.
fn total_gas_limit<'a>(txs: impl IntoIterator<Item = &'a kovanica_types::Transaction>) -> u64 {
    txs.into_iter()
        .fold(0u64, |acc, tx| acc.saturating_add(tx_gas_limit(tx)))
}

/// Serialized size of `value` in bytes, using the bincode encoding shared by
/// storage and the network.
///
/// This is the measure the consensus size limits use. bincode is deterministic
/// for a given value, so two nodes always agree on the number. The types
/// involved (blocks, transactions) contain no maps or other constructs whose
/// encoding bincode cannot size, so a failure here is treated as over-limit:
/// such a value could not be stored or relayed either.
fn encoded_len<T: serde::Serialize>(value: &T) -> u64 {
    bincode::serialized_size(value).unwrap_or(u64::MAX)
}

/// Errors specific to block manager operations.
#[derive(Error, Debug)]
pub enum BlockManagerError {
    #[error("Invalid block: {0}")]
    InvalidBlock(String),
    #[error("DAG store error: {0}")]
    DagStore(#[from] crate::DagStoreError),
    #[error("Crypto error: {0}")]
    Crypto(#[from] CryptoError),
    #[error("Not enough transactions for block")]
    NotEnoughTransactions,
    #[error("Round mismatch: expected {expected}, got {actual}")]
    RoundMismatch { expected: Round, actual: Round },
    #[error("Parent validation failed: {0}")]
    ParentValidation(String),
}

/// Block manager for proposing and validating blocks.
pub struct BlockManager {
    dag_store: Arc<DagStore>,
    /// Pending transactions waiting to be included in blocks.
    pending_txs: Arc<RwLock<VecDeque<Transaction>>>,
    /// The authority index of this validator.
    our_authority: RwLock<AuthorityIndex>,
    /// Our signing key for block signing.
    signing_key: RwLock<Option<SigningKey>>,
    authority_keys: RwLock<HashMap<AuthorityIndex, PublicKey>>,
    /// Stake amounts for each authority (for parent selection filtering).
    authority_stakes: RwLock<HashMap<AuthorityIndex, u64>>,
    /// Optional round watch receiver from consensus engine for current round tracking.
    round_receiver: RwLock<Option<watch::Receiver<Round>>>,
    /// VRF public keys per authority (from committee), used to verify block proofs.
    vrf_author_keys: RwLock<HashMap<AuthorityIndex, PublicKey>>,
    /// Verified VRF outputs (round → author → hash), produced by block manager on valid blocks.
    verified_vrf_outputs: RwLock<HashMap<Round, HashMap<AuthorityIndex, [u8; 32]>>>,
    /// Signing context (chain_id/epoch) for tx signing-hash checks.
    signing_ctx: kovanica_types::SigningContext,
    /// VRF key derived from validator seed (optional; wire upgrade active when set).
    vrf_keypair: RwLock<Option<kovanica_crypto::VRFKeyPair>>,
}

impl BlockManager {
    /// Create a new block manager.
    pub fn new(dag_store: Arc<DagStore>, signing_ctx: kovanica_types::SigningContext) -> Self {
        Self {
            dag_store,
            pending_txs: Arc::new(RwLock::new(VecDeque::new())),
            our_authority: RwLock::new(0), // Will be set when validator joins
            signing_key: RwLock::new(None),
            authority_keys: RwLock::new(HashMap::new()),
            authority_stakes: RwLock::new(HashMap::new()),
            round_receiver: RwLock::new(None),
            signing_ctx,
            vrf_keypair: RwLock::new(None),
            vrf_author_keys: RwLock::new(HashMap::new()),
            verified_vrf_outputs: RwLock::new(HashMap::new()),
        }
    }

    /// Set the committee stake amounts for parent selection filtering.
    pub fn set_authority_stakes(&self, stakes: HashMap<AuthorityIndex, u64>) {
        *self.authority_stakes.write() = stakes;
    }

    /// Set our authority index.
    pub fn set_authority(&self, authority: AuthorityIndex) {
        *self.our_authority.write() = authority;
    }

    /// Set our signing key (derives VRF secret from seed if available).
    pub fn set_signing_key(&self, key: SigningKey) {
        *self.signing_key.write() = Some(key.clone());
        // Derive VRF secret deterministically from the Ed25519 seed
        let seed_bytes: [u8; 32] = key.to_bytes();
        let secret = kovanica_crypto::derive_vrf_secret_from_seed(&seed_bytes);
        if let Ok(kp) = kovanica_crypto::VRFKeyPair::from_secret(secret) {
            *self.vrf_keypair.write() = Some(kp);
        }
    }

    /// Set the committee public keys used to authenticate block authors.
    pub fn set_authority_keys(&self, keys: HashMap<AuthorityIndex, PublicKey>) {
        *self.authority_keys.write() = keys;
    }

    /// Get our authority index.
    pub fn our_authority(&self) -> AuthorityIndex {
        *self.our_authority.read()
    }

    /// Set the round watch receiver from the consensus engine.
    /// This allows the block manager to track the current round from the consensus engine's watch channel.
    pub fn set_round_receiver(&self, receiver: watch::Receiver<Round>) {
        *self.round_receiver.write() = Some(receiver);
    }

    /// Get the current round from the consensus engine's watch channel.
    /// Returns 0 if no receiver is set or the channel is closed.
    pub fn current_round(&self) -> Round {
        if let Some(receiver) = self.round_receiver.read().as_ref() {
            *receiver.borrow()
        } else {
            0
        }
    }

    /// Add a transaction to the pending pool.
    pub fn add_transaction(&self, tx: Transaction) {
        let mut pending = self.pending_txs.write();
        pending.push_back(tx);
    }

    /// Add multiple transactions to the pending pool.
    pub fn add_transactions(&self, txs: Vec<Transaction>) {
        let mut pending = self.pending_txs.write();
        pending.extend(txs);
    }

    /// Get the next transactions for block proposal (up to MAX_TXS_PER_BLOCK).
    pub fn get_next_transactions(&self) -> Vec<Transaction> {
        let mut pending = self.pending_txs.write();
        let mut txs = Vec::new();
        for _ in 0..MAX_TXS_PER_BLOCK {
            if let Some(tx) = pending.pop_front() {
                txs.push(tx);
            } else {
                break;
            }
        }
        txs
    }

    /// Propose a new block for the given round (pulls from tx_pool).
    pub fn propose_block(&self, round: Round) -> Result<StatementBlock, BlockManagerError> {
        let txs = self.get_next_transactions();
        self.propose_block_with_txs(round, txs)
    }

    /// Propose a new block for the given round with specific transactions.
    /// Pulls from the internal tx_pool (-fed by add_transaction) and merges
    /// with any explicitly provided transactions. Sorted deterministically.
    pub fn propose_block_with_txs(
        &self,
        round: Round,
        transactions: Vec<Transaction>,
    ) -> Result<StatementBlock, BlockManagerError> {
        // Pull from mempool feed (audit 3.2 close)
        let mut txs = self.get_next_transactions();
        txs.extend(transactions);
        // Deterministic order: group by sender and sort by nonce within each sender.
        // This preserves the per-sender nonce sequence required for correct execution.
        // The mempool already prioritizes by fee rate; this sort only reorders
        // across senders, which is safe since different senders don't share nonces.
        txs.sort_by(|a, b| a.sender.cmp(&b.sender).then_with(|| a.nonce.cmp(&b.nonce)));
        txs.dedup_by(|a, b| a.hash == b.hash);
        if txs.len() > MAX_TXS_PER_BLOCK {
            txs.truncate(MAX_TXS_PER_BLOCK);
        }
        // Per-block gas budget: the sorted list is truncated at the first
        // transaction that would push the cumulative `Call` gas over
        // `BLOCK_GAS_BUDGET`. Because the list is ordered by (sender, nonce), a
        // tail drop only removes whole senders or a suffix of one sender's
        // nonces — never a gap in a per-sender nonce sequence.
        //
        // Activation-gated: below `GAS_HARDENING_ACTIVE_FROM_ROUND` the proposer
        // behaves exactly as before (no truncation), so a node that has not been
        // updated keeps proposing the same blocks.
        if kovanica_types::gas_hardening_active_from(round) {
            let mut gas_sum = 0u64;
            let mut keep = txs.len();
            for (index, tx) in txs.iter().enumerate() {
                gas_sum = gas_sum.saturating_add(tx_gas_limit(tx));
                if gas_sum > BLOCK_GAS_BUDGET {
                    keep = index;
                    break;
                }
            }
            // The surplus is dropped from this proposal; its pool entries were
            // already taken, so the sender re-broadcasts if it still wants them
            // mined. Consensus never sees an over-budget block either way —
            // `validate_block_content` rejects one.
            txs.truncate(keep);
        }
        // Get parent blocks from previous round with stake/validity filtering
        let parents = self.select_parents(round)?;

        // Create the block (without signature first)
        let block = self.create_block(round, parents, txs)?;

        // Sign the block
        let signed_block = self.sign_block(block)?;

        // Store the block
        self.dag_store.put_block(&signed_block)?;

        Ok(signed_block)
    }

    /// Propose a block that carries only this validator's VRF statement.
    ///
    /// The transaction pool is left untouched. The caller publishes this on
    /// a decide round so the next leader round can see a complete output set.
    pub fn propose_vrf_carrier(&self, round: Round) -> Result<StatementBlock, BlockManagerError> {
        let author = *self.our_authority.read();
        if self.vrf_keypair.read().is_none() || !self.vrf_author_keys.read().contains_key(&author) {
            return Err(BlockManagerError::InvalidBlock(
                "validator has no committee VRF key".into(),
            ));
        }
        let parents = self.select_parents(round)?;
        let block = self.create_block(round, parents, Vec::new())?;
        let signed_block = self.sign_block(block)?;
        self.dag_store.put_block(&signed_block)?;
        Ok(signed_block)
    }

    /// Install the committee VRF keys used to verify block statements.
    pub fn set_vrf_author_keys(&self, keys: HashMap<AuthorityIndex, PublicKey>) {
        *self.vrf_author_keys.write() = keys;
    }

    /// Verified VRF outputs, keyed by the round of the block that carried them.
    pub fn verified_vrf_outputs_snapshot(
        &self,
    ) -> HashMap<Round, HashMap<AuthorityIndex, [u8; 32]>> {
        self.verified_vrf_outputs.read().clone()
    }

    /// Select valid parent blocks from the most recent populated earlier round.
    /// Filters by: author in committee, stake > 0, valid signature (already validated on ingress).
    /// Returns up to committee_size parents (or a small default as fallback).
    ///
    /// Walks backwards from `round - 1` to `round - MAX_PARENT_ROUND_GAP` and
    /// uses the first round that actually contains blocks, so a gap in the DAG
    /// (a round with no committee-backed blocks) cannot orphan a block.
    fn select_parents(&self, round: Round) -> Result<Vec<BlockReference>, BlockManagerError> {
        if round == 0 {
            return Ok(Vec::new());
        }

        let authority_keys = self.authority_keys.read();
        let authority_stakes = self.authority_stakes.read();

        // Determine max parents: committee size if stakes are set, otherwise a reasonable default
        let max_parents = if !authority_stakes.is_empty() {
            authority_stakes.len()
        } else {
            // Fallback: use a small number to avoid excessive parent sets
            3usize
        };

        // Find the most recent populated round within the allowed gap.
        let min_round = round.saturating_sub(kovanica_types::MAX_PARENT_ROUND_GAP);
        let mut blocks = Vec::new();
        let mut probe = round - 1;
        loop {
            let candidate = self.dag_store.get_blocks_by_round(probe)?;
            if !candidate.is_empty() {
                blocks = candidate;
                break;
            }
            if probe <= min_round {
                break;
            }
            probe -= 1;
        }

        // Filter blocks: author must be in committee with stake > 0
        let parents: Vec<BlockReference> = blocks
            .into_iter()
            .filter(|b| {
                authority_keys.contains_key(&b.author)
                    && authority_stakes.get(&b.author).copied().unwrap_or(0) > 0
            })
            .take(max_parents)
            .map(|b| BlockReference {
                author: b.author,
                round: b.round,
                digest: b.digest,
            })
            .collect();

        Ok(parents)
    }

    /// Create a block without signing.
    fn create_block(
        &self,
        round: Round,
        parents: Vec<BlockReference>,
        transactions: Vec<Transaction>,
    ) -> Result<StatementBlock, BlockManagerError> {
        // Compute digest
        let merkle_root = StatementBlock::compute_merkle_root(&transactions);
        // Compute digest — include VRF statement only when we have a proof to attach
        let author = *self.our_authority.read();
        let mut statements = Vec::new();
        if let Some(ref kp) = *self.vrf_keypair.read() {
            let chain_id = self.signing_ctx.chain_id;
            let input = kovanica_types::block::vrf_input(chain_id, round, author);
            let proof = kovanica_crypto::vrf_prove(kp, input.as_bytes());
            statements = kovanica_crypto::encode_statements(&proof);
        }
        if kovanica_types::block::is_vrf_statement(&statements)
            && self.vrf_author_keys.read().contains_key(&author)
        {
            if let Some(output) = kovanica_crypto::decode_statements(&statements) {
                self.verified_vrf_outputs
                    .write()
                    .entry(round)
                    .or_default()
                    .entry(author)
                    .or_insert(output.hash);
            }
        }
        let digest = StatementBlock::compute_digest_statements(
            *self.our_authority.read(),
            round,
            &parents,
            &transactions,
            if kovanica_types::block::is_vrf_statement(&statements) {
                Some(&statements)
            } else {
                None
            },
        );

        Ok(StatementBlock {
            author: *self.our_authority.read(),
            round,
            parents,
            transactions,
            statements,
            signature: Signature([0; 64]),
            digest,
            merkle_root,
        })
    }

    /// Sign a block with our signing key.
    fn sign_block(&self, mut block: StatementBlock) -> Result<StatementBlock, BlockManagerError> {
        let signing_key = self
            .signing_key
            .read()
            .as_ref()
            .ok_or_else(|| BlockManagerError::Crypto(CryptoError::InvalidSignature))?
            .clone();

        let digest_bytes = block.digest.as_ref();
        let signature = crypto::sign(&signing_key, digest_bytes);

        block.signature = signature;
        Ok(block)
    }

    /// Validate a received block.
    pub fn validate_block(&self, block: &StatementBlock) -> Result<(), BlockManagerError> {
        // Round 0 is the canonical genesis block - validate it specially.
        if block.round == 0 {
            return self.validate_canonical_genesis(block);
        }

        self.validate_block_content(block)?;

        // Bounded validation: only the direct parents are read. Every stored
        // block was validated the same way before it was stored (see
        // `process_block`), so the history behind a valid parent is already
        // authenticated by induction. Parents below the durable prune
        // boundary are not looked up at all and are accepted as already
        // validated. Cost is O(parents), independent of DAG size.
        let prune_boundary = self.dag_store.prune_boundary()?;
        self.validate_parent_references_bounded(block, prune_boundary, true)?;

        Ok(())
    }

    fn validate_block_content(&self, block: &StatementBlock) -> Result<(), BlockManagerError> {
        if block.transactions.len() > MAX_TXS_PER_BLOCK {
            return Err(BlockManagerError::InvalidBlock(
                "too many transactions".to_string(),
            ));
        }

        // Gas-hardening activation gate. Both new block-validity rejections
        // (per-block budget here, per-transaction cap in `validate_transaction`)
        // apply only from `GAS_HARDENING_ACTIVE_FROM_ROUND`. Below it the block
        // is validated exactly as before, so a huge-gas block still validates
        // and a not-yet-updated node does not diverge from an updated one.
        let gas_hardening_active = kovanica_types::gas_hardening_active_from(block.round);

        // Per-block gas budget: `MAX_TXS_PER_BLOCK` bounds the count, this
        // bounds the interpreter work. Checked before per-transaction
        // validation so an over-budget block is rejected with the block-level
        // reason rather than a per-transaction one.
        if gas_hardening_active {
            let block_gas = total_gas_limit(&block.transactions);
            if block_gas > BLOCK_GAS_BUDGET {
                return Err(BlockManagerError::InvalidBlock(format!(
                    "block gas budget exceeded: {block_gas} > {BLOCK_GAS_BUDGET}"
                )));
            }
        }

        // Consensus size limits, gated on `SIZE_LIMITS_ACTIVE_FROM_ROUND` so
        // they are inert on a live chain that has not been upgraded in step.
        //
        // Sizes are measured on the bincode encoding, the same encoding used
        // for storage and the wire, so every node computes the same number for
        // the same value and the check is consensus deterministic. The block
        // cap is below the network frame cap, so a block that passes here can
        // always be relayed in one message.
        if kovanica_types::size_limits_active_from(block.round) {
            let block_bytes = encoded_len(block);
            if block_bytes > kovanica_types::MAX_BLOCK_BYTES as u64 {
                return Err(BlockManagerError::InvalidBlock(format!(
                    "block size {} exceeds maximum {}",
                    block_bytes,
                    kovanica_types::MAX_BLOCK_BYTES
                )));
            }
            for tx in &block.transactions {
                let tx_bytes = encoded_len(tx);
                if tx_bytes > kovanica_types::MAX_TX_BYTES as u64 {
                    return Err(BlockManagerError::InvalidBlock(format!(
                        "transaction size {tx_bytes} exceeds maximum {}",
                        kovanica_types::MAX_TX_BYTES
                    )));
                }
            }
        }

        // Validate each transaction's hash and basic structure
        for tx in &block.transactions {
            self.validate_transaction(tx, gas_hardening_active)?;
        }

        let computed_digest = StatementBlock::compute_digest_statements(
            block.author,
            block.round,
            &block.parents,
            &block.transactions,
            if !block.statements.is_empty() {
                Some(&block.statements)
            } else {
                None
            },
        );
        if computed_digest != block.digest {
            return Err(BlockManagerError::InvalidBlock(
                "Digest mismatch".to_string(),
            ));
        }

        // Wire-upgrade: verify VRF proof and record verified output when statements carry it.
        if let Some(output) = kovanica_crypto::decode_statements(&block.statements) {
            if let Some(vrf_pk) = self.vrf_author_keys.read().get(&block.author).copied() {
                let input = kovanica_types::block::vrf_input(
                    self.signing_ctx.chain_id,
                    block.round,
                    block.author,
                );
                if kovanica_crypto::vrf_verify(&vrf_pk, input.as_bytes(), &output).is_err() {
                    return Err(BlockManagerError::InvalidBlock(
                        "VRF proof verification failed".to_string(),
                    ));
                }
                // Record the verified output for leader selection
                let mut out_map = self.verified_vrf_outputs.write();
                out_map
                    .entry(block.round)
                    .or_default()
                    .insert(block.author, output.hash);
            }
        }

        // Verify merkle root matches transaction hashes
        let computed_merkle = StatementBlock::compute_merkle_root(&block.transactions);
        if computed_merkle != block.merkle_root {
            return Err(BlockManagerError::InvalidBlock(
                "Merkle root mismatch".to_string(),
            ));
        }

        let public_key = self
            .authority_keys
            .read()
            .get(&block.author)
            .copied()
            .ok_or_else(|| {
                BlockManagerError::InvalidBlock(format!("unknown block author {}", block.author))
            })?;
        crypto::verify_block_signature(&public_key, &block.digest, &block.signature)?;
        Ok(())
    }

    /// Validate a transaction's hash and basic structure.
    /// Full signature verification requires state access and is done in the mempool/execution layer.
    ///
    /// `gas_hardening_active` is derived from the containing block's round
    /// (`block.round >= GAS_HARDENING_ACTIVE_FROM_ROUND`); the per-transaction
    /// `Call` gas cap is enforced only when it is set, so pre-activation blocks
    /// validate exactly as before.
    fn validate_transaction(
        &self,
        tx: &kovanica_types::Transaction,
        gas_hardening_active: bool,
    ) -> Result<(), BlockManagerError> {
        // Verify cached hash matches domain-tagged signing hash (DOMAIN_TX)
        if tx.hash != tx.signing_hash(&self.signing_ctx) {
            return Err(BlockManagerError::InvalidBlock(
                "Transaction hash mismatch (DOMAIN_TX)".to_string(),
            ));
        }

        // Basic fee check: non-stake transactions must have a fee
        let is_stake = matches!(
            tx.kind,
            kovanica_types::TransactionKind::Stake { .. }
                | kovanica_types::TransactionKind::Delegate { .. }
        );
        if tx.fee == 0 && !is_stake {
            return Err(BlockManagerError::InvalidBlock(
                "Transaction fee is zero".to_string(),
            ));
        }

        // Gas cap (activation-gated): `Call.gas_limit` is charged as interpreter
        // fuel, so an uncapped value is unbounded per-transaction work. The
        // mempool enforces the same cap on admission; this is the consensus
        // backstop for transactions that arrive inside a block without ever
        // passing through the pool.
        if gas_hardening_active {
            if let kovanica_types::TransactionKind::Call { gas_limit, .. } = &tx.kind {
                if *gas_limit > MAX_TX_GAS_LIMIT {
                    return Err(BlockManagerError::InvalidBlock(format!(
                        "Transaction gas limit {gas_limit} exceeds maximum {MAX_TX_GAS_LIMIT}"
                    )));
                }
            }
        }

        // Note: Signature verification requires the sender's public key, which is not
        // available in the block manager. Full verification happens in mempool/execution
        // where account state can be accessed to resolve the sender's public key.
        Ok(())
    }

    /// Validate that round zero is the genesis block constructed by the node.
    /// Its digest is derived from its contents rather than a hard-coded hash.
    fn validate_canonical_genesis(&self, block: &StatementBlock) -> Result<(), BlockManagerError> {
        let canonical_digest = StatementBlock::compute_digest(0, 0, &[], &[]);
        if block.author != 0
            || block.round != 0
            || !block.parents.is_empty()
            || !block.transactions.is_empty()
            || !block.statements.is_empty()
            || block.signature != Signature([0; 64])
            || block.digest != canonical_digest
        {
            return Err(BlockManagerError::InvalidBlock(
                "invalid canonical genesis block".to_string(),
            ));
        }
        Ok(())
    }

    /// Structural parent checks that need no store access: parent count,
    /// `parent.round < block.round`, and the `MAX_PARENT_ROUND_GAP` window.
    fn validate_parent_structure(&self, block: &StatementBlock) -> Result<(), BlockManagerError> {
        let committee_size = {
            let stakes = self.authority_stakes.read();
            let keys = self.authority_keys.read();
            if !stakes.is_empty() {
                stakes.len()
            } else {
                keys.len()
            }
        };
        let max_parents = committee_size.max(kovanica_types::WAVE_LENGTH as usize);
        if block.parents.len() > max_parents {
            return Err(BlockManagerError::ParentValidation(format!(
                "too many parents: {} (max {})",
                block.parents.len(),
                max_parents
            )));
        }
        for parent_ref in &block.parents {
            if parent_ref.round >= block.round {
                return Err(BlockManagerError::ParentValidation(format!(
                    "Parent round {} is not before block round {}",
                    parent_ref.round, block.round
                )));
            }
            if block.round - parent_ref.round > kovanica_types::MAX_PARENT_ROUND_GAP {
                return Err(BlockManagerError::ParentValidation(format!(
                    "Parent round {} is too far behind block round {} (max gap {})",
                    parent_ref.round,
                    block.round,
                    kovanica_types::MAX_PARENT_ROUND_GAP
                )));
            }
        }
        Ok(())
    }

    /// Validate `block`'s parent references reading only its direct parents.
    ///
    /// Parents with `round < prune_boundary` are pruned history: they are not
    /// looked up and are accepted as already validated. Every other parent
    /// must exist with matching metadata. When `check_parent_content` is set,
    /// each loaded parent's own content (digest, merkle root, signature or
    /// canonical genesis) and its own parent *structure* are re-checked as a
    /// defence against blocks stored without validation; this never reads
    /// grandparents.
    fn validate_parent_references_bounded(
        &self,
        block: &StatementBlock,
        prune_boundary: Round,
        check_parent_content: bool,
    ) -> Result<(), BlockManagerError> {
        self.validate_parent_structure(block)?;
        for parent_ref in &block.parents {
            if parent_ref.round < prune_boundary {
                continue;
            }
            let parent = self.dag_store.get_block(&parent_ref.digest).map_err(|_| {
                BlockManagerError::ParentValidation(format!(
                    "Parent block {} not found",
                    parent_ref.digest
                ))
            })?;
            if parent.author != parent_ref.author || parent.round != parent_ref.round {
                return Err(BlockManagerError::ParentValidation(format!(
                    "Parent reference metadata does not match block {}",
                    parent_ref.digest
                )));
            }
            if check_parent_content {
                if parent.round == 0 {
                    self.validate_canonical_genesis(&parent)?;
                } else {
                    self.validate_block_content(&parent)?;
                    self.validate_parent_structure(&parent)?;
                }
            }
        }
        Ok(())
    }

    /// Check that each referenced parent exists, its round and author match
    /// the reference, that the parent strictly precedes the block, that the
    /// gap is within `MAX_PARENT_ROUND_GAP`, and that the parent count does not
    /// exceed the committee size (minimum 3).
    #[cfg(test)]
    fn validate_parent_references(&self, block: &StatementBlock) -> Result<(), BlockManagerError> {
        self.validate_parent_references_bounded(block, 0, false)
    }

    /// Process a received block (validate and store if valid).
    pub fn process_block(&self, block: &StatementBlock) -> Result<(), BlockManagerError> {
        self.validate_block(block)?;
        if !self.dag_store.has_block(&block.digest)? {
            self.dag_store.put_block(block)?;
        }
        Ok(())
    }

    /// Get pending transaction count.
    pub fn pending_count(&self) -> usize {
        self.pending_txs.read().len()
    }

    /// Clear pending transactions (e.g., after they've been included in a committed block).
    pub fn clear_pending(&self) {
        self.pending_txs.write().clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kovanica_types::{
        GAS_HARDENING_ACTIVE_FROM_ROUND, MAX_BLOCK_BYTES, MAX_TX_BYTES,
        SIZE_LIMITS_ACTIVE_FROM_ROUND,
    };
    const TEST_CTX: kovanica_types::SigningContext =
        kovanica_types::SigningContext::new(kovanica_types::signing::chain_id::LOCAL);
    #[test]
    fn received_block_requires_committee_signature_and_matching_digest() {
        let dir = tempfile::tempdir().expect("tempdir");
        let storage = kovanica_storage::Storage::new(dir.path().join("dag.redb")).unwrap();
        let store = Arc::new(DagStore::new(storage).unwrap());
        let manager = BlockManager::new(store, TEST_CTX);
        let (key, public_key) = crypto::generate_keypair();
        manager.set_authority_keys(HashMap::from([(0, public_key)]));

        let digest = StatementBlock::compute_digest(0, 1, &[], &[]);
        let valid = StatementBlock {
            author: 0,
            round: 1,
            parents: Vec::new(),
            transactions: Vec::new(),
            statements: Vec::new(),
            signature: crypto::sign(&key, digest.as_ref()),
            digest,
            merkle_root: Default::default(),
        };
        manager.validate_block(&valid).expect("valid signed block");

        let mut bad_signature = valid.clone();
        bad_signature.signature = Signature([0; 64]);
        assert!(manager.validate_block(&bad_signature).is_err());

        let mut bad_digest = valid;
        bad_digest.digest = Hash::zero();
        assert!(manager.validate_block(&bad_digest).is_err());

        let mut unknown_author = bad_digest;
        unknown_author.author = 9;
        unknown_author.digest = StatementBlock::compute_digest(9, 1, &[], &[]);
        assert!(manager.validate_block(&unknown_author).is_err());
    }

    #[test]
    fn valid_child_cannot_commit_a_pre_stored_invalid_ancestor() {
        let dir = tempfile::tempdir().expect("tempdir");
        let storage = kovanica_storage::Storage::new(dir.path().join("dag.redb")).unwrap();
        let store = Arc::new(DagStore::new(storage).unwrap());
        let manager = BlockManager::new(store.clone(), TEST_CTX);
        let (key, public_key) = crypto::generate_keypair();
        manager.set_authority_keys(HashMap::from([(0, public_key)]));

        let parent_digest = StatementBlock::compute_digest(0, 1, &[], &[]);
        let invalid_parent = StatementBlock {
            author: 0,
            round: 1,
            parents: Vec::new(),
            transactions: Vec::new(),
            statements: Vec::new(),
            signature: Signature([0; 64]),
            digest: parent_digest,
            merkle_root: Default::default(),
        };
        // Simulate the current network service's store-before-event behavior.
        store.put_block(&invalid_parent).unwrap();

        let parent_ref = BlockReference {
            author: invalid_parent.author,
            round: invalid_parent.round,
            digest: invalid_parent.digest,
        };
        let parents = vec![parent_ref];
        let child_digest = StatementBlock::compute_digest(0, 2, &parents, &[]);
        let child = StatementBlock {
            author: 0,
            round: 2,
            parents,
            transactions: Vec::new(),
            statements: Vec::new(),
            signature: crypto::sign(&key, child_digest.as_ref()),
            digest: child_digest,
            merkle_root: Default::default(),
        };

        assert!(manager.validate_block(&child).is_err());
    }

    #[test]
    fn rejects_noncanonical_round_zero_ancestor() {
        let dir = tempfile::tempdir().expect("tempdir");
        let storage = kovanica_storage::Storage::new(dir.path().join("dag.redb")).unwrap();
        let store = Arc::new(DagStore::new(storage).unwrap());
        let manager = BlockManager::new(store.clone(), TEST_CTX);
        let (key, public_key) = crypto::generate_keypair();
        manager.set_authority_keys(HashMap::from([(0, public_key)]));

        let mut malformed_genesis = StatementBlock {
            author: 0,
            round: 0,
            parents: Vec::new(),
            transactions: Vec::new(),
            statements: Vec::new(),
            signature: Signature([0; 64]),
            digest: StatementBlock::compute_digest(0, 0, &[], &[]),
            merkle_root: Default::default(),
        };
        // Keep the stored key and declared contents internally consistent but
        // violate the canonical genesis content invariant.
        malformed_genesis.author = 1;
        malformed_genesis.digest = StatementBlock::compute_digest(1, 0, &[], &[]);
        store.put_block(&malformed_genesis).unwrap();

        let parents = vec![BlockReference {
            author: malformed_genesis.author,
            round: malformed_genesis.round,
            digest: malformed_genesis.digest,
        }];
        let digest = StatementBlock::compute_digest(0, 1, &parents, &[]);
        let child = StatementBlock {
            author: 0,
            round: 1,
            parents,
            transactions: Vec::new(),
            statements: Vec::new(),
            signature: crypto::sign(&key, digest.as_ref()),
            digest,
            merkle_root: Default::default(),
        };

        assert!(manager.validate_block(&child).is_err());
    }

    #[test]
    fn rejects_nested_ancestor_with_invalid_parent_round_metadata() {
        let dir = tempfile::tempdir().expect("tempdir");
        let storage = kovanica_storage::Storage::new(dir.path().join("dag.redb")).unwrap();
        let store = Arc::new(DagStore::new(storage).unwrap());
        let manager = BlockManager::new(store.clone(), TEST_CTX);
        let (key, public_key) = crypto::generate_keypair();
        manager.set_authority_keys(HashMap::from([(0, public_key)]));

        let genesis = StatementBlock {
            author: 0,
            round: 0,
            parents: Vec::new(),
            transactions: Vec::new(),
            statements: Vec::new(),
            signature: Signature([0; 64]),
            digest: StatementBlock::compute_digest(0, 0, &[], &[]),
            merkle_root: Default::default(),
        };
        store.put_block(&genesis).unwrap();

        let genesis_parent = vec![BlockReference {
            author: genesis.author,
            round: genesis.round,
            digest: genesis.digest,
        }];
        let valid_digest = StatementBlock::compute_digest(0, 1, &genesis_parent, &[]);
        let valid_child = StatementBlock {
            author: 0,
            round: 1,
            parents: genesis_parent,
            transactions: Vec::new(),
            statements: Vec::new(),
            signature: crypto::sign(&key, valid_digest.as_ref()),
            digest: valid_digest,
            merkle_root: Default::default(),
        };
        manager
            .validate_block(&valid_child)
            .expect("canonical genesis is accepted as an ancestor");

        // The block's own digest and signature are valid, but its causal edge
        // falsely claims that genesis is at round one.
        let bad_parent_ref = BlockReference {
            author: genesis.author,
            round: 1,
            digest: genesis.digest,
        };
        let bad_parents = vec![bad_parent_ref];
        let bad_digest = StatementBlock::compute_digest(0, 1, &bad_parents, &[]);
        let bad_ancestor = StatementBlock {
            author: 0,
            round: 1,
            parents: bad_parents,
            transactions: Vec::new(),
            statements: Vec::new(),
            signature: crypto::sign(&key, bad_digest.as_ref()),
            digest: bad_digest,
            merkle_root: Default::default(),
        };
        store.put_block(&bad_ancestor).unwrap();

        let parents = vec![BlockReference {
            author: bad_ancestor.author,
            round: bad_ancestor.round,
            digest: bad_ancestor.digest,
        }];
        let digest = StatementBlock::compute_digest(0, 2, &parents, &[]);
        let child = StatementBlock {
            author: 0,
            round: 2,
            parents,
            transactions: Vec::new(),
            statements: Vec::new(),
            signature: crypto::sign(&key, digest.as_ref()),
            digest,
            merkle_root: Default::default(),
        };

        assert!(manager.validate_block(&child).is_err());
    }

    #[test]
    fn select_parents_filters_by_stake_and_committee() {
        let dir = tempfile::tempdir().expect("tempdir");
        let storage = kovanica_storage::Storage::new(dir.path().join("dag.redb")).unwrap();
        let store = Arc::new(DagStore::new(storage).unwrap());
        let manager = BlockManager::new(store.clone(), TEST_CTX);
        let (key0, pk0) = crypto::generate_keypair();
        let (key1, pk1) = crypto::generate_keypair();
        let (key2, pk2) = crypto::generate_keypair();

        // Set up committee with 3 authorities, but authority 2 has zero stake
        manager.set_authority_keys(HashMap::from([(0, pk0), (1, pk1), (2, pk2)]));
        manager.set_authority_stakes(HashMap::from([
            (0, 100),
            (1, 200),
            (2, 0), // zero stake - should be excluded
        ]));

        // Store genesis
        let genesis = StatementBlock {
            author: 0,
            round: 0,
            parents: Vec::new(),
            transactions: Vec::new(),
            statements: Vec::new(),
            signature: Signature([0; 64]),
            digest: StatementBlock::compute_digest(0, 0, &[], &[]),
            merkle_root: Default::default(),
        };
        store.put_block(&genesis).unwrap();

        // Store blocks from round 1 by all three authorities
        let parent_ref = BlockReference {
            author: 0,
            round: 0,
            digest: genesis.digest,
        };
        let parents = vec![parent_ref];

        let block0 = StatementBlock {
            author: 0,
            round: 1,
            parents: parents.clone(),
            transactions: Vec::new(),
            statements: Vec::new(),
            signature: crypto::sign(
                &key0,
                StatementBlock::compute_digest(0, 1, &parents, &[]).as_ref(),
            ),
            digest: StatementBlock::compute_digest(0, 1, &parents, &[]),
            merkle_root: Default::default(),
        };
        let block1 = StatementBlock {
            author: 1,
            round: 1,
            parents: parents.clone(),
            transactions: Vec::new(),
            statements: Vec::new(),
            signature: crypto::sign(
                &key1,
                StatementBlock::compute_digest(1, 1, &parents, &[]).as_ref(),
            ),
            digest: StatementBlock::compute_digest(1, 1, &parents, &[]),
            merkle_root: Default::default(),
        };
        let block2 = StatementBlock {
            author: 2,
            round: 1,
            parents: parents.clone(),
            transactions: Vec::new(),
            statements: Vec::new(),
            signature: crypto::sign(
                &key2,
                StatementBlock::compute_digest(2, 1, &parents, &[]).as_ref(),
            ),
            digest: StatementBlock::compute_digest(2, 1, &parents, &[]),
            merkle_root: Default::default(),
        };
        store.put_block(&block0).unwrap();
        store.put_block(&block1).unwrap();
        store.put_block(&block2).unwrap();

        // Select parents for round 2 - should only include authorities 0 and 1 (stake > 0)
        let parents_round2 = manager.select_parents(2).unwrap();
        assert_eq!(parents_round2.len(), 2);
        let authors: std::collections::HashSet<_> =
            parents_round2.iter().map(|p| p.author).collect();
        assert!(authors.contains(&0));
        assert!(authors.contains(&1));
        assert!(!authors.contains(&2));
    }

    #[test]
    fn select_parents_limits_to_committee_size() {
        let dir = tempfile::tempdir().expect("tempdir");
        let storage = kovanica_storage::Storage::new(dir.path().join("dag.redb")).unwrap();
        let store = Arc::new(DagStore::new(storage).unwrap());
        let manager = BlockManager::new(store.clone(), TEST_CTX);

        // Set up committee with 2 authorities
        let (key0, pk0) = crypto::generate_keypair();
        let (key1, pk1) = crypto::generate_keypair();
        manager.set_authority_keys(HashMap::from([(0, pk0), (1, pk1)]));
        manager.set_authority_stakes(HashMap::from([(0, 100), (1, 100)]));

        // Store genesis
        let genesis = StatementBlock {
            author: 0,
            round: 0,
            parents: Vec::new(),
            transactions: Vec::new(),
            statements: Vec::new(),
            signature: Signature([0; 64]),
            digest: StatementBlock::compute_digest(0, 0, &[], &[]),
            merkle_root: Default::default(),
        };
        store.put_block(&genesis).unwrap();

        // Store many blocks from round 1 by the two authorities
        let parent_ref = BlockReference {
            author: 0,
            round: 0,
            digest: genesis.digest,
        };
        let parents = vec![parent_ref];

        for i in 0..5 {
            let author = i % 2;
            let key = if author == 0 { &key0 } else { &key1 };
            let block = StatementBlock {
                author,
                round: 1,
                parents: parents.clone(),
                transactions: Vec::new(),
                statements: Vec::new(),
                signature: crypto::sign(
                    key,
                    StatementBlock::compute_digest(author, 1, &parents, &[]).as_ref(),
                ),
                digest: StatementBlock::compute_digest(author, 1, &parents, &[]),
                merkle_root: Default::default(),
            };
            store.put_block(&block).unwrap();
        }

        // Select parents for round 2 - should be limited to committee size (2)
        let parents_round2 = manager.select_parents(2).unwrap();
        assert_eq!(parents_round2.len(), 2);
    }

    #[test]
    fn select_parents_excludes_unknown_authorities() {
        let dir = tempfile::tempdir().expect("tempdir");
        let storage = kovanica_storage::Storage::new(dir.path().join("dag.redb")).unwrap();
        let store = Arc::new(DagStore::new(storage).unwrap());
        let manager = BlockManager::new(store.clone(), TEST_CTX);

        // Set up committee with only authority 0
        let (key0, pk0) = crypto::generate_keypair();
        manager.set_authority_keys(HashMap::from([(0, pk0)]));
        manager.set_authority_stakes(HashMap::from([(0, 100)]));

        // Store genesis
        let genesis = StatementBlock {
            author: 0,
            round: 0,
            parents: Vec::new(),
            transactions: Vec::new(),
            statements: Vec::new(),
            signature: Signature([0; 64]),
            digest: StatementBlock::compute_digest(0, 0, &[], &[]),
            merkle_root: Default::default(),
        };
        store.put_block(&genesis).unwrap();

        // Store block from round 1 by authority 0 (in committee)
        let parent_ref = BlockReference {
            author: 0,
            round: 0,
            digest: genesis.digest,
        };
        let parents = vec![parent_ref];

        let block0 = StatementBlock {
            author: 0,
            round: 1,
            parents: parents.clone(),
            transactions: Vec::new(),
            statements: Vec::new(),
            signature: crypto::sign(
                &key0,
                StatementBlock::compute_digest(0, 1, &parents, &[]).as_ref(),
            ),
            digest: StatementBlock::compute_digest(0, 1, &parents, &[]),
            merkle_root: Default::default(),
        };
        store.put_block(&block0).unwrap();

        // Store block from round 1 by authority 99 (NOT in committee)
        let (key99, pk99) = crypto::generate_keypair();
        let block99 = StatementBlock {
            author: 99,
            round: 1,
            parents: parents.clone(),
            transactions: Vec::new(),
            statements: Vec::new(),
            signature: crypto::sign(
                &key99,
                StatementBlock::compute_digest(99, 1, &parents, &[]).as_ref(),
            ),
            digest: StatementBlock::compute_digest(99, 1, &parents, &[]),
            merkle_root: Default::default(),
        };
        store.put_block(&block99).unwrap();

        // Select parents for round 2 - should only include authority 0
        let parents_round2 = manager.select_parents(2).unwrap();
        assert_eq!(parents_round2.len(), 1);
        assert_eq!(parents_round2[0].author, 0);
    }

    #[test]
    fn add_transaction_feeds_propose_block() {
        use kovanica_types::transaction::TransactionKind;
        let dir = tempfile::tempdir().expect("tempdir");
        let storage = kovanica_storage::Storage::new(dir.path().join("dag.redb")).unwrap();
        let store = Arc::new(DagStore::new(storage).unwrap());
        let manager = BlockManager::new(store.clone(), TEST_CTX);
        let (key, public_key) = crypto::generate_keypair();
        manager.set_authority(0);
        manager.set_authority_keys(HashMap::from([(0, public_key)]));
        manager.set_authority_stakes(HashMap::from([(0, 100)]));
        manager.set_signing_key(key);

        // Store genesis so select_parents works for round 1
        let genesis = StatementBlock {
            author: 0,
            round: 0,
            parents: Vec::new(),
            transactions: Vec::new(),
            statements: Vec::new(),
            signature: Signature([0; 64]),
            digest: StatementBlock::compute_digest(0, 0, &[], &[]),
            merkle_root: Default::default(),
        };
        store.put_block(&genesis).unwrap();

        // Build a dummy transaction (hash not required to match for proposal; block creation doesn't validate)
        let tx_hash = Hash::new(b"feed-test");
        let tx = Transaction {
            sender: kovanica_types::address::Address([0; 32]),
            nonce: 1,
            kind: TransactionKind::Transfer {
                to: kovanica_types::address::Address([1; 32]),
                amount: 1,
            },
            fee: 1,
            signature: Signature([0; 64]),
            hash: tx_hash,
        };

        manager.add_transaction(tx.clone());
        assert_eq!(manager.pending_count(), 1);

        let block = manager.propose_block(1).expect("propose with fed tx");
        assert_eq!(block.transactions.len(), 1);
        assert_eq!(block.transactions[0].hash, tx_hash);
    }

    /// Signed `Call` transaction with a valid signing hash and a non-zero fee.
    fn call_tx(nonce: u64, gas_limit: u64) -> Transaction {
        use kovanica_types::transaction::TransactionKind;
        let mut tx = Transaction {
            sender: kovanica_types::address::Address([0x11; 32]),
            nonce,
            kind: TransactionKind::Call {
                contract: kovanica_types::address::Address([0x22; 32]),
                value: 0,
                method: "probe".to_string(),
                args: Vec::new(),
                gas_limit,
            },
            fee: 1,
            signature: Signature([0; 64]),
            hash: Hash::zero(),
        };
        tx.hash = tx.signing_hash(&TEST_CTX);
        tx
    }

    /// Block carrying `txs` for a given `round`, signed for the
    /// committee-authenticated author 0.
    fn gas_block_at(round: u64, txs: Vec<Transaction>, key: &SigningKey) -> StatementBlock {
        let digest = StatementBlock::compute_digest(0, round, &[], &txs);
        let merkle_root = StatementBlock::compute_merkle_root(&txs);
        StatementBlock {
            author: 0,
            round,
            parents: Vec::new(),
            transactions: txs,
            statements: Vec::new(),
            signature: crypto::sign(key, digest.as_ref()),
            digest,
            merkle_root,
        }
    }

    /// Round immediately below activation, or `None` when activation is at
    /// genesis (round 0) and there is no pre-activation behavior to observe.
    fn round_below_activation() -> Option<u64> {
        GAS_HARDENING_ACTIVE_FROM_ROUND.checked_sub(1)
    }

    fn gas_txs(count: u64) -> Vec<Transaction> {
        (0..count)
            .map(|nonce| call_tx(nonce, MAX_TX_GAS_LIMIT))
            .collect()
    }

    /// The activation gate controls the **block-validity** rejections: below
    /// `GAS_HARDENING_ACTIVE_FROM_ROUND` a block carrying a transaction far
    /// above the per-tx cap still validates (old behavior, no fork); from that
    /// round on the same block is rejected.
    #[test]
    fn gas_hardening_gate_is_inert_below_and_enforced_at_activation() {
        let dir = tempfile::tempdir().expect("tempdir");
        let storage = kovanica_storage::Storage::new(dir.path().join("dag.redb")).unwrap();
        let store = Arc::new(DagStore::new(storage).unwrap());
        let manager = BlockManager::new(store, TEST_CTX);
        let (key, public_key) = crypto::generate_keypair();
        manager.set_authority_keys(HashMap::from([(0, public_key)]));

        let huge = MAX_TX_GAS_LIMIT * 100;

        // Below activation: both the per-tx cap and the per-block budget are
        // inert, so a single huge-gas call still validates (and its total is
        // itself far above `BLOCK_GAS_BUDGET`, proving the budget is skipped).
        if let Some(below) = round_below_activation() {
            assert!(huge > BLOCK_GAS_BUDGET);
            let block = gas_block_at(below, vec![call_tx(0, huge)], &key);
            manager
                .validate_block_content(&block)
                .expect("below activation a huge-gas block must still validate");
        }

        // At/above activation: the same transaction is rejected.
        let at = GAS_HARDENING_ACTIVE_FROM_ROUND;
        let block = gas_block_at(at, vec![call_tx(0, huge)], &key);
        let err = manager
            .validate_block_content(&block)
            .expect_err("at activation a huge-gas block must be rejected");
        assert!(
            err.to_string().contains("gas budget"),
            "expected a block-budget rejection, got: {err}"
        );

        // Per-transaction cap (budget not yet reached): one over the cap is
        // rejected from activation on, while exactly the cap is accepted.
        let over_cap = gas_block_at(at, vec![call_tx(0, MAX_TX_GAS_LIMIT + 1)], &key);
        let err = manager
            .validate_block_content(&over_cap)
            .expect_err("at activation a transaction over the cap must be rejected");
        assert!(
            err.to_string().contains("exceeds maximum"),
            "expected a per-transaction cap rejection, got: {err}"
        );

        let at_cap = gas_block_at(at, vec![call_tx(0, MAX_TX_GAS_LIMIT)], &key);
        manager
            .validate_block_content(&at_cap)
            .expect("exactly at the per-tx cap is accepted once active");
    }

    // The per-block sum of `Call` gas limits is bounded once active: exactly
    // the budget passes, one maximal transaction over is rejected with the
    // block-level reason.
    #[test]
    fn validate_block_content_enforces_per_block_gas_budget_when_active() {
        let dir = tempfile::tempdir().expect("tempdir");
        let storage = kovanica_storage::Storage::new(dir.path().join("dag.redb")).unwrap();
        let store = Arc::new(DagStore::new(storage).unwrap());
        let manager = BlockManager::new(store, TEST_CTX);
        let (key, public_key) = crypto::generate_keypair();
        manager.set_authority_keys(HashMap::from([(0, public_key)]));

        assert_eq!(
            BLOCK_GAS_BUDGET,
            8 * MAX_TX_GAS_LIMIT,
            "budget is defined as eight maximal transactions"
        );

        let at = GAS_HARDENING_ACTIVE_FROM_ROUND;
        let at_budget = gas_block_at(at, gas_txs(8), &key);
        manager
            .validate_block_content(&at_budget)
            .expect("spending exactly the per-block budget is accepted");

        let over_budget = gas_block_at(at, gas_txs(9), &key);
        let err = manager
            .validate_block_content(&over_budget)
            .expect_err("a block over the gas budget must be rejected");
        assert!(err.to_string().contains("gas budget"), "unexpected: {err}");
    }

    // Proposal keeps the per-block gas budget only once active, by dropping a
    // tail of the (sender, nonce)-sorted list (preserving every included nonce
    // prefix). Below activation the proposer is unchanged and keeps all txs.
    #[test]
    fn propose_block_truncates_to_the_gas_budget_only_when_active() {
        let dir = tempfile::tempdir().expect("tempdir");
        let storage = kovanica_storage::Storage::new(dir.path().join("dag.redb")).unwrap();
        let store = Arc::new(DagStore::new(storage).unwrap());
        let manager = BlockManager::new(store.clone(), TEST_CTX);
        let (key, public_key) = crypto::generate_keypair();
        manager.set_authority(0);
        manager.set_authority_keys(HashMap::from([(0, public_key)]));
        manager.set_authority_stakes(HashMap::from([(0, 100)]));
        manager.set_signing_key(key);

        // Store genesis so select_parents works for round 1.
        let genesis = StatementBlock {
            author: 0,
            round: 0,
            parents: Vec::new(),
            transactions: Vec::new(),
            statements: Vec::new(),
            signature: Signature([0; 64]),
            digest: StatementBlock::compute_digest(0, 0, &[], &[]),
            merkle_root: Default::default(),
        };
        store.put_block(&genesis).unwrap();

        // Below activation: no truncation (old behavior).
        if let Some(below) = round_below_activation() {
            manager.add_transactions(gas_txs(9));
            let block = manager
                .propose_block(below)
                .expect("propose below activation");
            assert_eq!(
                block.transactions.len(),
                9,
                "below activation the proposer must not drop transactions"
            );
        }

        // At/above activation: the ninth maximal call is dropped, the nonce
        // prefix is preserved, and the proposal validates under the new rules.
        let at = GAS_HARDENING_ACTIVE_FROM_ROUND;
        manager.add_transactions(gas_txs(9));
        let block = manager.propose_block(at).expect("propose at activation");

        assert_eq!(
            block.transactions.len(),
            8,
            "the ninth maximal call must be dropped"
        );
        assert_eq!(
            total_gas_limit(&block.transactions),
            BLOCK_GAS_BUDGET,
            "the proposed block spends at most the budget"
        );
        let nonces: Vec<u64> = block.transactions.iter().map(|tx| tx.nonce).collect();
        assert_eq!(nonces, (0..8).collect::<Vec<_>>(), "nonce prefix preserved");
        manager
            .validate_block_content(&block)
            .expect("the proposed block must itself validate");
    }

    fn make_block(
        author: AuthorityIndex,
        round: Round,
        parents: Vec<BlockReference>,
        tag: &str,
    ) -> StatementBlock {
        StatementBlock {
            author,
            round,
            parents,
            transactions: Vec::new(),
            statements: tag.as_bytes().to_vec(),
            signature: Signature([0; 64]),
            digest: Hash::new(format!("kovanica-block-manager-test/{tag}").as_bytes()),
            merkle_root: Default::default(),
        }
    }

    // #3: parent selection walks over empty rounds instead of stopping at the
    // immediately preceding (possibly empty) round.
    #[test]
    fn select_parents_skips_empty_rounds() {
        let dir = tempfile::tempdir().expect("tempdir");
        let storage = kovanica_storage::Storage::new(dir.path().join("dag.redb")).unwrap();
        let store = Arc::new(DagStore::new(storage).unwrap());
        let manager = BlockManager::new(store.clone(), TEST_CTX);
        let (_key, public_key) = crypto::generate_keypair();
        manager.set_authority_keys(HashMap::from([(0, public_key)]));
        manager.set_authority_stakes(HashMap::from([(0, 100)]));

        // Only round 5 is populated; rounds 6 and 7 are empty.
        let round5 = make_block(0, 5, vec![], "round-5");
        store.put_block(&round5).unwrap();

        let parents = manager.select_parents(8).unwrap();
        assert_eq!(parents.len(), 1, "walk skips empty rounds 7 and 6");
        assert_eq!(parents[0].round, 5);
        assert_eq!(parents[0].digest, round5.digest);
    }

    // #3: a block exactly `MAX_PARENT_ROUND_GAP` behind is reachable; anything
    // further is outside the window and yields no parents.
    #[test]
    fn select_parents_respects_gap_window() {
        let dir = tempfile::tempdir().expect("tempdir");
        let storage = kovanica_storage::Storage::new(dir.path().join("dag.redb")).unwrap();
        let store = Arc::new(DagStore::new(storage).unwrap());
        let manager = BlockManager::new(store.clone(), TEST_CTX);
        let (_key, public_key) = crypto::generate_keypair();
        manager.set_authority_keys(HashMap::from([(0, public_key)]));
        manager.set_authority_stakes(HashMap::from([(0, 100)]));

        let genesis = make_block(0, 0, vec![], "genesis");
        store.put_block(&genesis).unwrap();

        // Gap == MAX_PARENT_ROUND_GAP: round 0 is still inside the window.
        let at_limit = manager
            .select_parents(kovanica_types::MAX_PARENT_ROUND_GAP)
            .unwrap();
        assert_eq!(at_limit.len(), 1);
        assert_eq!(at_limit[0].digest, genesis.digest);

        // Gap > MAX_PARENT_ROUND_GAP: round 0 is unreachable.
        let beyond = manager
            .select_parents(kovanica_types::MAX_PARENT_ROUND_GAP + 2)
            .unwrap();
        assert!(
            beyond.is_empty(),
            "no parent within the MAX_PARENT_ROUND_GAP window"
        );
    }

    // #3: `validate_parent_references` enforces the gap, ordering and count
    // bounds.
    #[test]
    fn validate_parent_references_enforces_gap_round_and_count_bounds() {
        let dir = tempfile::tempdir().expect("tempdir");
        let storage = kovanica_storage::Storage::new(dir.path().join("dag.redb")).unwrap();
        let store = Arc::new(DagStore::new(storage).unwrap());
        let manager = BlockManager::new(store.clone(), TEST_CTX);

        let genesis = make_block(0, 0, vec![], "genesis");
        store.put_block(&genesis).unwrap();
        let genesis_ref = BlockReference {
            author: genesis.author,
            round: genesis.round,
            digest: genesis.digest,
        };

        // Gap exactly at the limit is accepted.
        let at_limit = make_block(
            0,
            kovanica_types::MAX_PARENT_ROUND_GAP,
            vec![genesis_ref],
            "at-limit",
        );
        manager
            .validate_parent_references(&at_limit)
            .expect("gap == MAX_PARENT_ROUND_GAP must be accepted");

        // Gap beyond the limit is rejected.
        let beyond = make_block(
            0,
            kovanica_types::MAX_PARENT_ROUND_GAP + 1,
            vec![genesis_ref],
            "beyond-limit",
        );
        assert!(
            manager.validate_parent_references(&beyond).is_err(),
            "gap > MAX_PARENT_ROUND_GAP must be rejected"
        );

        // A parent that is not strictly behind the block is rejected.
        let same_round_parent = BlockReference {
            author: 0,
            round: 5,
            digest: Hash::new(b"kovanica-block-manager-test/same-round"),
        };
        let same_round = make_block(0, 5, vec![same_round_parent], "same-round");
        assert!(
            manager.validate_parent_references(&same_round).is_err(),
            "parent round >= block round must be rejected"
        );

        // More parents than the committee/wave ceiling (3) is rejected.
        let too_many_parents: Vec<BlockReference> = (0..4)
            .map(|i| BlockReference {
                author: 0,
                round: 0,
                digest: Hash::new(format!("kovanica-block-manager-test/many-{i}").as_bytes()),
            })
            .collect();
        let too_many = make_block(0, 10, too_many_parents, "too-many");
        assert!(
            manager.validate_parent_references(&too_many).is_err(),
            "more than max_parents parents must be rejected"
        );
    }

    // -----------------------------------------------------------------
    // Task #4: bounded validation + durable prune boundary
    // -----------------------------------------------------------------

    fn signed(
        key: &SigningKey,
        author: AuthorityIndex,
        round: Round,
        parents: Vec<BlockReference>,
    ) -> StatementBlock {
        let digest = StatementBlock::compute_digest(author, round, &parents, &[]);
        StatementBlock {
            author,
            round,
            parents,
            transactions: Vec::new(),
            statements: Vec::new(),
            signature: crypto::sign(key, digest.as_ref()),
            digest,
            merkle_root: Default::default(),
        }
    }

    fn bref(block: &StatementBlock) -> BlockReference {
        BlockReference {
            author: block.author,
            round: block.round,
            digest: block.digest,
        }
    }

    fn genesis_block() -> StatementBlock {
        StatementBlock {
            author: 0,
            round: 0,
            parents: Vec::new(),
            transactions: Vec::new(),
            statements: Vec::new(),
            signature: Signature([0; 64]),
            digest: StatementBlock::compute_digest(0, 0, &[], &[]),
            merkle_root: Default::default(),
        }
    }

    /// Store genesis + a single-author chain for rounds 1..=top, each block
    /// processed through `process_block` (validated before stored).
    fn build_chain(
        manager: &BlockManager,
        store: &DagStore,
        key: &SigningKey,
        top: Round,
    ) -> Vec<StatementBlock> {
        let genesis = genesis_block();
        store.put_block(&genesis).unwrap();
        let mut chain = vec![genesis];
        for round in 1..=top {
            let b = signed(key, 0, round, vec![bref(chain.last().unwrap())]);
            manager.process_block(&b).expect("chain block valid");
            chain.push(b);
        }
        chain
    }

    #[test]
    fn prune_validate_new_block_with_pruned_ancestor_passes() {
        let dir = tempfile::tempdir().expect("tempdir");
        let storage = kovanica_storage::Storage::new(dir.path().join("dag.redb")).unwrap();
        let store = Arc::new(DagStore::new(storage).unwrap());
        let manager = BlockManager::new(store.clone(), TEST_CTX);
        let (key, pk) = crypto::generate_keypair();
        manager.set_authority_keys(HashMap::from([(0, pk)]));

        let chain = build_chain(&manager, &store, &key, 9);
        // wave 3, window 1 => prune waves < 2, i.e. rounds 0..=5.
        let pruned = store.prune_waves_before(3, 1).unwrap();
        assert!(pruned > 0);
        assert_eq!(store.prune_boundary().unwrap(), 6);
        assert!(!store.has_block(&chain[5].digest).unwrap());

        // Parent (round 9) is live; its ancestors below round 6 are pruned.
        let child = signed(&key, 0, 10, vec![bref(&chain[9])]);
        manager
            .validate_block(&child)
            .expect("a block whose history is pruned must still validate");

        // A parent that is itself below the boundary is accepted unread.
        let over_pruned = signed(&key, 0, 10, vec![bref(&chain[4])]);
        manager
            .validate_block(&over_pruned)
            .expect("parent below the prune boundary is accepted as validated");
    }

    #[test]
    fn prune_validate_missing_parent_above_boundary_rejected() {
        let dir = tempfile::tempdir().expect("tempdir");
        let storage = kovanica_storage::Storage::new(dir.path().join("dag.redb")).unwrap();
        let store = Arc::new(DagStore::new(storage).unwrap());
        let manager = BlockManager::new(store.clone(), TEST_CTX);
        let (key, pk) = crypto::generate_keypair();
        manager.set_authority_keys(HashMap::from([(0, pk)]));

        let chain = build_chain(&manager, &store, &key, 9);
        store.prune_waves_before(3, 1).unwrap();
        assert_eq!(store.prune_boundary().unwrap(), 6);

        // Never stored, round 8 >= boundary 6.
        let ghost = signed(&key, 0, 8, vec![bref(&chain[6])]);
        let child = signed(&key, 0, 10, vec![bref(&chain[9]), bref(&ghost)]);
        let err = manager.validate_block(&child).expect_err("missing parent");
        assert!(
            err.to_string().contains("not found"),
            "unexpected error: {err}"
        );
        // Exactly at the boundary is still looked up (and missing).
        let at_boundary = signed(&key, 0, 6, vec![bref(&chain[4])]);
        let child = signed(&key, 0, 10, vec![bref(&at_boundary)]);
        assert!(manager.validate_block(&child).is_err());
    }

    #[test]
    fn prune_validate_reads_only_direct_parents() {
        let dir = tempfile::tempdir().expect("tempdir");
        let storage = kovanica_storage::Storage::new(dir.path().join("dag.redb")).unwrap();
        let store = Arc::new(DagStore::new(storage).unwrap());
        let manager = BlockManager::new(store.clone(), TEST_CTX);
        let (key, pk) = crypto::generate_keypair();
        manager.set_authority_keys(HashMap::from([(0, pk)]));

        let chain = build_chain(&manager, &store, &key, 40);
        let child = signed(&key, 0, 41, vec![bref(&chain[40])]);
        let before = store.get_block_calls();
        manager.validate_block(&child).expect("valid");
        let reads = store.get_block_calls() - before;
        assert!(
            reads <= child.parents.len() as u64,
            "validation read {reads} blocks for {} direct parent(s); history depth is 40",
            child.parents.len()
        );
    }

    #[test]
    fn prune_validate_boundary_survives_restart() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("dag.redb");
        let (key, pk) = crypto::generate_keypair();
        let chain = {
            let storage = kovanica_storage::Storage::new(&path).unwrap();
            let store = Arc::new(DagStore::new(storage).unwrap());
            let manager = BlockManager::new(store.clone(), TEST_CTX);
            manager.set_authority_keys(HashMap::from([(0, pk)]));
            let chain = build_chain(&manager, &store, &key, 9);
            store.prune_waves_before(3, 1).unwrap();
            chain
        };

        // Reopen the redb database.
        let storage = kovanica_storage::Storage::new(&path).unwrap();
        let store = Arc::new(DagStore::new(storage).unwrap());
        assert_eq!(store.prune_boundary().unwrap(), 6, "boundary is durable");
        let manager = BlockManager::new(store.clone(), TEST_CTX);
        manager.set_authority_keys(HashMap::from([(0, pk)]));
        let child = signed(&key, 0, 10, vec![bref(&chain[9]), bref(&chain[3])]);
        manager
            .validate_block(&child)
            .expect("after restart, pruned parents/ancestors are still accepted");
    }
    /// Signed `Deploy` transaction carrying `code_len` bytes of bytecode.
    fn deploy_tx(nonce: u64, code_len: usize) -> Transaction {
        use kovanica_types::transaction::TransactionKind;
        let mut tx = Transaction {
            sender: kovanica_types::address::Address([0x11; 32]),
            nonce,
            kind: TransactionKind::Deploy {
                code: vec![0u8; code_len],
            },
            fee: 1,
            signature: Signature([0; 64]),
            hash: Hash::zero(),
        };
        tx.hash = tx.signing_hash(&TEST_CTX);
        tx
    }

    /// The size limits are gated exactly like the gas rules: inert below
    /// `SIZE_LIMITS_ACTIVE_FROM_ROUND`, enforced from it, so an upgraded node
    /// never diverges from one that has not been upgraded yet.
    #[test]
    fn size_limits_gate_is_inert_below_and_enforced_at_activation() {
        let dir = tempfile::tempdir().expect("tempdir");
        let storage = kovanica_storage::Storage::new(dir.path().join("dag.redb")).unwrap();
        let store = Arc::new(DagStore::new(storage).unwrap());
        let manager = BlockManager::new(store, TEST_CTX);
        let (key, public_key) = crypto::generate_keypair();
        manager.set_authority_keys(HashMap::from([(0, public_key)]));

        // A transaction whose encoding is over the cap, and a block made of
        // them that is over the block cap.
        let oversized = deploy_tx(0, MAX_TX_BYTES);
        let oversized_block_txs: Vec<Transaction> =
            (0..4).map(|n| deploy_tx(n, 300 * 1024)).collect();

        // Below activation both are still accepted: that is the behavior a
        // node without the limits has, and matching it is what avoids a fork.
        if let Some(below) = SIZE_LIMITS_ACTIVE_FROM_ROUND.checked_sub(1) {
            let block = gas_block_at(below, vec![oversized.clone()], &key);
            manager
                .validate_block_content(&block)
                .expect("below activation an oversized transaction must still validate");
            let block = gas_block_at(below, oversized_block_txs.clone(), &key);
            manager
                .validate_block_content(&block)
                .expect("below activation an oversized block must still validate");
        }

        // At activation the transaction is rejected on its own size.
        let at = SIZE_LIMITS_ACTIVE_FROM_ROUND;
        let block = gas_block_at(at, vec![oversized], &key);
        let err = manager
            .validate_block_content(&block)
            .expect_err("at activation an oversized transaction must be rejected");
        assert!(
            err.to_string().contains("transaction size"),
            "expected a transaction-size rejection, got: {err}"
        );

        // A transaction comfortably under the cap still passes.
        let block = gas_block_at(at, vec![deploy_tx(0, MAX_TX_BYTES / 2)], &key);
        manager
            .validate_block_content(&block)
            .expect("a transaction under the cap is accepted once active");
    }

    /// A block can exceed `MAX_BLOCK_BYTES` while every transaction in it is
    /// individually legal: the block cap is checked separately.
    #[test]
    fn size_limits_reject_a_block_over_the_block_cap_when_active() {
        let dir = tempfile::tempdir().expect("tempdir");
        let storage = kovanica_storage::Storage::new(dir.path().join("dag.redb")).unwrap();
        let store = Arc::new(DagStore::new(storage).unwrap());
        let manager = BlockManager::new(store, TEST_CTX);
        let (key, public_key) = crypto::generate_keypair();
        manager.set_authority_keys(HashMap::from([(0, public_key)]));

        let at = SIZE_LIMITS_ACTIVE_FROM_ROUND;

        // Each transaction is under `MAX_TX_BYTES`; together they are not.
        let big: Vec<Transaction> = (0..4).map(|n| deploy_tx(n, 300 * 1024)).collect();
        let block = gas_block_at(at, big, &key);
        assert!(
            encoded_len(&block) > MAX_BLOCK_BYTES as u64,
            "the fixture must actually exceed the block cap"
        );
        let err = manager
            .validate_block_content(&block)
            .expect_err("a block over the cap must be rejected");
        assert!(
            err.to_string().contains("block size"),
            "expected a block-size rejection, got: {err}"
        );

        // Two such transactions fit, so the block is accepted.
        let fits: Vec<Transaction> = (0..2).map(|n| deploy_tx(n, 300 * 1024)).collect();
        let block = gas_block_at(at, fits, &key);
        assert!(encoded_len(&block) < MAX_BLOCK_BYTES as u64);
        manager
            .validate_block_content(&block)
            .expect("a block under the cap is accepted once active");
    }
}
