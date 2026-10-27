//! Transaction mempool with fee-based prioritization.
//!
//! # Admission
//!
//! [`Mempool::add_transaction`] runs the cheap, stateless checks first and the
//! expensive ones last, so junk is turned away before we pay for a signature
//! check or a storage read:
//!
//! 1. size, gas limit, zero fee, minimum fee rate;
//! 2. `tx.hash` must equal `tx.signing_hash()` (the hash is the pool key and
//!    the dedup key, so it must be bound to the signed content);
//! 3. duplicate hash;
//! 4. Ed25519 signature;
//! 5. account state: nonce window, per-sender limit, same-nonce replacement
//!    (replace-by-fee), cumulative balance of everything the sender has
//!    pending, and pool capacity (eviction only of lower fee-rate entries).
//!
//! # Nonces
//!
//! A sender's pending transactions always form one contiguous nonce run that
//! starts at the account nonce. A new transaction must either extend the run
//! (`nonce == next`) or replace a queued transaction with the same nonce for a
//! fee at least [`MempoolConfig::replacement_fee_bump_percent`] higher.
//!
//! # Lifecycle
//!
//! `queued` → (proposed by [`Mempool::get_next_transactions`]) → `in flight`
//! → removed by [`Mempool::remove_committed_transactions`] once a block with
//! it is committed. In-flight entries that are not committed within
//! [`MempoolConfig::in_flight_timeout`] go back to the queue. Nothing is
//! dropped silently: every removal updates all indexes and the size total.
//!
//! All pool state lives behind a single mutex, so there is no lock ordering
//! to get wrong.

#![deny(unsafe_code)]
#![allow(missing_docs)]
#![allow(clippy::result_large_err)]
#![allow(clippy::large_enum_variant)]

use kovanica_storage::Storage;
use kovanica_types::{
    hash::Hash,
    transaction::{Transaction, TransactionKind},
    Address,
};
use parking_lot::Mutex;
use std::cmp::Reverse;
use std::collections::{BTreeMap, BinaryHeap, HashMap, HashSet, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::{debug, info, warn};

/// Upper bound on hashes waiting in the propagation queue.
const MAX_PENDING_PROPAGATION: usize = 10_000;

/// Proposal priority: (fee rate, fee, reversed sender bytes, hash bytes).
type Priority = (u64, u64, Reverse<[u8; 32]>, [u8; 32]);

/// One tracked transaction.
#[derive(Clone, Debug)]
struct Entry {
    tx: Transaction,
    size: usize,
    fee_rate: u64,
    /// `Some(t)` once handed out for a block proposal at `t`.
    in_flight_since: Option<Instant>,
    /// `false` for transactions returned from non-blue blocks: they were
    /// already gossiped once and must not be re-broadcast from this pool.
    gossip: bool,
}

/// Everything mutable about the pool, guarded by one lock.
#[derive(Default)]
struct PoolState {
    /// Every tracked transaction (queued and in flight).
    by_hash: HashMap<Hash, Entry>,
    /// Queued (not in flight) transactions by fee rate.
    by_fee_rate: BTreeMap<u64, VecDeque<Hash>>,
    /// Per-sender nonce → hash, for queued and in-flight transactions.
    by_sender: HashMap<Address, BTreeMap<u64, Hash>>,
    /// Transactions not yet propagated (bounded).
    pending_propagation: VecDeque<Hash>,
    /// Sum of serialized sizes of every tracked transaction.
    total_size: usize,
}

impl PoolState {
    fn enqueue(&mut self, hash: Hash, fee_rate: u64) {
        self.by_fee_rate
            .entry(fee_rate)
            .or_default()
            .push_back(hash);
    }

    fn dequeue(&mut self, hash: &Hash, fee_rate: u64) {
        if let Some(queue) = self.by_fee_rate.get_mut(&fee_rate) {
            queue.retain(|h| h != hash);
            if queue.is_empty() {
                self.by_fee_rate.remove(&fee_rate);
            }
        }
    }

    fn insert(&mut self, entry: Entry) {
        let hash = entry.tx.hash;
        self.enqueue(hash, entry.fee_rate);
        self.by_sender
            .entry(entry.tx.sender)
            .or_default()
            .insert(entry.tx.nonce, hash);
        self.total_size += entry.size;
        if entry.gossip {
            self.pending_propagation.push_back(hash);
        }
        while self.pending_propagation.len() > MAX_PENDING_PROPAGATION {
            self.pending_propagation.pop_front();
        }
        self.by_hash.insert(hash, entry);
    }

    /// Remove one transaction from every index.
    fn remove(&mut self, hash: &Hash) -> Option<Entry> {
        let entry = self.by_hash.remove(hash)?;
        if entry.in_flight_since.is_none() {
            self.dequeue(hash, entry.fee_rate);
        }
        if let Some(nonces) = self.by_sender.get_mut(&entry.tx.sender) {
            if nonces.get(&entry.tx.nonce) == Some(hash) {
                nonces.remove(&entry.tx.nonce);
            }
            if nonces.is_empty() {
                self.by_sender.remove(&entry.tx.sender);
            }
        }
        self.total_size = self.total_size.saturating_sub(entry.size);
        Some(entry)
    }

    /// Remove `sender`'s transactions with nonce `>= from` (keeps the run
    /// contiguous when something in the middle has to go).
    fn remove_sender_from(&mut self, sender: &Address, from: u64) -> usize {
        let hashes: Vec<Hash> = self
            .by_sender
            .get(sender)
            .map(|nonces| nonces.range(from..).map(|(_, h)| *h).collect())
            .unwrap_or_default();
        hashes.iter().filter(|h| self.remove(h).is_some()).count()
    }

    /// Remove `sender`'s transactions with nonce `< below` (already used).
    fn remove_sender_below(&mut self, sender: &Address, below: u64) -> usize {
        let hashes: Vec<Hash> = self
            .by_sender
            .get(sender)
            .map(|nonces| nonces.range(..below).map(|(_, h)| *h).collect())
            .unwrap_or_default();
        hashes.iter().filter(|h| self.remove(h).is_some()).count()
    }

    /// Lowest fee-rate queued transaction, if any.
    fn lowest_queued(&self) -> Option<(u64, Hash)> {
        self.by_fee_rate
            .iter()
            .find_map(|(rate, queue)| queue.back().map(|h| (*rate, *h)))
    }

    /// Put in-flight entries older than `timeout` back in the queue.
    pub fn requeue_stale(&mut self, now: Instant, timeout: Duration) -> usize {
        let stale: Vec<(Hash, u64)> = self
            .by_hash
            .iter()
            .filter(|(_, e)| {
                e.in_flight_since
                    .is_some_and(|since| now.duration_since(since) >= timeout)
            })
            .map(|(h, e)| (*h, e.fee_rate))
            .collect();
        for (hash, fee_rate) in &stale {
            if let Some(entry) = self.by_hash.get_mut(hash) {
                entry.in_flight_since = None;
            }
            self.enqueue(*hash, *fee_rate);
        }
        stale.len()
    }
}

/// Mempool implementation with fee-based prioritization.
pub struct Mempool {
    config: MempoolConfig,
    storage: Arc<Storage>,
    /// Signing context (chain_id/epoch) for tx hash + signature checks.
    signing_ctx: kovanica_types::SigningContext,
    state: Mutex<PoolState>,
    /// Last time we rebroadcast transactions.
    last_rebroadcast: Mutex<Instant>,
}

/// Value moved out of the sender's balance by `kind` at execution time
/// (mirrors the balance check the mempool already did; no new semantics).
fn immediate_value(kind: &TransactionKind) -> u64 {
    match kind {
        TransactionKind::Transfer { amount, .. } => *amount,
        TransactionKind::Stake { amount } => *amount,
        TransactionKind::Unstake { .. } => 0, // funds not returned until unbonding ends
        TransactionKind::Delegate { amount, .. } => *amount,
        TransactionKind::ClaimRewards { .. } => 0,
        TransactionKind::Deploy { .. } => 0,
        TransactionKind::Call { .. } => 0,
        TransactionKind::RegisterLightNode { stake, .. } => *stake,
        TransactionKind::ExitLightNode => 0,
        TransactionKind::SubmitLightWitness { .. } => 0,
        TransactionKind::SetCommission { .. } => 0,
        TransactionKind::ClaimTreasury { .. } => 0, // funds leave the treasury account, not the sender
        TransactionKind::Evidence { .. } => 0,      // the proof spends no funds
    }
}

/// Stake and delegate are fee-free by design; everything else pays a fee.
fn requires_fee(kind: &TransactionKind) -> bool {
    !matches!(
        kind,
        TransactionKind::Stake { .. } | TransactionKind::Delegate { .. }
    )
}

impl Mempool {
    /// Create a new mempool.
    pub fn new(
        config: MempoolConfig,
        storage: Arc<Storage>,
        signing_ctx: kovanica_types::SigningContext,
    ) -> Self {
        Self {
            config,
            storage,
            signing_ctx,
            state: Mutex::new(PoolState::default()),
            last_rebroadcast: Mutex::new(Instant::now()),
        }
    }

    /// Get a reference to the mempool configuration.
    pub fn config(&self) -> &MempoolConfig {
        &self.config
    }

    /// Signing context this mempool verifies transactions under.
    pub fn signing_context(&self) -> kovanica_types::SigningContext {
        self.signing_ctx
    }

    /// Get the number of transactions in the mempool (queued and in flight).
    pub fn len(&self) -> usize {
        self.state.lock().by_hash.len()
    }

    /// Check if the mempool is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Get a transaction by hash.
    pub fn get(&self, hash: &Hash) -> Option<Transaction> {
        self.state.lock().by_hash.get(hash).map(|e| e.tx.clone())
    }

    /// Check if a transaction exists in the mempool.
    pub fn contains(&self, hash: &Hash) -> bool {
        self.state.lock().by_hash.contains_key(hash)
    }

    /// Snapshot of the hashes of all transactions currently in the mempool.
    /// Non-destructive: used by RPC and diagnostics. The set reflects the
    /// queued + in-flight buckets, not the re-broadcast queue.
    pub fn pending_hashes(&self) -> Vec<Hash> {
        self.state.lock().by_hash.keys().copied().collect()
    }

    /// Add a transaction to the mempool. See the module docs for the rules.
    pub fn add_transaction(&self, tx: Transaction) -> Result<(), MempoolError> {
        self.admit(tx, true)
    }

    /// Re-admit transactions from non-blue (red) blocks of a committed
    /// sub-DAG (#13). Every transaction goes through the full v1 admission
    /// path of [`Mempool::add_transaction`] (size, fee, hash binding,
    /// signature, nonce, balance, per-sender and total pool limits), but is
    /// never queued for gossip or re-broadcast by default (set `gossip=true`
    /// to enable), and the caller must not penalise any peer for a rejection
    /// (there is no peer here).
    ///
    /// Transactions are processed in `(sender, nonce)` order so a returned
    /// nonce chain re-enters gap-free. One report entry per input, in input
    /// order.
    pub fn reinsert_returned(&self, txs: Vec<Transaction>, gossip: bool) -> Vec<ReinsertReport> {
        let mut order: Vec<usize> = (0..txs.len()).collect();
        order.sort_by_key(|&i| (txs[i].sender.0, txs[i].nonce));
        let mut outcomes: Vec<Option<ReinsertOutcome>> = vec![None; txs.len()];
        for i in order {
            let tx = txs[i].clone();
            let outcome = if self.is_committed(&tx) {
                ReinsertOutcome::AlreadyCommitted
            } else {
                match self.admit(tx, gossip) {
                    Ok(()) => ReinsertOutcome::Accepted,
                    Err(MempoolError::AlreadyExists) => ReinsertOutcome::Duplicate,
                    // Nonce consumed by a committed tx (this or a competing one).
                    Err(MempoolError::InvalidNonce { expected, got })
                        if got < expected && self.account_nonce(&txs[i]) > got =>
                    {
                        ReinsertOutcome::AlreadyCommitted
                    }
                    Err(e) => ReinsertOutcome::Invalid(e.to_string()),
                }
            };
            outcomes[i] = Some(outcome);
        }
        txs.iter()
            .zip(outcomes)
            .map(|(tx, outcome)| ReinsertReport {
                hash: tx.hash,
                outcome: outcome.unwrap_or_else(|| ReinsertOutcome::Invalid("unprocessed".into())),
            })
            .collect()
    }

    /// Whether `tx` (by hash) is already in a committed block, or its nonce
    /// is below the committed account nonce.
    fn is_committed(&self, tx: &Transaction) -> bool {
        let Ok(txn) = self.storage.begin_read() else {
            return false;
        };
        if matches!(
            self.storage
                .blocks()
                .get_block_for_transaction(&txn, &tx.hash),
            Ok(Some(_))
        ) {
            return true;
        }
        self.account_nonce(tx) > tx.nonce
    }

    fn account_nonce(&self, tx: &Transaction) -> u64 {
        self.storage
            .begin_read()
            .ok()
            .and_then(|txn| {
                self.storage
                    .state()
                    .get_account_or_default(&txn, &tx.sender)
                    .ok()
            })
            .map_or(0, |a| a.nonce)
    }

    /// Evidence is fee-free, but only from an active validator.
    ///
    /// The proof is self-authenticating, so *anyone* could relay a valid one
    /// and should not have to pay for the privilege. Allowing fee-free
    /// evidence from arbitrary accounts, however, would be free block space
    /// for junk that fails verification. Restricting the exemption to the
    /// active set keeps validator reporting free while everybody else pays
    /// the normal fee floor. Gossip already only accepts transactions whose
    /// sender key is a known committee key, so this matches the network edge.
    fn evidence_is_free(&self, tx: &Transaction) -> bool {
        if !matches!(tx.kind, TransactionKind::Evidence { .. }) || tx.fee != 0 {
            return false;
        }
        let Ok(txn) = self.storage.begin_read() else {
            return false;
        };
        let Ok(staking) = self.storage.state().load_staking_state(&txn) else {
            return false;
        };
        staking
            .validators
            .iter()
            .any(|v| v.address == tx.sender && v.active)
    }

    /// Next nonce the pool would accept from `sender`, including local
    /// pending transactions. Used by the node to sign its own evidence
    /// reports without racing the admission rule.
    pub fn next_nonce(&self, sender: &Address) -> Result<u64, MempoolError> {
        let txn = self.storage.begin_read()?;
        let account = self.storage.state().get_account_or_default(&txn, sender)?;
        let state = self.state.lock();
        let next = state
            .by_sender
            .get(sender)
            .and_then(|pending| pending.last_key_value())
            .map(|(nonce, _)| nonce + 1)
            .unwrap_or(account.nonce)
            .max(account.nonce);
        Ok(next)
    }

    /// Shared admission path; `gossip == false` keeps the tx local.
    fn admit(&self, tx: Transaction, gossip: bool) -> Result<(), MempoolError> {
        // --- 1. cheap stateless checks ---------------------------------
        let size = bincode::serialized_size(&tx)? as usize;
        if size > self.config.max_tx_size {
            return Err(MempoolError::TransactionTooLarge(size));
        }
        if let TransactionKind::Call { gas_limit, .. } = &tx.kind {
            if *gas_limit > self.config.max_gas_limit {
                return Err(MempoolError::GasLimitTooHigh);
            }
        }
        let fee_rate = tx.fee / size.max(1) as u64;
        if requires_fee(&tx.kind) && !self.evidence_is_free(&tx) {
            if tx.fee == 0 {
                return Err(MempoolError::ZeroFee);
            }
            if fee_rate < self.config.min_fee_rate {
                return Err(MempoolError::FeeTooLow {
                    fee_rate,
                    min_fee_rate: self.config.min_fee_rate,
                });
            }
        }

        // --- 2. hash binding --------------------------------------------
        if tx.hash != tx.signing_hash(&self.signing_ctx) {
            return Err(MempoolError::HashMismatch);
        }

        // --- 3. duplicate -----------------------------------------------
        if self.contains(&tx.hash) {
            return Err(MempoolError::AlreadyExists);
        }

        // --- 4. signature (expensive) -----------------------------------
        if !tx.verify_signature(&self.signing_ctx) {
            return Err(MempoolError::InvalidSignature);
        }

        // --- 5. account state (storage read, outside the pool lock) -----
        let account = {
            let txn = self.storage.begin_read()?;
            self.storage
                .state()
                .get_account_or_default(&txn, &tx.sender)?
        };
        if tx.nonce < account.nonce {
            return Err(MempoolError::InvalidNonce {
                expected: account.nonce,
                got: tx.nonce,
            });
        }

        let mut state = self.state.lock();
        if state.by_hash.contains_key(&tx.hash) {
            return Err(MempoolError::AlreadyExists);
        }
        // Anything below the account nonce has been used already.
        state.remove_sender_below(&tx.sender, account.nonce);

        let pending = state.by_sender.get(&tx.sender).cloned().unwrap_or_default();
        let mut replaces = None;
        if let Some(existing_hash) = pending.get(&tx.nonce) {
            let existing = &state.by_hash[existing_hash];
            if existing.in_flight_since.is_some() {
                return Err(MempoolError::NonceInFlight { nonce: tx.nonce });
            }
            let bump = existing
                .tx
                .fee
                .saturating_mul(self.config.replacement_fee_bump_percent)
                / 100;
            let min_fee = existing.tx.fee.saturating_add(bump.max(1));
            if tx.fee < min_fee {
                return Err(MempoolError::ReplacementUnderpriced {
                    fee: tx.fee,
                    min_fee,
                });
            }
            replaces = Some(*existing_hash);
        } else {
            let next = pending
                .last_key_value()
                .map(|(nonce, _)| nonce + 1)
                .unwrap_or(account.nonce)
                .max(account.nonce);
            if tx.nonce != next {
                return Err(MempoolError::InvalidNonce {
                    expected: next,
                    got: tx.nonce,
                });
            }
            if pending.len() >= self.config.max_txs_per_sender {
                return Err(MempoolError::TooManyFromSender {
                    limit: self.config.max_txs_per_sender,
                });
            }
        }

        // Cumulative balance: everything else this sender has pending must
        // still be payable together with this transaction.
        let already_pending: u64 = pending
            .values()
            .filter(|h| Some(**h) != replaces)
            .filter_map(|h| state.by_hash.get(h))
            .map(|e| immediate_value(&e.tx.kind).saturating_add(e.tx.fee))
            .fold(0u64, u64::saturating_add);
        let required = already_pending
            .saturating_add(immediate_value(&tx.kind))
            .saturating_add(tx.fee);
        if account.balance < required {
            return Err(MempoolError::InsufficientBalance {
                balance: account.balance,
                required,
            });
        }

        // Capacity: only evict strictly cheaper entries from other senders.
        let freed = replaces
            .and_then(|h| state.by_hash.get(&h))
            .map_or(0, |e| e.size);
        while state.total_size - freed + size > self.config.max_mempool_size {
            let Some((lowest_rate, victim)) = state.lowest_queued() else {
                return Err(MempoolError::Full);
            };
            let victim_sender = state.by_hash[&victim].tx.sender;
            if lowest_rate >= fee_rate || victim_sender == tx.sender {
                return Err(MempoolError::Full);
            }
            let victim_nonce = state.by_hash[&victim].tx.nonce;
            let evicted = state.remove_sender_from(&victim_sender, victim_nonce);
            warn!(
                %victim,
                fee_rate = lowest_rate,
                evicted,
                "evicted lower fee-rate transaction(s) from full mempool"
            );
        }

        if let Some(old) = replaces {
            state.remove(&old);
            debug!(old = %old, new = %tx.hash, nonce = tx.nonce, "replaced pending transaction");
        }
        let hash = tx.hash;
        state.insert(Entry {
            tx,
            size,
            fee_rate,
            in_flight_since: None,
            gossip,
        });
        info!(%hash, fee_rate, size, gossip, "added transaction to mempool");
        Ok(())
    }

    /// Take up to `max_txs` transactions for a block proposal.
    ///
    /// Highest fee rate first, but a sender's transactions are only ever
    /// returned in nonce order and without gaps. Returned transactions move to
    /// *in flight*: they stay tracked (and keep their nonces reserved) until
    /// [`Mempool::remove_committed_transactions`] removes them, or go back to
    /// the queue after [`MempoolConfig::in_flight_timeout`]. Nothing that is
    /// not returned is lost.
    pub fn get_next_transactions(&self, max_txs: usize) -> Vec<Transaction> {
        let now = Instant::now();
        let mut state = self.state.lock();
        let requeued = state.requeue_stale(now, self.config.in_flight_timeout);
        if requeued > 0 {
            info!(requeued, "re-queued uncommitted in-flight transactions");
        }

        // Debug: log mempool state
        info!(
            total_txs = state.by_hash.len(),
            queued_txs = state.by_fee_rate.values().map(|q| q.len()).sum::<usize>(),
            in_flight_txs = state
                .by_hash
                .values()
                .filter(|e| e.in_flight_since.is_some())
                .count(),
            senders = state.by_sender.len(),
            "get_next_transactions called"
        );

        // Per sender: the queued run that directly follows any in-flight
        // prefix, in nonce order.
        let mut runs: HashMap<Address, VecDeque<Hash>> = HashMap::new();
        for (sender, nonces) in &state.by_sender {
            // First pass: find the highest in-flight nonce for this sender.
            let mut highest_in_flight: Option<u64> = None;
            for (nonce, hash) in nonces {
                if let Some(e) = state.by_hash.get(hash) {
                    if e.in_flight_since.is_some() {
                        highest_in_flight = Some(*nonce);
                    }
                }
            }

            // Second pass: build the run starting from (highest_in_flight + 1)
            // for queued transactions only.
            let run_start = match highest_in_flight {
                Some(n) => n + 1,
                None => 0,
            };
            let mut run = VecDeque::new();
            let mut expected: Option<u64> = None;
            for (nonce, hash) in nonces {
                if *nonce < run_start {
                    continue; // Skip in-flight prefix
                }
                if let Some(e) = expected {
                    if e != *nonce {
                        break; // True gap in queued transactions
                    }
                }
                expected = Some(nonce + 1);
                match state.by_hash.get(hash) {
                    Some(e) if e.in_flight_since.is_some() => {
                        // This shouldn't happen since we filtered by run_start,
                        // but just in case: skip this nonce and stop.
                        break;
                    }
                    Some(_) => run.push_back(*hash),
                    None => break,
                }
            }
            if !run.is_empty() {
                info!(%sender, run_len = run.len(), run_start, "built run for sender");
                runs.insert(*sender, run);
            } else {
                info!(%sender, run_start, "no run built for sender (empty or no queued txs after in-flight prefix)");
            }
        }

        // Merge the runs by fee rate (then fee, then sender bytes for
        // determinism), always taking a sender's next nonce.
        let key = |state: &PoolState, hash: &Hash| -> Priority {
            let e = &state.by_hash[hash];
            (e.fee_rate, e.tx.fee, Reverse(e.tx.sender.0), hash.0)
        };
        let mut heap: BinaryHeap<Priority> = runs
            .values()
            .filter_map(|run| run.front())
            .map(|h| key(&state, h))
            .collect();
        let mut selected = Vec::new();
        while selected.len() < max_txs {
            let Some((_, _, Reverse(sender), hash)) = heap.pop() else {
                break;
            };
            selected.push(Hash(hash));
            if let Some(run) = runs.get_mut(&Address(sender)) {
                run.pop_front();
                if let Some(next) = run.front() {
                    heap.push(key(&state, next));
                }
            }
        }

        let mut result = Vec::with_capacity(selected.len());
        for hash in selected {
            let Some(fee_rate) = state.by_hash.get(&hash).map(|e| e.fee_rate) else {
                continue;
            };
            state.dequeue(&hash, fee_rate);
            if let Some(entry) = state.by_hash.get_mut(&hash) {
                entry.in_flight_since = Some(now);
                result.push(entry.tx.clone());
            }
        }
        result
    }

    /// Remove transactions that have been included in a committed block.
    ///
    /// Prefer [`Mempool::remove_committed_transactions`], which also drops
    /// pooled transactions made stale by a committed nonce.
    pub fn remove_committed(&self, committed_txs: &[Hash]) {
        let mut state = self.state.lock();
        for hash in committed_txs {
            state.remove(hash);
        }
    }

    /// Remove committed transactions and anything they made stale: for each
    /// committed `(sender, nonce)`, every pooled transaction of that sender
    /// with a nonce `<=` it is dropped (even a different transaction with the
    /// same nonce, e.g. one committed via another validator's pool).
    pub fn remove_committed_transactions(&self, committed: &[Transaction]) -> usize {
        let mut highest: HashMap<Address, u64> = HashMap::new();
        for tx in committed {
            let slot = highest.entry(tx.sender).or_insert(tx.nonce);
            *slot = (*slot).max(tx.nonce);
        }
        let mut state = self.state.lock();
        let mut removed: HashSet<Hash> = HashSet::new();
        for tx in committed {
            if state.remove(&tx.hash).is_some() {
                removed.insert(tx.hash);
            }
        }
        let mut stale = 0;
        for (sender, nonce) in highest {
            stale += state.remove_sender_below(&sender, nonce.saturating_add(1));
        }
        removed.len() + stale
    }

    /// Get transactions ready for propagation.
    pub fn get_pending_propagation(&self) -> Vec<Hash> {
        self.state.lock().pending_propagation.drain(..).collect()
    }

    /// Mark transactions as propagated.
    pub fn mark_propagated(&self, hashes: &[Hash]) {
        // Already removed from pending_propagation when we called get_pending_propagation
        // This is a no-op but kept for API consistency
        let _ = hashes;
    }

    /// Rebroadcast queued transactions (called periodically).
    pub fn rebroadcast(&self) -> Vec<Transaction> {
        let mut last_rebroadcast = self.last_rebroadcast.lock();
        if last_rebroadcast.elapsed() < self.config.rebroadcast_interval {
            return Vec::new();
        }
        *last_rebroadcast = Instant::now();
        let txs = self
            .state
            .lock()
            .by_hash
            .values()
            .filter(|e| e.in_flight_since.is_none() && e.gossip)
            .map(|e| e.tx.clone())
            .collect::<Vec<_>>();
        if !txs.is_empty() {
            info!(count = txs.len(), "rebroadcasting transactions");
        }
        txs
    }

    /// Get mempool statistics.
    ///
    /// `fee_rates` covers queued transactions only; `tx_count` and
    /// `total_size` cover everything tracked (queued and in flight).
    pub fn stats(&self) -> MempoolStats {
        let state = self.state.lock();
        MempoolStats {
            tx_count: state.by_hash.len(),
            total_size: state.total_size,
            fee_rates: state
                .by_fee_rate
                .iter()
                .map(|(rate, queue)| (*rate, queue.len()))
                .collect(),
        }
    }

    /// Re-queue transactions that have been in-flight longer than the
    /// configured timeout back into the queued state, so they can be
    /// proposed again by a future `get_next_transactions` call during
    /// periodic rebroadcast.
    pub fn requeue_stale(&self, now: Instant, timeout: Duration) -> usize {
        let mut state = self.state.lock();
        state.requeue_stale(now, timeout)
    }

    /// Return in-flight transactions for a specific sender back to queued state.
    /// Called when leader is skipped so their in-flight txs can be re-proposed.
    pub fn return_in_flight_for_sender(&self, sender: &Address, _now: Instant) -> usize {
        let mut state = self.state.lock();
        let mut returned = 0;
        // Find all in-flight entries for this sender
        let stale: Vec<(Hash, u64)> = state
            .by_hash
            .iter()
            .filter(|(_, e)| e.in_flight_since.is_some() && e.tx.sender == *sender)
            .map(|(h, e)| (*h, e.fee_rate))
            .collect();
        for (hash, fee_rate) in &stale {
            if let Some(entry) = state.by_hash.get_mut(hash) {
                entry.in_flight_since = None;
            }
            state.enqueue(*hash, *fee_rate);
            returned += 1;
        }
        returned
    }
}

/// Mempool configuration.
#[derive(Clone, Debug)]
pub struct MempoolConfig {
    /// Maximum size of the mempool in bytes.
    pub max_mempool_size: usize,
    /// Maximum size of a single transaction in bytes.
    pub max_tx_size: usize,
    /// Maximum gas limit for contract calls. Defaults to
    /// [`kovanica_types::MAX_TX_GAS_LIMIT`]; an operator's override is honoured
    /// here, but the consensus path enforces the canonical cap independently.
    pub max_gas_limit: u64,
    /// Interval for rebroadcasting transactions.
    pub rebroadcast_interval: std::time::Duration,
    /// Minimum fee rate (fee per serialized byte, integer division) for
    /// fee-paying transactions. Enforced at admission.
    ///
    /// Defaults to `0`: the previous default of `1` was never enforced, and
    /// enforcing it would reject the CLI's default 1-atom fee. Choosing a
    /// real fee floor is a fee-policy decision left to the operator.
    pub min_fee_rate: u64,
    /// Maximum pending (queued + in-flight) transactions per sender.
    pub max_txs_per_sender: usize,
    /// Minimum fee increase, in percent, to replace a queued transaction
    /// with the same sender and nonce.
    pub replacement_fee_bump_percent: u64,
    /// How long a proposed transaction may stay in flight without being
    /// committed before it is queued again.
    pub in_flight_timeout: Duration,
}

impl Default for MempoolConfig {
    fn default() -> Self {
        Self {
            max_mempool_size: 100 * 1024 * 1024, // 100 MB
            max_tx_size: 1024 * 1024,            // 1 MB
            max_gas_limit: kovanica_types::MAX_TX_GAS_LIMIT,
            rebroadcast_interval: std::time::Duration::from_secs(30),
            min_fee_rate: 0,
            max_txs_per_sender: 64,
            replacement_fee_bump_percent: 10,
            in_flight_timeout: Duration::from_secs(15),
        }
    }
}

/// Mempool statistics.
#[derive(Clone, Debug)]
pub struct MempoolStats {
    pub tx_count: usize,
    pub total_size: usize,
    pub fee_rates: Vec<(u64, usize)>, // (fee_rate, count)
}

/// Per-transaction result of [`Mempool::reinsert_returned`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReinsertOutcome {
    /// Admitted back into the pool (local only, not gossiped).
    Accepted,
    /// Already pending in the pool.
    Duplicate,
    /// Already in a committed block, or its nonce was consumed.
    AlreadyCommitted,
    /// Failed validation or a pool limit; the reason is the mempool error.
    Invalid(String),
}

/// Report entry for one returned transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReinsertReport {
    pub hash: Hash,
    pub outcome: ReinsertOutcome,
}

/// Errors that can occur in mempool operations.
#[derive(Debug, thiserror::Error)]
pub enum MempoolError {
    #[error("Transaction already exists in mempool")]
    AlreadyExists,
    #[error("Invalid signature")]
    InvalidSignature,
    #[error("Invalid nonce: expected {expected}, got {got}")]
    InvalidNonce { expected: u64, got: u64 },
    #[error("Transaction has zero fee")]
    ZeroFee,
    #[error("Insufficient balance: {balance} required {required}")]
    InsufficientBalance { balance: u64, required: u64 },
    #[error("Gas limit too high")]
    GasLimitTooHigh,
    #[error("Transaction too large: {0} bytes")]
    TransactionTooLarge(usize),
    #[error("Mempool is full")]
    Full,
    #[error("Transaction hash does not match its signing hash")]
    HashMismatch,
    #[error("Fee rate {fee_rate} below minimum {min_fee_rate}")]
    FeeTooLow { fee_rate: u64, min_fee_rate: u64 },
    #[error("Replacement fee {fee} too low, need at least {min_fee}")]
    ReplacementUnderpriced { fee: u64, min_fee: u64 },
    #[error("Nonce {nonce} is already in a proposed block")]
    NonceInFlight { nonce: u64 },
    #[error("Too many pending transactions from sender (limit {limit})")]
    TooManyFromSender { limit: usize },
    #[error("Crypto error: {0}")]
    Crypto(#[from] kovanica_crypto::CryptoError),
    #[error("Storage error: {0}")]
    Storage(#[from] kovanica_storage::StorageError),
    #[error("State store error: {0}")]
    StateStore(#[from] kovanica_storage::StateStoreError),
    #[error("Serialization error: {0}")]
    Serialization(#[from] bincode::Error),
}

#[cfg(test)]
mod tests {
    use super::*;
    const TEST_CTX: kovanica_types::SigningContext =
        kovanica_types::SigningContext::new(kovanica_types::signing::chain_id::LOCAL);

    use kovanica_storage::state_store::Account;
    use kovanica_storage::Storage;
    use kovanica_types::crypto::{PublicKey, SigningKey};
    use kovanica_types::{Address, Signature};
    use std::{fs, path::PathBuf};

    const STRESS_TX_COUNT: usize = 10_000;

    fn build_signed_tx(
        sender: Address,
        nonce: u64,
        kind: TransactionKind,
        fee: u64,
        signing_key: &SigningKey,
    ) -> Transaction {
        let kind_for_tx = kind.clone();
        let mut tx = Transaction {
            sender,
            nonce,
            kind: kind_for_tx,
            fee,
            signature: Signature([0; 64]),
            hash: Hash::zero(),
        };

        let signing_hash = tx.signing_hash(&TEST_CTX);
        let signature = kovanica_crypto::sign(signing_key, signing_hash.as_ref());

        tx.signature = signature;
        tx.hash = signing_hash;
        tx
    }

    fn stress_keypair() -> (SigningKey, PublicKey) {
        let (sk, vk) = kovanica_crypto::generate_keypair();
        let pk = vk;
        (sk, pk)
    }

    fn stress_transaction(
        index: usize,
        (signing_key, _public_key): (SigningKey, PublicKey),
    ) -> Transaction {
        let mut recipient = [0; 32];
        recipient[..8].copy_from_slice(&(index as u64).to_be_bytes());

        // Use a consistent sender address pattern (based on index for deterministic behavior)
        // All transactions will have nonce = 0 since they're added to mempool simultaneously
        let sender = Address::from_public_key(&_public_key);
        let kind = TransactionKind::Transfer {
            to: Address(recipient),
            amount: index as u64 + 1,
        };

        // Build signed transaction - nonce = 0 since all are submitted simultaneously
        let fee = 1;
        let mut tx = build_signed_tx(sender, 0, kind.clone(), fee, &signing_key);

        // Keep the fee rate in ten deterministic buckets while ensuring every
        // transaction has a non-zero fee and the same serialized size.
        let size = bincode::serialize(&tx)
            .expect("serialize stress transaction")
            .len();
        tx.fee = size as u64 * (1 + (index % 10) as u64);

        // Re-sign with updated fee since fee is part of the signing hash
        let signing_hash = tx.signing_hash(&TEST_CTX);
        tx.signature = kovanica_crypto::sign(&signing_key, signing_hash.as_ref());
        tx.hash = signing_hash;
        tx
    }

    fn stress_storage_path() -> PathBuf {
        std::env::temp_dir().join(format!(
            "kovanica-mempool-stress-{}.redb",
            std::process::id()
        ))
    }

    #[test]
    fn stress_admits_10k_pending_transactions() {
        let db_path = stress_storage_path();
        // A previous interrupted run may have left its process-specific DB behind.
        let _ = fs::remove_file(&db_path);
        let storage = Arc::new(Storage::new(&db_path).expect("create test storage"));

        // Conflict-aware selection (Phase 16.5) only inlines a contiguous nonce
        // sequence per sender, so a 10k stress pool must use 10k distinct
        // senders (each at nonce 0) to exercise the full selection path.
        let keypairs: Vec<(SigningKey, PublicKey)> =
            (0..STRESS_TX_COUNT).map(|_| stress_keypair()).collect();

        // Set up one funded account per sender.
        let write_txn = storage.begin_write().unwrap();
        {
            let state = storage.state();
            for (_, public_key) in &keypairs {
                let sender = Address::from_public_key(public_key);
                let account = Account {
                    balance: 1_000_000,
                    nonce: 0,
                    code_hash: [0; 32],
                    code: Vec::new(),
                };
                state.set_account(&write_txn, &sender, &account).unwrap();
            }
        }
        write_txn.commit().unwrap();

        let config = MempoolConfig {
            // 64 MiB is deliberately much larger than the serialized 10k set.
            max_mempool_size: 64 * 1024 * 1024,
            max_tx_size: 1024 * 1024,
            ..MempoolConfig::default()
        };
        let pool = Mempool::new(config.clone(), storage.clone(), TEST_CTX);

        let transactions: Vec<_> = (0..STRESS_TX_COUNT)
            .map(|i| stress_transaction(i, keypairs[i].clone()))
            .collect();
        let expected_total_size: usize = transactions
            .iter()
            .map(|tx| {
                bincode::serialize(tx)
                    .expect("serialize expected transaction")
                    .len()
            })
            .sum();

        assert!(pool.is_empty());
        for tx in &transactions {
            pool.add_transaction(tx.clone())
                .expect("admit valid stress transaction");
        }

        assert_eq!(pool.len(), STRESS_TX_COUNT);
        assert!(!pool.is_empty());
        assert!(expected_total_size < config.max_mempool_size);

        for expected in &transactions {
            assert!(pool.contains(&expected.hash), "missing {}", expected.hash);
            let actual = pool
                .get(&expected.hash)
                .expect("lookup inserted transaction");
            assert_eq!(
                bincode::serialize(&actual).expect("serialize lookup"),
                bincode::serialize(expected).expect("serialize expected")
            );
        }

        let stats = pool.stats();
        assert_eq!(stats.tx_count, STRESS_TX_COUNT);
        assert_eq!(stats.total_size, expected_total_size);
        assert!(stats.total_size <= config.max_mempool_size);
        assert_eq!(
            stats
                .fee_rates
                .iter()
                .map(|(_, count)| count)
                .sum::<usize>(),
            STRESS_TX_COUNT
        );

        // This consumes the fee-priority queue, so keep it after the lookup and
        // accounting assertions. The returned transactions must be the full set.
        let next = pool.get_next_transactions(STRESS_TX_COUNT);
        assert_eq!(next.len(), STRESS_TX_COUNT);
        let returned: HashMap<_, _> = next.into_iter().map(|tx| (tx.hash, tx)).collect();
        assert_eq!(returned.len(), STRESS_TX_COUNT);
        for expected in &transactions {
            let actual = returned
                .get(&expected.hash)
                .expect("proposal queue returned every inserted hash");
            assert_eq!(
                bincode::serialize(actual).expect("serialize queued transaction"),
                bincode::serialize(expected).expect("serialize expected")
            );
        }

        drop(pool);
        drop(storage);
        fs::remove_file(db_path).expect("remove test storage");
    }

    #[test]
    fn test_transaction_validation_edge_cases() {
        use kovanica_crypto::generate_keypair;
        use kovanica_types::transaction::TransactionKind;

        let db_path = std::env::temp_dir().join(format!(
            "kovanica-mempool-validation-test-{}.redb",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&db_path);
        let storage = Arc::new(Storage::new(&db_path).expect("create test storage"));

        // Create a test account with known balance and nonce
        let (signing_key, public_key) = generate_keypair();
        let sender = Address::from_public_key(&public_key);

        // Set up account in storage with balance = 1000 and nonce = 5
        let txn = storage.begin_write().unwrap();
        {
            let state = storage.state();
            let account = Account {
                balance: 1000,
                nonce: 5,
                code_hash: [0; 32],
                code: Vec::new(),
            };
            state.set_account(&txn, &sender, &account).unwrap();
        }
        txn.commit().unwrap();

        let config = MempoolConfig::default();
        let pool = Mempool::new(config, storage.clone(), TEST_CTX);

        // Test 1: Valid transaction should pass
        let valid_tx = build_signed_tx(
            sender,
            5, // matches account nonce
            TransactionKind::Transfer {
                to: Address([2u8; 32]),
                amount: 100,
            },
            10, // fee
            &signing_key,
        );

        assert!(
            pool.add_transaction(valid_tx.clone()).is_ok(),
            "Valid transaction accepted"
        );

        // Test 2: Transaction with invalid signature should be rejected
        // (distinct recipient so its hash is not a duplicate of `valid_tx`)
        let mut invalid_sig_tx = build_signed_tx(
            sender,
            5,
            TransactionKind::Transfer {
                to: Address([9u8; 32]),
                amount: 100,
            },
            10,
            &signing_key,
        );
        invalid_sig_tx.signature = Signature([0; 64]); // Invalid signature
        assert!(
            matches!(
                pool.add_transaction(invalid_sig_tx.clone()),
                Err(MempoolError::InvalidSignature)
            ),
            "Transaction with invalid signature should be rejected"
        );

        // Test 3: Transaction with wrong nonce (too low) should be rejected
        let low_nonce_tx = build_signed_tx(
            sender,
            4, // Less than account nonce (5)
            TransactionKind::Transfer {
                to: Address([2u8; 32]),
                amount: 100,
            },
            10,
            &signing_key,
        );
        assert!(
            matches!(
                pool.add_transaction(low_nonce_tx.clone()),
                Err(MempoolError::InvalidNonce {
                    expected: 5,
                    got: 4
                })
            ),
            "Transaction with nonce too low should be rejected"
        );

        // Test 4: Transaction leaving a nonce gap should be rejected
        // (5 is pending, so the next admissible nonce is 6).
        let high_nonce_tx = build_signed_tx(
            sender,
            7,
            TransactionKind::Transfer {
                to: Address([2u8; 32]),
                amount: 100,
            },
            10,
            &signing_key,
        );
        assert!(
            matches!(
                pool.add_transaction(high_nonce_tx.clone()),
                Err(MempoolError::InvalidNonce {
                    expected: 6,
                    got: 7
                })
            ),
            "Transaction with a nonce gap should be rejected"
        );

        // Test 5: Transaction with insufficient balance should be rejected.
        // The balance must cover everything pending: (100 + 10) for nonce 5
        // plus (1000 + 10) for this one = 1120 > 1000.
        let insufficient_balance_tx = build_signed_tx(
            sender,
            6,
            TransactionKind::Transfer {
                to: Address([3u8; 32]),
                amount: 1000,
            },
            10, // fee
            &signing_key,
        );
        assert!(
            matches!(
                pool.add_transaction(insufficient_balance_tx.clone()),
                Err(MempoolError::InsufficientBalance {
                    balance: 1000,
                    required: 1120
                })
            ),
            "Transaction with insufficient balance should be rejected"
        );

        // Test 6: Transaction with zero fee (non-stake) should be rejected
        let zero_fee_tx = build_signed_tx(
            sender,
            5, // matches account nonce
            TransactionKind::Transfer {
                to: Address([4u8; 32]),
                amount: 50,
            },
            0, // zero fee
            &signing_key,
        );
        assert!(
            matches!(
                pool.add_transaction(zero_fee_tx.clone()),
                Err(MempoolError::ZeroFee)
            ),
            "Transaction with zero fee (non-stake) should be rejected"
        );

        // Test 7: Stake transaction with zero fee should be allowed
        let stake_tx = build_signed_tx(
            sender,
            6, // next nonce after the pending transfer
            TransactionKind::Stake { amount: 50 },
            0, // zero fee allowed for stake
            &signing_key,
        );
        assert!(
            pool.add_transaction(stake_tx).is_ok(),
            "Stake transaction with zero fee should be accepted"
        );

        // Clean up
        drop(pool);
        drop(storage);
        let _ = std::fs::remove_file(db_path);
    }

    // ------------------------------------------------------------------
    // Admission / lifecycle tests
    // ------------------------------------------------------------------

    struct Fixture {
        _dir: tempfile::TempDir,
        storage: Arc<Storage>,
    }

    impl Fixture {
        fn new() -> Self {
            let dir = tempfile::tempdir().expect("tempdir");
            let storage = Arc::new(Storage::new(dir.path().join("m.redb")).expect("storage"));
            Self { _dir: dir, storage }
        }

        fn funded(&self, balance: u64, nonce: u64) -> (SigningKey, Address) {
            let (sk, pk) = kovanica_crypto::generate_keypair();
            let sender = Address::from_public_key(&pk);
            let txn = self.storage.begin_write().unwrap();
            self.storage
                .state()
                .set_account(
                    &txn,
                    &sender,
                    &Account {
                        balance,
                        nonce,
                        code_hash: [0; 32],
                        code: Vec::new(),
                    },
                )
                .unwrap();
            txn.commit().unwrap();
            (sk, sender)
        }

        fn pool(&self, config: MempoolConfig) -> Mempool {
            Mempool::new(config, self.storage.clone(), TEST_CTX)
        }
    }

    fn transfer(
        sk: &SigningKey,
        sender: Address,
        nonce: u64,
        amount: u64,
        fee: u64,
    ) -> Transaction {
        build_signed_tx(
            sender,
            nonce,
            TransactionKind::Transfer {
                to: Address([7u8; 32]),
                amount,
            },
            fee,
            sk,
        )
    }

    fn assert_consistent(pool: &Mempool) {
        let state = pool.state.lock();
        let queued: usize = state.by_fee_rate.values().map(|q| q.len()).sum();
        let in_flight = state
            .by_hash
            .values()
            .filter(|e| e.in_flight_since.is_some())
            .count();
        assert_eq!(queued + in_flight, state.by_hash.len(), "queue/index drift");
        let by_sender: usize = state.by_sender.values().map(|m| m.len()).sum();
        assert_eq!(by_sender, state.by_hash.len(), "sender index drift");
        let size: usize = state.by_hash.values().map(|e| e.size).sum();
        assert_eq!(size, state.total_size, "size accounting drift");
    }

    #[test]
    fn hash_must_be_bound_to_signing_hash() {
        let fx = Fixture::new();
        let (sk, sender) = fx.funded(1_000, 0);
        let pool = fx.pool(MempoolConfig::default());
        let mut tx = transfer(&sk, sender, 0, 1, 10);
        tx.hash = Hash::new(b"attacker chosen");
        assert!(matches!(
            pool.add_transaction(tx),
            Err(MempoolError::HashMismatch)
        ));
        assert!(pool.is_empty());
    }

    #[test]
    fn min_fee_rate_is_enforced_for_fee_paying_kinds() {
        let fx = Fixture::new();
        let (sk, sender) = fx.funded(1_000_000, 0);
        let pool = fx.pool(MempoolConfig {
            min_fee_rate: 2,
            ..MempoolConfig::default()
        });
        let cheap = transfer(&sk, sender, 0, 1, 10);
        assert!(matches!(
            pool.add_transaction(cheap),
            Err(MempoolError::FeeTooLow {
                min_fee_rate: 2,
                ..
            })
        ));
        let size = bincode::serialized_size(&transfer(&sk, sender, 0, 1, 10)).unwrap();
        let ok = transfer(&sk, sender, 0, 1, size * 2);
        pool.add_transaction(ok).expect("fee rate 2 admitted");
        // Stake stays fee-free by design.
        let stake = build_signed_tx(sender, 1, TransactionKind::Stake { amount: 1 }, 0, &sk);
        pool.add_transaction(stake)
            .expect("zero-fee stake admitted");
    }

    #[test]
    fn same_nonce_replacement_requires_fee_bump() {
        let fx = Fixture::new();
        let (sk, sender) = fx.funded(1_000_000, 0);
        let pool = fx.pool(MempoolConfig::default());
        let first = transfer(&sk, sender, 0, 1, 100);
        pool.add_transaction(first.clone()).unwrap();

        let underpriced = transfer(&sk, sender, 0, 2, 105);
        assert!(matches!(
            pool.add_transaction(underpriced),
            Err(MempoolError::ReplacementUnderpriced {
                fee: 105,
                min_fee: 110
            })
        ));
        let bumped = transfer(&sk, sender, 0, 2, 110);
        pool.add_transaction(bumped.clone())
            .expect("10% bump replaces");
        assert!(!pool.contains(&first.hash));
        assert!(pool.contains(&bumped.hash));
        assert_eq!(pool.len(), 1);
        assert_consistent(&pool);
    }

    #[test]
    fn nonces_must_be_contiguous_and_per_sender_limit_holds() {
        let fx = Fixture::new();
        let (sk, sender) = fx.funded(1_000_000, 3);
        let pool = fx.pool(MempoolConfig {
            max_txs_per_sender: 2,
            ..MempoolConfig::default()
        });
        assert!(matches!(
            pool.add_transaction(transfer(&sk, sender, 4, 1, 10)),
            Err(MempoolError::InvalidNonce {
                expected: 3,
                got: 4
            })
        ));
        pool.add_transaction(transfer(&sk, sender, 3, 1, 10))
            .unwrap();
        pool.add_transaction(transfer(&sk, sender, 4, 1, 10))
            .unwrap();
        assert!(matches!(
            pool.add_transaction(transfer(&sk, sender, 5, 1, 10)),
            Err(MempoolError::TooManyFromSender { limit: 2 })
        ));
    }

    #[test]
    fn full_pool_evicts_only_cheaper_transactions_and_keeps_indexes_consistent() {
        let fx = Fixture::new();
        let (sk_a, a) = fx.funded(1_000_000, 0);
        let (sk_b, b) = fx.funded(1_000_000, 0);
        let (sk_c, c) = fx.funded(1_000_000, 0);
        let probe = transfer(&sk_a, a, 0, 1, 1);
        let size = bincode::serialized_size(&probe).unwrap() as usize;
        // Room for exactly two transactions.
        let pool = fx.pool(MempoolConfig {
            max_mempool_size: size * 2,
            ..MempoolConfig::default()
        });
        let a0 = transfer(&sk_a, a, 0, 1, size as u64); // rate 1
        let a1 = transfer(&sk_a, a, 1, 1, size as u64 * 5); // rate 5
        pool.add_transaction(a0.clone()).unwrap();
        pool.add_transaction(a1.clone()).unwrap();

        // Same or lower rate than the cheapest entry: rejected, nothing lost.
        let b0_cheap = transfer(&sk_b, b, 0, 1, size as u64);
        assert!(matches!(
            pool.add_transaction(b0_cheap),
            Err(MempoolError::Full)
        ));
        assert_eq!(pool.len(), 2);

        // Higher rate: evicts a0 *and* a1 (a1 would be unexecutable without
        // a0), so the pool never holds a nonce gap.
        let c0 = transfer(&sk_c, c, 0, 1, size as u64 * 3);
        pool.add_transaction(c0.clone()).unwrap();
        assert!(!pool.contains(&a0.hash));
        assert!(!pool.contains(&a1.hash));
        assert!(pool.contains(&c0.hash));
        assert_consistent(&pool);
        let stats = pool.stats();
        assert_eq!(stats.tx_count, 1);
        assert_eq!(stats.total_size, size);
    }

    #[test]
    fn proposal_keeps_nonce_order_and_loses_nothing() {
        let fx = Fixture::new();
        let (sk_a, a) = fx.funded(1_000_000, 0);
        let (sk_b, b) = fx.funded(1_000_000, 0);
        let pool = fx.pool(MempoolConfig::default());
        // a: nonce 0 cheap, nonce 1 expensive. b: one mid-priced tx.
        let a0 = transfer(&sk_a, a, 0, 1, 10);
        let a1 = transfer(&sk_a, a, 1, 1, 100_000);
        let b0 = transfer(&sk_b, b, 0, 1, 5_000);
        for tx in [&a0, &a1, &b0] {
            pool.add_transaction(tx.clone()).unwrap();
        }

        // First proposal: returns the two highest fee-rate transaction FRONTS.
        // Sender a has run [a0, a1] (front is a0), sender b has run [b0] (front is b0).
        // Fee rates: a0=10/size, b0=5000/size.
        // First pick: b0 (highest fee rate front) from sender b.
        // Second pick: a0 (next front) from sender a.
        // So first proposal returns [b0, a0] (ordered by fee rate).
        // a1 stays queued behind a0.
        let first = pool.get_next_transactions(2);
        assert_eq!(first.len(), 2);
        // Both b0 and a0 should be in the first proposal (a1 is left queued behind a0).
        let first_hashes: std::collections::HashSet<_> = first.iter().map(|t| t.hash).collect();
        assert!(
            first_hashes.contains(&b0.hash),
            "b0 should be in first proposal"
        );
        assert!(
            first_hashes.contains(&a0.hash),
            "a0 should be in first proposal"
        );
        assert!(
            !first_hashes.contains(&a1.hash),
            "a1 should NOT be in first proposal (behind a0)"
        );
        // Everything is still tracked (queued + in-flight).
        assert_eq!(pool.len(), 3);

        // Second proposal: b0 and a0 are in-flight.
        // Sender a has a1 at nonce 1 still queued (run now starts at nonce 1 after a0 is in-flight).
        // Sender b has no more queued transactions.
        // So second proposal should return a1.
        let second = pool.get_next_transactions(10);
        assert_eq!(
            second.len(),
            1,
            "sender a's queued tx a1 should be returned after a0 is in-flight"
        );
        assert_eq!(second[0].hash, a1.hash);

        // Pool still tracks all 3 transactions.
        assert_eq!(pool.len(), 3);

        // Third proposal (immediate): a0,a1,b0 are in-flight, returns 0.
        assert!(
            pool.get_next_transactions(10).is_empty(),
            "all in flight, not re-proposed"
        );
        assert_consistent(&pool);
    }

    #[test]
    fn uncommitted_in_flight_transactions_are_requeued() {
        let fx = Fixture::new();
        let (sk, sender) = fx.funded(1_000_000, 0);
        let pool = fx.pool(MempoolConfig {
            in_flight_timeout: Duration::from_millis(0),
            ..MempoolConfig::default()
        });
        let tx = transfer(&sk, sender, 0, 1, 10);
        pool.add_transaction(tx.clone()).unwrap();
        assert_eq!(pool.get_next_transactions(10).len(), 1);
        // Timeout 0: the next proposal re-queues it.
        assert_eq!(pool.get_next_transactions(10), vec![tx]);
        assert_consistent(&pool);
    }

    #[test]
    fn in_flight_nonce_cannot_be_replaced() {
        let fx = Fixture::new();
        let (sk, sender) = fx.funded(1_000_000, 0);
        let pool = fx.pool(MempoolConfig::default());
        pool.add_transaction(transfer(&sk, sender, 0, 1, 10))
            .unwrap();
        pool.get_next_transactions(10);
        assert!(matches!(
            pool.add_transaction(transfer(&sk, sender, 0, 2, 1_000)),
            Err(MempoolError::NonceInFlight { nonce: 0 })
        ));
        // But the sender can keep going with the next nonce.
        pool.add_transaction(transfer(&sk, sender, 1, 1, 10))
            .unwrap();
    }

    #[test]
    fn committed_transactions_and_stale_nonces_are_removed() {
        let fx = Fixture::new();
        let (sk, sender) = fx.funded(1_000_000, 0);
        let pool = fx.pool(MempoolConfig::default());
        let t0 = transfer(&sk, sender, 0, 1, 10);
        let t1 = transfer(&sk, sender, 1, 1, 10);
        let t2 = transfer(&sk, sender, 2, 1, 10);
        for tx in [&t0, &t1, &t2] {
            pool.add_transaction(tx.clone()).unwrap();
        }
        pool.get_next_transactions(1);
        // Another validator committed a *different* tx with nonce 1.
        let other1 = transfer(&sk, sender, 1, 99, 50);
        let removed = pool.remove_committed_transactions(&[t0.clone(), other1]);
        assert_eq!(removed, 2, "t0 committed, t1 made stale");
        assert!(!pool.contains(&t0.hash));
        assert!(!pool.contains(&t1.hash));
        assert!(pool.contains(&t2.hash));
        assert_consistent(&pool);
        assert_eq!(
            pool.stats().total_size,
            bincode::serialized_size(&t2).unwrap() as usize
        );
    }

    #[test]
    fn concurrent_stats_and_removal_do_not_deadlock() {
        let fx = Fixture::new();
        let pool = Arc::new(fx.pool(MempoolConfig::default()));
        let mut txs = Vec::new();
        for _ in 0..50 {
            let (sk, sender) = fx.funded(1_000_000, 0);
            let tx = transfer(&sk, sender, 0, 1, 10);
            pool.add_transaction(tx.clone()).unwrap();
            txs.push(tx);
        }
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        let reader = {
            let pool = pool.clone();
            let done_tx = done_tx.clone();
            std::thread::spawn(move || {
                for _ in 0..2_000 {
                    let _ = pool.stats();
                }
                done_tx.send(()).unwrap();
            })
        };
        let writer = {
            let pool = pool.clone();
            std::thread::spawn(move || {
                for tx in txs {
                    pool.remove_committed(&[tx.hash]);
                    let _ = pool.get_next_transactions(5);
                }
                done_tx.send(()).unwrap();
            })
        };
        for _ in 0..2 {
            done_rx
                .recv_timeout(Duration::from_secs(20))
                .expect("no deadlock between stats and removal");
        }
        reader.join().unwrap();
        writer.join().unwrap();
        assert!(pool.is_empty());
    }

    // --- #13 reinsert_returned ----------------------------------------

    #[test]
    fn reinsert_reports_each_case_in_input_order() {
        let fx = Fixture::new();
        let (sk, sender) = fx.funded(1_000_000, 3);
        let pool = fx.pool(MempoolConfig::default());
        let pooled = transfer(&sk, sender, 3, 1, 1_000);
        pool.add_transaction(pooled.clone()).unwrap();
        let next = transfer(&sk, sender, 4, 1, 1_000);
        let committed = transfer(&sk, sender, 2, 1, 1_000); // nonce < account nonce
        let mut forged = transfer(&sk, sender, 5, 1, 1_000);
        forged.signature = kovanica_types::Signature([9; 64]);

        let report = pool.reinsert_returned(
            vec![
                forged.clone(),
                next.clone(),
                pooled.clone(),
                committed.clone(),
            ],
            false,
        );
        let outcomes: Vec<_> = report.iter().map(|r| r.outcome.clone()).collect();
        assert_eq!(report[0].hash, forged.hash);
        assert!(matches!(&outcomes[0], ReinsertOutcome::Invalid(r) if r.contains("signature")));
        assert_eq!(outcomes[1], ReinsertOutcome::Accepted);
        assert_eq!(outcomes[2], ReinsertOutcome::Duplicate);
        assert_eq!(outcomes[3], ReinsertOutcome::AlreadyCommitted);
        assert!(pool.contains(&next.hash));
    }

    #[test]
    fn reinsert_orders_nonce_chain_and_never_gossips() {
        let fx = Fixture::new();
        let (sk, sender) = fx.funded(1_000_000, 0);
        let pool = fx.pool(MempoolConfig {
            rebroadcast_interval: Duration::ZERO,
            ..MempoolConfig::default()
        });
        // Reversed nonce order on input: still all accepted.
        let txs: Vec<_> = (0..3)
            .rev()
            .map(|n| transfer(&sk, sender, n, 1, 1_000))
            .collect();
        let report = pool.reinsert_returned(txs, false);
        assert!(
            report
                .iter()
                .all(|r| r.outcome == ReinsertOutcome::Accepted),
            "{report:?}"
        );
        assert_eq!(pool.len(), 3);
        assert!(
            pool.get_pending_propagation().is_empty(),
            "returned txs must not be gossiped"
        );
        assert!(
            pool.rebroadcast().is_empty(),
            "returned txs must not be re-broadcast"
        );
        // A normally submitted tx is still gossiped.
        let (sk2, sender2) = fx.funded(1_000_000, 0);
        pool.add_transaction(transfer(&sk2, sender2, 0, 1, 1_000))
            .unwrap();
        assert_eq!(pool.get_pending_propagation().len(), 1);
    }

    #[test]
    fn reinsert_respects_per_sender_and_total_limits() {
        let fx = Fixture::new();
        let (sk, sender) = fx.funded(1_000_000, 0);
        let pool = fx.pool(MempoolConfig {
            max_txs_per_sender: 2,
            ..MempoolConfig::default()
        });
        let txs: Vec<_> = (0..3).map(|n| transfer(&sk, sender, n, 1, 1_000)).collect();
        let report = pool.reinsert_returned(txs, false);
        assert_eq!(report[0].outcome, ReinsertOutcome::Accepted);
        assert_eq!(report[1].outcome, ReinsertOutcome::Accepted);
        assert!(
            matches!(&report[2].outcome, ReinsertOutcome::Invalid(r) if r.contains("Too many"))
        );

        // Total pool limit: room for exactly one transaction.
        let (sk_a, a) = fx.funded(1_000_000, 0);
        let (sk_b, b) = fx.funded(1_000_000, 0);
        let first = transfer(&sk_a, a, 0, 1, 1_000);
        let size = bincode::serialized_size(&first).unwrap() as usize;
        let small = fx.pool(MempoolConfig {
            max_mempool_size: size,
            ..MempoolConfig::default()
        });
        let report = small.reinsert_returned(vec![first, transfer(&sk_b, b, 0, 1, 1_000)], false);
        let accepted = report
            .iter()
            .filter(|r| r.outcome == ReinsertOutcome::Accepted)
            .count();
        assert_eq!(accepted, 1, "{report:?}");
        assert!(report
            .iter()
            .any(|r| matches!(&r.outcome, ReinsertOutcome::Invalid(m) if m.contains("full"))));
    }
}
