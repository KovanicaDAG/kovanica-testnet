//! Contract dispatch layer — the real execution path for the four contract
//! crates (`kovanica-htlc`, `kovanica-vault`, `kovanica-multisig`, `kovanica-token`).
//!
//! Two paths share one state model:
//!
//! - **Native dispatch** ([`execute_contract_call`]): bincode-decodes the
//!   fixed ABI argument tuple, calls the crate's typed API directly through a
//!   [`ContractHost`], bincode-encodes the Ok result. Byte-for-byte identical
//!   results to the wasm path (both encode the same values with the same
//!   `bincode` configuration).
//! - **Wasmi dispatch** ([`ContractRunner::execute_wasm_call`]): compiles the
//!   crate's `wasm32-unknown-unknown` cdylib artifact and runs the same entry
//!   name through [`kovanica_runtime::Runtime`], whose `env` imports are backed by
//!   the *same* [`ContractHost`].
//!
//! ## `ContractHost` semantics (FIXED — read before changing)
//!
//! A `ContractHost` is created per call and holds:
//!
//! - an immutable context: contract address, caller, block height, timestamp;
//! - **one redb read snapshot** ([`redb::ReadTransaction`]) covering the whole
//!   call, so repeated reads are repeatable even if another writer commits
//!   mid-call (redb is MVCC: read transactions may coexist with write
//!   transactions — verified against redb 2.6 source: `begin_read` documents
//!   "Read transactions may exist concurrently with writes", and
//!   `start_write_transaction` only waits for other *write* transactions);
//! - an **in-memory overlay**: pending storage writes, touched accounts, and
//!   emitted events.
//!
//! Reads consult the overlay first, then the snapshot. Storage writes are
//! **namespaced by contract address**: the table key is
//! `(contract_addr, blake3(raw_key))` — contracts pass their raw (variable
//! length) keys, the host derives the fixed 32-byte table key with
//! [`kovanica_common::hash`], so two contracts can use the same raw key without
//! collision.
//!
//! **Commit rules:**
//!
//! - [`ContractHost::commit`] is called *only* after the entry point returned
//!   `Ok`. It flushes the overlay into a single redb write transaction
//!   (snapshot dropped first) and returns the emitted events.
//! - **Single-writer mode** ([`ContractHost::new_in_txn`], used for every
//!   on-chain `Call`): reads go through the sub-DAG's open
//!   [`redb::WriteTransaction`] (so earlier writes such as the fee are
//!   visible) and `commit` applies the overlay into that same transaction —
//!   no second redb writer is ever opened. The apply is all-or-nothing via a
//!   pre-image journal. Standalone mode (`new`) keeps the snapshot + own
//!   write commit and must not be used while another writer is open.
//! - On a contract error (`ContractError`) the host is simply dropped:
//!   nothing — no storage write, no balance delta, no event — is committed.
//! - A failed backing read sets a *sticky* read error; `commit` then refuses
//!   to flush, so a transient storage failure can never silently corrupt a
//!   contract record (the call surfaces as [`ExecutionError::Other`]).
//!
//! Native balances are moved through the `ACCOUNTS` table
//! (`kovanica_storage::state_store::Account`); `amount > u64::MAX` maps to
//! `ContractError::Overflow`, a balance shortfall to `InsufficientBalance`.
//!
//! ## Spend authorization and host custody
//!
//! A contract may only spend (a) its **own** funds or (b) an amount the
//! signer **explicitly approved**. [`Host::transfer`] classifies `from`:
//!
//! 1. `from == contract` — own funds. Spendable is the contract account
//!    balance **minus the total held in custody**, so own spends can never
//!    touch escrowed funds. `to` is credited as a real account.
//! 2. `from == caller` while signed **attached value** (`Call.value`)
//!    remains — the value was already moved from the signer to the
//!    contract's real account before the entry point ran, so this pull only
//!    books up to the remaining attached value in the custody ledger under
//!    `to` (e.g. the HTLC/vault escrow address); no real balance moves again.
//!    `to` may not be the contract or the caller. Pulling more than the
//!    remaining attached value is `Unauthorized`.
//! 3. `from` has a custody balance in **this contract's** ledger — release:
//!    the ledger entry and the contract account are debited, `to` is credited
//!    as a real account.
//! 4. Anything else — `ContractError::Unauthorized`, nothing moved.
//!
//! **Attached value (`Call.value`, signature format v1).** Before the
//! entry point runs, [`ContractHost::attach_value`] moves the signed `value`
//! from the caller's real account to the contract's real account (rejected
//! with `InsufficientBalance` if the caller cannot cover it). Like every
//! host write it lives in the overlay, so a failed call moves nothing.
//! Value not booked into custody stays in the contract's own funds. The
//! former interim args-based create approval (decoding the `amount` of
//! `htlc_create`/`vault_create` arguments) is removed.
//!
//! **Custody ledger.** Custody balances are *virtual sub-accounts* stored in
//! the contract's own namespaced storage under the reserved raw-key prefix
//! [`RESERVED_HOST_PREFIX`] (`kvnc/host/`): `kvnc/host/custody/<addr32>`
//! (u64 LE) per sub-account and `kvnc/host/custody_total` (u64 LE). The
//! funds themselves sit in the contract's real account. Contracts cannot
//! read or write the reserved prefix: such an access marks the call as
//! failed (sticky error) and nothing is committed. Because the ledger is
//! per contract, one contract can never release another contract's custody,
//! and a user's real balance is never a custody balance.
//!
//! **Visibility:** escrow addresses (`htlc/escrow`, `vault/escrow`) hold a
//! *real* balance of 0; the escrowed amount is part of the contract
//! account's balance and is visible per escrow via the custody ledger.
//!
//! **Native dispatch** ([`execute_contract_call`]) rejects a contract address
//! without deployed code, and trusts its `caller` argument as the signer — it
//! must only be called with a signature-verified caller.

use std::cell::RefCell;
use std::collections::{BTreeMap, HashMap};

use kovanica_common::{ContractError, ContractResult, Host};
use kovanica_htlc::Htlc;
use kovanica_multisig::Multisig;
#[cfg(test)]
use kovanica_runtime::DEFAULT_CONTRACT_MEMORY_PAGES;
use kovanica_runtime::{ExecutionConfig, Runtime};
use kovanica_storage::state_store::Account;
use kovanica_storage::{tables, BincodeSerialize, Storage, StorageError};
use kovanica_token::Token;
use kovanica_types::Address;
use kovanica_vault::Vault;
use redb::{ReadTransaction, ReadableTable, WriteTransaction};
use serde::de::DeserializeOwned;
use serde::Serialize;
use tracing::debug;

use crate::ExecutionError;

/// Raw storage-key prefix reserved for host bookkeeping inside a contract's
/// namespace. Contract `storage_get`/`storage_set` on it are rejected.
pub const RESERVED_HOST_PREFIX: &[u8] = b"kvnc/host/";
/// Raw-key prefix of one custody sub-account entry (followed by 32 bytes).
const CUSTODY_PREFIX: &[u8] = b"kvnc/host/custody/";
/// Raw key of the per-contract custody total.
const CUSTODY_TOTAL_KEY: &[u8] = b"kvnc/host/custody_total";

fn custody_key(address: &[u8; 32]) -> Vec<u8> {
    let mut key = Vec::with_capacity(CUSTODY_PREFIX.len() + 32);
    key.extend_from_slice(CUSTODY_PREFIX);
    key.extend_from_slice(address);
    key
}

/// The 16 dispatchable contract entry points (FIXED ABI, Lane 3a).
///
/// The native [`execute_contract_call`] dispatcher, the wasm exports of the
/// four contract crates, and `docs/CONTRACTS.md` must stay in sync with this
/// table (enforced by `dispatch_covers_all_16_entry_points`).
pub const ENTRY_POINTS: &[&str] = &[
    "htlc_create",
    "htlc_claim",
    "htlc_refund",
    "vault_create",
    "vault_claim",
    "vault_cancel",
    "multisig_create",
    "multisig_propose",
    "multisig_confirm",
    "multisig_execute",
    "token_create",
    "token_transfer",
    "token_approve",
    "token_transfer_from",
    "token_mint",
    "token_burn",
];

/// Returns whether `name` is one of the 16 dispatchable entry points.
pub fn is_entry_point(name: &str) -> bool {
    ENTRY_POINTS.contains(&name)
}

/// One event emitted during a contract call. Returned by
/// [`ContractHost::commit`] — events of a failed call are discarded with
/// everything else.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ContractEvent {
    /// Address the event is attributed to: the contract address for contract
    /// calls (native typed or wasmi), or the involved account for native
    /// ledger events. Exposed as the `address` field of `kovanica_getLogs`.
    ///
    /// This field is part of the persisted receipt layout (receipts are stored
    /// with `bincode`), so it must not be reordered or removed without a
    /// storage migration.
    pub address: Address,
    /// Event topic (e.g. `b"htlc_claimed"`).
    pub topic: Vec<u8>,
    /// Event payload.
    pub data: Vec<u8>,
}

/// Host implementation over persistent [`Storage`] with a per-call overlay.
///
/// See the module docs for the exact semantics (namespacing, snapshot,
/// commit rules).
pub struct ContractHost<'a> {
    storage: &'a Storage,
    contract: Address,
    caller: Address,
    block_height: u64,
    timestamp: u64,
    /// Read view held for the whole call: a standalone snapshot, or the
    /// caller's open write transaction (single-writer mode).
    reads: Reads<'a>,
    /// Raw contract key → value; the contract address is applied at commit.
    storage_writes: BTreeMap<Vec<u8>, Vec<u8>>,
    /// Accounts touched by `transfer`/`balance_of` (balance possibly
    /// mutated), keyed by the raw 32-byte address (`kovanica_types::Address`
    /// itself does not implement `Ord`).
    accounts: BTreeMap<[u8; 32], Account>,
    events: Vec<ContractEvent>,
    /// First backing-read failure or policy violation (reserved-prefix
    /// access); when set, [`ContractHost::commit`] refuses to flush so a
    /// failed read can never be mistaken for "absent".
    read_error: RefCell<Option<String>>,
    /// Remaining signed attached value (`Call.value`) the contract may book
    /// into custody on behalf of the caller.
    attached_value: u64,
}

impl<'a> ContractHost<'a> {
    /// Open a host for one call against `storage`.
    ///
    /// The redb read snapshot is opened eagerly; a failure here aborts the
    /// call before any contract code runs.
    pub fn new(
        storage: &'a Storage,
        contract: Address,
        caller: Address,
        block_height: u64,
        timestamp: u64,
    ) -> Result<Self, ExecutionError> {
        let reads = Reads::Snapshot(storage.begin_read()?);
        Ok(Self {
            storage,
            contract,
            caller,
            block_height,
            timestamp,
            reads,
            storage_writes: BTreeMap::new(),
            accounts: BTreeMap::new(),
            events: Vec::new(),
            read_error: RefCell::new(None),
            attached_value: 0,
        })
    }

    /// Open a host that reads from and commits into the caller's already
    /// open write transaction (single-writer mode).
    ///
    /// Reads see every write made earlier in that transaction (e.g. the fee
    /// already deducted). On success, [`ContractHost::commit`] applies the
    /// overlay into `txn` (no second redb writer, no redb commit); on
    /// failure the host is dropped and `txn` is untouched.
    pub fn new_in_txn(
        storage: &'a Storage,
        txn: &'a WriteTransaction,
        contract: Address,
        caller: Address,
        block_height: u64,
        timestamp: u64,
    ) -> Self {
        Self {
            storage,
            contract,
            caller,
            block_height,
            timestamp,
            reads: Reads::Txn(txn),
            storage_writes: BTreeMap::new(),
            accounts: BTreeMap::new(),
            events: Vec::new(),
            read_error: RefCell::new(None),
            attached_value: 0,
        }
    }

    /// Attach the signed `Call.value`: move `value` from the caller's real
    /// account to the contract's real account (overlay only; dropped if the
    /// call fails) and make it available for custody bookings.
    pub fn attach_value(&mut self, value: u64) -> Result<(), ContractError> {
        if value == 0 {
            return Ok(());
        }
        let caller = self.caller;
        let contract = self.contract;
        if caller == contract {
            return Err(ContractError::Unauthorized);
        }
        let balance = self.load_account(&caller)?.balance;
        self.move_real(&caller, &contract, value, balance)?;
        self.attached_value = value;
        Ok(())
    }

    /// Whether the contract account has deployed code (snapshot read).
    fn contract_has_code(&self) -> Result<bool, ExecutionError> {
        let account = self.reads.account(&self.contract)?;
        Ok(!account.code.is_empty())
    }

    /// Read a host-internal u64 from the reserved prefix (overlay first).
    fn host_u64(&self, raw_key: &[u8]) -> Result<u64, ContractError> {
        let raw = if let Some(value) = self.storage_writes.get(raw_key) {
            Some(value.clone())
        } else {
            match self
                .reads
                .storage(&self.contract, &Self::namespace(raw_key))
            {
                Ok(value) => value,
                Err(err) => {
                    self.record_read_error(format!("custody read failed: {err}"));
                    return Err(ContractError::Custom(500));
                }
            }
        };
        match raw {
            None => Ok(0),
            Some(bytes) => match <[u8; 8]>::try_from(bytes.as_slice()) {
                Ok(arr) => Ok(u64::from_le_bytes(arr)),
                Err(_) => {
                    self.record_read_error("corrupt custody entry".to_string());
                    Err(ContractError::Custom(500))
                }
            },
        }
    }

    fn set_host_u64(&mut self, raw_key: Vec<u8>, value: u64) {
        self.storage_writes
            .insert(raw_key, value.to_le_bytes().to_vec());
    }

    /// Custody balance of `address` in this contract's ledger.
    pub fn custody_balance(&self, address: &[u8; 32]) -> Result<u64, ContractError> {
        self.host_u64(&custody_key(address))
    }

    /// Total custody held by this contract.
    pub fn custody_total(&self) -> Result<u64, ContractError> {
        self.host_u64(CUSTODY_TOTAL_KEY)
    }

    /// Move `amount` between two real accounts through the overlay, checking
    /// `available` (the spendable part of `from`) first.
    fn move_real(
        &mut self,
        from: &Address,
        to: &Address,
        amount: u64,
        available: u64,
    ) -> ContractResult<()> {
        if available < amount {
            return Err(ContractError::InsufficientBalance);
        }
        if from == to {
            return Ok(());
        }
        let mut sender = self.load_account(from)?;
        let mut recipient = self.load_account(to)?;
        sender.balance = sender
            .balance
            .checked_sub(amount)
            .ok_or(ContractError::InsufficientBalance)?;
        recipient.balance = recipient
            .balance
            .checked_add(amount)
            .ok_or(ContractError::Overflow)?;
        self.accounts.insert(from.0, sender);
        self.accounts.insert(to.0, recipient);
        Ok(())
    }

    /// Fixed table key for a raw contract key: `blake3(raw_key)`.
    fn namespace(raw_key: &[u8]) -> [u8; 32] {
        kovanica_common::hash(raw_key)
    }

    fn record_read_error(&self, message: String) {
        let mut slot = self.read_error.borrow_mut();
        if slot.is_none() {
            *slot = Some(message);
        }
    }

    /// Load an account through the overlay (touched accounts win) or the
    /// read snapshot. Records a sticky error on backing-read failure.
    fn load_account(&self, address: &Address) -> Result<Account, ContractError> {
        if let Some(account) = self.accounts.get(&address.0) {
            return Ok(account.clone());
        }
        match self.reads.account(address) {
            Ok(account) => Ok(account),
            Err(err) => {
                self.record_read_error(format!("account read failed for {address:?}: {err}"));
                // Sticky error blocks commit; this code only aborts the call.
                Err(ContractError::Custom(500))
            }
        }
    }

    /// Events emitted so far (moved out; the host keeps working).
    pub fn take_events(&mut self) -> Vec<ContractEvent> {
        std::mem::take(&mut self.events)
    }

    /// Commit the overlay to persistent storage and return the emitted
    /// events.
    ///
    /// Called **only** on contract success. Steps:
    ///
    /// 1. Refuse if a backing read failed (sticky error).
    /// 2. Drop the read snapshot (redb allows a read transaction to stay open
    ///    across a write transaction, but the snapshot is released promptly
    ///    so it cannot pin freed pages any longer than needed).
    /// 3. Flush storage writes and touched accounts into ONE write
    ///    transaction; commit.
    pub fn commit(self) -> Result<Vec<ContractEvent>, ExecutionError> {
        if let Some(message) = self.read_error.borrow().clone() {
            return Err(ExecutionError::Other(format!(
                "contract call discarded, nothing committed: {message}"
            )));
        }
        let ContractHost {
            storage,
            contract,
            reads,
            storage_writes,
            accounts,
            events,
            ..
        } = self;
        match reads {
            Reads::Txn(txn) => {
                // Single-writer mode: apply into the caller's transaction.
                // All-or-nothing: pre-images are captured first and restored
                // if any write fails, so `txn` never holds a partial call.
                let journal = WriteJournal::capture(txn, &contract, &storage_writes, &accounts)?;
                if let Err(err) = apply_overlay(storage, txn, &contract, storage_writes, accounts) {
                    journal.restore(txn)?;
                    return Err(err);
                }
                Ok(events)
            }
            Reads::Snapshot(snapshot) => {
                drop(snapshot);
                let txn = storage.begin_write()?;
                apply_overlay(storage, &txn, &contract, storage_writes, accounts)?;
                txn.commit().map_err(StorageError::Commit)?;
                Ok(events)
            }
        }
    }
}

/// Read view of a [`ContractHost`].
enum Reads<'a> {
    /// Standalone call: one redb read snapshot for the whole call.
    Snapshot(ReadTransaction),
    /// Single-writer mode: the caller's open write transaction.
    Txn(&'a WriteTransaction),
}

fn decode_account(raw: Option<Vec<u8>>) -> Account {
    raw.map(|v| Account::from_bytes(&v).unwrap_or_default())
        .unwrap_or_default()
}

fn get_row<K, T>(table: &T, key: K) -> Result<Option<Vec<u8>>, ExecutionError>
where
    K: redb::Key + for<'k> std::borrow::Borrow<K::SelfType<'k>> + 'static,
    T: ReadableTable<K, Vec<u8>>,
{
    Ok(table.get(key)?.map(|v| v.value()))
}

impl Reads<'_> {
    fn account(&self, address: &Address) -> Result<Account, ExecutionError> {
        let raw = match self {
            Reads::Snapshot(rt) => get_row(&rt.open_table(tables::ACCOUNTS)?, address.0)?,
            Reads::Txn(txn) => get_row(&txn.open_table(tables::ACCOUNTS)?, address.0)?,
        };
        Ok(decode_account(raw))
    }

    fn storage(
        &self,
        contract: &Address,
        key: &[u8; 32],
    ) -> Result<Option<Vec<u8>>, ExecutionError> {
        let k = (contract.0, *key);
        match self {
            Reads::Snapshot(rt) => get_row(&rt.open_table(tables::CONTRACT_STORAGE)?, k),
            Reads::Txn(txn) => get_row(&txn.open_table(tables::CONTRACT_STORAGE)?, k),
        }
    }
}

/// Write the overlay of one successful call into `txn`.
fn apply_overlay(
    storage: &Storage,
    txn: &WriteTransaction,
    contract: &Address,
    storage_writes: BTreeMap<Vec<u8>, Vec<u8>>,
    accounts: BTreeMap<[u8; 32], Account>,
) -> Result<(), ExecutionError> {
    for (raw_key, value) in storage_writes {
        storage
            .state()
            .set_storage(txn, contract, ContractHost::namespace(&raw_key), value)?;
    }
    for (address, account) in accounts {
        storage
            .state()
            .set_account(txn, &Address(address), &account)?;
    }
    Ok(())
}

/// `CONTRACT_STORAGE` key: (contract address, namespaced key).
type StorageRowKey = ([u8; 32], [u8; 32]);

/// Pre-images of every row a call overlay is about to write.
struct WriteJournal {
    storage_rows: Vec<(StorageRowKey, Option<Vec<u8>>)>,
    account_rows: Vec<([u8; 32], Option<Vec<u8>>)>,
}

impl WriteJournal {
    fn capture(
        txn: &WriteTransaction,
        contract: &Address,
        storage_writes: &BTreeMap<Vec<u8>, Vec<u8>>,
        accounts: &BTreeMap<[u8; 32], Account>,
    ) -> Result<Self, ExecutionError> {
        let table = txn.open_table(tables::CONTRACT_STORAGE)?;
        let mut storage_rows = Vec::with_capacity(storage_writes.len());
        for raw_key in storage_writes.keys() {
            let k = (contract.0, ContractHost::namespace(raw_key));
            storage_rows.push((k, get_row(&table, k)?));
        }
        drop(table);
        let table = txn.open_table(tables::ACCOUNTS)?;
        let mut account_rows = Vec::with_capacity(accounts.len());
        for address in accounts.keys() {
            account_rows.push((*address, get_row(&table, *address)?));
        }
        Ok(Self {
            storage_rows,
            account_rows,
        })
    }

    fn restore(self, txn: &WriteTransaction) -> Result<(), ExecutionError> {
        let mut table = txn.open_table(tables::CONTRACT_STORAGE)?;
        for (k, pre) in self.storage_rows {
            match pre {
                Some(v) => {
                    table.insert(k, v)?;
                }
                None => {
                    table.remove(k)?;
                }
            }
        }
        drop(table);
        let mut table = txn.open_table(tables::ACCOUNTS)?;
        for (k, pre) in self.account_rows {
            match pre {
                Some(v) => {
                    table.insert(k, v)?;
                }
                None => {
                    table.remove(k)?;
                }
            }
        }
        Ok(())
    }
}

impl Host for ContractHost<'_> {
    fn caller(&self) -> [u8; 32] {
        self.caller.0
    }

    fn contract_address(&self) -> [u8; 32] {
        self.contract.0
    }

    fn block_height(&self) -> u64 {
        self.block_height
    }

    fn timestamp(&self) -> u64 {
        self.timestamp
    }

    fn balance_of(&self, addr: &[u8; 32]) -> u128 {
        let address = Address(*addr);
        match self.load_account(&address) {
            Ok(account) => u128::from(account.balance),
            // Sticky error is already recorded; contract sees 0 and the call
            // is discarded at commit.
            Err(_) => 0,
        }
    }

    fn transfer(&mut self, from: &[u8; 32], to: &[u8; 32], amount: u128) -> ContractResult<()> {
        // See the module docs ("Spend authorization and host custody").
        // Every branch validates fully before mutating the overlay.
        if amount > u64::MAX as u128 {
            return Err(ContractError::Overflow);
        }
        let amount = amount as u64;
        let contract = self.contract;
        let to_addr = Address(*to);

        // 1. Own funds: account balance minus everything held in custody.
        if *from == contract.0 {
            let balance = self.load_account(&contract)?.balance;
            let spendable = balance.saturating_sub(self.custody_total()?);
            return self.move_real(&contract, &to_addr, amount, spendable);
        }

        // 2. Attached value: book up to the remaining signed value into
        //    custody (the funds already sit in the contract account).
        if *from == self.caller.0 && self.attached_value > 0 {
            if amount > self.attached_value || *to == contract.0 || *to == self.caller.0 {
                return Err(ContractError::Unauthorized);
            }
            let entry = self.custody_balance(to)?;
            let total = self.custody_total()?;
            let new_entry = entry.checked_add(amount).ok_or(ContractError::Overflow)?;
            let new_total = total.checked_add(amount).ok_or(ContractError::Overflow)?;
            self.set_host_u64(custody_key(to), new_entry);
            self.set_host_u64(CUSTODY_TOTAL_KEY.to_vec(), new_total);
            self.attached_value -= amount;
            return Ok(());
        }

        // 3. Release from this contract's custody ledger to a real account.
        let entry = self.custody_balance(from)?;
        if entry == 0 {
            return Err(ContractError::Unauthorized);
        }
        if entry < amount {
            return Err(ContractError::InsufficientBalance);
        }
        let total = self.custody_total()?;
        let contract_balance = self.load_account(&contract)?.balance;
        if total < amount || contract_balance < amount {
            // Ledger invariant broken (custody not backed by the account).
            self.record_read_error("custody ledger not backed by contract balance".into());
            return Err(ContractError::Custom(500));
        }
        self.move_real(&contract, &to_addr, amount, contract_balance)?;
        self.set_host_u64(custody_key(from), entry - amount);
        self.set_host_u64(CUSTODY_TOTAL_KEY.to_vec(), total - amount);
        Ok(())
    }

    fn emit_event(&mut self, topic: &[u8], data: &[u8]) {
        self.events.push(ContractEvent {
            address: self.contract,
            topic: topic.to_vec(),
            data: data.to_vec(),
        });
    }

    fn storage_get(&self, key: &[u8]) -> Option<Vec<u8>> {
        if key.starts_with(RESERVED_HOST_PREFIX) {
            self.record_read_error("contract accessed the reserved host prefix".into());
            return None;
        }
        if let Some(value) = self.storage_writes.get(key) {
            return Some(value.clone());
        }
        match self.reads.storage(&self.contract, &Self::namespace(key)) {
            Ok(value) => value,
            Err(err) => {
                self.record_read_error(format!("storage read failed: {err}"));
                // Treated as "absent" by the contract; sticky error blocks
                // commit, so absence is never trusted after a failed read.
                None
            }
        }
    }

    fn storage_set(&mut self, key: &[u8], value: &[u8]) {
        if key.starts_with(RESERVED_HOST_PREFIX) {
            // `Host::storage_set` cannot return an error: refuse the write
            // and fail the whole call at commit (sticky error).
            self.record_read_error("contract wrote the reserved host prefix".into());
            return;
        }
        self.storage_writes.insert(key.to_vec(), value.to_vec());
    }
}

// ---------------------------------------------------------------------------
// Native dispatch (canonical path)
// ---------------------------------------------------------------------------

/// Execute one contract entry point natively and commit on success.
///
/// - Contract error ([`ContractError`]) → [`ExecutionError::Contract`],
///   **nothing committed** (the [`ContractHost`] is dropped uncommitted).
/// - Corrupt argument bytes → [`ExecutionError::Contract`] with
///   `InvalidInput`, mirroring what the wasm entry point returns for the same
///   input.
/// - Unknown entry name → [`ExecutionError::Other`].
/// - Contract address without deployed code → [`ExecutionError::Validation`]
///   (nothing runs).
/// - `caller` is trusted as the signer: only call this with a
///   signature-verified caller. Attached `value` is 0 (use
///   [`execute_contract_call_with_value`] for a signed `Call.value`).
/// - On success the overlay is committed and the bincode-encoded Ok result is
///   returned (identical bytes to the wasm path).
pub fn execute_contract_call(
    entry: &str,
    contract: Address,
    caller: Address,
    height: u64,
    timestamp: u64,
    args: &[u8],
    storage: &Storage,
) -> Result<Vec<u8>, ExecutionError> {
    let mut host = ContractHost::new(storage, contract, caller, height, timestamp)?;
    if !host.contract_has_code()? {
        return Err(ExecutionError::Validation(
            "Contract not found: no deployed code at the contract address".to_string(),
        ));
    }
    let out = dispatch_entry(entry, &mut host, args)?;
    let events = host.commit()?;
    log_events(&events);
    Ok(out)
}

/// Standalone (test/offline) native call with a signed attached `value`
/// moved from `caller` to `contract` before the entry point runs.
#[allow(clippy::too_many_arguments)]
pub fn execute_contract_call_with_value(
    entry: &str,
    contract: Address,
    caller: Address,
    height: u64,
    timestamp: u64,
    args: &[u8],
    value: u64,
    storage: &Storage,
) -> Result<Vec<u8>, ExecutionError> {
    let mut host = ContractHost::new(storage, contract, caller, height, timestamp)?;
    if !host.contract_has_code()? {
        return Err(ExecutionError::Validation(
            "Contract not found: no deployed code at the contract address".to_string(),
        ));
    }
    host.attach_value(value)?;
    let out = dispatch_entry(entry, &mut host, args)?;
    let events = host.commit()?;
    log_events(&events);
    Ok(out)
}

/// [`execute_contract_call`] in single-writer mode: reads see `txn`'s
/// earlier writes and a successful call is applied into `txn` (the caller
/// commits). A failed call leaves `txn` untouched.
#[allow(clippy::too_many_arguments)]
pub fn execute_contract_call_in_txn(
    entry: &str,
    contract: Address,
    caller: Address,
    height: u64,
    timestamp: u64,
    args: &[u8],
    value: u64,
    storage: &Storage,
    txn: &WriteTransaction,
) -> Result<(Vec<u8>, Vec<ContractEvent>), ExecutionError> {
    let mut host = ContractHost::new_in_txn(storage, txn, contract, caller, height, timestamp);
    if !host.contract_has_code()? {
        return Err(ExecutionError::Validation(
            "Contract not found: no deployed code at the contract address".to_string(),
        ));
    }
    host.attach_value(value)?;
    let out = dispatch_entry(entry, &mut host, args)?;
    let events = host.commit()?;
    log_events(&events);
    Ok((out, events))
}

/// Decode bincode arguments; failure maps to the same error the wasm entry
/// point reports for corrupt arguments (`InvalidInput`).
fn dec<T: DeserializeOwned>(args: &[u8]) -> Result<T, ExecutionError> {
    bincode::deserialize(args).map_err(|_| ExecutionError::Contract(ContractError::InvalidInput))
}

/// Encode an Ok result exactly like the wasm entry points (`bincode` of the
/// same value; `()` encodes to zero bytes, matching the null success return).
fn enc<T: Serialize>(value: &T) -> Result<Vec<u8>, ExecutionError> {
    bincode::serialize(value).map_err(|err| ExecutionError::Other(format!("encode failed: {err}")))
}

/// Match `entry` against [`ENTRY_POINTS`] and run the typed API.
fn dispatch_entry(
    entry: &str,
    host: &mut ContractHost<'_>,
    args: &[u8],
) -> Result<Vec<u8>, ExecutionError> {
    match entry {
        // --- kovanica-htlc -----------------------------------------------------
        "htlc_create" => {
            let (claimer, amount, hash_lock, expiry): (
                [u8; 32],
                kovanica_common::Amount,
                [u8; 32],
                kovanica_common::Timestamp,
            ) = dec(args)?;
            enc(&Htlc::create(host, claimer, amount, hash_lock, expiry)?)
        }
        "htlc_claim" => {
            let (id, preimage): ([u8; 32], Vec<u8>) = dec(args)?;
            Htlc::claim(host, id, &preimage)?;
            enc(&())
        }
        "htlc_refund" => {
            let id: [u8; 32] = dec(args)?;
            Htlc::refund(host, id)?;
            enc(&())
        }

        // --- kovanica-vault ----------------------------------------------------
        "vault_create" => {
            let (beneficiary, amount, schedule): (
                [u8; 32],
                kovanica_common::Amount,
                kovanica_vault::VestingSchedule,
            ) = dec(args)?;
            enc(&Vault::create(host, beneficiary, amount, schedule)?)
        }
        "vault_claim" => {
            let id: kovanica_vault::VaultId = dec(args)?;
            enc(&Vault::claim(host, id)?)
        }
        "vault_cancel" => {
            let id: kovanica_vault::VaultId = dec(args)?;
            Vault::cancel(host, id)?;
            enc(&())
        }

        // --- kovanica-multisig -------------------------------------------------
        "multisig_create" => {
            let (owners, threshold): (Vec<[u8; 32]>, u32) = dec(args)?;
            enc(&Multisig::create(host, owners, threshold)?)
        }
        "multisig_propose" => {
            let (id, to, amount, data): (
                kovanica_multisig::MultisigId,
                [u8; 32],
                kovanica_common::Amount,
                Vec<u8>,
            ) = dec(args)?;
            enc(&Multisig::propose(host, id, to, amount, data)?)
        }
        "multisig_confirm" => {
            let (id, tx_id): (kovanica_multisig::MultisigId, kovanica_multisig::TxId) = dec(args)?;
            Multisig::confirm(host, id, tx_id)?;
            enc(&())
        }
        "multisig_execute" => {
            let (id, tx_id): (kovanica_multisig::MultisigId, kovanica_multisig::TxId) = dec(args)?;
            Multisig::execute(host, id, tx_id)?;
            enc(&())
        }

        // --- kovanica-token ----------------------------------------------------
        "token_create" => {
            let (name, symbol, decimals, initial_supply): (
                String,
                String,
                u8,
                kovanica_common::Amount,
            ) = dec(args)?;
            Token::create(host, name, symbol, decimals, initial_supply)?;
            enc(&())
        }
        "token_transfer" => {
            let (to, amount): ([u8; 32], kovanica_common::Amount) = dec(args)?;
            Token::transfer(host, to, amount)?;
            enc(&())
        }
        "token_approve" => {
            let (spender, amount): ([u8; 32], kovanica_common::Amount) = dec(args)?;
            Token::approve(host, spender, amount)?;
            enc(&())
        }
        "token_transfer_from" => {
            let (from, to, amount): ([u8; 32], [u8; 32], kovanica_common::Amount) = dec(args)?;
            Token::transfer_from(host, from, to, amount)?;
            enc(&())
        }
        "token_mint" => {
            let (to, amount): ([u8; 32], kovanica_common::Amount) = dec(args)?;
            Token::mint(host, to, amount)?;
            enc(&())
        }
        "token_burn" => {
            let amount: kovanica_common::Amount = dec(args)?;
            Token::burn(host, amount)?;
            enc(&())
        }

        other => Err(ExecutionError::Other(format!(
            "unknown contract entry point: {other}"
        ))),
    }
}

fn log_events(events: &[ContractEvent]) {
    for event in events {
        debug!(
            target: "kovanica-execution",
            topic = %String::from_utf8_lossy(&event.topic),
            data_len = event.data.len(),
            "contract event"
        );
    }
}

// ---------------------------------------------------------------------------
// Wasmi dispatch
// ---------------------------------------------------------------------------

/// Parameters for one wasm contract call. Bundled in a struct because the
/// call has more than the usual number of inputs (clippy
/// `too_many_arguments`).
pub struct WasmCall<'a> {
    /// Raw wasm bytes of the contract (compiled once per runner and cached
    /// under `blake3(wasm)`).
    pub wasm: &'a [u8],
    /// Entry point name — must be one of [`ENTRY_POINTS`].
    pub entry: &'a str,
    /// Contract address the call runs against (storage namespace).
    pub contract: Address,
    /// Caller address (`kovanica_caller`).
    pub caller: Address,
    /// Block height (`kovanica_block_height`).
    pub height: u64,
    /// Timestamp (`kovanica_timestamp`).
    pub timestamp: u64,
    /// Bincode arguments (same encoding as the native path).
    pub args: &'a [u8],
    /// Persistent storage backing the [`ContractHost`].
    pub storage: &'a Storage,
    /// Open write transaction to run in (single-writer mode). `None` runs
    /// standalone with its own read snapshot and its own write commit —
    /// never use `None` while another write transaction is open.
    pub txn: Option<&'a WriteTransaction>,
    /// Signed attached value (`Call.value`), moved caller -> contract before
    /// the entry point runs; `0` when unused.
    pub value: u64,
    /// Gas / memory limits for this call.
    pub config: &'a ExecutionConfig,
}

/// Runs contract entry points, either natively or through the wasmi runtime.
///
/// Holds the compiled-module cache; native calls ignore it (the typed API is
/// linked directly). The dispatch decision is explicit: use
/// [`ContractRunner::execute_contract_call`] for the native path and
/// [`ContractRunner::execute_wasm_call`] for the wasm path — there is no
/// automatic fallback, so a wasm bug cannot silently change ledger behavior.
pub struct ContractRunner {
    runtime: Runtime,
    /// Compiled modules keyed by `blake3(wasm)`.
    ///
    /// Intentionally in-memory only: wasmi 0.40 `Module` has no stable
    /// serialization format, so a disk cache would have to store raw bytes
    /// and recompile, which gives no benefit over the host OS page cache. Revisit
    /// if compile time becomes a bottleneck.
    modules: HashMap<[u8; 32], kovanica_runtime::Module>,
}

impl ContractRunner {
    pub fn new() -> Self {
        Self {
            runtime: Runtime::new(),
            modules: HashMap::new(),
        }
    }

    /// Native dispatch — thin wrapper over [`execute_contract_call`]
    /// (kept so callers can hold a runner instance and share its module
    /// cache across wasm calls).
    // The wrapper deliberately mirrors the free function's fixed 7-argument
    // contract ABI signature; `&self` makes 8 and trips the default lint
    // threshold. Bundling into a struct would duplicate `WasmCall` for a
    // one-line delegation.
    #[allow(clippy::too_many_arguments)]
    pub fn execute_contract_call(
        &self,
        entry: &str,
        contract: Address,
        caller: Address,
        height: u64,
        timestamp: u64,
        args: &[u8],
        storage: &Storage,
    ) -> Result<Vec<u8>, ExecutionError> {
        execute_contract_call(entry, contract, caller, height, timestamp, args, storage)
    }

    /// Validate `wasm_bytes` by compiling them with the same wasmi engine the
    /// interpreter uses, discarding the module.
    ///
    /// Deterministic: the same bytes always give the same result on every node
    /// (the engine is fixed and compilation has no nondeterministic inputs), so
    /// it is safe to gate a consensus rule on this outcome. The module cache is
    /// deliberately not populated — a deployed contract that is never called
    /// should not grow the in-memory cache, and a valid module still compiles
    /// on its first call.
    ///
    /// Used by the activation-gated `Deploy` bytecode check in
    /// [`crate::ExecutionContext`].
    pub fn validate_module(&self, wasm_bytes: &[u8]) -> Result<(), kovanica_runtime::RuntimeError> {
        self.runtime.validate_contract_module(wasm_bytes)
    }

    /// Execute `call.entry` inside the wasm module via [`kovanica_runtime::Runtime`].
    ///
    /// Commit semantics match the native path: the [`ContractHost`] is
    /// committed only when the runtime returns `Ok` (including
    /// `Ok(empty)`); any [`kovanica_runtime::RuntimeError`] — contract rejection,
    /// out of gas, missing export, trap — drops the host uncommitted.
    ///
    /// Returns the output bytes and the emitted events.
    pub fn execute_wasm_call(
        &mut self,
        call: WasmCall<'_>,
    ) -> Result<(Vec<u8>, Vec<ContractEvent>), ExecutionError> {
        let mut gas_used = 0u64;
        self.execute_wasm_call_with_gas(call, &mut gas_used)
    }

    /// Same as [`ContractRunner::execute_wasm_call`], but also reports the
    /// fuel the wasmi store actually consumed into `gas_used`.
    ///
    /// The runtime writes `*gas_used` on every outcome where the interpreter
    /// store was created — success, contract rejection, and out of gas (where
    /// it equals `call.config.gas_limit`). Failures before the interpreter
    /// starts (compilation, value attach) leave it at `0`.
    pub fn execute_wasm_call_with_gas(
        &mut self,
        call: WasmCall<'_>,
        gas_used: &mut u64,
    ) -> Result<(Vec<u8>, Vec<ContractEvent>), ExecutionError> {
        let key = kovanica_common::hash(call.wasm);
        if !self.modules.contains_key(&key) {
            let module = self.runtime.compile(call.wasm)?;
            self.modules.insert(key, module);
        }
        let module = &self.modules[&key];

        let mut host = match call.txn {
            Some(txn) => ContractHost::new_in_txn(
                call.storage,
                txn,
                call.contract,
                call.caller,
                call.height,
                call.timestamp,
            ),
            None => ContractHost::new(
                call.storage,
                call.contract,
                call.caller,
                call.height,
                call.timestamp,
            )?,
        };
        host.attach_value(call.value)?;
        // Runtime errors propagate before `commit` — nothing is persisted.
        // `gas_used` was already written by the runtime on that path.
        let out = self.runtime.execute_with_gas(
            module,
            call.entry,
            call.args,
            call.config,
            &mut host,
            gas_used,
        )?;
        let events = host.commit()?;
        log_events(&events);
        Ok((out, events))
    }
}

impl Default for ContractRunner {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::call_args;
    use kovanica_common::{Amount, ContractError};
    use std::path::{Path, PathBuf};
    use tempfile::TempDir;

    /// Raw storage key of the kovanica-token singleton state (FIXED, see the
    /// kovanica-token header docs).
    const TOKEN_STATE_KEY: &[u8] = b"kvnc/v1/state";

    /// Walk up from this crate's manifest dir to the `[workspace]` Cargo.toml.
    ///
    /// `CARGO_MANIFEST_DIR` is `crates/kovanica-execution`, so a single `.parent()`
    /// would point at `crates/` and place the isolated wasm target dir in an
    /// un-ignored `crates/target/`. The root `target/` is git-ignored.
    pub(crate) fn workspace_root() -> PathBuf {
        let start = Path::new(env!("CARGO_MANIFEST_DIR"));
        let mut dir = start;
        loop {
            if let Ok(text) = std::fs::read_to_string(dir.join("Cargo.toml")) {
                if text.contains("[workspace]") {
                    return dir.to_path_buf();
                }
            }
            match dir.parent() {
                Some(parent) => dir = parent,
                None => return start.to_path_buf(),
            }
        }
    }

    /// Thread-safe build of a contract wasm artifact in an isolated target directory.
    pub(crate) fn build_contract_wasm(contract_pkg: &str) -> Option<Vec<u8>> {
        static BUILD_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
        let _guard = BUILD_LOCK.lock().unwrap();

        let workspace = workspace_root();

        let probe = std::process::Command::new("rustup")
            .args(["target", "list", "--installed"])
            .output();
        let probe = match probe {
            Ok(output) if output.status.success() => output,
            _ => {
                eprintln!("SKIP wasm build for {contract_pkg}: rustup unavailable");
                return None;
            }
        };
        let has_target = String::from_utf8_lossy(&probe.stdout)
            .lines()
            .any(|line| line.trim() == "wasm32-unknown-unknown");
        if !has_target {
            eprintln!(
                "SKIP wasm build for {contract_pkg}: wasm32-unknown-unknown target not installed"
            );
            return None;
        }

        let target_dir = workspace.join("target").join("contract-wasm-e2e");
        let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_string());
        let build = std::process::Command::new(&cargo)
            .current_dir(&workspace)
            .env("CARGO_TARGET_DIR", &target_dir)
            .env("RUSTFLAGS", "-C link-arg=--allow-undefined")
            .args([
                "build",
                "-p",
                contract_pkg,
                "--target",
                "wasm32-unknown-unknown",
                "--release",
            ])
            .output()
            .expect("failed to spawn cargo for the wasm contract build");
        assert!(
            build.status.success(),
            "wasm contract build failed for {contract_pkg}:\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&build.stdout),
            String::from_utf8_lossy(&build.stderr)
        );

        let wasm_file = format!("{}.wasm", contract_pkg.replace('-', "_"));
        let wasm_path = target_dir
            .join("wasm32-unknown-unknown")
            .join("release")
            .join(wasm_file);
        let wasm = std::fs::read(&wasm_path)
            .unwrap_or_else(|err| panic!("built wasm missing at {}: {err}", wasm_path.display()));
        assert!(!wasm.is_empty(), "empty wasm artifact");
        Some(wasm)
    }

    fn open_storage() -> (TempDir, Storage) {
        let dir = tempfile::tempdir().expect("tempdir");
        let storage = Storage::new(dir.path().join("test.redb")).expect("storage");
        (dir, storage)
    }

    fn addr(tag: u8) -> Address {
        Address([tag; 32])
    }

    /// Set the real balance of `address`, keeping any deployed code.
    fn fund(storage: &Storage, address: &Address, balance: u64) {
        let txn = storage.begin_write().expect("write txn");
        let mut account = storage
            .state()
            .get_account_or_default_write(&txn, address)
            .expect("account");
        account.balance = balance;
        storage
            .state()
            .set_account(&txn, address, &account)
            .expect("set_account");
        txn.commit().expect("commit");
    }

    /// Mark `address` as a deployed contract (non-empty code), keeping its
    /// balance. Native dispatch refuses addresses without code.
    fn deploy(storage: &Storage, address: &Address) {
        let txn = storage.begin_write().expect("write txn");
        let mut account = storage
            .state()
            .get_account_or_default_write(&txn, address)
            .expect("account");
        account.code = b"\0asm-test-contract".to_vec();
        account.code_hash = kovanica_common::hash(&account.code);
        storage
            .state()
            .set_account(&txn, address, &account)
            .expect("set_account");
        txn.commit().expect("commit");
    }

    /// Custody balance of `holder` in `contract`'s ledger, read from storage.
    fn custody(storage: &Storage, contract: &Address, holder: &Address) -> u64 {
        let host = ContractHost::new(storage, *contract, addr(0), 0, 0).expect("host");
        host.custody_balance(&holder.0).expect("custody read")
    }

    fn custody_total(storage: &Storage, contract: &Address) -> u64 {
        let host = ContractHost::new(storage, *contract, addr(0), 0, 0).expect("host");
        host.custody_total().expect("custody total read")
    }

    fn native_balance(storage: &Storage, address: &Address) -> u64 {
        let txn = storage.begin_read().expect("read txn");
        storage
            .state()
            .get_account_or_default(&txn, address)
            .expect("account")
            .balance
    }

    /// Read the token singleton straight out of persistent storage (proves
    /// the committed bytes, independent of any dispatch path).
    fn token_state(storage: &Storage, contract: &Address) -> Token {
        let txn = storage.begin_read().expect("read txn");
        let key = kovanica_common::hash(TOKEN_STATE_KEY);
        let raw = storage
            .state()
            .get_storage(&txn, contract, &key)
            .expect("storage read")
            .expect("token singleton state after a successful call");
        bincode::deserialize(&raw).expect("token state deserializes")
    }

    fn token_create_args(supply: Amount) -> Vec<u8> {
        bincode::serialize(&("KUNA Test".to_string(), "TKT".to_string(), 9u8, supply))
            .expect("encode")
    }

    // (a) Native dispatch e2e: create → transfer, persisted across runner
    // instances, namespaced per contract address, contract error commits
    // nothing.
    #[test]
    fn native_token_dispatch_persists_across_runner_instances() {
        let (_dir, storage) = open_storage();
        let creator = addr(1);
        let recipient = addr(2);
        let contract_a = addr(10);
        let contract_b = addr(11);
        deploy(&storage, &contract_a);
        deploy(&storage, &contract_b);
        let create = token_create_args(1_000);

        // Runner instance 1 creates the token under contract A.
        let runner1 = ContractRunner::new();
        runner1
            .execute_contract_call(
                "token_create",
                contract_a,
                creator,
                1,
                1_000,
                &create,
                &storage,
            )
            .expect("token_create");

        // A FRESH runner instance must observe what instance 1 committed —
        // this is the persistence + commit proof.
        let runner2 = ContractRunner::new();
        let transfer = bincode::serialize(&(recipient.0, 400u128)).expect("encode");
        runner2
            .execute_contract_call(
                "token_transfer",
                contract_a,
                creator,
                2,
                1_100,
                &transfer,
                &storage,
            )
            .expect("token_transfer");

        let token = token_state(&storage, &contract_a);
        assert_eq!(token.balances.get(&creator.0), Some(&600));
        assert_eq!(token.balances.get(&recipient.0), Some(&400));
        assert_eq!(token.total_supply, 1_000);
        assert_eq!(token.owner, creator.0);

        // Namespacing: the same entry point under a different contract
        // address starts from a fresh singleton (it would fail with
        // AlreadyExists if state were shared across contracts).
        let runner3 = ContractRunner::new();
        runner3
            .execute_contract_call(
                "token_create",
                contract_b,
                creator,
                3,
                1_200,
                &create,
                &storage,
            )
            .expect("token_create under a second contract address");
        let token_b = token_state(&storage, &contract_b);
        assert_eq!(token_b.balances.get(&creator.0), Some(&1_000));
        // Contract A is untouched by B's writes.
        let token = token_state(&storage, &contract_a);
        assert_eq!(token.balances.get(&creator.0), Some(&600));

        // Contract error ⇒ nothing committed: an above-balance transfer must
        // fail and leave both balances exactly as they were. `creator` holds
        // 600 under contract A, so 700 is above balance.
        let over = bincode::serialize(&(recipient.0, 700u128)).expect("encode");
        let err = runner3
            .execute_contract_call(
                "token_transfer",
                contract_a,
                creator,
                4,
                1_300,
                &over,
                &storage,
            )
            .expect_err("transfer above the balance must fail");
        assert!(
            matches!(
                err,
                ExecutionError::Contract(ContractError::InsufficientBalance)
            ),
            "unexpected error: {err:?}"
        );
        let token = token_state(&storage, &contract_a);
        assert_eq!(token.balances.get(&creator.0), Some(&600));
        assert_eq!(token.balances.get(&recipient.0), Some(&400));
    }

    const PREIMAGE: &[u8] = b"kovanica-preimage";

    fn htlc_create_args(claimer: &Address, amount: u128, expiry: u64) -> Vec<u8> {
        bincode::serialize(&(claimer.0, amount, kovanica_common::hash(PREIMAGE), expiry))
            .expect("encode")
    }

    /// Deploy the HTLC contract, fund `sender`, create a 500 swap expiring at
    /// t=1000 (created at t=100). Returns the swap id and escrow address.
    fn setup_htlc(
        storage: &Storage,
        contract: &Address,
        sender: &Address,
        claimer: &Address,
    ) -> ([u8; 32], Address) {
        deploy(storage, contract);
        fund(storage, sender, 1_000);
        let out = execute_contract_call_with_value(
            "htlc_create",
            *contract,
            *sender,
            1,
            100,
            &htlc_create_args(claimer, 500, 1_000),
            500,
            storage,
        )
        .expect("htlc_create");
        let id: [u8; 32] = bincode::deserialize(&out).expect("swap id");
        (id, Address(kovanica_htlc::escrow_address(&id)))
    }

    // (b) HTLC create → claim through host custody. The create approval pulls
    // exactly the signed 500 from the signer into the contract's account and
    // books it under the escrow address; the escrow's REAL balance stays 0.
    #[test]
    fn htlc_create_claim_moves_funds_through_custody() {
        let (_dir, storage) = open_storage();
        let (sender, claimer, contract) = (addr(1), addr(2), addr(20));
        let (id, escrow) = setup_htlc(&storage, &contract, &sender, &claimer);

        assert_eq!(native_balance(&storage, &sender), 500);
        assert_eq!(native_balance(&storage, &contract), 500);
        assert_eq!(
            native_balance(&storage, &escrow),
            0,
            "escrow real balance is 0"
        );
        assert_eq!(custody(&storage, &contract, &escrow), 500);
        assert_eq!(custody_total(&storage, &contract), 500);

        let claim = bincode::serialize(&(id, PREIMAGE.to_vec())).expect("encode");
        execute_contract_call("htlc_claim", contract, claimer, 2, 500, &claim, &storage)
            .expect("htlc_claim");
        assert_eq!(native_balance(&storage, &claimer), 500);
        assert_eq!(native_balance(&storage, &contract), 0);
        assert_eq!(native_balance(&storage, &sender), 500);
        assert_eq!(custody(&storage, &contract, &escrow), 0);
        assert_eq!(custody_total(&storage, &contract), 0);

        // Double claim is rejected and moves nothing.
        let again =
            execute_contract_call("htlc_claim", contract, claimer, 3, 600, &claim, &storage)
                .expect_err("double claim must fail");
        assert!(
            matches!(again, ExecutionError::Contract(ContractError::InvalidInput)),
            "{again:?}"
        );
        assert_eq!(native_balance(&storage, &claimer), 500);
        assert_eq!(custody_total(&storage, &contract), 0);
    }

    #[test]
    fn htlc_refund_returns_custody_to_sender() {
        let (_dir, storage) = open_storage();
        let (sender, claimer, contract) = (addr(1), addr(2), addr(20));
        let (id, escrow) = setup_htlc(&storage, &contract, &sender, &claimer);
        let refund = bincode::serialize(&id).expect("encode");

        // Early refund is rejected and leaves the ledger untouched.
        let early =
            execute_contract_call("htlc_refund", contract, sender, 2, 999, &refund, &storage)
                .expect_err("refund before expiry");
        assert!(
            matches!(early, ExecutionError::Contract(ContractError::NotExpired)),
            "{early:?}"
        );
        assert_eq!(custody(&storage, &contract, &escrow), 500);
        assert_eq!(native_balance(&storage, &sender), 500);

        // Anyone may trigger the refund after expiry; funds go to the sender.
        execute_contract_call(
            "htlc_refund",
            contract,
            addr(9),
            3,
            1_000,
            &refund,
            &storage,
        )
        .expect("refund after expiry");
        assert_eq!(native_balance(&storage, &sender), 1_000);
        assert_eq!(native_balance(&storage, &contract), 0);
        assert_eq!(custody(&storage, &contract, &escrow), 0);
        assert_eq!(custody_total(&storage, &contract), 0);
    }

    #[test]
    fn vault_create_claim_cancel_through_custody() {
        let (_dir, storage) = open_storage();
        let (creator, beneficiary, contract) = (addr(1), addr(2), addr(21));
        deploy(&storage, &contract);
        fund(&storage, &creator, 1_000);

        let schedule = kovanica_vault::VestingSchedule::Linear {
            start: 100,
            end: 200,
            cliff: None,
        };
        let create = bincode::serialize(&(beneficiary.0, 1_000u128, schedule)).expect("encode");
        let out = execute_contract_call_with_value(
            "vault_create",
            contract,
            creator,
            1,
            50,
            &create,
            1_000,
            &storage,
        )
        .expect("vault_create");
        let id: kovanica_vault::VaultId = bincode::deserialize(&out).expect("vault id");
        let escrow = Address(kovanica_vault::escrow_address(&id));
        assert_eq!(native_balance(&storage, &creator), 0);
        assert_eq!(native_balance(&storage, &contract), 1_000);
        assert_eq!(native_balance(&storage, &escrow), 0);
        assert_eq!(custody(&storage, &contract, &escrow), 1_000);

        // Half vested at t=150.
        let id_args = bincode::serialize(&id).expect("encode");
        let out = execute_contract_call(
            "vault_claim",
            contract,
            beneficiary,
            2,
            150,
            &id_args,
            &storage,
        )
        .expect("vault_claim");
        let claimed: Amount = bincode::deserialize(&out).expect("claimed");
        assert_eq!(claimed, 500);
        assert_eq!(native_balance(&storage, &beneficiary), 500);
        assert_eq!(custody(&storage, &contract, &escrow), 500);

        // Creator cancels and reclaims the unclaimed rest.
        execute_contract_call(
            "vault_cancel",
            contract,
            creator,
            3,
            160,
            &id_args,
            &storage,
        )
        .expect("vault_cancel");
        assert_eq!(native_balance(&storage, &creator), 500);
        assert_eq!(native_balance(&storage, &contract), 0);
        assert_eq!(custody(&storage, &contract, &escrow), 0);
        assert_eq!(custody_total(&storage, &contract), 0);
    }

    // Own spends can never dip into custody.
    #[test]
    fn own_spend_cannot_touch_custody() {
        let (_dir, storage) = open_storage();
        let (sender, claimer, contract) = (addr(1), addr(2), addr(20));
        setup_htlc(&storage, &contract, &sender, &claimer);
        // Contract now holds 500 custody; add 100 of its own funds.
        fund(&storage, &contract, 600);

        let mut host = ContractHost::new(&storage, contract, addr(5), 2, 200).expect("host");
        assert_eq!(
            host.transfer(&contract.0, &addr(6).0, 101),
            Err(ContractError::InsufficientBalance)
        );
        host.transfer(&contract.0, &addr(6).0, 100)
            .expect("own funds spendable");
        host.commit().expect("commit");
        assert_eq!(native_balance(&storage, &contract), 500);
        assert_eq!(custody_total(&storage, &contract), 500);
    }

    // Contract B cannot release contract A's custody.
    #[test]
    fn contract_cannot_release_another_contracts_custody() {
        let (_dir, storage) = open_storage();
        let (sender, claimer, contract_a) = (addr(1), addr(2), addr(20));
        let contract_b = addr(22);
        let attacker = addr(3);
        let (_id, escrow) = setup_htlc(&storage, &contract_a, &sender, &claimer);

        let mut host = ContractHost::new(&storage, contract_b, attacker, 2, 200).expect("host");
        assert_eq!(
            host.transfer(&escrow.0, &attacker.0, 500),
            Err(ContractError::Unauthorized)
        );
        drop(host);
        assert_eq!(custody(&storage, &contract_a, &escrow), 500);
        assert_eq!(native_balance(&storage, &contract_a), 500);
        assert_eq!(native_balance(&storage, &attacker), 0);
    }

    // Contracts cannot forge or read the custody ledger.
    #[test]
    fn reserved_host_prefix_is_inaccessible_to_contracts() {
        let (_dir, storage) = open_storage();
        let contract = addr(20);
        let escrow = addr(7);

        let mut host = ContractHost::new(&storage, contract, addr(1), 1, 100).expect("host");
        host.storage_set(&custody_key(&escrow.0), &1_000u64.to_le_bytes());
        host.storage_set(b"ordinary", b"value");
        let err = host.commit().expect_err("reserved write fails the call");
        assert!(matches!(err, ExecutionError::Other(_)), "{err:?}");
        assert_eq!(custody(&storage, &contract, &escrow), 0);
        let txn = storage.begin_read().expect("read");
        assert_eq!(
            storage
                .state()
                .get_storage(&txn, &contract, &kovanica_common::hash(b"ordinary"))
                .expect("read"),
            None,
            "nothing of the failed call is committed"
        );
        drop(txn);

        let host = ContractHost::new(&storage, contract, addr(1), 1, 100).expect("host");
        assert_eq!(host.storage_get(CUSTODY_TOTAL_KEY), None);
        assert!(host.commit().is_err(), "reserved read fails the call");
    }

    // A failed call leaves the custody ledger and balances untouched.
    #[test]
    fn failed_create_commits_no_custody() {
        let (_dir, storage) = open_storage();
        let (sender, claimer, contract) = (addr(1), addr(2), addr(20));
        deploy(&storage, &contract);
        fund(&storage, &sender, 100);

        // Attached value above the sender's balance.
        let err = execute_contract_call_with_value(
            "htlc_create",
            contract,
            sender,
            1,
            100,
            &htlc_create_args(&claimer, 500, 1_000),
            500,
            &storage,
        )
        .expect_err("insufficient balance");
        assert!(
            matches!(
                err,
                ExecutionError::Contract(ContractError::InsufficientBalance)
            ),
            "{err:?}"
        );
        assert_eq!(native_balance(&storage, &sender), 100);
        assert_eq!(native_balance(&storage, &contract), 0);
        assert_eq!(custody_total(&storage, &contract), 0);

        // A pull followed by a dropped (uncommitted) host persists nothing.
        fund(&storage, &sender, 1_000);
        let mut host = ContractHost::new(&storage, contract, sender, 1, 100).expect("host");
        host.attach_value(500).expect("attach");
        host.transfer(&sender.0, &addr(7).0, 500).expect("pull");
        drop(host);
        assert_eq!(native_balance(&storage, &sender), 1_000);
        assert_eq!(custody_total(&storage, &contract), 0);
    }

    // Attached value: up to the signed value, signer only, custody only.
    #[test]
    fn attached_value_bounds_custody_pulls() {
        let (_dir, storage) = open_storage();
        let (signer, other, contract, escrow) = (addr(1), addr(2), addr(20), addr(7));
        fund(&storage, &signer, 1_000);
        fund(&storage, &other, 1_000);

        let mut host = ContractHost::new(&storage, contract, signer, 1, 100).expect("host");
        host.attach_value(500).expect("attach");
        // Above the attached value is rejected.
        assert_eq!(
            host.transfer(&signer.0, &escrow.0, 501),
            Err(ContractError::Unauthorized)
        );
        // Not from a non-signer.
        assert_eq!(
            host.transfer(&other.0, &escrow.0, 100),
            Err(ContractError::Unauthorized)
        );
        // Not into the contract's own funds or back to the caller.
        assert_eq!(
            host.transfer(&signer.0, &contract.0, 100),
            Err(ContractError::Unauthorized)
        );
        assert_eq!(
            host.transfer(&signer.0, &signer.0, 100),
            Err(ContractError::Unauthorized)
        );
        // Partial pulls up to the attached value …
        host.transfer(&signer.0, &escrow.0, 300).expect("pull 300");
        host.transfer(&signer.0, &escrow.0, 200).expect("pull 200");
        // … and no more.
        assert_eq!(
            host.transfer(&signer.0, &escrow.0, 1),
            Err(ContractError::Unauthorized)
        );
        host.commit().expect("commit");

        // Exactly the value moved; it sits in custody, not in escrow's account.
        assert_eq!(native_balance(&storage, &signer), 500);
        assert_eq!(native_balance(&storage, &escrow), 0);
        assert_eq!(native_balance(&storage, &contract), 500);
        assert_eq!(custody(&storage, &contract, &escrow), 500);
        assert_eq!(native_balance(&storage, &other), 1_000);
    }

    // Old behaviour: htlc_create args alone authorised pulling the caller's
    // funds. Without attached value the caller is not spendable.
    #[test]
    fn create_without_value_cannot_pull_caller_funds() {
        let (_dir, storage) = open_storage();
        let (sender, claimer, contract) = (addr(1), addr(2), addr(20));
        deploy(&storage, &contract);
        fund(&storage, &sender, 1_000);
        let err = execute_contract_call(
            "htlc_create",
            contract,
            sender,
            1,
            100,
            &htlc_create_args(&claimer, 500, 1_000),
            &storage,
        )
        .expect_err("no attached value");
        assert!(
            matches!(err, ExecutionError::Contract(ContractError::Unauthorized)),
            "{err:?}"
        );
        assert_eq!(native_balance(&storage, &sender), 1_000);
        assert_eq!(custody_total(&storage, &contract), 0);
    }

    // Value larger than the create amount: the rest stays as contract funds.
    #[test]
    fn surplus_value_stays_with_contract() {
        let (_dir, storage) = open_storage();
        let (sender, claimer, contract) = (addr(1), addr(2), addr(20));
        deploy(&storage, &contract);
        fund(&storage, &sender, 1_000);
        execute_contract_call_with_value(
            "htlc_create",
            contract,
            sender,
            1,
            100,
            &htlc_create_args(&claimer, 500, 1_000),
            600,
            &storage,
        )
        .expect("create");
        assert_eq!(native_balance(&storage, &sender), 400);
        assert_eq!(native_balance(&storage, &contract), 600);
        assert_eq!(custody_total(&storage, &contract), 500);
    }

    #[test]
    fn native_dispatch_rejects_contract_without_code() {
        let (_dir, storage) = open_storage();
        let (victim, attacker) = (addr(1), addr(3));
        fund(&storage, &victim, 1_000);

        // Naming a user account as "contract" (e.g. to run multisig_execute
        // against its own balance) must fail before anything runs.
        let args = bincode::serialize(&(vec![attacker.0], 1u32)).expect("encode");
        let err =
            execute_contract_call("multisig_create", victim, attacker, 1, 100, &args, &storage)
                .expect_err("no deployed code");
        assert!(matches!(err, ExecutionError::Validation(_)), "{err:?}");
        assert_eq!(native_balance(&storage, &victim), 1_000);
        let txn = storage.begin_read().expect("read");
        assert_eq!(
            storage
                .state()
                .get_account_or_default(&txn, &victim)
                .expect("account")
                .code,
            Vec::<u8>::new()
        );
    }

    // Regression: a contract could move funds out of ANY account through
    // `Host::transfer`. Draining a third party's account must fail with
    // `Unauthorized` and leave every balance unchanged, even after commit.
    #[test]
    fn contract_cannot_drain_foreign_account() {
        let (_dir, storage) = open_storage();
        let victim = addr(1);
        let caller = addr(2);
        let attacker = addr(3);
        let contract = addr(20);
        fund(&storage, &victim, 1_000);
        fund(&storage, &caller, 1_000);
        fund(&storage, &contract, 50);

        let mut host = ContractHost::new(&storage, contract, caller, 1, 100).expect("host");
        assert_eq!(
            host.transfer(&victim.0, &attacker.0, 1_000),
            Err(ContractError::Unauthorized),
            "third-party account must not be spendable"
        );
        assert_eq!(
            host.transfer(&caller.0, &attacker.0, 1_000),
            Err(ContractError::Unauthorized),
            "the caller's account is not implicitly approved either"
        );
        // The overlay was not touched by the rejected transfers.
        assert_eq!(host.balance_of(&victim.0), 1_000);
        assert_eq!(host.balance_of(&caller.0), 1_000);
        assert_eq!(host.balance_of(&attacker.0), 0);
        host.commit().expect("commit");

        assert_eq!(native_balance(&storage, &victim), 1_000);
        assert_eq!(native_balance(&storage, &caller), 1_000);
        assert_eq!(native_balance(&storage, &attacker), 0);
        assert_eq!(native_balance(&storage, &contract), 50);
    }

    // The contract may still spend its own balance (multisig payout path).
    #[test]
    fn contract_can_spend_own_account() {
        let (_dir, storage) = open_storage();
        let caller = addr(2);
        let recipient = addr(4);
        let contract = addr(20);
        fund(&storage, &contract, 500);

        let mut host = ContractHost::new(&storage, contract, caller, 1, 100).expect("host");
        host.transfer(&contract.0, &recipient.0, 200)
            .expect("own funds are spendable");
        assert_eq!(
            host.transfer(&contract.0, &recipient.0, 1_000),
            Err(ContractError::InsufficientBalance)
        );
        host.commit().expect("commit");

        assert_eq!(native_balance(&storage, &contract), 300);
        assert_eq!(native_balance(&storage, &recipient), 200);
    }

    // Every advertised entry point reaches the dispatcher: with an empty
    // argument buffer each one fails during argument decoding (InvalidInput),
    // never with "unknown entry point". This pins the native table to the
    // 16 names of the FIXED ABI.
    #[test]
    fn dispatch_covers_all_16_entry_points() {
        let (_dir, storage) = open_storage();
        let contract = addr(30);
        let caller = addr(1);
        deploy(&storage, &contract);
        assert_eq!(ENTRY_POINTS.len(), 16);
        assert_eq!(
            ENTRY_POINTS.iter().filter(|e| is_entry_point(e)).count(),
            16
        );
        for entry in ENTRY_POINTS {
            let err = execute_contract_call(entry, contract, caller, 1, 100, &[], &storage)
                .expect_err("empty arguments must fail decoding");
            assert!(
                matches!(err, ExecutionError::Contract(ContractError::InvalidInput)),
                "entry {entry}: unexpected error {err:?}"
            );
        }
        let err = execute_contract_call("does_not_exist", contract, caller, 1, 100, &[], &storage)
            .expect_err("unknown entry point");
        assert!(matches!(err, ExecutionError::Other(_)), "{err:?}");
        assert!(!is_entry_point("does_not_exist"));
    }

    // (d) Wasmi e2e: build kovanica-token for wasm32 inside the test (isolated
    // CARGO_TARGET_DIR), run token_create + token_transfer through the real
    // Runtime → env imports → ContractHost path, then prove the committed
    // bytes with the native path over the same storage.
    //
    // Skips gracefully (eprintln + return) when rustup or the wasm32 target
    // is unavailable; once the target is confirmed, a build failure is a real
    // failure and fails the test.
    //
    // NOTE (Lane 3a integration gap, out of this lane's scope): the `env`
    // externs in `kovanica-common/src/wasm.rs` are declared without
    // `#[link(wasm_import_module = "env")]`, so a plain `cargo build
    // --target wasm32-unknown-unknown` fails at link time with "undefined
    // symbol: kovanica_caller" (rust-lld does not auto-import bare externs).
    // The test works around it with `-C link-arg=--allow-undefined`, which
    // imports the undefined symbols from the default wasm module — `env` —
    // producing the exact import section the ABI requires (verified).
    // `cargo check --target wasm32-unknown-unknown` passes either way because
    // check does not link; the durable fix belongs in kovanica-common.
    #[test]
    fn wasmi_e2e_kovanica_token_wasm() {
        let wasm = match build_contract_wasm("kovanica-token") {
            Some(w) => w,
            None => return,
        };

        let (_dir, storage) = open_storage();
        let creator = addr(1);
        let recipient = addr(2);
        let contract = addr(40);
        deploy(&storage, &contract);
        let config = ExecutionConfig {
            gas_limit: 100_000_000,
            memory_limit_pages: DEFAULT_CONTRACT_MEMORY_PAGES,
        };
        let mut runner = ContractRunner::new();

        // wasm path: create + transfer through the real env imports.
        let create = token_create_args(1_000);
        runner
            .execute_wasm_call(WasmCall {
                wasm: &wasm,
                entry: "token_create",
                contract,
                caller: creator,
                height: 1,
                timestamp: 1_000,
                args: &create,
                storage: &storage,
                txn: None,
                value: 0,
                config: &config,
            })
            .expect("wasm token_create");

        let transfer = bincode::serialize(&(recipient.0, 400u128)).expect("encode");
        runner
            .execute_wasm_call(WasmCall {
                wasm: &wasm,
                entry: "token_transfer",
                contract,
                caller: creator,
                height: 2,
                timestamp: 1_100,
                args: &transfer,
                storage: &storage,
                txn: None,
                value: 0,
                config: &config,
            })
            .expect("wasm token_transfer");

        // The wasm guest's kovanica_storage_set calls must have committed into
        // the namespaced table of THIS contract address.
        let token = token_state(&storage, &contract);
        assert_eq!(token.balances.get(&creator.0), Some(&600));
        assert_eq!(token.balances.get(&recipient.0), Some(&400));
        assert_eq!(token.owner, creator.0);

        // Cross-path interop: native dispatch reads and updates the exact
        // state the wasm path wrote.
        let native_transfer = bincode::serialize(&(recipient.0, 100u128)).expect("encode");
        execute_contract_call(
            "token_transfer",
            contract,
            creator,
            3,
            1_200,
            &native_transfer,
            &storage,
        )
        .expect("native token_transfer over wasm-written state");
        let token = token_state(&storage, &contract);
        assert_eq!(token.balances.get(&creator.0), Some(&500));
        assert_eq!(token.balances.get(&recipient.0), Some(&500));
    }

    /// Helper to assert contract errors across both native and wasmi dispatch.
    fn assert_contract_err(err: &ExecutionError, expected: ContractError) {
        match err {
            ExecutionError::Runtime(kovanica_runtime::RuntimeError::Contract(code)) => {
                assert_eq!(
                    *code,
                    expected.code(),
                    "expected error code {}, got {}",
                    expected.code(),
                    code
                );
            }
            ExecutionError::Contract(c) => {
                assert_eq!(c, &expected);
            }
            other => panic!("expected contract error {expected:?}, got {other:?}"),
        }
    }

    #[test]
    fn wasmi_e2e_kovanica_htlc_wasm() {
        let wasm = match build_contract_wasm("kovanica-htlc") {
            Some(w) => w,
            None => return,
        };
        let (_dir, storage) = open_storage();
        let sender = addr(1);
        let claimer = addr(2);
        let third_party = addr(3);
        let contract = addr(41);
        deploy(&storage, &contract);
        fund(&storage, &sender, 5_000);
        let config = ExecutionConfig {
            gas_limit: 100_000_000,
            memory_limit_pages: DEFAULT_CONTRACT_MEMORY_PAGES,
        };
        let mut runner = ContractRunner::new();

        let preimage = b"my_preimage_for_htlc_swap";
        let hash_lock = kovanica_common::hash(preimage);
        let expiry = 1_000u64;

        // 1. Successful create via wasm with attached value 1_000
        let create_args = call_args::encode_htlc_create(claimer.0, 1_000, hash_lock, expiry)
            .expect("encode create");
        let (out, _) = runner
            .execute_wasm_call(WasmCall {
                wasm: &wasm,
                entry: "htlc_create",
                contract,
                caller: sender,
                height: 1,
                timestamp: 100,
                args: &create_args,
                storage: &storage,
                txn: None,
                value: 1_000,
                config: &config,
            })
            .expect("wasm htlc_create");
        let id: [u8; 32] = bincode::deserialize(&out).expect("swap id");
        let escrow = Address(kovanica_htlc::escrow_address(&id));

        assert_eq!(native_balance(&storage, &sender), 4_000);
        assert_eq!(native_balance(&storage, &contract), 1_000);
        assert_eq!(custody(&storage, &contract, &escrow), 1_000);

        // 2. Failure case: duplicate create must fail (AlreadyExists)
        let dup_err = runner
            .execute_wasm_call(WasmCall {
                wasm: &wasm,
                entry: "htlc_create",
                contract,
                caller: sender,
                height: 2,
                timestamp: 105,
                args: &create_args,
                storage: &storage,
                txn: None,
                value: 1_000,
                config: &config,
            })
            .expect_err("duplicate create must fail");
        assert_contract_err(&dup_err, ContractError::AlreadyExists);
        assert_eq!(native_balance(&storage, &sender), 4_000);

        // 3. Failure case: claim by unauthorized caller (not claimer)
        let claim_args = call_args::encode_htlc_claim(id, preimage).expect("encode claim");
        let unauth_err = runner
            .execute_wasm_call(WasmCall {
                wasm: &wasm,
                entry: "htlc_claim",
                contract,
                caller: third_party,
                height: 3,
                timestamp: 200,
                args: &claim_args,
                storage: &storage,
                txn: None,
                value: 0,
                config: &config,
            })
            .expect_err("unauthorized claimer must fail");
        assert_contract_err(&unauth_err, ContractError::Unauthorized);

        // 4. Failure case: claim with wrong preimage
        let bad_claim_args =
            call_args::encode_htlc_claim(id, b"wrong_preimage").expect("encode claim");
        let mismatch_err = runner
            .execute_wasm_call(WasmCall {
                wasm: &wasm,
                entry: "htlc_claim",
                contract,
                caller: claimer,
                height: 4,
                timestamp: 200,
                args: &bad_claim_args,
                storage: &storage,
                txn: None,
                value: 0,
                config: &config,
            })
            .expect_err("wrong preimage must fail");
        assert_contract_err(&mismatch_err, ContractError::HashMismatch);

        // 5. Failure case: refund before expiry
        let refund_args = call_args::encode_htlc_refund(id).expect("encode refund");
        let not_exp_err = runner
            .execute_wasm_call(WasmCall {
                wasm: &wasm,
                entry: "htlc_refund",
                contract,
                caller: sender,
                height: 5,
                timestamp: 500, // < expiry (1000)
                args: &refund_args,
                storage: &storage,
                txn: None,
                value: 0,
                config: &config,
            })
            .expect_err("refund before expiry must fail");
        assert_contract_err(&not_exp_err, ContractError::NotExpired);

        // 6. Successful claim by claimer before expiry
        runner
            .execute_wasm_call(WasmCall {
                wasm: &wasm,
                entry: "htlc_claim",
                contract,
                caller: claimer,
                height: 6,
                timestamp: 500,
                args: &claim_args,
                storage: &storage,
                txn: None,
                value: 0,
                config: &config,
            })
            .expect("wasm htlc_claim");
        assert_eq!(native_balance(&storage, &claimer), 1_000);
        assert_eq!(native_balance(&storage, &contract), 0);
        assert_eq!(custody_total(&storage, &contract), 0);

        // 7. Failure case: claim already claimed
        let claimed_err = runner
            .execute_wasm_call(WasmCall {
                wasm: &wasm,
                entry: "htlc_claim",
                contract,
                caller: claimer,
                height: 7,
                timestamp: 550,
                args: &claim_args,
                storage: &storage,
                txn: None,
                value: 0,
                config: &config,
            })
            .expect_err("double claim must fail");
        assert_contract_err(&claimed_err, ContractError::InvalidInput);

        // 8. Test refund path: create swap2, expire it, refund it
        let create_args2 =
            call_args::encode_htlc_create(claimer.0, 500, hash_lock, 800).expect("encode create2");
        let (out2, _) = runner
            .execute_wasm_call(WasmCall {
                wasm: &wasm,
                entry: "htlc_create",
                contract,
                caller: sender,
                height: 8,
                timestamp: 600,
                args: &create_args2,
                storage: &storage,
                txn: None,
                value: 500,
                config: &config,
            })
            .expect("wasm htlc_create2");
        let id2: [u8; 32] = bincode::deserialize(&out2).expect("swap id2");
        assert_eq!(native_balance(&storage, &sender), 3_500);

        // Claim at t >= expiry (800) fails with Expired
        let claim_args2 = call_args::encode_htlc_claim(id2, preimage).expect("encode claim2");
        let exp_err = runner
            .execute_wasm_call(WasmCall {
                wasm: &wasm,
                entry: "htlc_claim",
                contract,
                caller: claimer,
                height: 9,
                timestamp: 850,
                args: &claim_args2,
                storage: &storage,
                txn: None,
                value: 0,
                config: &config,
            })
            .expect_err("expired claim must fail");
        assert_contract_err(&exp_err, ContractError::Expired);

        // Refund after expiry succeeds (triggered by third party, funds return to sender)
        let refund_args2 = call_args::encode_htlc_refund(id2).expect("encode refund2");
        runner
            .execute_wasm_call(WasmCall {
                wasm: &wasm,
                entry: "htlc_refund",
                contract,
                caller: third_party,
                height: 10,
                timestamp: 850,
                args: &refund_args2,
                storage: &storage,
                txn: None,
                value: 0,
                config: &config,
            })
            .expect("wasm htlc_refund");
        assert_eq!(native_balance(&storage, &sender), 4_000);
        assert_eq!(custody_total(&storage, &contract), 0);
    }

    #[test]
    fn wasmi_e2e_kovanica_vault_wasm() {
        let wasm = match build_contract_wasm("kovanica-vault") {
            Some(w) => w,
            None => return,
        };
        let (_dir, storage) = open_storage();
        let creator = addr(1);
        let beneficiary = addr(2);
        let third_party = addr(3);
        let contract = addr(42);
        deploy(&storage, &contract);
        fund(&storage, &creator, 10_000);
        let config = ExecutionConfig {
            gas_limit: 100_000_000,
            memory_limit_pages: DEFAULT_CONTRACT_MEMORY_PAGES,
        };
        let mut runner = ContractRunner::new();

        let schedule = kovanica_vault::VestingSchedule::Linear {
            start: 1_000,
            end: 3_000,
            cliff: None,
        };

        // 1. Successful vault_create via wasm with attached value 2_000
        let create_args =
            call_args::encode_vault_create(beneficiary.0, 2_000, &schedule).expect("encode create");
        let (out, _) = runner
            .execute_wasm_call(WasmCall {
                wasm: &wasm,
                entry: "vault_create",
                contract,
                caller: creator,
                height: 1,
                timestamp: 500,
                args: &create_args,
                storage: &storage,
                txn: None,
                value: 2_000,
                config: &config,
            })
            .expect("wasm vault_create");
        let id: kovanica_vault::VaultId = bincode::deserialize(&out).expect("vault id");
        let escrow = Address(kovanica_vault::escrow_address(&id));

        assert_eq!(native_balance(&storage, &creator), 8_000);
        assert_eq!(native_balance(&storage, &contract), 2_000);
        assert_eq!(custody(&storage, &contract, &escrow), 2_000);

        // 2. Failure case: claim by third party (not beneficiary) -> Unauthorized
        let claim_args = call_args::encode_vault_claim(id).expect("encode claim");
        let unauth_err = runner
            .execute_wasm_call(WasmCall {
                wasm: &wasm,
                entry: "vault_claim",
                contract,
                caller: third_party,
                height: 2,
                timestamp: 2_000,
                args: &claim_args,
                storage: &storage,
                txn: None,
                value: 0,
                config: &config,
            })
            .expect_err("unauthorized claim must fail");
        assert_contract_err(&unauth_err, ContractError::Unauthorized);

        // 3. Claim before vesting (timestamp 800 < start 1000) -> returns 0
        let (zero_out, _) = runner
            .execute_wasm_call(WasmCall {
                wasm: &wasm,
                entry: "vault_claim",
                contract,
                caller: beneficiary,
                height: 3,
                timestamp: 800,
                args: &claim_args,
                storage: &storage,
                txn: None,
                value: 0,
                config: &config,
            })
            .expect("claim before start returns 0");
        let claimed_amount: Amount = bincode::deserialize(&zero_out).expect("amount");
        assert_eq!(claimed_amount, 0);
        assert_eq!(native_balance(&storage, &beneficiary), 0);

        // 4. Claim halfway (timestamp 2_000: (2000-1000)/(3000-1000) = 50% = 1_000)
        let (claim_out, _) = runner
            .execute_wasm_call(WasmCall {
                wasm: &wasm,
                entry: "vault_claim",
                contract,
                caller: beneficiary,
                height: 4,
                timestamp: 2_000,
                args: &claim_args,
                storage: &storage,
                txn: None,
                value: 0,
                config: &config,
            })
            .expect("claim halfway");
        let claimed_amount: Amount = bincode::deserialize(&claim_out).expect("amount");
        assert_eq!(claimed_amount, 1_000);
        assert_eq!(native_balance(&storage, &beneficiary), 1_000);
        assert_eq!(native_balance(&storage, &contract), 1_000);
        assert_eq!(custody(&storage, &contract, &escrow), 1_000);

        // 5. Failure case: cancel by non-creator -> Unauthorized
        let cancel_args = call_args::encode_vault_cancel(id).expect("encode cancel");
        let unauth_cancel = runner
            .execute_wasm_call(WasmCall {
                wasm: &wasm,
                entry: "vault_cancel",
                contract,
                caller: beneficiary,
                height: 5,
                timestamp: 2_100,
                args: &cancel_args,
                storage: &storage,
                txn: None,
                value: 0,
                config: &config,
            })
            .expect_err("non-creator cancel must fail");
        assert_contract_err(&unauth_cancel, ContractError::Unauthorized);

        // 6. Creator cancels: remaining 1_000 returns to creator
        runner
            .execute_wasm_call(WasmCall {
                wasm: &wasm,
                entry: "vault_cancel",
                contract,
                caller: creator,
                height: 6,
                timestamp: 2_100,
                args: &cancel_args,
                storage: &storage,
                txn: None,
                value: 0,
                config: &config,
            })
            .expect("vault_cancel");
        assert_eq!(native_balance(&storage, &creator), 9_000);
        assert_eq!(native_balance(&storage, &contract), 0);
        assert_eq!(custody_total(&storage, &contract), 0);

        // 7. Failure case: cancel already cancelled -> InvalidInput
        let dup_cancel = runner
            .execute_wasm_call(WasmCall {
                wasm: &wasm,
                entry: "vault_cancel",
                contract,
                caller: creator,
                height: 7,
                timestamp: 2_200,
                args: &cancel_args,
                storage: &storage,
                txn: None,
                value: 0,
                config: &config,
            })
            .expect_err("double cancel must fail");
        assert_contract_err(&dup_cancel, ContractError::InvalidInput);
    }

    #[test]
    fn wasmi_e2e_kovanica_multisig_wasm() {
        let wasm = match build_contract_wasm("kovanica-multisig") {
            Some(w) => w,
            None => return,
        };
        let (_dir, storage) = open_storage();
        let owner1 = addr(1);
        let owner2 = addr(2);
        let owner3 = addr(3);
        let non_owner = addr(9);
        let recipient = addr(4);
        let contract = addr(43);
        deploy(&storage, &contract);
        fund(&storage, &contract, 50_000); // Multisig contract holds native balance to disburse
        let config = ExecutionConfig {
            gas_limit: 100_000_000,
            memory_limit_pages: DEFAULT_CONTRACT_MEMORY_PAGES,
        };
        let mut runner = ContractRunner::new();

        // 1. Failure case: invalid threshold 0 or > owners.len() -> InvalidInput
        let invalid_create =
            call_args::encode_multisig_create(&[owner1.0, owner2.0], 0).expect("encode");
        let inv_err = runner
            .execute_wasm_call(WasmCall {
                wasm: &wasm,
                entry: "multisig_create",
                contract,
                caller: owner1,
                height: 1,
                timestamp: 100,
                args: &invalid_create,
                storage: &storage,
                txn: None,
                value: 0,
                config: &config,
            })
            .expect_err("threshold 0 must fail");
        assert_contract_err(&inv_err, ContractError::InvalidInput);

        // 2. Successful multisig_create with threshold 2
        let create_args = call_args::encode_multisig_create(&[owner1.0, owner2.0, owner3.0], 2)
            .expect("encode create");
        let (out, _) = runner
            .execute_wasm_call(WasmCall {
                wasm: &wasm,
                entry: "multisig_create",
                contract,
                caller: owner1,
                height: 2,
                timestamp: 100,
                args: &create_args,
                storage: &storage,
                txn: None,
                value: 0,
                config: &config,
            })
            .expect("wasm multisig_create");
        let id: kovanica_multisig::MultisigId = bincode::deserialize(&out).expect("multisig id");

        // 3. Failure case: second create on singleton -> AlreadyExists
        let dup_err = runner
            .execute_wasm_call(WasmCall {
                wasm: &wasm,
                entry: "multisig_create",
                contract,
                caller: owner1,
                height: 3,
                timestamp: 105,
                args: &create_args,
                storage: &storage,
                txn: None,
                value: 0,
                config: &config,
            })
            .expect_err("second create must fail");
        assert_contract_err(&dup_err, ContractError::AlreadyExists);

        // 4. Failure case: propose by non-owner -> Unauthorized
        let prop_args = call_args::encode_multisig_propose(id, recipient.0, 10_000, &[])
            .expect("encode propose");
        let unauth_prop = runner
            .execute_wasm_call(WasmCall {
                wasm: &wasm,
                entry: "multisig_propose",
                contract,
                caller: non_owner,
                height: 4,
                timestamp: 110,
                args: &prop_args,
                storage: &storage,
                txn: None,
                value: 0,
                config: &config,
            })
            .expect_err("non-owner propose must fail");
        assert_contract_err(&unauth_prop, ContractError::Unauthorized);

        // 5. Successful propose by owner1 -> returns tx_id = 1 (proposer auto-confirms, 1 confirmation)
        let (p_out, _) = runner
            .execute_wasm_call(WasmCall {
                wasm: &wasm,
                entry: "multisig_propose",
                contract,
                caller: owner1,
                height: 5,
                timestamp: 120,
                args: &prop_args,
                storage: &storage,
                txn: None,
                value: 0,
                config: &config,
            })
            .expect("wasm multisig_propose");
        let tx_id: kovanica_multisig::TxId = bincode::deserialize(&p_out).expect("tx_id");
        assert_eq!(tx_id, 1);

        // 6. Failure case: execute before threshold reached (1 of 2) -> ThresholdNotMet
        let exec_args = call_args::encode_multisig_execute(id, tx_id).expect("encode exec");
        let th_err = runner
            .execute_wasm_call(WasmCall {
                wasm: &wasm,
                entry: "multisig_execute",
                contract,
                caller: owner1,
                height: 6,
                timestamp: 130,
                args: &exec_args,
                storage: &storage,
                txn: None,
                value: 0,
                config: &config,
            })
            .expect_err("execute before threshold must fail");
        assert_contract_err(&th_err, ContractError::ThresholdNotMet);

        // 7. Failure case: double confirm by proposer -> AlreadyExists
        let conf_args = call_args::encode_multisig_confirm(id, tx_id).expect("encode confirm");
        let dbl_conf = runner
            .execute_wasm_call(WasmCall {
                wasm: &wasm,
                entry: "multisig_confirm",
                contract,
                caller: owner1,
                height: 7,
                timestamp: 140,
                args: &conf_args,
                storage: &storage,
                txn: None,
                value: 0,
                config: &config,
            })
            .expect_err("double confirm must fail");
        assert_contract_err(&dbl_conf, ContractError::AlreadyExists);

        // 8. Confirm by owner2 (now 2 of 2 confirmations)
        runner
            .execute_wasm_call(WasmCall {
                wasm: &wasm,
                entry: "multisig_confirm",
                contract,
                caller: owner2,
                height: 8,
                timestamp: 150,
                args: &conf_args,
                storage: &storage,
                txn: None,
                value: 0,
                config: &config,
            })
            .expect("wasm multisig_confirm");

        // 9. Execute (can be called by any caller)
        runner
            .execute_wasm_call(WasmCall {
                wasm: &wasm,
                entry: "multisig_execute",
                contract,
                caller: non_owner,
                height: 9,
                timestamp: 160,
                args: &exec_args,
                storage: &storage,
                txn: None,
                value: 0,
                config: &config,
            })
            .expect("wasm multisig_execute");
        assert_eq!(native_balance(&storage, &contract), 40_000);
        assert_eq!(native_balance(&storage, &recipient), 10_000);

        // 10. Failure case: execute already executed tx -> InvalidInput
        let dup_exec = runner
            .execute_wasm_call(WasmCall {
                wasm: &wasm,
                entry: "multisig_execute",
                contract,
                caller: owner1,
                height: 10,
                timestamp: 170,
                args: &exec_args,
                storage: &storage,
                txn: None,
                value: 0,
                config: &config,
            })
            .expect_err("re-execute must fail");
        assert_contract_err(&dup_exec, ContractError::InvalidInput);
    }
    // Native path in single-writer mode: reads see uncommitted writes of the
    // outer transaction, and the result is applied into it (no 2nd writer).
    #[test]
    fn native_call_in_txn_sees_outer_writes_and_applies_into_it() {
        let (_dir, storage) = open_storage();
        let caller = addr(1);
        let contract = addr(50);
        deploy(&storage, &contract);
        let txn = storage.begin_write().expect("outer txn");
        // Uncommitted funding, visible only through `txn`.
        storage
            .state()
            .set_account(
                &txn,
                &caller,
                &Account {
                    balance: 700,
                    ..Default::default()
                },
            )
            .expect("fund in txn");
        let args = htlc_create_args(&addr(2), 700, 10_000);
        execute_contract_call_in_txn(
            "htlc_create",
            contract,
            caller,
            1,
            1_000,
            &args,
            700,
            &storage,
            &txn,
        )
        .expect("htlc_create in outer txn");
        // Still inside the same transaction, nothing else opened a writer.
        txn.commit().expect("outer commit");
        assert_eq!(native_balance(&storage, &caller), 0);
        assert_eq!(native_balance(&storage, &contract), 700);
        assert_eq!(custody_total(&storage, &contract), 700);
    }

    // Native path in single-writer mode: a failing call writes nothing.
    #[test]
    fn failed_native_call_in_txn_writes_nothing() {
        let (_dir, storage) = open_storage();
        let caller = addr(1);
        let contract = addr(51);
        deploy(&storage, &contract);
        fund(&storage, &caller, 100);
        let txn = storage.begin_write().expect("outer txn");
        // Attached value exceeds the balance → InsufficientBalance.
        let args = htlc_create_args(&addr(2), 500, 10_000);
        let err = execute_contract_call_in_txn(
            "htlc_create",
            contract,
            caller,
            1,
            1_000,
            &args,
            500,
            &storage,
            &txn,
        )
        .expect_err("must fail");
        assert!(matches!(err, ExecutionError::Contract(_)), "{err:?}");
        txn.commit().expect("outer commit");
        assert_eq!(native_balance(&storage, &caller), 100);
        assert_eq!(native_balance(&storage, &contract), 0);
        assert_eq!(custody_total(&storage, &contract), 0);
    }
    // HTLC and vault create through Call.value in single-writer mode.
    #[test]
    fn htlc_and_vault_create_via_value_in_txn() {
        let (_dir, storage) = open_storage();
        let caller = addr(1);
        let (htlc, vault) = (addr(60), addr(61));
        deploy(&storage, &htlc);
        deploy(&storage, &vault);
        fund(&storage, &caller, 2_000);
        let txn = storage.begin_write().expect("outer txn");
        let args = htlc_create_args(&addr(2), 500, 10_000);
        execute_contract_call_in_txn(
            "htlc_create",
            htlc,
            caller,
            1,
            100,
            &args,
            500,
            &storage,
            &txn,
        )
        .expect("htlc_create");
        let schedule = kovanica_vault::VestingSchedule::Absolute { unlock_at: 1_000 };
        let vargs = bincode::serialize(&(addr(3).0, 700u128, schedule)).expect("encode");
        execute_contract_call_in_txn(
            "vault_create",
            vault,
            caller,
            1,
            100,
            &vargs,
            700,
            &storage,
            &txn,
        )
        .expect("vault_create");
        // Create amount above the attached value: rejected, nothing moved.
        let err = execute_contract_call_in_txn(
            "htlc_create",
            htlc,
            caller,
            1,
            100,
            &htlc_create_args(&addr(4), 500, 10_000),
            499,
            &storage,
            &txn,
        )
        .expect_err("value too small");
        assert!(
            matches!(err, ExecutionError::Contract(ContractError::Unauthorized)),
            "{err:?}"
        );
        txn.commit().expect("commit");
        assert_eq!(native_balance(&storage, &caller), 800);
        assert_eq!(custody_total(&storage, &htlc), 500);
        assert_eq!(custody_total(&storage, &vault), 700);
    }
}
