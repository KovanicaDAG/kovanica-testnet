//! State storage for Kovanica.
//!
//! Stores account balances, nonces, contract code/storage, and staking state.

use crate::{address_to_bytes, BincodeSerialize, StorageError};
use bincode::Options;
use kovanica_staking::{Delegation, StakingState, TreasuryState, ValidatorInfo};
use kovanica_types::hash::Hash;
use kovanica_types::{
    decode_with_version, encode_with_version, Address, Stake, EPOCH_COMMITTEE_VERSION,
};
use redb::{ReadTransaction, ReadableTable, WriteTransaction};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use thiserror::Error;

/// Errors specific to state store operations.
#[derive(Debug, Error)]
pub enum StateStoreError {
    #[error("Account not found: {0}")]
    NotFound(String),
    /// A snapshot payload could not be decoded (bad magic, bad bincode).
    #[error("Snapshot format error: {0}")]
    SnapshotFormat(String),
    /// A snapshot failed verification and was not applied.
    #[error("Snapshot verification failed: {0}")]
    SnapshotVerify(String),
    /// A debit larger than the account balance; nothing was written.
    #[error("Insufficient balance: account {address} has {balance}, debit {amount}")]
    InsufficientBalance {
        /// Account being debited.
        address: String,
        /// Balance before the (rejected) debit.
        balance: u64,
        /// Requested debit.
        amount: u64,
    },
    #[error("Serialization error: {0}")]
    Serialization(#[from] bincode::Error),
    #[error("Database error: {0}")]
    Database(#[from] redb::DatabaseError),
    #[error("Transaction error: {0}")]
    Transaction(#[from] redb::TransactionError),
    #[error("Table error: {0}")]
    Table(#[from] redb::TableError),
    #[error("Commit error: {0}")]
    Commit(#[from] redb::CommitError),
    #[error("Storage error: {0}")]
    Storage(#[from] redb::StorageError),
}

/// Account state in the Kovanica blockchain.
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct Account {
    /// Account balance in base units.
    pub balance: u64,
    /// Transaction nonce (prevents replay).
    pub nonce: u64,
    /// Contract code hash (empty for EOAs).
    pub code_hash: [u8; 32],
    /// Contract code (only for contract accounts).
    pub code: Vec<u8>,
}

/// Configuration for state pruning.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PruningConfig {
    /// Number of recent committed leader heights to keep full state for.
    pub keep_recent: u64,
    /// Maximum number of state roots to keep in history.
    pub max_state_roots: u64,
}

impl Default for PruningConfig {
    fn default() -> Self {
        Self {
            keep_recent: 1000,     // Keep last 1000 committed leaders
            max_state_roots: 2000, // Keep up to 2000 state roots
        }
    }
}

/// Magic prefix of the versioned snapshot byte format.
pub const SNAPSHOT_MAGIC: [u8; 8] = *b"KVSNSP01";

/// Current snapshot format version.
pub const SNAPSHOT_VERSION: u32 = 1;

/// Reserved account-tree address that carries the full-state commitment.
///
/// From `kovanica_types::STATE_COMMITMENT_ACTIVE_FROM_ROUND` the sealed
/// state root is the account tree plus one leaf at this address whose
/// `(balance, nonce)` are two little-endian `u64` words of
/// [`aux_state_leaf`], a 128-bit digest of every snapshot table (the account
/// rows including contract `code_hash`/`code`, contract code, contract
/// storage and staking). A genuine account stored at this address is left out
/// of the tree so the commitment is unambiguous. No key pair maps to it (it
/// is not the address of any public key), so honest accounts are never
/// affected.
pub const AUX_STATE_LEAF_ADDRESS: [u8; 32] = [0xff; 32];

/// Domain tag for [`aux_state_leaf`].
const AUX_STATE_DOMAIN: &[u8] = b"KUNA/aux-state/v1";

/// Digest of the full state as the `(balance, nonce)` pair stored at
/// [`AUX_STATE_LEAF_ADDRESS`].
///
/// The account tree itself only commits balance and nonce. This digest covers
/// what it does not: the raw account rows (so contract `code_hash` and `code`
/// are bound too), contract code, contract storage and staking. Account rows
/// with zero balance, zero nonce and no code are skipped, matching how the
/// tree treats an absent account. A forged staking, contract or account-code
/// row changes the digest, and with it the root a commit-seal quorum signed.
pub fn aux_state_leaf(data: &SnapshotData) -> Result<(u64, u64), StateStoreError> {
    let mut accounts = Vec::with_capacity(data.accounts.len());
    for (key, value) in &data.accounts {
        let account = Account::from_bytes(value)?;
        if account.balance == 0
            && account.nonce == 0
            && account.code.is_empty()
            && account.code_hash == [0u8; 32]
        {
            continue;
        }
        accounts.push((key.clone(), value.clone()));
    }
    let aux = SnapshotData {
        accounts,
        contract_code: data.contract_code.clone(),
        contract_storage: data.contract_storage.clone(),
        staking_state: data.staking_state.clone(),
        ..SnapshotData::default()
    };
    let rows_root = snapshot_state_root(&aux)?;
    let mut preimage = AUX_STATE_DOMAIN.to_vec();
    preimage.extend_from_slice(&rows_root.0);
    let digest = Hash::new(&preimage).0;
    let mut lo = [0u8; 8];
    let mut hi = [0u8; 8];
    lo.copy_from_slice(&digest[..8]);
    hi.copy_from_slice(&digest[8..16]);
    Ok((u64::from_le_bytes(lo), u64::from_le_bytes(hi)))
}

/// Serialized state snapshot: every state table plus the height and state
/// root it was taken at.
///
/// The framing is [`SNAPSHOT_MAGIC`] followed by `bincode` of this struct.
/// Bytes without the magic are read as a legacy (pre-header) payload that
/// decodes to the same tables with `version = 0`, `height = 0` and a zero
/// state root, so an old file still imports through
/// [`StateStore::import_snapshot`] while
/// [`StateStore::import_verified_snapshot`] refuses it (there is nothing to
/// verify).
#[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq, Eq)]
pub struct SnapshotData {
    /// Format version; 0 means a legacy payload without the header.
    pub version: u32,
    /// Committed-leader height the snapshot reflects.
    pub height: u64,
    /// Sorted-KV Merkle root over the tables below.
    pub state_root: [u8; 32],
    /// Accounts table rows: address -> bincode(Account).
    pub accounts: Vec<(Vec<u8>, Vec<u8>)>,
    /// Contract code table rows: code hash -> wasm bytes.
    pub contract_code: Vec<(Vec<u8>, Vec<u8>)>,
    /// Contract storage rows: bincode((address, slot)) -> value.
    pub contract_storage: Vec<(Vec<u8>, Vec<u8>)>,
    /// Staking state rows: key -> bincode(value).
    pub staking_state: Vec<(Vec<u8>, Vec<u8>)>,
    /// Sealed leader header at `height`, if recorded.
    #[serde(default)]
    pub leader_header: Option<kovanica_types::LeaderHeader>,
    /// Commit seals over `leader_header`.
    #[serde(default)]
    pub commit_seals: Vec<kovanica_types::CommitSeal>,
    /// Frozen seal committee for `leader_header.epoch`, if recorded.
    #[serde(default)]
    pub epoch_committee: Option<Vec<kovanica_types::SealCommitteeSnapshotMember>>,
}

/// Result of a successful [`StateStore::import_verified_snapshot`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerifiedSnapshot {
    /// Committed-leader height of the imported state.
    pub height: u64,
    /// `leader_round` of the sealed header that certified the state. It is
    /// covered by the verified commit-seal quorum, unlike any value read back
    /// out of the imported staking rows.
    pub leader_round: u64,
}

/// State store for accounts, contracts, and staking.
pub struct StateStore {
    pruning: PruningConfig,
}

impl StateStore {
    /// Create a new state store, initializing tables if needed.
    pub fn new(db: &redb::Database) -> Result<Self, StorageError> {
        Self::with_pruning(db, PruningConfig::default())
    }

    /// Create a new state store with custom pruning config.
    pub fn with_pruning(db: &redb::Database, pruning: PruningConfig) -> Result<Self, StorageError> {
        let write_txn = db.begin_write().map_err(StorageError::Transaction)?;
        {
            let _ = write_txn.open_table(crate::tables::ACCOUNTS)?;
            let _ = write_txn.open_table(crate::tables::CONTRACT_CODE)?;
            let _ = write_txn.open_table(crate::tables::CONTRACT_STORAGE)?;
            let _ = write_txn.open_table(crate::tables::STAKING_STATE)?;
            let _ = write_txn.open_table(crate::tables::STATE_ROOT)?;
            let _ = write_txn.open_table(crate::tables::LEADER_HEADERS)?;
            let _ = write_txn.open_table(crate::tables::COMMIT_SEALS)?;
            let _ = write_txn.open_table(crate::tables::EXECUTED_TX_HASHES)?;
            let _ = write_txn.open_table(crate::tables::LIGHT_SET)?;
            let _ = write_txn.open_table(crate::tables::GENESIS_DIGEST)?;
        }
        write_txn.commit().map_err(StorageError::Commit)?;
        Ok(Self { pruning })
    }

    // ============================================================
    // Account operations
    /// Get an account by address.
    pub fn get_account(
        &self,
        txn: &ReadTransaction,
        address: &Address,
    ) -> Result<Account, StateStoreError> {
        let key = address_to_bytes(address);
        let table = txn.open_table(crate::tables::ACCOUNTS)?;
        let value = table
            .get(key)?
            .ok_or_else(|| StateStoreError::NotFound(format!("account {}", address)))?;
        Ok(Account::from_bytes(&value.value())?)
    }

    /// Get an account, returning default if not found.
    pub fn get_account_or_default(
        &self,
        txn: &ReadTransaction,
        address: &Address,
    ) -> Result<Account, StateStoreError> {
        let key = address_to_bytes(address);
        let table = txn.open_table(crate::tables::ACCOUNTS)?;
        let value = table.get(key)?;
        Ok(value
            .map(|v| Account::from_bytes(&v.value()).unwrap_or_default())
            .unwrap_or_default())
    }

    /// Get an account, returning default if not found (write transaction variant).
    pub fn get_account_or_default_write(
        &self,
        txn: &WriteTransaction,
        address: &Address,
    ) -> Result<Account, StateStoreError> {
        let key = address_to_bytes(address);
        let table = txn.open_table(crate::tables::ACCOUNTS)?;
        let value = table.get(key)?;
        let account = value
            .map(|v| Account::from_bytes(&v.value()).unwrap_or_default())
            .unwrap_or_default();
        drop(table);
        Ok(account)
    }

    /// Set an account.
    pub fn set_account(
        &self,
        txn: &WriteTransaction,
        address: &Address,
        account: &Account,
    ) -> Result<(), StateStoreError> {
        let key = address_to_bytes(address);
        let mut table = txn.open_table(crate::tables::ACCOUNTS)?;
        table.insert(key, account.to_bytes()?)?;
        Ok(())
    }

    /// Update account balance.
    pub fn add_balance(
        &self,
        txn: &WriteTransaction,
        address: &Address,
        amount: u64,
    ) -> Result<u64, StateStoreError> {
        let key = address_to_bytes(address);
        let table = txn.open_table(crate::tables::ACCOUNTS)?;
        let value = table.get(key)?;
        let mut account = value
            .map(|v| Account::from_bytes(&v.value()).unwrap_or_default())
            .unwrap_or_default();
        drop(table);
        account.balance = account.balance.saturating_add(amount);
        self.set_account(txn, address, &account)?;
        Ok(account.balance)
    }

    /// Subtract `amount` from an existing account's balance and return the
    /// new balance.
    ///
    /// Errors with `NotFound` if the account does not exist and with
    /// `InsufficientBalance` if `amount` exceeds the balance; in both cases
    /// nothing is written. Safe to combine with other table operations in
    /// the same write transaction: the ACCOUNTS table and its read guard
    /// are dropped before the write.
    pub fn sub_balance(
        &self,
        txn: &WriteTransaction,
        address: &Address,
        amount: u64,
    ) -> Result<u64, StateStoreError> {
        let key = address_to_bytes(address);
        let mut account = {
            let table = txn.open_table(crate::tables::ACCOUNTS)?;
            let value = table
                .get(key)?
                .ok_or_else(|| StateStoreError::NotFound(format!("account {}", address)))?;
            Account::from_bytes(&value.value())?
            // `value` (read guard) and `table` are dropped at the end of
            // this block, before `set_account` reopens ACCOUNTS.
        };
        account.balance = account.balance.checked_sub(amount).ok_or_else(|| {
            StateStoreError::InsufficientBalance {
                address: address.to_string(),
                balance: account.balance,
                amount,
            }
        })?;
        self.set_account(txn, address, &account)?;
        Ok(account.balance)
    }

    /// Increment account nonce.
    pub fn increment_nonce(
        &self,
        txn: &WriteTransaction,
        address: &Address,
    ) -> Result<u64, StateStoreError> {
        let key = address_to_bytes(address);
        let table = txn.open_table(crate::tables::ACCOUNTS)?;
        let value = table.get(key)?;
        let mut account = value
            .map(|v| Account::from_bytes(&v.value()).unwrap_or_default())
            .unwrap_or_default();
        drop(table);
        account.nonce = account.nonce.saturating_add(1);
        self.set_account(txn, address, &account)?;
        Ok(account.nonce)
    }

    /// Set account nonce.
    pub fn set_nonce(
        &self,
        txn: &WriteTransaction,
        address: &Address,
        nonce: u64,
    ) -> Result<(), StateStoreError> {
        let key = address_to_bytes(address);
        let table = txn.open_table(crate::tables::ACCOUNTS)?;
        let value = table.get(key)?;
        let mut account = value
            .map(|v| Account::from_bytes(&v.value()).unwrap_or_default())
            .unwrap_or_default();
        drop(table);
        account.nonce = nonce;
        self.set_account(txn, address, &account)?;
        Ok(())
    }

    // ============================================================
    // Contract operations
    // ============================================================

    /// Deploy contract code.
    pub fn deploy_contract(
        &self,
        txn: &WriteTransaction,
        address: &Address,
        code: Vec<u8>,
    ) -> Result<[u8; 32], StateStoreError> {
        // Compute code hash
        let code_hash = blake3::hash(&code);
        let code_hash_bytes: [u8; 32] = code_hash.as_bytes().clone().try_into().unwrap();

        // Store code
        {
            let mut table = txn.open_table(crate::tables::CONTRACT_CODE)?;
            table.insert(code_hash_bytes, code.clone())?;
        }

        // Update account
        let key = address_to_bytes(address);
        let table = txn.open_table(crate::tables::ACCOUNTS)?;
        let value = table.get(key)?;
        let mut account = value
            .map(|v| Account::from_bytes(&v.value()).unwrap_or_default())
            .unwrap_or_default();
        drop(table);
        account.code_hash = code_hash_bytes;
        account.code = code;
        self.set_account(txn, address, &account)?;

        Ok(code_hash_bytes)
    }

    /// Get contract code by hash.
    pub fn get_contract_code(
        &self,
        txn: &ReadTransaction,
        code_hash: &[u8; 32],
    ) -> Result<Option<Vec<u8>>, StateStoreError> {
        let table = txn.open_table(crate::tables::CONTRACT_CODE)?;
        Ok(table.get(*code_hash)?.map(|v| v.value().to_vec()))
    }

    /// Get contract storage value.
    pub fn get_storage(
        &self,
        txn: &ReadTransaction,
        contract: &Address,
        key: &[u8; 32],
    ) -> Result<Option<Vec<u8>>, StateStoreError> {
        let contract_bytes = address_to_bytes(contract);
        let table = txn.open_table(crate::tables::CONTRACT_STORAGE)?;
        Ok(table
            .get((contract_bytes, *key))?
            .map(|v| v.value().to_vec()))
    }

    /// Set contract storage value.
    pub fn set_storage(
        &self,
        txn: &WriteTransaction,
        contract: &Address,
        key: [u8; 32],
        value: Vec<u8>,
    ) -> Result<(), StateStoreError> {
        let contract_bytes = address_to_bytes(contract);
        let mut table = txn.open_table(crate::tables::CONTRACT_STORAGE)?;
        table.insert((contract_bytes, key), value)?;
        Ok(())
    }

    // ============================================================
    // Staking state operations
    // ============================================================

    /// Save the entire staking state.
    pub fn save_staking_state(
        &self,
        txn: &WriteTransaction,
        state: &StakingState,
    ) -> Result<(), StateStoreError> {
        let mut table = txn.open_table(crate::tables::STAKING_STATE)?;
        table.insert("staking", state.to_bytes()?)?;
        Ok(())
    }

    /// Store the light-node set. This is a separate table from staking state.
    pub fn save_light_set(
        &self,
        txn: &WriteTransaction,
        set: &kovanica_staking::LightSet,
    ) -> Result<(), StateStoreError> {
        let mut table = txn.open_table(crate::tables::LIGHT_SET)?;
        table.insert("current", set.to_bytes()?)?;
        Ok(())
    }

    /// Remove the light-node set row, if one was written.
    pub fn clear_light_set(&self, txn: &WriteTransaction) -> Result<(), StateStoreError> {
        let mut table = txn.open_table(crate::tables::LIGHT_SET)?;
        table.remove("current")?;
        Ok(())
    }

    /// Load the light-node set from a write transaction.
    pub fn load_light_set_write(
        &self,
        txn: &WriteTransaction,
    ) -> Result<Option<kovanica_staking::LightSet>, StateStoreError> {
        let table = txn.open_table(crate::tables::LIGHT_SET)?;
        let bytes = table.get("current")?.map(|guard| guard.value().to_vec());
        match bytes {
            Some(bytes) => Ok(Some(kovanica_staking::LightSet::from_bytes(&bytes)?)),
            None => Ok(None),
        }
    }

    /// Load the light-node set from a read transaction.
    pub fn load_light_set(
        &self,
        txn: &ReadTransaction,
    ) -> Result<Option<kovanica_staking::LightSet>, StateStoreError> {
        let table = txn.open_table(crate::tables::LIGHT_SET)?;
        let bytes = table.get("current")?.map(|guard| guard.value().to_vec());
        match bytes {
            Some(bytes) => Ok(Some(kovanica_staking::LightSet::from_bytes(&bytes)?)),
            None => Ok(None),
        }
    }

    /// Load the staking state.
    pub fn load_staking_state(
        &self,
        txn: &ReadTransaction,
    ) -> Result<StakingState, StateStoreError> {
        let table = txn.open_table(crate::tables::STAKING_STATE)?;
        let value = table
            .get("staking")?
            .ok_or_else(|| StateStoreError::NotFound("staking state".to_string()))?;
        Ok(StakingState::from_bytes(&value.value())?)
    }

    // ============================================================
    // Genesis digest operations
    // ============================================================

    /// Persist the digest of the configured genesis contents.
    ///
    /// Idempotent: called at genesis time and, for data dirs created before
    /// the digest existed, once on the next start. A mismatch is detected and
    /// refused by the node, so the writer never overwrites an existing value
    /// with a different one silently (the node checks before writing).
    pub fn save_genesis_digest(
        &self,
        txn: &WriteTransaction,
        digest: &Hash,
    ) -> Result<(), StateStoreError> {
        let mut table = txn.open_table(crate::tables::GENESIS_DIGEST)?;
        table.insert("genesis", digest.0)?;
        Ok(())
    }

    /// Load the persisted genesis digest, if one was written.
    pub fn load_genesis_digest(
        &self,
        txn: &ReadTransaction,
    ) -> Result<Option<Hash>, StateStoreError> {
        let table = txn.open_table(crate::tables::GENESIS_DIGEST)?;
        Ok(table.get("genesis")?.map(|v| Hash(v.value())))
    }

    // ============================================================
    // State root operations (for snapshots/light clients)
    // ============================================================

    /// Rebuild the account sparse Merkle from the accounts table and store
    /// it as the state root at `committed_leader_height`.
    ///
    /// Only balance and nonce are committed. A row with both at zero is
    /// skipped, so it matches an absent account. Call this at the end of a
    /// committed-leader write, after every account mutation in that
    /// transaction.
    pub fn commit_account_smt(
        &self,
        txn: &WriteTransaction,
        committed_leader_height: u64,
    ) -> Result<kovanica_types::hash::Hash, StateStoreError> {
        self.commit_state_smt(txn, committed_leader_height, false)
    }

    /// Like [`Self::commit_account_smt`], optionally committing to the full
    /// state.
    ///
    /// With `commit_full_state` the tree gains the reserved leaf
    /// [`AUX_STATE_LEAF_ADDRESS`] holding a digest of the contract code,
    /// contract storage and staking tables (see [`aux_state_leaf`]), so the
    /// returned root, and therefore the sealed header root, authenticates
    /// every table a state-sync snapshot carries. Execution passes
    /// `kovanica_types::state_commitment_active_from(leader_round)`. Call it
    /// after every table mutation of the commit, in the same transaction.
    pub fn commit_state_smt(
        &self,
        txn: &WriteTransaction,
        committed_leader_height: u64,
        commit_full_state: bool,
    ) -> Result<kovanica_types::hash::Hash, StateStoreError> {
        let mut tree = kovanica_types::AccountSmt::empty();
        let mut aux = SnapshotData::default();
        {
            let table = txn.open_table(crate::tables::ACCOUNTS)?;
            for entry in table.iter()? {
                let (key, value) = entry?;
                if commit_full_state {
                    aux.accounts
                        .push((key.value().to_vec(), value.value().to_vec()));
                }
                let account = Account::from_bytes(&value.value())?;
                if account.balance == 0 && account.nonce == 0 {
                    continue;
                }
                let mut address = [0u8; 32];
                address.copy_from_slice(key.value().as_ref());
                if commit_full_state && address == AUX_STATE_LEAF_ADDRESS {
                    // The reserved leaf wins; see AUX_STATE_LEAF_ADDRESS.
                    continue;
                }
                tree.insert(
                    kovanica_types::Address(address),
                    account.balance,
                    account.nonce,
                );
            }
        }
        if commit_full_state {
            {
                let table = txn.open_table(crate::tables::CONTRACT_CODE)?;
                for entry in table.iter()? {
                    let (k, v) = entry?;
                    aux.contract_code
                        .push((k.value().to_vec(), v.value().to_vec()));
                }
            }
            {
                let table = txn.open_table(crate::tables::CONTRACT_STORAGE)?;
                for entry in table.iter()? {
                    let (k, v) = entry?;
                    aux.contract_storage
                        .push((bincode::serialize(&k.value())?, v.value().to_vec()));
                }
            }
            {
                let table = txn.open_table(crate::tables::STAKING_STATE)?;
                for entry in table.iter()? {
                    let (k, v) = entry?;
                    aux.staking_state
                        .push((k.value().as_bytes().to_vec(), v.value().to_vec()));
                }
            }
            let (balance, nonce) = aux_state_leaf(&aux)?;
            tree.insert(
                kovanica_types::Address(AUX_STATE_LEAF_ADDRESS),
                balance,
                nonce,
            );
        }
        let root = tree.root();
        self.save_state_root(txn, committed_leader_height, &root)?;
        Ok(root)
    }

    /// Prove `address` against the accounts currently stored.
    ///
    /// The proof's root is the tree of those rows. It matches
    /// [`Self::commit_account_smt`] when no account write happened since
    /// that call.
    pub fn prove_account(
        &self,
        txn: &ReadTransaction,
        address: &kovanica_types::Address,
    ) -> Result<kovanica_types::StateProof, StateStoreError> {
        let mut tree = kovanica_types::AccountSmt::empty();
        let mut found: Option<Account> = None;
        {
            let table = txn.open_table(crate::tables::ACCOUNTS)?;
            for entry in table.iter()? {
                let (key, value) = entry?;
                let account = Account::from_bytes(&value.value())?;
                let mut row_address = [0u8; 32];
                row_address.copy_from_slice(key.value().as_ref());
                if row_address == address.0 {
                    found = Some(account.clone());
                }
                if account.balance == 0 && account.nonce == 0 {
                    continue;
                }
                tree.insert(
                    kovanica_types::Address(row_address),
                    account.balance,
                    account.nonce,
                );
            }
        }
        let (present, balance, nonce) = match found {
            Some(account) if account.balance != 0 || account.nonce != 0 => {
                (true, account.balance, account.nonce)
            }
            _ => (false, 0, 0),
        };
        // From STATE_COMMITMENT_ACTIVE_FROM_ROUND the stored root also holds
        // the reserved full-state leaf. Prove against whichever tree matches
        // the latest stored root so account proofs keep verifying.
        let saved = self.get_latest_state_root(txn)?.map(|(_, root)| root);
        if saved.is_some_and(|saved| saved != tree.root()) {
            let mut committed = tree.clone();
            let aux = self.collect_snapshot_tables(txn)?;
            let (aux_balance, aux_nonce) = aux_state_leaf(&aux)?;
            committed.insert(
                kovanica_types::Address(AUX_STATE_LEAF_ADDRESS),
                aux_balance,
                aux_nonce,
            );
            if saved == Some(committed.root()) {
                tree = committed;
            }
        }
        let proof = tree.prove(address, balance, nonce, present);
        Ok(kovanica_types::StateProof {
            state_root: tree.root(),
            address: *address,
            balance,
            nonce,
            present,
            siblings: proof.siblings.to_vec(),
        })
    }

    /// Store the locally executed leader header.
    ///
    /// A header already stored at this height with a different hash is
    /// replaced, and every seal at that height is deleted. The local
    /// execution result is the one later seals must match.
    pub fn save_leader_header(
        &self,
        txn: &WriteTransaction,
        header: &kovanica_types::LeaderHeader,
    ) -> Result<(), StateStoreError> {
        let bytes = bincode::serialize(header)?;
        let height = header.committed_height;
        let new_hash = header.hash();
        let replaced = {
            let table = txn.open_table(crate::tables::LEADER_HEADERS)?;
            let existing = table.get(height)?.map(|guard| guard.value().to_vec());
            match existing {
                Some(bytes) => {
                    let old: kovanica_types::LeaderHeader = bincode::deserialize(&bytes)?;
                    old.hash() != new_hash
                }
                None => false,
            }
        };
        if replaced {
            self.delete_seals_at(txn, height)?;
        }
        let mut table = txn.open_table(crate::tables::LEADER_HEADERS)?;
        table.insert(height, bytes)?;
        Ok(())
    }

    /// Leader header stored for `height`, if this node has executed it.
    pub fn get_leader_header(
        &self,
        txn: &ReadTransaction,
        height: u64,
    ) -> Result<Option<kovanica_types::LeaderHeader>, StateStoreError> {
        let table = txn.open_table(crate::tables::LEADER_HEADERS)?;
        let bytes = table.get(height)?.map(|guard| guard.value().to_vec());
        match bytes {
            Some(bytes) => Ok(Some(bincode::deserialize(&bytes)?)),
            None => Ok(None),
        }
    }

    /// Highest stored leader header. Keys are committed heights, so the
    /// last row is the latest.
    pub fn get_latest_leader_header(
        &self,
        txn: &ReadTransaction,
    ) -> Result<Option<kovanica_types::LeaderHeader>, StateStoreError> {
        let table = txn.open_table(crate::tables::LEADER_HEADERS)?;
        let mut latest = None;
        for entry in table.iter()? {
            let (_height, value) = entry?;
            let bytes = value.value().to_vec();
            latest = Some(bincode::deserialize(&bytes)?);
        }
        Ok(latest)
    }

    /// Store one seal. A different signature already stored for the same
    /// authority is left in place.
    pub fn save_commit_seal(
        &self,
        txn: &WriteTransaction,
        height: u64,
        seal: &kovanica_types::CommitSeal,
    ) -> Result<(), StateStoreError> {
        let mut table = txn.open_table(crate::tables::COMMIT_SEALS)?;
        let key = (height, seal.authority_index);
        if table.get(key)?.is_some() {
            return Ok(());
        }
        table.insert(key, seal.signature.0.to_vec())?;
        Ok(())
    }

    /// Store `seal` only when the header at `height` hashes to `header_hash`.
    pub fn save_seal_if_header(
        &self,
        txn: &WriteTransaction,
        height: u64,
        header_hash: &kovanica_types::hash::Hash,
        seal: &kovanica_types::CommitSeal,
    ) -> Result<bool, StateStoreError> {
        let stored_hash = {
            let table = txn.open_table(crate::tables::LEADER_HEADERS)?;
            let bytes = table.get(height)?.map(|guard| guard.value().to_vec());
            match bytes {
                Some(bytes) => {
                    let header: kovanica_types::LeaderHeader = bincode::deserialize(&bytes)?;
                    Some(header.hash())
                }
                None => None,
            }
        };
        if stored_hash.as_ref() != Some(header_hash) {
            return Ok(false);
        }
        self.save_commit_seal(txn, height, seal)?;
        Ok(true)
    }

    /// Seals stored for `height`, in authority-index order.
    pub fn seals_for(
        &self,
        txn: &ReadTransaction,
        height: u64,
    ) -> Result<Vec<kovanica_types::CommitSeal>, StateStoreError> {
        let table = txn.open_table(crate::tables::COMMIT_SEALS)?;
        let mut seals = Vec::new();
        for entry in table.range((height, 0u16)..=(height, u16::MAX))? {
            let (key, value) = entry?;
            let (_, index) = key.value();
            let bytes = value.value().to_vec();
            if bytes.len() != 64 {
                return Err(StateStoreError::NotFound(format!(
                    "commit seal at height {height} authority {index} has {} bytes",
                    bytes.len()
                )));
            }
            let mut signature = [0u8; 64];
            signature.copy_from_slice(&bytes);
            seals.push(kovanica_types::CommitSeal {
                authority_index: index,
                signature: kovanica_types::Signature(signature),
            });
        }
        Ok(seals)
    }

    /// Replace the executed-transaction hash list for `height`.
    pub fn save_executed_tx_hashes(
        &self,
        txn: &WriteTransaction,
        height: u64,
        hashes: &[kovanica_types::hash::Hash],
    ) -> Result<(), StateStoreError> {
        let bytes = bincode::serialize(hashes)?;
        let mut table = txn.open_table(crate::tables::EXECUTED_TX_HASHES)?;
        table.insert(height, bytes)?;
        Ok(())
    }

    /// Executed-transaction hashes for `height`, if recorded.
    pub fn get_executed_tx_hashes(
        &self,
        txn: &ReadTransaction,
        height: u64,
    ) -> Result<Option<Vec<kovanica_types::hash::Hash>>, StateStoreError> {
        let table = txn.open_table(crate::tables::EXECUTED_TX_HASHES)?;
        let bytes = table.get(height)?.map(|guard| guard.value().to_vec());
        match bytes {
            Some(bytes) => Ok(Some(bincode::deserialize(&bytes)?)),
            None => Ok(None),
        }
    }

    /// The frozen seal committee snapshot for `epoch`, if one was written.
    ///
    /// Each member carries `(authority index, public key, stake, vrf_public_key)`.
    /// The first three are the exact triple `kovanica_types::committee_seal_hash`
    /// hashes (see [`kovanica_types::SealCommitteeSnapshotMember::seal_member`]);
    /// the VRF key is stored so a restarted node can rebuild the boot committee
    /// WITH its VRF keys (B3). `None` before the first seal of the epoch.
    ///
    /// Versioned encoding: magic byte (0x4B) + version (u8) + payload.
    /// - Version 1: new format with SealCommitteeSnapshotMember (with optional vrf_public_key)
    /// - No prefix: old untagged format (Vec<SealCommitteeMember> tuples)
    /// - Unknown version: clear error
    ///
    /// Old rows deserialize with vrf_public_key = None; they are NOT backfilled
    /// from the current staking state (the key may have changed since then).
    /// The leader for those epochs follows the existing rule for committees
    /// without VRF keys (round-robin).
    pub fn get_epoch_committee(
        &self,
        txn: &ReadTransaction,
        epoch: u64,
    ) -> Result<Option<Vec<kovanica_types::SealCommitteeSnapshotMember>>, StateStoreError> {
        // redb creates tables lazily on first write, so on a database that has
        // never sealed in this epoch the table does not exist yet. That is the
        // "no snapshot" case, not an error.
        let table = match txn.open_table(crate::tables::EPOCH_COMMITTEE) {
            Ok(table) => table,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        let bytes = table.get(epoch)?.map(|guard| guard.value().to_vec());
        match bytes {
            Some(bytes) => {
                // Check for versioned encoding
                match decode_with_version(&bytes) {
                    Ok((EPOCH_COMMITTEE_VERSION, payload)) => {
                        // New format (v1): Vec<SealCommitteeSnapshotMember> - STRICT decode
                        let options = bincode::DefaultOptions::new()
                            .with_fixint_encoding()
                            .reject_trailing_bytes();
                        let decoded: Vec<kovanica_types::SealCommitteeSnapshotMember> =
                            options.deserialize(payload)?;
                        Ok(Some(decoded))
                    }
                    Ok((v, _)) => {
                        // Known magic but unknown version
                        Err(Box::new(bincode::ErrorKind::Custom(format!(
                            "epoch committee decode error: unknown version {}",
                            v
                        )))
                        .into())
                    }
                    Err("no version prefix") => {
                        // Unversioned row: could be main-era (Vec<SealCommitteeSnapshotMember>)
                        // or pre-83c8dcf format (Vec<SealCommitteeMember> tuples).
                        // Try main-era format FIRST with strict options.
                        let options = bincode::DefaultOptions::new()
                            .with_fixint_encoding()
                            .reject_trailing_bytes();
                        if let Ok(main_era) = options
                            .deserialize::<Vec<kovanica_types::SealCommitteeSnapshotMember>>(&bytes)
                        {
                            Ok(Some(main_era))
                        } else {
                            // Fall back to pre-83c8dcf format (3-field tuples) with strict options
                            let old_format: Vec<kovanica_types::SealCommitteeMember> =
                                options.deserialize(&bytes)?;
                            // Convert to SnapshotMember with vrf_public_key = None.
                            // The caller (build_committee_for_round) will backfill from staking state if needed.
                            let converted: Vec<kovanica_types::SealCommitteeSnapshotMember> =
                                old_format
                                    .into_iter()
                                    .map(|(index, public_key, stake)| {
                                        kovanica_types::SealCommitteeSnapshotMember {
                                            index,
                                            public_key,
                                            stake,
                                            vrf_public_key: None,
                                        }
                                    })
                                    .collect();
                            Ok(Some(converted))
                        }
                    }
                    Err(e) => {
                        // Truncated or other error
                        Err(Box::new(bincode::ErrorKind::Custom(format!(
                            "epoch committee decode error: {}",
                            e
                        )))
                        .into())
                    }
                }
            }
            None => Ok(None),
        }
    }

    /// Freeze the seal committee snapshot for `epoch` if none exists yet.
    ///
    /// First writer wins: a snapshot already stored for `epoch` is left
    /// in place and the incoming `members` are ignored, so the very first seal
    /// of an epoch pins the committee every later seal and the RPC agree on.
    /// Returns the snapshot now in force for `epoch`.
    ///
    /// Writes with versioned encoding: magic byte (0x4B) + version (1) + payload.
    pub fn put_epoch_committee_if_absent(
        &self,
        txn: &WriteTransaction,
        epoch: u64,
        members: &[kovanica_types::SealCommitteeSnapshotMember],
    ) -> Result<Vec<kovanica_types::SealCommitteeSnapshotMember>, StateStoreError> {
        let mut table = txn.open_table(crate::tables::EPOCH_COMMITTEE)?;
        if let Some(existing) = table.get(epoch)? {
            // Decode existing with version handling
            let existing_bytes = existing.value().to_vec();
            let decoded = match decode_with_version(&existing_bytes) {
                Ok((EPOCH_COMMITTEE_VERSION, payload)) => bincode::deserialize::<
                    Vec<kovanica_types::SealCommitteeSnapshotMember>,
                >(payload)?,
                Ok((v, _)) => {
                    // Known magic but unknown version
                    return Err(Box::new(bincode::ErrorKind::Custom(format!(
                        "epoch committee decode error: unknown version {}",
                        v
                    )))
                    .into());
                }
                Err("no version prefix") => {
                    // Old format stored - convert and return as new format
                    let old: Vec<kovanica_types::SealCommitteeMember> =
                        bincode::deserialize(&existing_bytes)?;
                    old.into_iter()
                        .map(|(index, public_key, stake)| {
                            kovanica_types::SealCommitteeSnapshotMember {
                                index,
                                public_key,
                                stake,
                                vrf_public_key: None,
                            }
                        })
                        .collect()
                }
                Err(e) => {
                    return Err(Box::new(bincode::ErrorKind::Custom(format!(
                        "epoch committee decode error: {}",
                        e
                    )))
                    .into());
                }
            };
            return Ok(decoded);
        }
        // Write new format with version prefix
        let payload = bincode::serialize(members)?;
        let bytes = encode_with_version(EPOCH_COMMITTEE_VERSION, &payload);
        table.insert(epoch, &bytes)?;
        Ok(members.to_vec())
    }

    fn delete_seals_at(&self, txn: &WriteTransaction, height: u64) -> Result<(), StateStoreError> {
        let keys: Vec<(u64, u16)> = {
            let table = txn.open_table(crate::tables::COMMIT_SEALS)?;
            let mut keys = Vec::new();
            for entry in table.range((height, 0u16)..=(height, u16::MAX))? {
                let (key, _) = entry?;
                keys.push(key.value());
            }
            keys
        };
        if keys.is_empty() {
            return Ok(());
        }
        let mut table = txn.open_table(crate::tables::COMMIT_SEALS)?;
        for key in keys {
            table.remove(key)?;
        }
        Ok(())
    }

    /// Save state root for a committed leader height.
    pub fn save_state_root(
        &self,
        txn: &WriteTransaction,
        committed_leader_height: u64,
        state_root: &kovanica_types::hash::Hash,
    ) -> Result<(), StateStoreError> {
        let mut table = txn.open_table(crate::tables::STATE_ROOT)?;
        table.insert(&committed_leader_height, state_root.0)?;
        Ok(())
    }

    /// Get state root for a committed leader height.
    pub fn get_state_root(
        &self,
        txn: &ReadTransaction,
        committed_leader_height: u64,
    ) -> Result<Option<kovanica_types::hash::Hash>, StateStoreError> {
        let table = txn.open_table(crate::tables::STATE_ROOT)?;
        Ok(table
            .get(&committed_leader_height)?
            .map(|v| kovanica_types::hash::Hash(v.value())))
    }

    /// Get latest state root.
    pub fn get_latest_state_root(
        &self,
        txn: &ReadTransaction,
    ) -> Result<Option<(u64, kovanica_types::hash::Hash)>, StateStoreError> {
        let table = txn.open_table(crate::tables::STATE_ROOT)?;
        let mut latest = None;
        for entry in table.iter()? {
            let (height, hash) = entry?;
            latest = Some((height.value(), kovanica_types::hash::Hash(hash.value())));
        }
        Ok(latest)
    }

    // ============================================================
    // Sorted KV Merkle root
    // ============================================================

    /// Compute a deterministic sorted key-value Merkle root over all
    /// state tables (accounts, contract code, contract storage,
    /// staking state). Each leaf = H(key || value) using BLAKE3.
    /// Keys are sorted lexicographically (as byte arrays) before
    /// hashing so the result is deterministic.
    pub fn compute_state_root(
        &self,
        txn: &ReadTransaction,
    ) -> Result<kovanica_types::hash::Hash, StateStoreError> {
        let data = self.collect_snapshot_tables(txn)?;
        snapshot_state_root(&data)
    }

    /// Collect every state table into a [`SnapshotData`].
    ///
    /// Header fields (`version`, `height`, `state_root`) are left at their
    /// defaults; callers that need them filled use [`Self::snapshot_bytes`].
    /// Shared by [`Self::compute_state_root`] and snapshot export so both hash
    /// exactly the same rows.
    fn collect_snapshot_tables(
        &self,
        txn: &ReadTransaction,
    ) -> Result<SnapshotData, StateStoreError> {
        let mut data = SnapshotData::default();

        {
            let table = txn.open_table(crate::tables::ACCOUNTS)?;
            for entry in table.iter()? {
                let (k, v) = entry?;
                data.accounts.push((k.value().to_vec(), v.value().to_vec()));
            }
        }
        {
            let table = txn.open_table(crate::tables::CONTRACT_CODE)?;
            for entry in table.iter()? {
                let (k, v) = entry?;
                data.contract_code
                    .push((k.value().to_vec(), v.value().to_vec()));
            }
        }
        {
            let table = txn.open_table(crate::tables::CONTRACT_STORAGE)?;
            for entry in table.iter()? {
                let (k, v) = entry?;
                let k_bytes = bincode::serialize(&k.value())?;
                data.contract_storage.push((k_bytes, v.value().to_vec()));
            }
        }
        {
            let table = txn.open_table(crate::tables::STAKING_STATE)?;
            for entry in table.iter()? {
                let (k, v) = entry?;
                data.staking_state
                    .push((k.value().as_bytes().to_vec(), v.value().to_vec()));
            }
        }

        Ok(data)
    }

    /// Height the current state reflects: the newest saved state root, else
    /// the newest committed leader header, else 0 on a fresh database.
    ///
    /// This is the height [`Self::snapshot_bytes`] stamps into the header.
    pub fn snapshot_height(&self, txn: &ReadTransaction) -> Result<u64, StateStoreError> {
        if let Some((height, _)) = self.get_latest_state_root(txn)? {
            return Ok(height);
        }
        if let Some(header) = self.get_latest_leader_header(txn)? {
            return Ok(header.committed_height);
        }
        Ok(0)
    }

    /// Serialize the full state into the versioned snapshot byte format:
    /// [`SNAPSHOT_MAGIC`] followed by `bincode(`[`SnapshotData`]`)` with the
    /// height and state root filled in.
    ///
    /// Used by the file export and by the P2P state-sync export side.
    pub fn snapshot_bytes(&self, txn: &ReadTransaction) -> Result<Vec<u8>, StateStoreError> {
        let mut data = self.collect_snapshot_tables(txn)?;
        data.version = SNAPSHOT_VERSION;
        data.height = self.snapshot_height(txn)?;
        data.state_root = snapshot_state_root(&data)?.0;
        data.leader_header = self.get_leader_header(txn, data.height)?;
        data.commit_seals = self.seals_for(txn, data.height)?;
        if let Some(header) = &data.leader_header {
            data.epoch_committee = self.get_epoch_committee(txn, header.epoch)?;
        }
        let mut bytes = Vec::with_capacity(SNAPSHOT_MAGIC.len() + 64);
        bytes.extend_from_slice(&SNAPSHOT_MAGIC);
        bytes.extend_from_slice(&bincode::serialize(&data)?);
        Ok(bytes)
    }

    /// Decode snapshot bytes, accepting the versioned format and the legacy
    /// header-less payload (returned with `version = 0`, `height = 0` and a
    /// zero state root).
    ///
    /// Legacy payloads carry nothing to verify; they stay importable through
    /// [`Self::import_snapshot`] but are refused by
    /// [`Self::import_verified_snapshot`].
    pub fn decode_snapshot(bytes: &[u8]) -> Result<SnapshotData, StateStoreError> {
        if let Some(payload) = bytes.strip_prefix(SNAPSHOT_MAGIC.as_slice()) {
            if let Ok(data) = bincode::deserialize::<SnapshotData>(payload) {
                return Ok(data);
            }
            #[derive(Deserialize)]
            struct V1WithoutSeals {
                version: u32,
                height: u64,
                state_root: [u8; 32],
                accounts: Vec<(Vec<u8>, Vec<u8>)>,
                contract_code: Vec<(Vec<u8>, Vec<u8>)>,
                contract_storage: Vec<(Vec<u8>, Vec<u8>)>,
                staking_state: Vec<(Vec<u8>, Vec<u8>)>,
                #[serde(default)]
                leader_header: Option<kovanica_types::LeaderHeader>,
            }
            if let Ok(v1) = bincode::deserialize::<V1WithoutSeals>(payload) {
                return Ok(SnapshotData {
                    version: v1.version,
                    height: v1.height,
                    state_root: v1.state_root,
                    accounts: v1.accounts,
                    contract_code: v1.contract_code,
                    contract_storage: v1.contract_storage,
                    staking_state: v1.staking_state,
                    leader_header: v1.leader_header,
                    commit_seals: Vec::new(),
                    epoch_committee: None,
                });
            }
            #[derive(Deserialize)]
            struct V1WithoutHeader {
                version: u32,
                height: u64,
                state_root: [u8; 32],
                accounts: Vec<(Vec<u8>, Vec<u8>)>,
                contract_code: Vec<(Vec<u8>, Vec<u8>)>,
                contract_storage: Vec<(Vec<u8>, Vec<u8>)>,
                staking_state: Vec<(Vec<u8>, Vec<u8>)>,
            }
            let v1: V1WithoutHeader = bincode::deserialize(payload)
                .map_err(|e| StateStoreError::SnapshotFormat(e.to_string()))?;
            return Ok(SnapshotData {
                version: v1.version,
                height: v1.height,
                state_root: v1.state_root,
                accounts: v1.accounts,
                contract_code: v1.contract_code,
                contract_storage: v1.contract_storage,
                staking_state: v1.staking_state,
                leader_header: None,
                commit_seals: Vec::new(),
                epoch_committee: None,
            });
        }

        #[derive(Deserialize, Default)]
        struct LegacySnapshotData {
            accounts: Vec<(Vec<u8>, Vec<u8>)>,
            contract_code: Vec<(Vec<u8>, Vec<u8>)>,
            contract_storage: Vec<(Vec<u8>, Vec<u8>)>,
            staking_state: Vec<(Vec<u8>, Vec<u8>)>,
        }
        let legacy: LegacySnapshotData = bincode::deserialize(bytes)
            .map_err(|e| StateStoreError::SnapshotFormat(e.to_string()))?;
        Ok(SnapshotData {
            version: 0,
            height: 0,
            state_root: [0u8; 32],
            accounts: legacy.accounts,
            contract_code: legacy.contract_code,
            contract_storage: legacy.contract_storage,
            staking_state: legacy.staking_state,
            leader_header: None,
            commit_seals: Vec::new(),
            epoch_committee: None,
        })
    }

    /// Replace every state table with the snapshot's rows.
    ///
    /// Only ever called inside a write transaction; nothing is visible until
    /// the caller commits, so a later failure leaves the old state intact.
    fn apply_snapshot(
        &self,
        txn: &WriteTransaction,
        data: &SnapshotData,
        epoch_committee: Option<&[kovanica_types::SealCommitteeSnapshotMember]>,
    ) -> Result<(), StateStoreError> {
        {
            let table = txn.open_table(crate::tables::ACCOUNTS)?;
            let keys: Vec<[u8; 32]> = table
                .iter()?
                .filter_map(|e| e.ok())
                .map(|(k, _)| k.value())
                .collect();
            drop(table);
            let mut table = txn.open_table(crate::tables::ACCOUNTS)?;
            for k in keys {
                table.remove(k)?;
            }
            for (k, v) in &data.accounts {
                let k32: [u8; 32] = k.as_slice().try_into().unwrap_or([0; 32]);
                table.insert(k32, v.clone())?;
            }
        }
        {
            let table = txn.open_table(crate::tables::CONTRACT_CODE)?;
            let keys: Vec<[u8; 32]> = table
                .iter()?
                .filter_map(|e| e.ok())
                .map(|(k, _)| k.value())
                .collect();
            drop(table);
            let mut table = txn.open_table(crate::tables::CONTRACT_CODE)?;
            for k in keys {
                table.remove(k)?;
            }
            for (k, v) in &data.contract_code {
                let k32: [u8; 32] = k.as_slice().try_into().unwrap_or([0; 32]);
                table.insert(k32, v.clone())?;
            }
        }
        {
            let table = txn.open_table(crate::tables::CONTRACT_STORAGE)?;
            let keys: Vec<([u8; 32], [u8; 32])> = table
                .iter()?
                .filter_map(|e| e.ok())
                .map(|(k, _)| {
                    let b = k.value();
                    let serialized = bincode::serialize(&b).unwrap_or_default();
                    bincode::deserialize(&serialized[..]).unwrap_or_default()
                })
                .collect();
            drop(table);
            let mut table = txn.open_table(crate::tables::CONTRACT_STORAGE)?;
            for k in keys {
                table.remove(k)?;
            }
            for (k, v) in &data.contract_storage {
                let k_tuple: ([u8; 32], [u8; 32]) = bincode::deserialize(k)?;
                table.insert(k_tuple, v.clone())?;
            }
        }
        {
            let table = txn.open_table(crate::tables::STAKING_STATE)?;
            let keys: Vec<String> = table
                .iter()?
                .filter_map(|e| e.ok())
                .map(|(k, _)| k.value().to_string())
                .collect();
            drop(table);
            let mut table = txn.open_table(crate::tables::STAKING_STATE)?;
            for k in keys {
                table.remove(k.as_str())?;
            }
            for (_k, v) in &data.staking_state {
                table.insert("staking", v.clone())?;
            }
        }
        if let Some(header) = &data.leader_header {
            self.save_leader_header(txn, header)?;
            for seal in &data.commit_seals {
                self.save_commit_seal(txn, header.committed_height, seal)?;
            }
            if let Some(members) = epoch_committee {
                let _ = self.put_epoch_committee_if_absent(txn, header.epoch, members)?;
            }
            self.save_state_root(txn, data.height, &header.state_root)?;
        }
        Ok(())
    }

    /// Decode, verify and apply a snapshot payload in one write transaction.
    ///
    /// Verification runs before anything is applied:
    /// 1. the payload must be the versioned format (a legacy payload has no
    ///    height/state root and is refused),
    /// 2. the state root is recomputed over the received tables and must equal
    ///    the root the snapshot header claims (catches a corrupted stream or a
    ///    peer that tampered with the payload),
    /// 3. `height` must not be below `min_height` (the caller's local
    ///    committed height), so a snapshot can never roll state backwards,
    /// 4. a sealed [`kovanica_types::LeaderHeader`] at `height` with a verified
    ///    commit-seal quorum (`floor(2T/3) + 1` stake, signed for
    ///    `chain_id` only) must certify the state, and the header's
    ///    `state_root` must be the **full-state commitment** recomputed from
    ///    the received accounts, contract code/storage and staking rows (see
    ///    [`AUX_STATE_LEAF_ADDRESS`]). A sealed header with real accounts but
    ///    forged staking or contract rows therefore fails here,
    /// 5. the committee that must have signed comes from this node's own
    ///    database (see the committee rule on `resolve_snapshot_seal_committee`);
    ///    a committee carried inside the snapshot is never trusted.
    ///
    /// `chain_id` is the node's own chain id; seals for any other chain are
    /// refused.
    ///
    /// On any failure the error explains why and the caller must not commit
    /// the transaction. Returns the applied height and the sealed header's
    /// `leader_round`, which is the only value the caller may use to anchor
    /// the consensus catch-up cursor (the staking rows are data too, but their
    /// `committed_leader_height` is not a sealed round).
    pub fn import_verified_snapshot(
        &self,
        txn: &WriteTransaction,
        bytes: &[u8],
        min_height: u64,
        chain_id: u64,
    ) -> Result<VerifiedSnapshot, StateStoreError> {
        let data = Self::decode_snapshot(bytes)?;
        if data.version == 0 {
            return Err(StateStoreError::SnapshotVerify(
                "legacy snapshot has no height/state root; refusing unverified import".to_string(),
            ));
        }
        if data.height < min_height {
            return Err(StateStoreError::SnapshotVerify(format!(
                "snapshot height {} is below local height {min_height}; refusing rollback",
                data.height
            )));
        }
        let recomputed = snapshot_state_root(&data)?;
        if recomputed.0 != data.state_root {
            return Err(StateStoreError::SnapshotVerify(format!(
                "state root mismatch: header {} != recomputed {}",
                Hash(data.state_root).to_hex(),
                recomputed.to_hex()
            )));
        }
        let (header, committee) = verify_snapshot_seal_quorum(txn, &data, chain_id)?;
        self.apply_snapshot(txn, &data, Some(&committee))?;
        Ok(VerifiedSnapshot {
            height: data.height,
            leader_round: header.leader_round,
        })
    }

    /// Export a snapshot of all state data to a file using bincode.
    pub fn export_snapshot<P: AsRef<std::path::Path>>(
        &self,
        txn: &ReadTransaction,
        path: P,
    ) -> Result<(), StateStoreError> {
        let bytes = self.snapshot_bytes(txn)?;
        std::fs::write(path.as_ref(), &bytes)
            .map_err(|e| StateStoreError::NotFound(format!("snapshot write error: {e}")))?;
        Ok(())
    }

    /// Restore a snapshot from a file. Requires a write transaction.
    ///
    /// Accepts both the versioned format written by
    /// [`Self::export_snapshot`] and legacy header-less payloads. This is the
    /// permissive path (no root/height check); use
    /// [`Self::import_verified_snapshot`] for anything received over the
    /// network.
    pub fn import_snapshot<P: AsRef<std::path::Path>>(
        &self,
        txn: &WriteTransaction,
        path: P,
    ) -> Result<(), StateStoreError> {
        let bytes = std::fs::read(path.as_ref())
            .map_err(|e| StateStoreError::NotFound(format!("snapshot read error: {e}")))?;
        let data = Self::decode_snapshot(&bytes)?;
        self.apply_snapshot(txn, &data, data.epoch_committee.as_deref())
    }

    /// Prune old state roots beyond the configured retention.
    ///
    /// Two independent floors are honoured, whichever keeps *more* history:
    /// * `PruningConfig::max_state_roots` — keep the most recent N roots by
    ///   count;
    /// * `PruningConfig::keep_recent` — keep every root within this many
    ///   heights of the newest stored root, regardless of count.
    ///
    /// `keep_recent` is the field a live node may need at least a light-client
    /// reorg window for, so it is never allowed to drop a root that
    /// `max_state_roots` alone would have kept.
    pub fn prune_state_roots(&self, txn: &WriteTransaction) -> Result<u64, StateStoreError> {
        let table = txn.open_table(crate::tables::STATE_ROOT)?;
        let mut roots: Vec<u64> = table
            .iter()?
            .filter_map(|e| e.ok())
            .map(|(k, _)| k.value())
            .collect();
        drop(table);

        let Some(latest) = roots.iter().copied().max() else {
            return Ok(0);
        };
        // Roots at or above this height are protected by `keep_recent`.
        let recent_floor = latest.saturating_sub(self.pruning.keep_recent);

        // Ascending order: index `len - max_state_roots` is the newest root the
        // count cap would keep, so every earlier index is beyond the cap.
        roots.sort_unstable();
        let keep_from_index = roots
            .len()
            .saturating_sub(self.pruning.max_state_roots as usize);

        let mut table = txn.open_table(crate::tables::STATE_ROOT)?;
        let mut removed = 0u64;
        for (index, height) in roots.iter().enumerate() {
            let within_root_cap = index >= keep_from_index;
            let within_recent = *height >= recent_floor;
            if within_root_cap || within_recent {
                continue;
            }
            if table.remove(*height)?.is_some() {
                removed += 1;
            }
        }

        Ok(removed)
    }

    /// Prune every state root strictly below `min_height`, bounded per call.
    ///
    /// Used by the node's opt-in retention maintenance: `min_height` is derived
    /// from the committed tip minus the operator's retention window. Two limits
    /// always apply on top of that:
    /// * `PruningConfig::keep_recent` — never remove a root within this many
    ///   heights of the newest stored root, even when `min_height` is larger
    ///   (the configured window can tighten history, never loosen the
    ///   light-client floor);
    /// * `max_batch` — remove at most this many rows in one write transaction
    ///   (0 is a no-op), so a tick over a long chain stays bounded.
    ///
    /// Returns the number of roots removed.
    pub fn prune_state_roots_below(
        &self,
        txn: &WriteTransaction,
        min_height: u64,
        max_batch: usize,
    ) -> Result<u64, StateStoreError> {
        if max_batch == 0 {
            return Ok(0);
        }
        let table = txn.open_table(crate::tables::STATE_ROOT)?;
        let mut roots: Vec<u64> = table
            .iter()?
            .filter_map(|e| e.ok())
            .map(|(k, _)| k.value())
            .collect();
        drop(table);

        let Some(latest) = roots.iter().copied().max() else {
            return Ok(0);
        };
        let recent_floor = latest.saturating_sub(self.pruning.keep_recent);
        // The effective exclusive bound is the lower of the caller's height and
        // the protected window, so `keep_recent` is always respected.
        let bound = min_height.min(recent_floor);

        roots.sort_unstable();
        let mut table = txn.open_table(crate::tables::STATE_ROOT)?;
        let mut removed = 0u64;
        for height in roots {
            if removed as usize >= max_batch {
                break;
            }
            if height >= bound {
                // Ascending order: nothing later is removable either.
                break;
            }
            if table.remove(height)?.is_some() {
                removed += 1;
            }
        }

        Ok(removed)
    }

    /// Get the current pruning configuration.
    pub fn pruning_config(&self) -> &PruningConfig {
        &self.pruning
    }
}

/// Deterministic sorted key-value Merkle root over a snapshot's tables.
///
/// The single source of truth for both
/// [`StateStore::compute_state_root`] (which collects the live tables first)
/// and snapshot verification: a snapshot is only applied when this value
/// equals the root its header claims. Leaves are BLAKE3 hashes of
/// `leaf_key || value`, folded in lexicographic leaf-key order so the result
/// is independent of table iteration order.
fn snapshot_state_root(data: &SnapshotData) -> Result<Hash, StateStoreError> {
    let mut entries: BTreeMap<Vec<u8>, Vec<u8>> = BTreeMap::new();

    // Accounts: the raw address is the leaf key; leaf = address || account.
    for (key, value) in &data.accounts {
        let mut combined = key.clone();
        combined.extend_from_slice(value);
        entries.insert(key.clone(), combined);
    }
    // Contract code: leaf = "code:" || code_hash || code.
    for (key, value) in &data.contract_code {
        let mut leaf_key = b"code:".to_vec();
        leaf_key.extend_from_slice(key);
        let mut combined = leaf_key.clone();
        combined.extend_from_slice(value);
        entries.insert(leaf_key, combined);
    }
    // Contract storage: leaf = "storage:" || address || slot || value.
    for (key, value) in &data.contract_storage {
        let key_pair: ([u8; 32], [u8; 32]) = bincode::deserialize(key)?;
        let mut leaf_key = b"storage:".to_vec();
        leaf_key.extend_from_slice(&key_pair.0);
        leaf_key.extend_from_slice(&key_pair.1);
        let mut combined = leaf_key.clone();
        combined.extend_from_slice(value);
        entries.insert(leaf_key, combined);
    }
    // Staking: leaf = "staking:" || key || value.
    for (key, value) in &data.staking_state {
        let mut leaf_key = b"staking:".to_vec();
        leaf_key.extend_from_slice(key);
        let mut combined = leaf_key.clone();
        combined.extend_from_slice(value);
        entries.insert(leaf_key, combined);
    }

    let mut leaves: Vec<[u8; 32]> = Vec::with_capacity(entries.len());
    for (_, combined) in entries {
        leaves.push(Hash::new(&combined).0);
    }
    Ok(Hash(merkle_root(leaves)))
}

/// Recompute the sealed state root a snapshot must carry in its leader header:
/// the account sparse Merkle root (`AccountSmt`) over the `accounts` rows,
/// matching [`StateStore::commit_state_smt`] with `commit_full_state`, plus the
/// reserved [`AUX_STATE_LEAF_ADDRESS`] leaf that binds the account `code`
/// fields, contract code, contract storage and staking rows.
///
/// A header root without that leaf (the pre-activation account-only root)
/// never equals this value, so such a snapshot cannot be authenticated and is
/// refused.
fn snapshot_committed_root(data: &SnapshotData) -> Result<Hash, StateStoreError> {
    let mut tree = kovanica_types::AccountSmt::empty();
    for (key, value) in &data.accounts {
        let account = Account::from_bytes(value)?;
        if account.balance == 0 && account.nonce == 0 {
            continue;
        }
        let address_bytes: [u8; 32] = key.as_slice().try_into().map_err(|_| {
            StateStoreError::SnapshotFormat("account key is not 32 bytes".to_string())
        })?;
        if address_bytes == AUX_STATE_LEAF_ADDRESS {
            continue;
        }
        tree.insert(
            kovanica_types::Address(address_bytes),
            account.balance,
            account.nonce,
        );
    }
    let (balance, nonce) = aux_state_leaf(data)?;
    tree.insert(
        kovanica_types::Address(AUX_STATE_LEAF_ADDRESS),
        balance,
        nonce,
    );
    Ok(tree.root())
}

fn committee_members_from_staking(
    staking: &StakingState,
) -> Vec<kovanica_types::SealCommitteeSnapshotMember> {
    staking
        .committee_order()
        .into_iter()
        .enumerate()
        .filter_map(|(index, validator)| {
            let public_key = validator.public_key?;
            Some(kovanica_types::SealCommitteeSnapshotMember {
                index: index as u16,
                public_key,
                stake: validator.stake,
                vrf_public_key: validator
                    .vrf_public_key
                    .as_ref()
                    .map(|v| kovanica_types::PublicKey(v.0)),
            })
        })
        .collect()
}

fn decode_epoch_committee_bytes(
    bytes: &[u8],
) -> Result<Vec<kovanica_types::SealCommitteeSnapshotMember>, StateStoreError> {
    match decode_with_version(bytes) {
        Ok((EPOCH_COMMITTEE_VERSION, payload)) => {
            let options = bincode::DefaultOptions::new()
                .with_fixint_encoding()
                .reject_trailing_bytes();
            Ok(options.deserialize(payload)?)
        }
        Ok((v, _)) => Err(StateStoreError::SnapshotFormat(format!(
            "epoch committee decode error: unknown version {v}"
        ))),
        Err("no version prefix") => {
            let options = bincode::DefaultOptions::new()
                .with_fixint_encoding()
                .reject_trailing_bytes();
            if let Ok(main_era) =
                options.deserialize::<Vec<kovanica_types::SealCommitteeSnapshotMember>>(bytes)
            {
                Ok(main_era)
            } else {
                let old_format: Vec<kovanica_types::SealCommitteeMember> =
                    options.deserialize(bytes)?;
                Ok(old_format
                    .into_iter()
                    .map(
                        |(index, public_key, stake)| kovanica_types::SealCommitteeSnapshotMember {
                            index,
                            public_key,
                            stake,
                            vrf_public_key: None,
                        },
                    )
                    .collect())
            }
        }
        Err(e) => Err(StateStoreError::SnapshotFormat(format!(
            "epoch committee decode error: {e}"
        ))),
    }
}

/// Resolve the committee that must have signed a snapshot's header, from
/// this node's **own** database only.
///
/// Committee rule (no self-certifying fallback):
/// 1. local `EPOCH_COMMITTEE` frozen for the header's `epoch`,
/// 2. local `STAKING_STATE` active validator committee (seeded at genesis),
/// 3. any other locally frozen epoch committee.
///
/// The first candidate whose [`kovanica_types::committee_seal_hash`] equals
/// the sealed header's `committee_hash` is returned. A committee (or staking
/// state) carried inside the snapshot is never consulted: the peer that
/// supplies the snapshot would otherwise name the keys that certify it. If the
/// node holds no local committee at all the import is refused.
///
/// Honest snapshots after a validator rotation are accepted whenever the
/// sealed committee is one this node knows locally: it froze the epoch itself
/// (rotation executed before it fell behind), or its genesis/last-synced
/// staking set is still the sealed set. A node that slept through a rotation
/// that changed the active set cannot authenticate the new set from local data
/// and fails closed with an explicit error; it must obtain that epoch's
/// committee from a source it trusts (operator-provided frozen committee, or
/// block-by-block sync from a point it has certified), never from the
/// snapshot sender.
fn resolve_snapshot_seal_committee(
    txn: &WriteTransaction,
    epoch: u64,
    committee_hash: Hash,
) -> Result<Vec<kovanica_types::SealCommitteeSnapshotMember>, StateStoreError> {
    let mut candidates: Vec<Vec<kovanica_types::SealCommitteeSnapshotMember>> = Vec::new();
    if let Ok(table) = txn.open_table(crate::tables::EPOCH_COMMITTEE) {
        if let Some(guard) = table.get(epoch)? {
            let members = decode_epoch_committee_bytes(&guard.value())?;
            if !members.is_empty() {
                candidates.push(members);
            }
        }
    }
    if let Ok(table) = txn.open_table(crate::tables::STAKING_STATE) {
        if let Some(guard) = table.get("staking")? {
            let staking = StakingState::from_bytes(&guard.value())?;
            let members = committee_members_from_staking(&staking);
            if !members.is_empty() {
                candidates.push(members);
            }
        }
    }
    if let Ok(table) = txn.open_table(crate::tables::EPOCH_COMMITTEE) {
        for entry in table.iter()? {
            let (key, value) = entry?;
            if key.value() == epoch {
                continue;
            }
            if let Ok(members) = decode_epoch_committee_bytes(&value.value()) {
                if !members.is_empty() {
                    candidates.push(members);
                }
            }
        }
    }
    if candidates.is_empty() {
        return Err(StateStoreError::SnapshotVerify(
            "no local validator committee or staking state to verify the snapshot seals against; \
             refusing (a committee supplied inside the snapshot is not trusted)"
                .to_string(),
        ));
    }
    for members in candidates {
        let hash = kovanica_types::committee_seal_hash(
            epoch,
            &kovanica_types::snapshot_seal_members(&members),
        );
        if hash == committee_hash {
            return Ok(members);
        }
    }
    Err(StateStoreError::SnapshotVerify(format!(
        "sealed header committee_hash {} (epoch {epoch}) matches no committee known locally; \
         the active validator set changed since this node last held it, refusing",
        committee_hash.to_hex()
    )))
}

/// Verify that `data` carries a sealed [`kovanica_types::LeaderHeader`] at
/// `data.height`, that its `state_root` is the full-state commitment of the
/// received tables, and that a stake quorum of [`kovanica_types::CommitSeal`]s
/// signed it for `chain_id` (the node's own chain only) under a committee this
/// node already knows. Returns the verified header and the committee used.
fn verify_snapshot_seal_quorum(
    txn: &WriteTransaction,
    data: &SnapshotData,
    chain_id: u64,
) -> Result<
    (
        kovanica_types::LeaderHeader,
        Vec<kovanica_types::SealCommitteeSnapshotMember>,
    ),
    StateStoreError,
> {
    let header = data.leader_header.as_ref().ok_or_else(|| {
        StateStoreError::SnapshotVerify(
            "snapshot is missing sealed leader header; refusing uncertified import".to_string(),
        )
    })?;
    if header.committed_height != data.height {
        return Err(StateStoreError::SnapshotVerify(format!(
            "sealed header height {} != snapshot height {}",
            header.committed_height, data.height
        )));
    }
    if header.timestamp != 0 {
        return Err(StateStoreError::SnapshotVerify(
            "sealed header timestamp is not zero".to_string(),
        ));
    }
    if data.commit_seals.is_empty() {
        return Err(StateStoreError::SnapshotVerify(
            "snapshot has no commit seals; refusing uncertified import".to_string(),
        ));
    }
    let committed_root = snapshot_committed_root(data)?;
    if header.state_root != committed_root {
        return Err(StateStoreError::SnapshotVerify(format!(
            "sealed header state_root {} != full-state commitment {} recomputed from the \
             snapshot accounts, contracts and staking; the seal does not cover this state",
            header.state_root.to_hex(),
            committed_root.to_hex()
        )));
    }
    let members = resolve_snapshot_seal_committee(txn, header.epoch, header.committee_hash)?;
    let authorities = members
        .iter()
        .map(|member| kovanica_types::Authority {
            index: member.index,
            public_key: member.public_key,
            vrf_public_key: member.vrf_public_key,
            address: kovanica_types::Address::from_public_key(&member.public_key),
            stake: member.stake,
            network_address: String::new(),
        })
        .collect();
    let committee = kovanica_types::Committee::new(header.epoch, authorities);
    kovanica_crypto::verify_commit_seals(chain_id, header, &data.commit_seals, &committee)
        .map_err(|e| {
            StateStoreError::SnapshotVerify(format!(
                "commit seal quorum verification failed for chain {chain_id}: {e:?}"
            ))
        })?;
    Ok((header.clone(), members))
}

/// Compute binary Merkle root from sorted leaf hashes.
fn merkle_root(mut leaves: Vec<[u8; 32]>) -> [u8; 32] {
    if leaves.is_empty() {
        return [0u8; 32];
    }
    while leaves.len() > 1 {
        if leaves.len() % 2 == 1 {
            leaves.push(leaves[leaves.len() - 1]);
        }
        let mut next_level = Vec::with_capacity(leaves.len() / 2);
        for pair in leaves.chunks(2) {
            let mut combined = pair[0].to_vec();
            combined.extend_from_slice(&pair[1]);
            let hash = kovanica_types::hash::Hash::new(&combined);
            next_level.push(hash.0);
        }
        leaves = next_level;
    }
    leaves[0]
}

#[cfg(test)]
mod sub_balance_tests {
    use super::*;
    use crate::Storage;
    use kovanica_types::Address;
    use tempfile::tempdir;

    fn seeded(balance: u64) -> (tempfile::TempDir, Storage, Address) {
        let dir = tempdir().unwrap();
        let storage = Storage::new(dir.path().join("sub.db")).unwrap();
        let addr = Address([9; 32]);
        let txn = storage.begin_write().unwrap();
        storage.state().add_balance(&txn, &addr, balance).unwrap();
        txn.commit().unwrap();
        (dir, storage, addr)
    }

    fn balance(storage: &Storage, addr: &Address) -> u64 {
        let txn = storage.begin_write().unwrap();
        storage
            .state()
            .get_account_or_default_write(&txn, addr)
            .unwrap()
            .balance
    }

    #[test]
    fn sub_balance_then_other_table_op_in_one_txn_commits() {
        let (_dir, storage, addr) = seeded(1_000);
        let other = Address([8; 32]);
        let txn = storage.begin_write().unwrap();
        let left = storage.state().sub_balance(&txn, &addr, 300).unwrap();
        assert_eq!(left, 700);
        // Another ACCOUNTS write and a STAKING_STATE table op in the same txn.
        storage.state().add_balance(&txn, &other, 300).unwrap();
        txn.open_table(crate::tables::STAKING_STATE).unwrap();
        txn.commit().unwrap();
        assert_eq!(balance(&storage, &addr), 700);
        assert_eq!(balance(&storage, &other), 300);
    }

    #[test]
    fn sub_balance_overdraft_is_rejected_and_balance_unchanged() {
        let (_dir, storage, addr) = seeded(100);
        let txn = storage.begin_write().unwrap();
        let err = storage.state().sub_balance(&txn, &addr, 101).unwrap_err();
        assert!(
            matches!(err, StateStoreError::InsufficientBalance { .. }),
            "got {err:?}"
        );
        txn.commit().unwrap();
        assert_eq!(balance(&storage, &addr), 100);
    }

    #[test]
    fn sub_balance_exact_balance_to_zero() {
        let (_dir, storage, addr) = seeded(250);
        let txn = storage.begin_write().unwrap();
        assert_eq!(storage.state().sub_balance(&txn, &addr, 250).unwrap(), 0);
        txn.commit().unwrap();
        assert_eq!(balance(&storage, &addr), 0);
    }
}

#[cfg(test)]
mod account_smt_tests {
    use super::*;
    use crate::Storage;
    use kovanica_types::Address;
    use tempfile::tempdir;

    #[test]
    fn committed_root_matches_an_account_proof() {
        let dir = tempdir().unwrap();
        let storage = Storage::new(dir.path().join("smt.db")).unwrap();
        let addr = Address([4; 32]);
        let other = Address([8; 32]);
        let root = {
            let txn = storage.begin_write().unwrap();
            storage
                .state()
                .set_account(
                    &txn,
                    &addr,
                    &Account {
                        balance: 25,
                        nonce: 2,
                        code_hash: [9; 32],
                        code: vec![1, 2, 3],
                    },
                )
                .unwrap();
            storage
                .state()
                .set_account(
                    &txn,
                    &other,
                    &Account {
                        balance: 0,
                        nonce: 0,
                        code_hash: [1; 32],
                        code: vec![9],
                    },
                )
                .unwrap();
            let root = storage.state().commit_account_smt(&txn, 3).unwrap();
            txn.commit().unwrap();
            root
        };
        let txn = storage.begin_read().unwrap();
        let proof = storage.state().prove_account(&txn, &addr).unwrap();
        assert_eq!(proof.state_root, root);
        assert!(proof.present);
        assert_eq!(proof.balance, 25);
        assert_eq!(proof.nonce, 2);
        assert!(proof.verify());
        let absent = storage.state().prove_account(&txn, &other).unwrap();
        assert!(!absent.present);
        assert_eq!(absent.state_root, root);
        assert!(absent.verify());
        let saved = storage.state().get_state_root(&txn, 3).unwrap();
        assert_eq!(saved, Some(root));
    }
}

#[cfg(test)]
mod leader_header_tests {
    use super::*;
    use crate::Storage;
    use kovanica_types::{CommitSeal, Hash, LeaderHeader, Signature};
    use tempfile::tempdir;

    fn header(height: u64, state: u8) -> LeaderHeader {
        LeaderHeader {
            committed_height: height,
            leader_round: 3,
            leader_digest: Hash::new([height as u8]),
            leader_author: 0,
            parent_leader_digest: Hash::zero(),
            tx_merkle_root: Hash::zero(),
            executed_tx_root: Hash::zero(),
            non_blue_root: Hash::zero(),
            blue_root: Hash::zero(),
            mysticghost: false,
            state_root: Hash::new([state]),
            epoch: 0,
            committee_hash: Hash::zero(),
            timestamp: 0,
        }
    }

    fn seal(index: u16, byte: u8) -> CommitSeal {
        CommitSeal {
            authority_index: index,
            signature: Signature([byte; 64]),
        }
    }

    #[test]
    fn replacing_a_header_drops_seals_for_that_height() {
        let dir = tempdir().unwrap();
        let storage = Storage::new(dir.path().join("seals.db")).unwrap();
        let first = header(1, 1);
        let txn = storage.begin_write().unwrap();
        storage.state().save_leader_header(&txn, &first).unwrap();
        storage
            .state()
            .save_commit_seal(&txn, 1, &seal(0, 9))
            .unwrap();
        storage
            .state()
            .save_executed_tx_hashes(&txn, 1, &[Hash::new([3u8])])
            .unwrap();
        txn.commit().unwrap();

        let second = header(1, 2);
        assert_ne!(first.hash(), second.hash());
        let txn = storage.begin_write().unwrap();
        storage.state().save_leader_header(&txn, &second).unwrap();
        let kept = storage
            .state()
            .save_seal_if_header(&txn, 1, &first.hash(), &seal(1, 4))
            .unwrap();
        assert!(!kept);
        let stored = storage
            .state()
            .save_seal_if_header(&txn, 1, &second.hash(), &seal(1, 4))
            .unwrap();
        assert!(stored);
        txn.commit().unwrap();

        let txn = storage.begin_read().unwrap();
        let loaded = storage.state().get_leader_header(&txn, 1).unwrap().unwrap();
        assert_eq!(loaded.hash(), second.hash());
        let seals = storage.state().seals_for(&txn, 1).unwrap();
        assert_eq!(seals.len(), 1);
        assert_eq!(seals[0].authority_index, 1);
        let hashes = storage
            .state()
            .get_executed_tx_hashes(&txn, 1)
            .unwrap()
            .unwrap();
        assert_eq!(hashes, vec![Hash::new([3u8])]);
        assert!(storage
            .state()
            .get_leader_header(&txn, 9)
            .unwrap()
            .is_none());
    }
}

#[cfg(test)]
mod snapshot_tests {
    use super::*;
    use crate::Storage;
    use kovanica_types::Address;
    use tempfile::tempdir;

    /// Fresh storage with one seeded account and a quorum-sealed leader header
    /// at `height` (defaulting to height `0`) so [`StateStore::snapshot_height`]
    /// reports that height and [`StateStore::import_verified_snapshot`] can
    /// verify the commit-seal quorum. The header seals the full-state
    /// commitment (accounts + contracts + staking).
    fn seeded_storage(name: &str, height: Option<u64>) -> (tempfile::TempDir, Storage) {
        seeded_storage_with_staking(name, height, false)
    }

    /// Chain id the test seals are signed for and the importer is told it runs on.
    const TEST_CHAIN: u64 = 1337;

    /// Like [`seeded_storage`], optionally with a persisted staking state and
    /// a deployed contract row, so a forged copy of them is observable.
    fn seeded_storage_with_staking(
        name: &str,
        height: Option<u64>,
        with_staking: bool,
    ) -> (tempfile::TempDir, Storage) {
        let dir = tempdir().unwrap();
        let storage = Storage::new(dir.path().join(name)).unwrap();
        {
            let h = height.unwrap_or(0);
            let key = kovanica_types::SigningKey::from_bytes(&[7u8; 32]);
            let pk = kovanica_types::PublicKey(key.verifying_key().to_bytes());
            let members = vec![kovanica_types::SealCommitteeSnapshotMember {
                index: 0,
                public_key: pk,
                stake: kovanica_staking::MIN_VALIDATOR_STAKE,
                vrf_public_key: None,
            }];
            let committee_hash = kovanica_types::committee_seal_hash(
                0,
                &kovanica_types::snapshot_seal_members(&members),
            );
            let txn = storage.begin_write().unwrap();
            let acct = Account {
                balance: 1234,
                nonce: 2,
                code_hash: [1; 32],
                code: vec![9, 9, 9],
            };
            storage
                .state()
                .set_account(&txn, &Address([4; 32]), &acct)
                .unwrap();
            if with_staking {
                let mut staking = StakingState::new();
                staking.committed_leader_height = h + 1;
                storage.state().save_staking_state(&txn, &staking).unwrap();
                storage
                    .state()
                    .deploy_contract(&txn, &Address([5; 32]), vec![0, 1, 2, 3])
                    .unwrap();
            }
            let smt_root = storage.state().commit_state_smt(&txn, h, true).unwrap();
            storage
                .state()
                .put_epoch_committee_if_absent(&txn, 0, &members)
                .unwrap();
            let header = kovanica_types::LeaderHeader {
                committed_height: h,
                leader_round: (h + 1) * kovanica_types::WAVE_LENGTH,
                leader_digest: Hash::new([h as u8]),
                leader_author: 0,
                parent_leader_digest: Hash::zero(),
                tx_merkle_root: Hash::zero(),
                executed_tx_root: Hash::zero(),
                non_blue_root: Hash::zero(),
                blue_root: Hash::zero(),
                mysticghost: false,
                state_root: smt_root,
                epoch: 0,
                committee_hash,
                timestamp: 0,
            };
            let seal = kovanica_types::CommitSeal {
                authority_index: 0,
                signature: kovanica_crypto::sign(&key, &header.seal_message(1337)),
            };
            storage.state().save_leader_header(&txn, &header).unwrap();
            storage.state().save_commit_seal(&txn, h, &seal).unwrap();
            txn.commit().unwrap();
        }
        (dir, storage)
    }

    #[test]
    fn snapshot_bytes_round_trip_and_verified_import() {
        let (_src_dir, src) = seeded_storage("src.redb", Some(5));
        let bytes = {
            let txn = src.begin_read().unwrap();
            src.state().snapshot_bytes(&txn).unwrap()
        };
        assert!(bytes.starts_with(&SNAPSHOT_MAGIC), "versioned framing");

        let data = StateStore::decode_snapshot(&bytes).unwrap();
        assert_eq!(data.version, SNAPSHOT_VERSION);
        assert_eq!(data.height, 5, "header carries the snapshot height");
        let txn = src.begin_read().unwrap();
        let expected = src.state().compute_state_root(&txn).unwrap();
        assert_eq!(
            data.state_root, expected.0,
            "header root equals the root over the live tables"
        );

        // Verified import into a fresh database.
        let (_dst_dir, dst) = seeded_storage("dst.redb", None);
        {
            let txn = dst.begin_write().unwrap();
            let verified = dst
                .state()
                .import_verified_snapshot(&txn, &bytes, 0, TEST_CHAIN)
                .expect("verified import");
            assert_eq!(verified.height, 5);
            assert_eq!(verified.leader_round, 6 * kovanica_types::WAVE_LENGTH);
            txn.commit().unwrap();
        }
        let txn = dst.begin_read().unwrap();
        let restored = dst.state().get_account(&txn, &Address([4; 32])).unwrap();
        assert_eq!(restored.balance, 1234);
    }

    #[test]
    fn verified_import_rejects_tampered_tables() {
        let (_src_dir, src) = seeded_storage("src.redb", None);
        let bytes = {
            let txn = src.begin_read().unwrap();
            src.state().snapshot_bytes(&txn).unwrap()
        };

        // Change one account byte while keeping the claimed header root.
        let mut data = StateStore::decode_snapshot(&bytes).unwrap();
        data.accounts[0].1.push(0xee);
        let mut tampered = SNAPSHOT_MAGIC.to_vec();
        tampered.extend_from_slice(&bincode::serialize(&data).unwrap());

        let (_dst_dir, dst) = seeded_storage("dst.redb", None);
        // Distinct destination state so "nothing was applied" is observable
        // (the seed alone matches the snapshot's account values).
        {
            let txn = dst.begin_write().unwrap();
            dst.state()
                .set_account(
                    &txn,
                    &Address([4; 32]),
                    &Account {
                        balance: 999,
                        nonce: 7,
                        code_hash: [2; 32],
                        code: vec![1],
                    },
                )
                .unwrap();
            txn.commit().unwrap();
        }
        let txn = dst.begin_write().unwrap();
        let err = dst
            .state()
            .import_verified_snapshot(&txn, &tampered, 0, TEST_CHAIN)
            .unwrap_err();
        assert!(
            matches!(err, StateStoreError::SnapshotVerify(_)),
            "expected verification failure, got {err:?}"
        );
        drop(txn);

        // Nothing was applied.
        let txn = dst.begin_read().unwrap();
        let acct = dst
            .state()
            .get_account_or_default(&txn, &Address([4; 32]))
            .unwrap();
        assert_eq!(acct.balance, 999, "tampered snapshot must not be applied");
        assert_eq!(acct.nonce, 7, "tampered snapshot must not be applied");
    }

    #[test]
    fn verified_import_rejects_height_regression() {
        let (_src_dir, src) = seeded_storage("src.redb", None);
        let mut bytes = {
            let txn = src.begin_read().unwrap();
            src.state().snapshot_bytes(&txn).unwrap()
        };
        let mut data = StateStore::decode_snapshot(&bytes).unwrap();
        data.height = 3;
        bytes = SNAPSHOT_MAGIC.to_vec();
        bytes.extend_from_slice(&bincode::serialize(&data).unwrap());

        let (_dst_dir, dst) = seeded_storage("dst.redb", None);
        let txn = dst.begin_write().unwrap();
        let err = dst
            .state()
            .import_verified_snapshot(&txn, &bytes, 10, TEST_CHAIN)
            .unwrap_err();
        assert!(
            matches!(err, StateStoreError::SnapshotVerify(_)),
            "expected verification failure, got {err:?}"
        );
    }

    #[test]
    fn legacy_payload_imports_permissively_but_not_verified() {
        // A legacy (pre-header) payload: the four raw tables, no magic.
        let legacy_accounts = vec![(
            vec![6u8; 32],
            bincode::serialize(&Account {
                balance: 77,
                nonce: 0,
                code_hash: [0; 32],
                code: Vec::new(),
            })
            .unwrap(),
        )];
        let legacy = bincode::serialize(&(
            legacy_accounts,
            Vec::<(Vec<u8>, Vec<u8>)>::new(),
            Vec::<(Vec<u8>, Vec<u8>)>::new(),
            Vec::<(Vec<u8>, Vec<u8>)>::new(),
        ))
        .unwrap();

        let decoded = StateStore::decode_snapshot(&legacy).unwrap();
        assert_eq!(decoded.version, 0, "legacy payloads have no header");
        assert_eq!(decoded.height, 0);
        assert_eq!(decoded.state_root, [0u8; 32]);

        let (_dir, storage) = seeded_storage("legacy.redb", None);
        // Verified import refuses it: there is nothing to verify.
        {
            let txn = storage.begin_write().unwrap();
            assert!(matches!(
                storage
                    .state()
                    .import_verified_snapshot(&txn, &legacy, 0, TEST_CHAIN)
                    .unwrap_err(),
                StateStoreError::SnapshotVerify(_)
            ));
        }
        // The permissive file path still imports it.
        let path = _dir.path().join("legacy.snap");
        std::fs::write(&path, &legacy).unwrap();
        {
            let txn = storage.begin_write().unwrap();
            storage
                .state()
                .import_snapshot(&txn, &path)
                .expect("legacy import");
            txn.commit().unwrap();
        }
        let txn = storage.begin_read().unwrap();
        let mut key = [0u8; 32];
        key.copy_from_slice(&[6u8; 32]);
        let acct = storage.state().get_account(&txn, &Address(key)).unwrap();
        assert_eq!(acct.balance, 77, "legacy payload must still import");
    }

    #[test]
    fn verified_import_rejects_snapshot_without_seal_quorum() {
        let (_src_dir, src) = seeded_storage("src.redb", Some(4));
        let valid_bytes = {
            let txn = src.begin_read().unwrap();
            src.state().snapshot_bytes(&txn).unwrap()
        };

        // 1. Missing leader header is rejected even when the snapshot root matches.
        let mut no_header = StateStore::decode_snapshot(&valid_bytes).unwrap();
        no_header.leader_header = None;
        let mut no_header_bytes = SNAPSHOT_MAGIC.to_vec();
        no_header_bytes.extend_from_slice(&bincode::serialize(&no_header).unwrap());

        let dst_dir = tempdir().unwrap();
        let dst = Storage::new(dst_dir.path().join("dst.redb")).unwrap();
        {
            let txn = dst.begin_write().unwrap();
            let err = dst
                .state()
                .import_verified_snapshot(&txn, &no_header_bytes, 0, TEST_CHAIN)
                .unwrap_err();
            assert!(
                matches!(err, StateStoreError::SnapshotVerify(_)),
                "snapshot without sealed header must fail verification: {err:?}"
            );
        }

        // 2. Empty seal set is rejected.
        let mut no_seals = StateStore::decode_snapshot(&valid_bytes).unwrap();
        no_seals.commit_seals.clear();
        let mut no_seals_bytes = SNAPSHOT_MAGIC.to_vec();
        no_seals_bytes.extend_from_slice(&bincode::serialize(&no_seals).unwrap());
        {
            let txn = dst.begin_write().unwrap();
            let err = dst
                .state()
                .import_verified_snapshot(&txn, &no_seals_bytes, 0, TEST_CHAIN)
                .unwrap_err();
            assert!(
                matches!(err, StateStoreError::SnapshotVerify(_)),
                "snapshot without seals must fail verification: {err:?}"
            );
        }

        // 3. Sub-quorum seal set (2 of 4 equal-stake validators = 50% < 2/3+1) is rejected.
        let mut sub_quorum = StateStore::decode_snapshot(&valid_bytes).unwrap();
        let keys: Vec<kovanica_types::SigningKey> = (1u8..=4)
            .map(|b| kovanica_types::SigningKey::from_bytes(&[b; 32]))
            .collect();
        let members: Vec<kovanica_types::SealCommitteeSnapshotMember> = keys
            .iter()
            .enumerate()
            .map(|(i, k)| kovanica_types::SealCommitteeSnapshotMember {
                index: i as u16,
                public_key: kovanica_types::PublicKey(k.verifying_key().to_bytes()),
                stake: kovanica_staking::MIN_VALIDATOR_STAKE,
                vrf_public_key: None,
            })
            .collect();
        let committee_hash = kovanica_types::committee_seal_hash(
            0,
            &kovanica_types::snapshot_seal_members(&members),
        );
        let mut header = sub_quorum.leader_header.clone().unwrap();
        header.committee_hash = committee_hash;
        sub_quorum.epoch_committee = Some(members.clone());
        // Populate local committee in dst
        {
            let txn = dst.begin_write().unwrap();
            dst.state()
                .put_epoch_committee_if_absent(&txn, 0, &members)
                .unwrap();
            txn.commit().unwrap();
        }
        // Only 2 of 4 sign: 100_000 < floor(2 * 200_000 / 3) + 1 = 133_334.
        sub_quorum.commit_seals = keys[..2]
            .iter()
            .enumerate()
            .map(|(i, k)| kovanica_types::CommitSeal {
                authority_index: i as u16,
                signature: kovanica_crypto::sign(k, &header.seal_message(TEST_CHAIN)),
            })
            .collect();
        sub_quorum.leader_header = Some(header.clone());
        let mut sub_quorum_bytes = SNAPSHOT_MAGIC.to_vec();
        sub_quorum_bytes.extend_from_slice(&bincode::serialize(&sub_quorum).unwrap());
        {
            let txn = dst.begin_write().unwrap();
            let err = dst
                .state()
                .import_verified_snapshot(&txn, &sub_quorum_bytes, 0, TEST_CHAIN)
                .unwrap_err();
            assert!(
                matches!(err, StateStoreError::SnapshotVerify(_)),
                "sub-quorum snapshot must fail verification: {err:?}"
            );
        }

        // 4. With 3 of 4 validators signing (>= 2/3+1 quorum), verification succeeds.
        let mut full_quorum = sub_quorum;
        full_quorum.commit_seals = keys[..3]
            .iter()
            .enumerate()
            .map(|(i, k)| kovanica_types::CommitSeal {
                authority_index: i as u16,
                signature: kovanica_crypto::sign(k, &header.seal_message(TEST_CHAIN)),
            })
            .collect();
        let mut full_quorum_bytes = SNAPSHOT_MAGIC.to_vec();
        full_quorum_bytes.extend_from_slice(&bincode::serialize(&full_quorum).unwrap());
        {
            let txn = dst.begin_write().unwrap();
            let verified = dst
                .state()
                .import_verified_snapshot(&txn, &full_quorum_bytes, 0, TEST_CHAIN)
                .expect("3-of-4 quorum snapshot must import");
            assert_eq!(verified.height, 4);
            assert_eq!(verified.leader_round, 5 * kovanica_types::WAVE_LENGTH);
            txn.commit().unwrap();
        }
    }

    #[test]
    fn verified_import_rejects_forged_staking_state() {
        let (_src_dir, src) = seeded_storage_with_staking("src.redb", Some(5), true);
        let bytes = {
            let txn = src.begin_read().unwrap();
            src.state().snapshot_bytes(&txn).unwrap()
        };

        let mut data = StateStore::decode_snapshot(&bytes).unwrap();
        assert!(
            !data.staking_state.is_empty(),
            "snapshot must carry staking rows"
        );
        // Tamper with the staking state row (e.g. forge a validator / increase stake)
        data.staking_state[0].1.push(0xbb);
        let mut tampered = SNAPSHOT_MAGIC.to_vec();
        tampered.extend_from_slice(&bincode::serialize(&data).unwrap());

        let (_dst_dir, dst) = seeded_storage("dst.redb", None);
        let txn = dst.begin_write().unwrap();
        let err = dst
            .state()
            .import_verified_snapshot(&txn, &tampered, 0, TEST_CHAIN)
            .unwrap_err();
        assert!(
            matches!(err, StateStoreError::SnapshotVerify(_)),
            "snapshot with forged staking must be rejected: {err:?}"
        );
    }

    #[test]
    fn verified_import_rejects_forged_contract_code_or_storage() {
        let (_src_dir, src) = seeded_storage_with_staking("src.redb", Some(5), true);
        let bytes = {
            let txn = src.begin_read().unwrap();
            src.state().snapshot_bytes(&txn).unwrap()
        };

        // 1. Tamper with contract code in an otherwise sealed snapshot
        let mut data = StateStore::decode_snapshot(&bytes).unwrap();
        assert!(
            !data.contract_code.is_empty(),
            "snapshot must carry contract code"
        );
        data.contract_code[0].1.push(0xef);
        let mut tampered = SNAPSHOT_MAGIC.to_vec();
        tampered.extend_from_slice(&bincode::serialize(&data).unwrap());

        let (_dst_dir, dst) = seeded_storage("dst.redb", None);
        let txn = dst.begin_write().unwrap();
        let err = dst
            .state()
            .import_verified_snapshot(&txn, &tampered, 0, TEST_CHAIN)
            .unwrap_err();
        assert!(
            matches!(err, StateStoreError::SnapshotVerify(_)),
            "snapshot with forged contract code must be rejected: {err:?}"
        );

        // 2. Tamper by injecting unauthorized contract storage
        let mut data2 = StateStore::decode_snapshot(&bytes).unwrap();
        let key_bytes = bincode::serialize(&([5u8; 32], [1u8; 32])).unwrap();
        data2.contract_storage.push((key_bytes, vec![4, 5, 6]));
        let mut tampered2 = SNAPSHOT_MAGIC.to_vec();
        tampered2.extend_from_slice(&bincode::serialize(&data2).unwrap());

        let err2 = dst
            .state()
            .import_verified_snapshot(&txn, &tampered2, 0, TEST_CHAIN)
            .unwrap_err();
        assert!(
            matches!(err2, StateStoreError::SnapshotVerify(_)),
            "snapshot with forged contract storage must be rejected: {err2:?}"
        );
    }

    #[test]
    fn verified_import_rejects_wrong_chain_seals() {
        let (_src_dir, src) = seeded_storage("src.redb", Some(5));
        let bytes = {
            let txn = src.begin_read().unwrap();
            src.state().snapshot_bytes(&txn).unwrap()
        };

        let (_dst_dir, dst) = seeded_storage("dst.redb", None);
        let txn = dst.begin_write().unwrap();
        // The snapshot was signed for TEST_CHAIN (1337). Importing on chain 1 or 4 must fail.
        let err = dst
            .state()
            .import_verified_snapshot(&txn, &bytes, 0, 1)
            .unwrap_err();
        assert!(
            matches!(err, StateStoreError::SnapshotVerify(_)),
            "wrong-chain seals must be rejected: {err:?}"
        );
    }

    #[test]
    fn verified_import_rejects_self_certifying_committee_fallback() {
        let (_src_dir, src) = seeded_storage("src.redb", Some(5));
        let bytes = {
            let txn = src.begin_read().unwrap();
            src.state().snapshot_bytes(&txn).unwrap()
        };

        // Destination node has a completely fresh database with NO local committee
        let dst_dir = tempdir().unwrap();
        let dst = Storage::new(dst_dir.path().join("fresh.redb")).unwrap();
        let txn = dst.begin_write().unwrap();
        let err = dst
            .state()
            .import_verified_snapshot(&txn, &bytes, 0, TEST_CHAIN)
            .unwrap_err();
        assert!(
            matches!(err, StateStoreError::SnapshotVerify(_)),
            "must reject when no local committee exists (no self-certifying snapshot committee fallback): {err:?}"
        );
    }
}

#[cfg(test)]
mod prune_tests {
    use super::*;
    use redb::Database;
    use tempfile::tempdir;

    /// A fresh database plus a state store with the supplied pruning config,
    /// seeded with state roots at heights `1..=count`.
    fn seeded(name: &str, pruning: PruningConfig, count: u64) -> (tempfile::TempDir, Database) {
        let dir = tempdir().unwrap();
        let db = Database::create(dir.path().join(name)).unwrap();
        let store = StateStore::with_pruning(&db, pruning).unwrap();
        let txn = db.begin_write().unwrap();
        for height in 1..=count {
            store
                .save_state_root(&txn, height, &Hash::new(b"root"))
                .unwrap();
        }
        txn.commit().unwrap();
        (dir, db)
    }

    fn stored_heights(db: &Database) -> Vec<u64> {
        let txn = db.begin_read().unwrap();
        let table = txn.open_table(crate::tables::STATE_ROOT).unwrap();
        let mut heights: Vec<u64> = table
            .iter()
            .unwrap()
            .map(|e| e.unwrap().0.value())
            .collect();
        heights.sort_unstable();
        heights
    }

    #[test]
    fn keep_recent_is_honoured_even_with_no_count_cap() {
        // max_state_roots = 0 would otherwise delete everything; keep_recent
        // must protect the newest 5 heights.
        let (_dir, db) = seeded(
            "keep_recent.redb",
            PruningConfig {
                keep_recent: 5,
                max_state_roots: 0,
            },
            20,
        );
        let store = StateStore::with_pruning(
            &db,
            PruningConfig {
                keep_recent: 5,
                max_state_roots: 0,
            },
        )
        .unwrap();

        let txn = db.begin_write().unwrap();
        let removed = store.prune_state_roots(&txn).unwrap();
        txn.commit().unwrap();

        assert_eq!(removed, 14, "heights 1..=14 removed");
        assert_eq!(stored_heights(&db), vec![15, 16, 17, 18, 19, 20]);
    }

    #[test]
    fn prune_state_roots_still_honours_max_state_roots() {
        // A zero `keep_recent` window leaves the count cap fully in charge.
        let pruning = PruningConfig {
            keep_recent: 0,
            max_state_roots: 3,
        };
        let (_dir, db) = seeded("cap.redb", pruning.clone(), 10);
        // The store is built before the write transaction below: redb holds one
        // write lock per database at a time.
        let store = StateStore::with_pruning(&db, pruning).unwrap();

        let txn = db.begin_write().unwrap();
        store.prune_state_roots(&txn).unwrap();
        txn.commit().unwrap();

        assert_eq!(stored_heights(&db), vec![8, 9, 10]);
    }

    #[test]
    fn prune_state_roots_is_a_noop_on_an_empty_table() {
        let pruning = PruningConfig::default();
        let (_dir, db) = seeded("empty.redb", pruning.clone(), 0);
        let store = StateStore::with_pruning(&db, pruning).unwrap();
        let txn = db.begin_write().unwrap();
        assert_eq!(store.prune_state_roots(&txn).unwrap(), 0);
        txn.commit().unwrap();
    }

    #[test]
    fn prune_state_roots_below_never_crosses_keep_recent() {
        let pruning = PruningConfig {
            keep_recent: 5,
            max_state_roots: 1000,
        };
        let (_dir, db) = seeded("below.redb", pruning.clone(), 20);
        let store = StateStore::with_pruning(&db, pruning).unwrap();

        // Caller asks to prune everything below 18, but keep_recent protects
        // everything at height >= 15.
        let txn = db.begin_write().unwrap();
        let removed = store.prune_state_roots_below(&txn, 18, 1000).unwrap();
        txn.commit().unwrap();

        assert_eq!(removed, 14);
        assert_eq!(stored_heights(&db), vec![15, 16, 17, 18, 19, 20]);
    }

    #[test]
    fn prune_state_roots_below_bounds_rows_per_call() {
        let pruning = PruningConfig {
            keep_recent: 5,
            max_state_roots: 2000,
        };
        let (_dir, db) = seeded("batch.redb", pruning.clone(), 20);
        let store = StateStore::with_pruning(&db, pruning).unwrap();

        let txn = db.begin_write().unwrap();
        assert_eq!(store.prune_state_roots_below(&txn, 15, 3).unwrap(), 3);
        txn.commit().unwrap();
        assert_eq!(
            stored_heights(&db),
            (4..=20).collect::<Vec<u64>>(),
            "only the three oldest heights are gone"
        );

        let txn = db.begin_write().unwrap();
        assert_eq!(store.prune_state_roots_below(&txn, 15, 0).unwrap(), 0);
        txn.commit().unwrap();
    }
}
