//! Persistent storage layer for Kovanica (redb backend + pruning).
//!
//! Provides three main storage components:
//! - `BlockStore`: Blocks, transactions, and block index
//! - `StateStore`: Account balances, nonces, contract code/storage, staking state
//! - `ConsensusStore`: DAG structure, commit tracker, decided rounds

#![deny(unsafe_code)]
#![allow(clippy::result_large_err)]
#![allow(clippy::large_enum_variant)]
#![allow(clippy::borrow_deref_ref)]
#![allow(clippy::useless_conversion)]
#![allow(clippy::clone_on_copy)]
#![allow(clippy::map_flatten)]
#![allow(unused_mut)]
#![allow(unused_variables)]
#![allow(unused_imports)]

use kovanica_types::{hash::Hash, Address};
use redb::{Database, ReadTransaction, ReadableTable, TableDefinition, WriteTransaction};
use serde::{Deserialize, Serialize};
use std::path::Path;
use thiserror::Error;
use tracing::warn;

pub mod address_tx_index;
pub mod block_store;
pub mod consensus_store;
pub mod state_store;

pub use address_tx_index::{
    index_committed_txs, query_tx_history, AddressTxIndexError, TxDirection, TxHistoryEntry,
    TxHistoryPage, TxHistoryQuery, ADDRESS_TX_INDEX_KEY_LEN, ADDRESS_TX_INDEX_VALUE_LEN,
    DEFAULT_TX_HISTORY_LIMIT, MAX_TX_HISTORY_LIMIT, ROLE_BOTH, ROLE_RECEIVED, ROLE_SENT,
};
pub use block_store::{BlockStore, BlockStoreError};
pub use consensus_store::{ConsensusStore, ConsensusStoreError};
pub use state_store::{StateStore, StateStoreError};
pub use tables::{
    ACCOUNTS, CONTRACT_CODE, CONTRACT_STORAGE, GENESIS_DIGEST, STAKING_STATE, STATE_ROOT,
};

/// Main storage handle combining all stores.
pub struct Storage {
    db: Database,
    block_store: BlockStore,
    state_store: StateStore,
    consensus_store: ConsensusStore,
}

impl Storage {
    /// Open or create a new storage at the given path.
    pub fn new<P: AsRef<Path>>(path: P) -> Result<Self, StorageError> {
        let db = Database::create(path).map_err(StorageError::Database)?;
        let block_store = BlockStore::new(&db)?;
        let state_store = StateStore::new(&db)?;
        let consensus_store = ConsensusStore::new(&db)?;

        Ok(Self {
            db,
            block_store,
            state_store,
            consensus_store,
        })
    }

    /// Get a reference to the block store.
    pub fn blocks(&self) -> &BlockStore {
        &self.block_store
    }

    /// Get a mutable reference to the block store.
    pub fn blocks_mut(&mut self) -> &mut BlockStore {
        &mut self.block_store
    }

    /// Get a reference to the state store.
    pub fn state(&self) -> &StateStore {
        &self.state_store
    }

    /// Get a mutable reference to the state store.
    pub fn state_mut(&mut self) -> &mut StateStore {
        &mut self.state_store
    }

    /// Get a reference to the consensus store.
    pub fn consensus(&self) -> &ConsensusStore {
        &self.consensus_store
    }

    /// Get a mutable reference to the consensus store.
    pub fn consensus_mut(&mut self) -> &mut ConsensusStore {
        &mut self.consensus_store
    }

    /// Begin a read transaction.
    pub fn begin_read(&self) -> Result<ReadTransaction, StorageError> {
        self.db.begin_read().map_err(StorageError::Transaction)
    }

    /// Begin a write transaction.
    pub fn begin_write(&self) -> Result<WriteTransaction, StorageError> {
        self.db.begin_write().map_err(StorageError::Transaction)
    }
}

/// Errors that can occur in storage operations.
#[derive(Error, Debug)]
pub enum StorageError {
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
    #[error("Block store error: {0}")]
    BlockStore(#[from] BlockStoreError),
    #[error("State store error: {0}")]
    StateStore(#[from] StateStoreError),
    #[error("Consensus store error: {0}")]
    ConsensusStore(#[from] ConsensusStoreError),
    #[error("Serialization error: {0}")]
    Serialization(#[from] bincode::Error),
    #[error("Not found: {0}")]
    NotFound(String),
}

/// Table definitions for redb.
pub mod tables {
    use super::*;
    use kovanica_types::block::StatementBlock;
    use kovanica_types::hash::Hash;
    use kovanica_types::Address;

    // Block store tables
    pub const BLOCKS: TableDefinition<[u8; 32], Vec<u8>> = TableDefinition::new("blocks");
    pub const BLOCK_HEIGHT: TableDefinition<u64, [u8; 32]> = TableDefinition::new("block_height");
    pub const BLOCK_TRANSACTIONS: TableDefinition<[u8; 32], Vec<u8>> =
        TableDefinition::new("block_transactions");
    pub const TRANSACTION_INDEX: TableDefinition<[u8; 32], [u8; 32]> =
        TableDefinition::new("tx_index"); // tx_hash -> block_hash
                                          // Address history (`address_tx_index`) is defined in `address_tx_index`.
                                          // It is a local RPC index: not a state-root input and not consensus bytes.

    // State store tables
    pub const ACCOUNTS: TableDefinition<[u8; 32], Vec<u8>> = TableDefinition::new("accounts");
    pub const CONTRACT_CODE: TableDefinition<[u8; 32], Vec<u8>> =
        TableDefinition::new("contract_code");
    pub const CONTRACT_STORAGE: TableDefinition<([u8; 32], [u8; 32]), Vec<u8>> =
        TableDefinition::new("contract_storage");
    pub const STAKING_STATE: TableDefinition<&'static str, Vec<u8>> =
        TableDefinition::new("staking_state");
    pub const STATE_ROOT: TableDefinition<u64, [u8; 32]> = TableDefinition::new("state_root"); // committed_leader_height -> state_root
    /// Committed-leader header (bincode), keyed by committed height.
    pub const LEADER_HEADERS: TableDefinition<u64, Vec<u8>> =
        TableDefinition::new("leader_headers");
    /// One commit seal: `(committed height, authority index)` -> signature bytes.
    pub const COMMIT_SEALS: TableDefinition<(u64, u16), Vec<u8>> =
        TableDefinition::new("commit_seals");
    /// Frozen seal committee snapshot for an epoch (bincode `Vec<(AuthorityIndex,
    /// PublicKey, Stake)>`), keyed by epoch number.
    ///
    /// The first seal produced in an epoch writes the snapshot; every later
    /// seal in that epoch and the RPC `getCommittee` path read the SAME frozen
    /// snapshot, so a mid-epoch join/evict/unbond cannot make the sealed
    /// header's `committee_hash` disagree with the committee the RPC serves.
    pub const EPOCH_COMMITTEE: TableDefinition<u64, Vec<u8>> =
        TableDefinition::new("epoch_committee");
    /// Transaction hashes execution applied at a committed height, in order.
    pub const EXECUTED_TX_HASHES: TableDefinition<u64, Vec<u8>> =
        TableDefinition::new("executed_tx_hashes");
    /// Light-node set (bincode). Not a field of `StakingState`.
    pub const LIGHT_SET: TableDefinition<&'static str, Vec<u8>> = TableDefinition::new("light_set");
    /// Persisted digest of the configured genesis contents. Written once at
    /// genesis time (and on first start of a pre-existing data dir); every
    /// later start recomputes the digest and refuses on mismatch unless
    /// explicitly overridden. Key: `"genesis"`.
    pub const GENESIS_DIGEST: TableDefinition<&'static str, [u8; 32]> =
        TableDefinition::new("genesis_digest");

    // Consensus store tables
    pub const DAG_BLOCKS: TableDefinition<[u8; 32], Vec<u8>> = TableDefinition::new("dag_blocks"); // StatementBlock serialized
    pub const DAG_PARENTS: TableDefinition<[u8; 32], Vec<u8>> = TableDefinition::new("dag_parents"); // block_hash -> parent hashes
    pub const DAG_CHILDREN: TableDefinition<[u8; 32], Vec<u8>> =
        TableDefinition::new("dag_children"); // block_hash -> child hashes
    pub const DAG_BY_ROUND: TableDefinition<(u64, u16), Vec<u8>> =
        TableDefinition::new("dag_by_round"); // (round, author) -> block_hashes
    pub const DAG_BY_AUTHOR: TableDefinition<(u16, u64), Vec<u8>> =
        TableDefinition::new("dag_by_author"); // (author, round) -> block_hash
    pub const COMMITTED_LEADER_HEIGHT: TableDefinition<&'static str, u64> =
        TableDefinition::new("committed_leader_height");
    pub const DECIDED_ROUNDS: TableDefinition<u64, Vec<u8>> =
        TableDefinition::new("decided_rounds"); // round -> decided leader hashes
    pub const LAST_COMMITED: TableDefinition<&'static str, [u8; 32]> =
        TableDefinition::new("last_committed"); // "last" -> leader block hash

    /// Consensus votes (bincode `Vote`), keyed by `(leader round, voter index)`.
    ///
    /// A node keeps the votes it accepted so it can serve the decision evidence
    /// for a leader round to a peer that joins later. The invariant this table
    /// exists to uphold: if a node can serve the block for round R, it can serve
    /// the votes for round R.
    pub const VOTES: TableDefinition<(u64, u16), Vec<u8>> = TableDefinition::new("votes");

    /// Accepted leader-slot timeouts: (round, voter) → bincode `Timeout`
    /// (PRO-40 (b)).
    ///
    /// Holds this node's own timeouts — written before they are broadcast, so
    /// a restart can never vote for a slot it already timed out — and the
    /// verified timeouts of other validators, from which a skip certificate
    /// can be rebuilt and served to a peer.
    pub const TIMEOUTS: TableDefinition<(u64, u16), Vec<u8>> = TableDefinition::new("timeouts");
}

// Helper trait for bincode serialization
pub trait BincodeSerialize: Serialize + for<'de> Deserialize<'de> {
    fn to_bytes(&self) -> Result<Vec<u8>, bincode::Error> {
        bincode::serialize(self)
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, bincode::Error>
    where
        Self: Sized,
    {
        bincode::deserialize(bytes)
    }
}

impl<T: Serialize + for<'de> Deserialize<'de>> BincodeSerialize for T {}

/// Serialize a Hash to bytes for table keys.
pub fn hash_to_bytes(hash: &Hash) -> [u8; 32] {
    hash.0
}

/// Serialize an Address to bytes for table keys.
pub fn address_to_bytes(addr: &Address) -> [u8; 32] {
    addr.0
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_storage_creation() {
        let dir = tempdir().unwrap();
        let storage = Storage::new(dir.path().join("test.db")).unwrap();
        let _txn = storage.begin_write().unwrap();
        // commit happens on transaction drop
    }

    #[test]
    fn test_state_root_determinism() {
        let dir = tempdir().unwrap();
        let db = Database::create(dir.path().join("test.db")).unwrap();
        let state = StateStore::new(&db).unwrap();
        let txn = db.begin_read().unwrap();
        let root1 = state.compute_state_root(&txn).unwrap();
        drop(txn);
        let txn2 = db.begin_read().unwrap();
        let root2 = state.compute_state_root(&txn2).unwrap();
        assert_eq!(root1.0, root2.0, "state root must be deterministic");
    }

    #[test]
    fn genesis_digest_roundtrips_and_is_idempotent() {
        use kovanica_types::hash::Hash;
        let dir = tempdir().unwrap();
        let storage = Storage::new(dir.path().join("genesis.db")).unwrap();
        let digest = Hash::new([7u8; 32]);

        // Absent until written.
        {
            let read = storage.begin_read().unwrap();
            assert!(storage
                .state()
                .load_genesis_digest(&read)
                .unwrap()
                .is_none());
        }
        // Write once.
        {
            let txn = storage.begin_write().unwrap();
            storage.state().save_genesis_digest(&txn, &digest).unwrap();
            txn.commit().unwrap();
        }
        // Idempotent rewrite of the same value.
        {
            let txn = storage.begin_write().unwrap();
            storage.state().save_genesis_digest(&txn, &digest).unwrap();
            txn.commit().unwrap();
        }
        let read = storage.begin_read().unwrap();
        assert_eq!(
            storage.state().load_genesis_digest(&read).unwrap(),
            Some(digest)
        );
    }

    #[test]
    fn test_snapshot_roundtrip() {
        use crate::state_store::{Account, StateStore};
        let dir = tempdir().unwrap();
        let db_path = dir.path().join("snap.db");
        let storage = Storage::new(&db_path).unwrap();

        // Write state
        {
            let txn = storage.begin_write().unwrap();
            let state = storage.state();
            let addr = kovanica_types::Address([7; 32]);
            let acct = Account {
                balance: 1000,
                nonce: 3,
                code_hash: [0; 32],
                code: vec![1, 2, 3],
            };
            state.set_account(&txn, &addr, &acct).unwrap();
            txn.commit().unwrap();
        }

        // Export
        let snap_path = dir.path().join("snap.bin");
        {
            let txn = storage.begin_read().unwrap();
            let state = storage.state();
            state.export_snapshot(&txn, &snap_path).unwrap();
        }

        // Restore into fresh DB
        let db_path2 = dir.path().join("snap2.db");
        let storage2 = Storage::new(&db_path2).unwrap();
        {
            let txn = storage2.begin_write().unwrap();
            let state = storage2.state();
            state.import_snapshot(&txn, &snap_path).unwrap();
            txn.commit().unwrap();
        }

        // Verify
        {
            let txn = storage2.begin_read().unwrap();
            let state = storage2.state();
            let addr = kovanica_types::Address([7; 32]);
            let restored = state.get_account(&txn, &addr).unwrap();
            assert_eq!(restored.balance, 1000);
            assert_eq!(restored.nonce, 3);
        }
    }
}
