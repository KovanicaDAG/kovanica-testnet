//! Block storage for Kovanica.
//!
//! Stores blocks, transactions, and provides indexing by height and hash.

use crate::{hash_to_bytes, BincodeSerialize, StorageError};
use kovanica_types::{
    block::{BlockReference, StatementBlock},
    hash::Hash,
    transaction::Transaction,
    Round,
};
use redb::{ReadTransaction, ReadableTable, WriteTransaction};
use thiserror::Error;

/// Errors specific to block store operations.
#[derive(Debug, Error)]
pub enum BlockStoreError {
    #[error("Block not found: {0}")]
    NotFound(String),
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

/// Block store for persisting blocks and transactions.
pub struct BlockStore;

impl BlockStore {
    /// Create a new block store, initializing tables if needed.
    pub fn new(db: &redb::Database) -> Result<Self, StorageError> {
        let write_txn = db.begin_write().map_err(StorageError::Transaction)?;
        {
            let _ = write_txn.open_table(crate::tables::BLOCKS)?;
            let _ = write_txn.open_table(crate::tables::BLOCK_HEIGHT)?;
            let _ = write_txn.open_table(crate::tables::BLOCK_TRANSACTIONS)?;
            let _ = write_txn.open_table(crate::tables::TRANSACTION_INDEX)?;
        }
        write_txn.commit().map_err(StorageError::Commit)?;
        Ok(Self)
    }

    /// Store a block and its transactions.
    pub fn put_block(
        &self,
        txn: &WriteTransaction,
        block: &StatementBlock,
        transactions: &[Transaction],
    ) -> Result<(), BlockStoreError> {
        let block_hash = hash_to_bytes(&block.digest);
        // Basic validation: digest must match recomputed hash; parent round consistency (audit 3.1)
        let computed = StatementBlock::compute_digest(
            block.author,
            block.round,
            &block.parents,
            &block.transactions,
        );
        if computed != block.digest {
            return Err(BlockStoreError::NotFound("block digest mismatch".into()));
        }
        // Parent round consistency check (parent exists? skip — needs full DAG; at least round advances correctly)
        for p in &block.parents {
            if p.round + 1 != block.round {
                return Err(BlockStoreError::NotFound("bad parent round".into()));
            }
        }
        let round = block.round;
        let author = block.author;

        // Serialize and store the block
        let block_bytes = block.to_bytes()?;
        {
            let mut table = txn.open_table(crate::tables::BLOCKS)?;
            table.insert(block_hash, block_bytes)?;
        }

        // Store block by height (round)
        {
            let mut table = txn.open_table(crate::tables::BLOCK_HEIGHT)?;
            table.insert(&round, &block_hash)?;
        }

        // Store transactions
        let tx_hashes: Vec<[u8; 32]> = transactions
            .iter()
            .map(|tx| hash_to_bytes(&tx.hash))
            .collect();
        let tx_bytes = tx_hashes.to_bytes()?;
        {
            let mut table = txn.open_table(crate::tables::BLOCK_TRANSACTIONS)?;
            table.insert(block_hash, tx_bytes)?;
        }

        // Index each transaction to this block
        {
            let mut table = txn.open_table(crate::tables::TRANSACTION_INDEX)?;
            for tx in transactions {
                let tx_hash = hash_to_bytes(&tx.hash);
                table.insert(tx_hash, block_hash)?;
            }
        }

        Ok(())
    }

    /// Get a block by its hash.
    pub fn get_block(
        &self,
        txn: &ReadTransaction,
        hash: &Hash,
    ) -> Result<StatementBlock, BlockStoreError> {
        let block_hash = hash_to_bytes(hash);
        let table = txn.open_table(crate::tables::BLOCKS)?;
        let value = table.get(block_hash)?.ok_or_else(|| {
            BlockStoreError::NotFound(format!("block {}", hex::encode(block_hash)))
        })?;
        Ok(StatementBlock::from_bytes(&value.value())?)
    }

    /// Get a block by round (height).
    pub fn get_block_by_height(
        &self,
        txn: &ReadTransaction,
        round: Round,
    ) -> Result<Option<StatementBlock>, BlockStoreError> {
        let table = txn.open_table(crate::tables::BLOCK_HEIGHT)?;
        let block_hash = match table.get(&round)? {
            Some(v) => v.value(),
            None => return Ok(None),
        };
        drop(table);
        self.get_block(txn, &Hash(block_hash)).map(Some)
    }

    /// Get blocks in a range of rounds.
    pub fn get_blocks_by_range(
        &self,
        txn: &ReadTransaction,
        start: Round,
        end: Round,
    ) -> Result<Vec<StatementBlock>, BlockStoreError> {
        let table = txn.open_table(crate::tables::BLOCK_HEIGHT)?;
        let mut blocks = Vec::new();
        for entry in table.range(start..=end)? {
            let (_, block_hash) = entry?;
            let block = self.get_block(txn, &Hash(block_hash.value()))?;
            blocks.push(block);
        }
        Ok(blocks)
    }

    /// Get all transaction hashes for a block.
    pub fn get_block_transactions(
        &self,
        txn: &ReadTransaction,
        block_hash: &Hash,
    ) -> Result<Vec<Hash>, BlockStoreError> {
        let key = hash_to_bytes(block_hash);
        let table = txn.open_table(crate::tables::BLOCK_TRANSACTIONS)?;
        let value = table.get(key)?.ok_or_else(|| {
            BlockStoreError::NotFound(format!("transactions for block {}", hex::encode(key)))
        })?;
        let tx_hashes: Vec<[u8; 32]> = BincodeSerialize::from_bytes(&value.value())?;
        Ok(tx_hashes.into_iter().map(Hash).collect())
    }

    /// Get the block hash that contains a transaction.
    pub fn get_block_for_transaction(
        &self,
        txn: &ReadTransaction,
        tx_hash: &Hash,
    ) -> Result<Option<Hash>, BlockStoreError> {
        let key = hash_to_bytes(tx_hash);
        let table = txn.open_table(crate::tables::TRANSACTION_INDEX)?;
        Ok(table.get(key)?.map(|v| Hash(v.value())))
    }

    /// Get the latest block (highest round).
    pub fn get_latest_block(
        &self,
        txn: &ReadTransaction,
    ) -> Result<Option<StatementBlock>, BlockStoreError> {
        let table = txn.open_table(crate::tables::BLOCK_HEIGHT)?;
        let mut latest_round = 0;
        let mut latest_hash = None;

        for entry in table.iter()? {
            let (round, hash) = entry?;
            if round.value() > latest_round {
                latest_round = round.value();
                latest_hash = Some(hash.value());
            }
        }

        match latest_hash {
            Some(h) => self.get_block(txn, &Hash(h)).map(Some),
            None => Ok(None),
        }
    }

    /// Check if a block exists.
    pub fn has_block(&self, txn: &ReadTransaction, hash: &Hash) -> Result<bool, BlockStoreError> {
        let key = hash_to_bytes(hash);
        let table = txn.open_table(crate::tables::BLOCKS)?;
        Ok(table.get(key)?.is_some())
    }

    /// Delete blocks below a certain round (pruning).
    ///
    /// Removes every stored block with `round < min_round`. Unbounded: for
    /// periodic maintenance on a live node prefer [`Self::prune_below_limited`],
    /// which caps the rows removed per write transaction.
    pub fn prune_below(
        &self,
        txn: &WriteTransaction,
        min_round: Round,
    ) -> Result<u64, BlockStoreError> {
        self.prune_below_limited(txn, min_round, usize::MAX)
    }

    /// Batched variant of [`Self::prune_below`].
    ///
    /// Deletes at most `max_blocks` blocks with `round < min_round`, oldest
    /// (lowest round) first, then returns the number deleted. A single call
    /// therefore keeps its write transaction short enough for a maintenance
    /// tick; call again on the next tick to make further progress. `max_blocks
    /// == 0` is a no-op.
    pub fn prune_below_limited(
        &self,
        txn: &WriteTransaction,
        min_round: Round,
        max_blocks: usize,
    ) -> Result<u64, BlockStoreError> {
        if max_blocks == 0 {
            return Ok(0);
        }
        // Collect rounds to prune first (can't modify while iterating). The
        // range yields keys in ascending order, so the batch is the oldest
        // blocks below `min_round`.
        let mut rounds_to_prune = Vec::new();
        {
            let table = txn.open_table(crate::tables::BLOCK_HEIGHT)?;
            for entry in table.range(0..min_round)? {
                let (round, block_hash) = entry?;
                rounds_to_prune.push((round.value(), block_hash.value()));
                if rounds_to_prune.len() >= max_blocks {
                    break;
                }
            }
        }

        // Now delete. The `BLOCK_HEIGHT` read handle is closed above: redb
        // refuses a second open of the same table inside one write transaction,
        // so it must be re-opened per deletion.
        let mut pruned = 0;
        for (round, block_hash) in rounds_to_prune {
            // Remove from blocks table
            {
                let mut blocks_table = txn.open_table(crate::tables::BLOCKS)?;
                blocks_table.remove(block_hash)?;
            }
            // Remove from block_height
            {
                let mut height_table = txn.open_table(crate::tables::BLOCK_HEIGHT)?;
                height_table.remove(&round)?;
            }
            // Remove from block_transactions and transaction_index
            {
                let mut tx_table = txn.open_table(crate::tables::BLOCK_TRANSACTIONS)?;
                if let Some(tx_hashes_bytes) = tx_table.get(block_hash)? {
                    let tx_hashes: Vec<[u8; 32]> =
                        BincodeSerialize::from_bytes(&tx_hashes_bytes.value())?;
                    let mut tx_index = txn.open_table(crate::tables::TRANSACTION_INDEX)?;
                    for tx_hash in tx_hashes {
                        tx_index.remove(tx_hash)?;
                    }
                }
                tx_table.remove(block_hash)?;
            }
            pruned += 1;
        }

        Ok(pruned)
    }
}

#[cfg(test)]
mod prune_tests {
    use super::*;
    use kovanica_types::crypto::Signature;
    use kovanica_types::AuthorityIndex;
    use tempfile::tempdir;

    /// A parentless block at `round` (digest recomputed so `put_block` accepts it).
    fn block(round: Round) -> StatementBlock {
        let author: AuthorityIndex = 0;
        let parents: Vec<BlockReference> = Vec::new();
        let transactions: Vec<Transaction> = Vec::new();
        let digest = StatementBlock::compute_digest(author, round, &parents, &transactions);
        StatementBlock {
            author,
            round,
            parents,
            transactions,
            statements: Vec::new(),
            signature: Signature([0u8; 64]),
            digest,
            merkle_root: Hash::new([0u8; 32]),
        }
    }

    fn seed_rounds(store: &BlockStore, txn: &WriteTransaction, rounds: &[Round]) {
        for &r in rounds {
            store.put_block(txn, &block(r), &[]).expect("put_block");
        }
    }

    #[test]
    fn prune_below_deletes_only_rounds_below_the_boundary() {
        let dir = tempdir().unwrap();
        let db = redb::Database::create(dir.path().join("blocks.redb")).unwrap();
        let store = BlockStore::new(&db).unwrap();

        let txn = db.begin_write().unwrap();
        seed_rounds(&store, &txn, &[1, 2, 3, 4, 5]);
        txn.commit().unwrap();

        let txn = db.begin_write().unwrap();
        let pruned = store.prune_below(&txn, 4).unwrap();
        txn.commit().unwrap();
        assert_eq!(pruned, 3, "rounds 1,2,3 pruned");

        let read = db.begin_read().unwrap();
        assert!(store.get_block_by_height(&read, 3).unwrap().is_none());
        assert!(
            store.get_block_by_height(&read, 4).unwrap().is_some(),
            "boundary round must survive"
        );
        assert!(
            store.get_block_by_height(&read, 5).unwrap().is_some(),
            "rounds above the boundary must survive"
        );
    }

    #[test]
    fn prune_below_limited_bounds_rows_per_call() {
        let dir = tempdir().unwrap();
        let db = redb::Database::create(dir.path().join("blocks.redb")).unwrap();
        let store = BlockStore::new(&db).unwrap();

        let txn = db.begin_write().unwrap();
        seed_rounds(&store, &txn, &[1, 2, 3, 4, 5]);
        txn.commit().unwrap();

        // First call removes at most two of the three candidates.
        let txn = db.begin_write().unwrap();
        assert_eq!(store.prune_below_limited(&txn, 4, 2).unwrap(), 2);
        txn.commit().unwrap();
        {
            let read = db.begin_read().unwrap();
            assert!(store.get_block_by_height(&read, 1).unwrap().is_none());
            assert!(store.get_block_by_height(&read, 2).unwrap().is_none());
            assert!(
                store.get_block_by_height(&read, 3).unwrap().is_some(),
                "batch cap must leave the remainder for the next tick"
            );
        }

        // A second call finishes the job; nothing below the boundary remains.
        let txn = db.begin_write().unwrap();
        assert_eq!(store.prune_below_limited(&txn, 4, 2).unwrap(), 1);
        txn.commit().unwrap();
        let read = db.begin_read().unwrap();
        assert!(store.get_block_by_height(&read, 3).unwrap().is_none());
        assert!(store.get_block_by_height(&read, 4).unwrap().is_some());
    }

    #[test]
    fn prune_below_limited_zero_is_a_noop() {
        let dir = tempdir().unwrap();
        let db = redb::Database::create(dir.path().join("blocks.redb")).unwrap();
        let store = BlockStore::new(&db).unwrap();

        let txn = db.begin_write().unwrap();
        seed_rounds(&store, &txn, &[1, 2]);
        txn.commit().unwrap();

        let txn = db.begin_write().unwrap();
        assert_eq!(store.prune_below_limited(&txn, 10, 0).unwrap(), 0);
        txn.commit().unwrap();
        let read = db.begin_read().unwrap();
        assert!(store.get_block_by_height(&read, 1).unwrap().is_some());
        assert!(store.get_block_by_height(&read, 2).unwrap().is_some());
    }
}
