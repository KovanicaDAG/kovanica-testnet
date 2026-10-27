//! Consensus storage for Kovanica.
//!
//! Stores DAG structure (blocks, parent/child links), commit tracker, and decided rounds.

use crate::{hash_to_bytes, BincodeSerialize, StorageError};
use kovanica_types::{
    block::{BlockReference, StatementBlock},
    hash::Hash,
    AuthorityIndex, CommittedSubDag, Round, Timeout, Vote,
};
use redb::{ReadTransaction, ReadableTable, WriteTransaction};
use thiserror::Error;

/// Errors specific to consensus store operations.
#[derive(Debug, Error)]
pub enum ConsensusStoreError {
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

/// Consensus store for DAG structure and commit tracking.
pub struct ConsensusStore;

impl ConsensusStore {
    /// Create a new consensus store, initializing tables if needed.
    pub fn new(db: &redb::Database) -> Result<Self, StorageError> {
        let write_txn = db.begin_write()?;
        {
            let _ = write_txn.open_table(crate::tables::DAG_BLOCKS)?;
            let _ = write_txn.open_table(crate::tables::DAG_PARENTS)?;
            let _ = write_txn.open_table(crate::tables::DAG_CHILDREN)?;
            let _ = write_txn.open_table(crate::tables::DAG_BY_ROUND)?;
            let _ = write_txn.open_table(crate::tables::DAG_BY_AUTHOR)?;
            let _ = write_txn.open_table(crate::tables::COMMITTED_LEADER_HEIGHT)?;
            let _ = write_txn.open_table(crate::tables::DECIDED_ROUNDS)?;
            let _ = write_txn.open_table(crate::tables::LAST_COMMITED)?;
            let _ = write_txn.open_table(crate::tables::VOTES)?;
            let _ = write_txn.open_table(crate::tables::GENESIS_DIGEST)?;
            let _ = write_txn.open_table(crate::tables::TIMEOUTS)?;
        }
        write_txn.commit()?;
        Ok(Self)
    }

    // ============================================================
    // DAG Block operations
    // ============================================================

    /// Store a DAG block with its parent/child links.
    pub fn put_dag_block(
        &self,
        txn: &WriteTransaction,
        block: &StatementBlock,
    ) -> Result<(), ConsensusStoreError> {
        let block_hash = hash_to_bytes(&block.digest);
        let round = block.round;
        let author = block.author;

        // Store the block
        {
            let mut table = txn.open_table(crate::tables::DAG_BLOCKS)?;
            table.insert(block_hash, block.to_bytes()?)?;
        }

        // Store parent links
        let parent_hashes: Vec<[u8; 32]> = block
            .parents
            .iter()
            .map(|p| hash_to_bytes(&p.digest))
            .collect();
        {
            let mut table = txn.open_table(crate::tables::DAG_PARENTS)?;
            table.insert(block_hash, parent_hashes.to_bytes()?)?;
        }

        // Update child links for each parent
        for parent_hash in &parent_hashes {
            let mut children = self.get_children_internal(&*txn, parent_hash)?;
            children.push(block_hash);
            let mut table = txn.open_table(crate::tables::DAG_CHILDREN)?;
            table.insert(*parent_hash, children.to_bytes()?)?;
        }

        // Index by round
        {
            let mut table = txn.open_table(crate::tables::DAG_BY_ROUND)?;
            let mut existing: Vec<[u8; 32]> = table
                .get((round, author))?
                .map(|v| BincodeSerialize::from_bytes(&v.value()).unwrap_or_default())
                .unwrap_or_default();
            existing.push(block_hash);
            table.insert((round, author), existing.to_bytes()?)?;
        }

        // Index by author
        {
            let mut table = txn.open_table(crate::tables::DAG_BY_AUTHOR)?;
            let mut existing: Vec<[u8; 32]> = table
                .get((author, round))?
                .map(|v| BincodeSerialize::from_bytes(&v.value()).unwrap_or_default())
                .unwrap_or_default();
            existing.push(block_hash);
            table.insert((author, round), existing.to_bytes()?)?;
        }

        Ok(())
    }

    /// Get a DAG block by hash.
    pub fn get_dag_block(
        &self,
        txn: &ReadTransaction,
        hash: &Hash,
    ) -> Result<StatementBlock, ConsensusStoreError> {
        let key = hash_to_bytes(hash);
        let table = txn.open_table(crate::tables::DAG_BLOCKS)?;
        let value = table.get(key)?.ok_or_else(|| {
            ConsensusStoreError::NotFound(format!("dag block {}", hex::encode(key)))
        })?;
        Ok(StatementBlock::from_bytes(&value.value())?)
    }

    /// Get parent hashes for a block.
    pub fn get_parents(
        &self,
        txn: &ReadTransaction,
        hash: &Hash,
    ) -> Result<Vec<Hash>, ConsensusStoreError> {
        let key = hash_to_bytes(hash);
        let table = txn.open_table(crate::tables::DAG_PARENTS)?;
        let value = table.get(key)?.ok_or_else(|| {
            ConsensusStoreError::NotFound(format!("parents for {}", hex::encode(key)))
        })?;
        let parent_hashes: Vec<[u8; 32]> = BincodeSerialize::from_bytes(&value.value())?;
        Ok(parent_hashes.into_iter().map(Hash).collect())
    }

    /// Get child hashes for a block (internal helper).
    fn get_children_internal(
        &self,
        txn: &WriteTransaction,
        hash: &[u8; 32],
    ) -> Result<Vec<[u8; 32]>, ConsensusStoreError> {
        let table = txn.open_table(crate::tables::DAG_CHILDREN)?;
        let value = table.get(*hash)?;
        Ok(value
            .map(|v| BincodeSerialize::from_bytes(&v.value()).unwrap_or_default())
            .unwrap_or_default())
    }

    /// Get child hashes for a block.
    pub fn get_children(
        &self,
        txn: &WriteTransaction,
        hash: &Hash,
    ) -> Result<Vec<Hash>, ConsensusStoreError> {
        let key = hash_to_bytes(hash);
        Ok(self
            .get_children_internal(txn, &key)?
            .into_iter()
            .map(Hash)
            .collect())
    }

    /// Get all blocks for a given round.
    pub fn get_blocks_by_round(
        &self,
        txn: &ReadTransaction,
        round: Round,
    ) -> Result<Vec<StatementBlock>, ConsensusStoreError> {
        let table = txn.open_table(crate::tables::DAG_BY_ROUND)?;
        let mut blocks = Vec::new();

        for entry in table.range((round, 0u16)..=(round, u16::MAX))? {
            let (_, block_hashes) = entry?;
            let hashes: Vec<[u8; 32]> = BincodeSerialize::from_bytes(&block_hashes.value())?;
            for hash in hashes {
                // Tolerate dangling index entries: a block may have been
                // pruned without its index key fully cleaned up.
                match self.get_dag_block(txn, &Hash(hash)) {
                    Ok(block) => blocks.push(block),
                    Err(ConsensusStoreError::NotFound(_)) => continue,
                    Err(e) => return Err(e),
                }
            }
        }
        Ok(blocks)
    }

    /// Get block for a specific author and round.
    pub fn get_block_by_author_round(
        &self,
        txn: &ReadTransaction,
        author: AuthorityIndex,
        round: Round,
    ) -> Result<Option<StatementBlock>, ConsensusStoreError> {
        let table = txn.open_table(crate::tables::DAG_BY_AUTHOR)?;
        let hashes: Option<Vec<[u8; 32]>> = table
            .get((author, round))?
            .map(|v| BincodeSerialize::from_bytes(&v.value()).ok())
            .flatten();

        match hashes {
            Some(hashes) if !hashes.is_empty() => {
                // Return the first (should only be one per author per round)
                Ok(Some(self.get_dag_block(txn, &Hash(hashes[0]))?))
            }
            _ => Ok(None),
        }
    }

    /// Check if a DAG block exists.
    pub fn has_dag_block(
        &self,
        txn: &ReadTransaction,
        hash: &Hash,
    ) -> Result<bool, ConsensusStoreError> {
        let key = hash_to_bytes(hash);
        let table = txn.open_table(crate::tables::DAG_BLOCKS)?;
        Ok(table.get(key)?.is_some())
    }

    // ============================================================
    // Commit tracker operations
    // ============================================================

    /// Get the current committed leader height.
    pub fn get_committed_leader_height(
        &self,
        txn: &ReadTransaction,
    ) -> Result<u64, ConsensusStoreError> {
        let table = txn.open_table(crate::tables::COMMITTED_LEADER_HEIGHT)?;
        Ok(table.get("height")?.map(|v| v.value()).unwrap_or(0))
    }

    /// Set the committed leader height.
    pub fn set_committed_leader_height(
        &self,
        txn: &WriteTransaction,
        height: u64,
    ) -> Result<(), ConsensusStoreError> {
        let mut table = txn.open_table(crate::tables::COMMITTED_LEADER_HEIGHT)?;
        table.insert("height", &height)?;
        Ok(())
    }

    /// Increment the committed leader height.
    pub fn increment_committed_leader_height(
        &self,
        txn: &WriteTransaction,
    ) -> Result<u64, ConsensusStoreError> {
        let table = txn.open_table(crate::tables::COMMITTED_LEADER_HEIGHT)?;
        let height = table.get("height")?.map(|v| v.value()).unwrap_or(0) + 1;
        drop(table);
        let mut table = txn.open_table(crate::tables::COMMITTED_LEADER_HEIGHT)?;
        table.insert("height", &height)?;
        Ok(height)
    }

    /// Get the last committed leader block hash.
    pub fn get_last_committed(
        &self,
        txn: &ReadTransaction,
    ) -> Result<Option<Hash>, ConsensusStoreError> {
        let table = txn.open_table(crate::tables::LAST_COMMITED)?;
        Ok(table.get("last")?.map(|v| Hash(v.value())))
    }

    /// Set the last committed leader block hash.
    pub fn set_last_committed(
        &self,
        txn: &WriteTransaction,
        hash: &Hash,
    ) -> Result<(), ConsensusStoreError> {
        let mut table = txn.open_table(crate::tables::LAST_COMMITED)?;
        table.insert("last", hash_to_bytes(hash))?;
        Ok(())
    }

    // ============================================================
    // Genesis marker (#86 follow-up)
    // ============================================================

    /// Persist the genesis config digest this consensus database belongs to.
    ///
    /// `state.redb` has its own copy; keeping one here too means a partial
    /// wipe (only `state.redb` removed) cannot reopen an old DAG and commit
    /// cursor under a freshly initialised genesis state.
    pub fn save_genesis_marker(
        &self,
        txn: &WriteTransaction,
        digest: &Hash,
    ) -> Result<(), ConsensusStoreError> {
        let mut table = txn.open_table(crate::tables::GENESIS_DIGEST)?;
        table.insert("genesis", digest.0)?;
        Ok(())
    }

    /// The genesis config digest stored in this consensus database, if any.
    pub fn load_genesis_marker(
        &self,
        txn: &ReadTransaction,
    ) -> Result<Option<Hash>, ConsensusStoreError> {
        let table = txn.open_table(crate::tables::GENESIS_DIGEST)?;
        Ok(table.get("genesis")?.map(|v| Hash(v.value())))
    }

    // ============================================================
    // Decided rounds operations
    // ============================================================

    /// Mark a round as decided with a leader hash.
    pub fn mark_round_decided(
        &self,
        txn: &WriteTransaction,
        round: Round,
        leader_hash: &Hash,
    ) -> Result<(), ConsensusStoreError> {
        let mut table = txn.open_table(crate::tables::DECIDED_ROUNDS)?;
        let mut existing: Vec<[u8; 32]> = table
            .get(round)?
            .map(|v| BincodeSerialize::from_bytes(&v.value()).unwrap_or_default())
            .unwrap_or_default();
        existing.push(hash_to_bytes(leader_hash));
        table.insert(round, existing.to_bytes()?)?;
        Ok(())
    }

    /// Check if a round is decided.
    pub fn is_round_decided(
        &self,
        txn: &ReadTransaction,
        round: Round,
    ) -> Result<bool, ConsensusStoreError> {
        let table = txn.open_table(crate::tables::DECIDED_ROUNDS)?;
        Ok(table.get(round)?.is_some())
    }

    /// Get decided leader hashes for a round.
    pub fn get_decided_leaders(
        &self,
        txn: &ReadTransaction,
        round: Round,
    ) -> Result<Vec<Hash>, ConsensusStoreError> {
        let table = txn.open_table(crate::tables::DECIDED_ROUNDS)?;
        Ok(table
            .get(round)?
            .map(|v| {
                let hashes: Vec<[u8; 32]> =
                    BincodeSerialize::from_bytes(&v.value()).unwrap_or_default();
                hashes.into_iter().map(Hash).collect()
            })
            .unwrap_or_default())
    }

    /// Get all decided rounds up to a maximum.
    pub fn get_decided_rounds(
        &self,
        txn: &ReadTransaction,
        max_round: Round,
    ) -> Result<Vec<Round>, ConsensusStoreError> {
        let table = txn.open_table(crate::tables::DECIDED_ROUNDS)?;
        let mut rounds = Vec::new();
        for entry in table.range(0..=max_round)? {
            let (round, _) = entry?;
            rounds.push(round.value());
        }
        Ok(rounds)
    }

    /// Highest round that still has at least one stored DAG block, if any.
    ///
    /// The consensus engine uses this to resume its round counter after a
    /// restart: replaying from round 0 would re-propose rounds the store
    /// already holds and abort on a conflicting decision. `None` means the
    /// DAG is empty (a fresh chain legitimately starts at round 0).
    pub fn max_dag_round(
        &self,
        txn: &ReadTransaction,
    ) -> Result<Option<Round>, ConsensusStoreError> {
        let table = txn.open_table(crate::tables::DAG_BY_ROUND)?;
        match table.range((0u64, 0u16)..)?.next_back() {
            Some(entry) => {
                let (key, _) = entry?;
                Ok(Some(key.value().0))
            }
            None => Ok(None),
        }
    }

    // ============================================================
    // Vote operations
    // ============================================================

    /// Store a vote for a leader round, keyed by `(leader_round, voter)`.
    /// Re-storing the same `(round, voter)` overwrites the previous entry.
    pub fn put_vote(&self, txn: &WriteTransaction, vote: &Vote) -> Result<(), ConsensusStoreError> {
        let mut table = txn.open_table(crate::tables::VOTES)?;
        table.insert((vote.leader_round, vote.voter), vote.to_bytes()?)?;
        Ok(())
    }

    /// All votes stored for a leader round, ordered by voter index (ascending).
    /// Returns an empty vec when the round has no votes.
    pub fn get_votes_for_round(
        &self,
        txn: &ReadTransaction,
        round: Round,
    ) -> Result<Vec<Vote>, ConsensusStoreError> {
        let table = txn.open_table(crate::tables::VOTES)?;
        let mut votes = Vec::new();

        for entry in table.range((round, 0u16)..=(round, u16::MAX))? {
            let (_, value) = entry?;
            let vote: Vote = BincodeSerialize::from_bytes(&value.value())?;
            votes.push(vote);
        }

        // The range scan already yields ascending keys, but sort explicitly so
        // the ordering guarantee does not depend on the storage backend.
        votes.sort_by_key(|vote| vote.voter);
        Ok(votes)
    }

    /// Persist a verified leader-slot timeout under (round, voter).
    pub fn put_timeout(
        &self,
        txn: &WriteTransaction,
        timeout: &Timeout,
    ) -> Result<(), ConsensusStoreError> {
        let mut table = txn.open_table(crate::tables::TIMEOUTS)?;
        table.insert((timeout.round, timeout.voter), timeout.to_bytes()?)?;
        Ok(())
    }

    /// All timeouts stored for a leader slot, ordered by voter index.
    pub fn get_timeouts_for_round(
        &self,
        txn: &ReadTransaction,
        round: Round,
    ) -> Result<Vec<Timeout>, ConsensusStoreError> {
        let table = txn.open_table(crate::tables::TIMEOUTS)?;
        let mut timeouts = Vec::new();
        for entry in table.range((round, 0u16)..=(round, u16::MAX))? {
            let (_, value) = entry?;
            let timeout: Timeout = BincodeSerialize::from_bytes(&value.value())?;
            timeouts.push(timeout);
        }
        timeouts.sort_by_key(|t| t.voter);
        Ok(timeouts)
    }

    /// Mark `round` decided as a certified skip: an entry with no leaders.
    ///
    /// The decided-round index then contains the round (so the commit cursor
    /// is restored past it) while `get_decided_leaders` returns nothing (so
    /// replay and causal-history walks commit nothing for it). Returns
    /// `false` without writing if the round already holds a leader decision.
    pub fn mark_round_skipped(
        &self,
        txn: &WriteTransaction,
        round: Round,
    ) -> Result<bool, ConsensusStoreError> {
        let mut table = txn.open_table(crate::tables::DECIDED_ROUNDS)?;
        let existing: Vec<[u8; 32]> = table
            .get(round)?
            .map(|v| BincodeSerialize::from_bytes(&v.value()).unwrap_or_default())
            .unwrap_or_default();
        if !existing.is_empty() {
            return Ok(false);
        }
        let empty: Vec<[u8; 32]> = Vec::new();
        table.insert(round, empty.to_bytes()?)?;
        Ok(true)
    }

    /// Whether a vote from `voter` for `leader_round` is stored.
    pub fn has_vote(
        &self,
        txn: &ReadTransaction,
        leader_round: Round,
        voter: AuthorityIndex,
    ) -> Result<bool, ConsensusStoreError> {
        let table = txn.open_table(crate::tables::VOTES)?;
        Ok(table.get((leader_round, voter))?.is_some())
    }

    /// Delete every vote for rounds strictly below `cutoff`. Returns the number of
    /// entries removed.
    /// Remove the votes of every leader round strictly below `cutoff`.
    ///
    /// At most `limit` rows are removed in one call so a retention pass is
    /// always bounded; the caller repeats the pass to make further progress.
    ///
    /// A caller must never prune votes ahead of the blocks they belong to: a
    /// joining node asks for the votes of a round *after* it synced that
    /// round's leader block, so a vote that is gone while its block is still
    /// served turns a catch-up into a stall.
    pub fn prune_votes_below(
        &self,
        txn: &WriteTransaction,
        cutoff: Round,
        limit: usize,
    ) -> Result<usize, ConsensusStoreError> {
        if limit == 0 {
            return Ok(0);
        }
        // Collect the keys first: redb does not allow mutating a table while a
        // range iterator over it is alive.
        let keys_to_remove: Vec<(u64, u16)> = {
            let table = txn.open_table(crate::tables::VOTES)?;
            let mut keys = Vec::new();
            for entry in table.range(..(cutoff, 0u16))?.take(limit) {
                let (key, _) = entry?;
                keys.push(key.value());
            }
            keys
        }; // table is dropped here

        if keys_to_remove.is_empty() {
            return Ok(0);
        }

        let mut table = txn.open_table(crate::tables::VOTES)?;
        for key in &keys_to_remove {
            table.remove(*key)?;
        }
        Ok(keys_to_remove.len())
    }

    // ============================================================
    // Pruning
    // ============================================================

    /// Prune DAG blocks below a certain round (keep only recent history).
    pub fn prune_dag_below(
        &self,
        txn: &WriteTransaction,
        min_round: Round,
    ) -> Result<u64, ConsensusStoreError> {
        let mut pruned = 0;

        // Collect blocks to prune and round/author index keys to remove
        let mut blocks_to_prune = Vec::new();
        let mut round_keys_to_remove = Vec::new();
        let mut author_keys_to_remove = Vec::new();

        {
            let table = txn.open_table(crate::tables::DAG_BY_ROUND)?;
            for entry in table.range((0u64, 0u16)..=(min_round, u16::MAX))? {
                let (key, block_hashes) = entry?;
                let hashes: Vec<[u8; 32]> = BincodeSerialize::from_bytes(&block_hashes.value())?;
                for hash in hashes {
                    blocks_to_prune.push(hash);
                }
                let (round, author) = key.value();
                round_keys_to_remove.push((round, author));
                author_keys_to_remove.push((author, round));
            }
        } // table is dropped here

        // Delete blocks and their links
        for block_hash in blocks_to_prune {
            // Remove from dag_blocks
            {
                let mut table = txn.open_table(crate::tables::DAG_BLOCKS)?;
                table.remove(block_hash)?;
            }
            // Remove from dag_parents
            {
                let mut table = txn.open_table(crate::tables::DAG_PARENTS)?;
                table.remove(block_hash)?;
            }
            // Update the deleted block's parents' children lists, and drop the
            // deleted block from each surviving child's parent list so no
            // dangling parent edge survives pruning (M2).
            {
                let parents = self.get_parents_internal(&*txn, &block_hash)?;
                for parent_hash in parents {
                    let mut children = self.get_children_internal(&*txn, &parent_hash)?;
                    children.retain(|h| *h != block_hash);
                    let mut child_table = txn.open_table(crate::tables::DAG_CHILDREN)?;
                    child_table.insert(parent_hash, children.to_bytes()?)?;
                }

                let children = self.get_children_internal(&*txn, &block_hash)?;
                for child_hash in children {
                    if child_hash == block_hash {
                        continue;
                    }
                    let mut table = txn.open_table(crate::tables::DAG_PARENTS)?;
                    let existing: Vec<[u8; 32]> = table
                        .get(child_hash)?
                        .map(|v| BincodeSerialize::from_bytes(&v.value()).unwrap_or_default())
                        .unwrap_or_default();
                    let filtered: Vec<[u8; 32]> =
                        existing.into_iter().filter(|h| *h != block_hash).collect();
                    if filtered.is_empty() {
                        table.remove(child_hash)?;
                    } else {
                        table.insert(child_hash, filtered.to_bytes()?)?;
                    }
                }
            }
            // Remove from dag_children
            {
                let mut table = txn.open_table(crate::tables::DAG_CHILDREN)?;
                table.remove(block_hash)?;
            }
            pruned += 1;
        }

        // Clean up round index
        {
            let mut round_table = txn.open_table(crate::tables::DAG_BY_ROUND)?;
            for key in round_keys_to_remove {
                round_table.remove(key)?;
            }
        }

        // Clean up author index alongside the round index so the author index
        // does not grow without bound and `get_block_by_author_round` cannot
        // resolve a pruned block (M2 m2).
        {
            let mut author_table = txn.open_table(crate::tables::DAG_BY_AUTHOR)?;
            for key in author_keys_to_remove {
                author_table.remove(key)?;
            }
        }

        Ok(pruned)
    }

    /// Internal helper to get parents without Hash wrapper.
    fn get_parents_internal(
        &self,
        txn: &WriteTransaction,
        hash: &[u8; 32],
    ) -> Result<Vec<[u8; 32]>, ConsensusStoreError> {
        let table = txn.open_table(crate::tables::DAG_PARENTS)?;
        let value = table.get(*hash)?;
        Ok(value
            .map(|v| BincodeSerialize::from_bytes(&v.value()).unwrap_or_default())
            .unwrap_or_default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{tables, Storage};
    use kovanica_types::crypto::Signature;
    use std::collections::HashSet;
    use tempfile::tempdir;

    fn make_block(author: AuthorityIndex, round: Round, tag: &str) -> StatementBlock {
        StatementBlock {
            author,
            round,
            parents: Vec::new(),
            transactions: Vec::new(),
            statements: tag.as_bytes().to_vec(),
            signature: Signature([0u8; 64]),
            digest: Hash::new(format!("kovanica-consensus-store-test/{tag}").as_bytes()),
            merkle_root: Hash::zero(),
        }
    }

    // #5a: `get_blocks_by_round` must skip index entries whose block no longer
    // exists (e.g. a hash left behind after pruning).
    #[test]
    fn get_blocks_by_round_skips_dangling_index_entries() {
        let dir = tempdir().unwrap();
        let storage = Storage::new(dir.path().join("consensus.redb")).unwrap();
        let store = storage.consensus();

        let block_a = make_block(0, 3, "a");
        let block_b = make_block(1, 3, "b");
        let stale = Hash::new(b"kovanica-consensus-store-test/stale");

        {
            let txn = storage.begin_write().unwrap();
            store.put_dag_block(&txn, &block_a).unwrap();
            store.put_dag_block(&txn, &block_b).unwrap();

            // Inject a hash that has no corresponding block into the
            // (round=3, author=0) index entry.
            {
                let mut table = txn.open_table(tables::DAG_BY_ROUND).unwrap();
                let mut existing: Vec<[u8; 32]> = table
                    .get((3u64, 0u16))
                    .unwrap()
                    .map(|v| BincodeSerialize::from_bytes(&v.value()).unwrap_or_default())
                    .unwrap_or_default();
                existing.push(hash_to_bytes(&stale));
                table
                    .insert((3u64, 0u16), existing.to_bytes().unwrap())
                    .unwrap();
            }
            txn.commit().unwrap();
        }

        let txn = storage.begin_read().unwrap();
        let round_blocks = store.get_blocks_by_round(&txn, 3).unwrap();
        assert_eq!(round_blocks.len(), 2, "stale index entry must be skipped");
        let digests: HashSet<Hash> = round_blocks.iter().map(|block| block.digest).collect();
        assert!(digests.contains(&block_a.digest));
        assert!(digests.contains(&block_b.digest));
        assert!(!digests.contains(&stale), "missing block must not surface");
    }

    fn make_vote(leader_round: Round, voter: AuthorityIndex, tag: &str) -> Vote {
        Vote {
            leader_round,
            leader_hash: Hash::new(format!("kovanica-consensus-store-test/vote/{tag}").as_bytes()),
            voter,
            signature: Signature([0u8; 64]),
        }
    }

    #[test]
    fn put_vote_then_get_votes_for_round_round_trips() {
        let dir = tempdir().unwrap();
        let storage = Storage::new(dir.path().join("votes.redb")).unwrap();
        let store = storage.consensus();

        let vote = make_vote(7, 3, "a");
        {
            let txn = storage.begin_write().unwrap();
            store.put_vote(&txn, &vote).unwrap();
            txn.commit().unwrap();
        }

        let txn = storage.begin_read().unwrap();
        let votes = store.get_votes_for_round(&txn, 7).unwrap();
        assert_eq!(votes.len(), 1, "exactly one vote must be stored");
        assert_eq!(votes[0].leader_round, vote.leader_round);
        assert_eq!(votes[0].leader_hash, vote.leader_hash);
        assert_eq!(votes[0].voter, vote.voter);
        assert_eq!(votes[0].signature, vote.signature);
        assert_eq!(votes[0], vote);
    }

    #[test]
    fn get_votes_for_round_returns_votes_sorted_by_voter() {
        let dir = tempdir().unwrap();
        let storage = Storage::new(dir.path().join("votes.redb")).unwrap();
        let store = storage.consensus();

        // Insert out of voter order to prove the accessor sorts.
        let voter_high = make_vote(9, 11, "high");
        let voter_low = make_vote(9, 2, "low");
        let voter_mid = make_vote(9, 7, "mid");
        {
            let txn = storage.begin_write().unwrap();
            store.put_vote(&txn, &voter_high).unwrap();
            store.put_vote(&txn, &voter_low).unwrap();
            store.put_vote(&txn, &voter_mid).unwrap();
            txn.commit().unwrap();
        }

        let txn = storage.begin_read().unwrap();
        let votes = store.get_votes_for_round(&txn, 9).unwrap();
        assert_eq!(votes.len(), 3, "all three votes must be returned");
        assert_eq!(
            votes.iter().map(|v| v.voter).collect::<Vec<_>>(),
            vec![2, 7, 11],
            "votes must be ordered by voter index ascending"
        );
        assert_eq!(votes[0], voter_low);
        assert_eq!(votes[1], voter_mid);
        assert_eq!(votes[2], voter_high);
    }

    #[test]
    fn has_vote_reports_stored_pairs_only() {
        let dir = tempdir().unwrap();
        let storage = Storage::new(dir.path().join("votes.redb")).unwrap();
        let store = storage.consensus();

        let vote = make_vote(4, 5, "a");
        {
            let txn = storage.begin_write().unwrap();
            store.put_vote(&txn, &vote).unwrap();
            txn.commit().unwrap();
        }

        let txn = storage.begin_read().unwrap();
        assert!(
            store.has_vote(&txn, 4, 5).unwrap(),
            "stored vote must be found"
        );
        assert!(
            !store.has_vote(&txn, 4, 6).unwrap(),
            "another voter for the same round must not be found"
        );
        assert!(
            !store.has_vote(&txn, 5, 5).unwrap(),
            "the same voter in another round must not be found"
        );
        assert!(
            store.get_votes_for_round(&txn, 123).unwrap().is_empty(),
            "a round without votes must return an empty vec"
        );
    }

    #[test]
    fn prune_votes_below_removes_only_older_rounds() {
        let dir = tempdir().unwrap();
        let storage = Storage::new(dir.path().join("votes.redb")).unwrap();
        let store = storage.consensus();

        let old_a = make_vote(1, 0, "old-a");
        let old_b = make_vote(1, 1, "old-b");
        let at_cutoff = make_vote(5, 0, "at-cutoff");
        let newer = make_vote(9, 0, "newer");
        {
            let txn = storage.begin_write().unwrap();
            store.put_vote(&txn, &old_a).unwrap();
            store.put_vote(&txn, &old_b).unwrap();
            store.put_vote(&txn, &at_cutoff).unwrap();
            store.put_vote(&txn, &newer).unwrap();
            txn.commit().unwrap();
        }

        {
            let txn = storage.begin_write().unwrap();
            let removed = store.prune_votes_below(&txn, 5, 64).unwrap();
            assert_eq!(removed, 2, "both votes below the cutoff must be removed");
            txn.commit().unwrap();
        }

        let txn = storage.begin_read().unwrap();
        assert!(
            store.get_votes_for_round(&txn, 1).unwrap().is_empty(),
            "votes below the cutoff must be gone"
        );
        let at_cutoff_votes = store.get_votes_for_round(&txn, 5).unwrap();
        assert_eq!(at_cutoff_votes.len(), 1, "the cutoff round must survive");
        assert_eq!(at_cutoff_votes[0], at_cutoff);
        let newer_votes = store.get_votes_for_round(&txn, 9).unwrap();
        assert_eq!(newer_votes.len(), 1, "rounds above the cutoff must survive");
        assert_eq!(newer_votes[0], newer);
        assert!(!store.has_vote(&txn, 1, 0).unwrap());
    }

    #[test]
    fn prune_votes_below_respects_the_batch_limit() {
        let dir = tempdir().unwrap();
        let storage = Storage::new(dir.path().join("votes-batch.redb")).unwrap();
        let store = storage.consensus();

        {
            let txn = storage.begin_write().unwrap();
            for round in 0..10 {
                store.put_vote(&txn, &make_vote(round, 0, "old")).unwrap();
            }
            txn.commit().unwrap();
        }

        let mut removed_total = 0;
        for _ in 0..10 {
            let txn = storage.begin_write().unwrap();
            let removed = store.prune_votes_below(&txn, 100, 3).unwrap();
            txn.commit().unwrap();
            removed_total += removed;
            if removed == 0 {
                break;
            }
        }
        assert_eq!(removed_total, 10, "repeated passes drain the table");

        let txn = storage.begin_read().unwrap();
        for round in 0..10 {
            assert!(
                store.get_votes_for_round(&txn, round).unwrap().is_empty(),
                "every vote must eventually be removed"
            );
        }
    }

    #[test]
    fn prune_votes_below_with_a_zero_limit_removes_nothing() {
        let dir = tempdir().unwrap();
        let storage = Storage::new(dir.path().join("votes-zero.redb")).unwrap();
        let store = storage.consensus();

        {
            let txn = storage.begin_write().unwrap();
            store.put_vote(&txn, &make_vote(1, 0, "old")).unwrap();
            txn.commit().unwrap();
        }

        let txn = storage.begin_write().unwrap();
        assert_eq!(store.prune_votes_below(&txn, 100, 0).unwrap(), 0);
        drop(txn);
        let read = storage.begin_read().unwrap();
        assert!(store.has_vote(&read, 1, 0).unwrap());
    }

    #[test]
    fn genesis_marker_round_trips_and_starts_empty() {
        let dir = tempdir().unwrap();
        let storage = Storage::new(dir.path().join("consensus.redb")).unwrap();
        let store = storage.consensus();
        assert_eq!(
            store
                .load_genesis_marker(&storage.begin_read().unwrap())
                .unwrap(),
            None
        );
        let digest = Hash([0x42; 32]);
        let txn = storage.begin_write().unwrap();
        store.save_genesis_marker(&txn, &digest).unwrap();
        txn.commit().unwrap();
        assert_eq!(
            store
                .load_genesis_marker(&storage.begin_read().unwrap())
                .unwrap(),
            Some(digest)
        );
    }

    // PRO-40 (b): timeouts round-trip, sorted by voter, per round.
    #[test]
    fn put_timeout_then_get_timeouts_for_round_round_trips_sorted() {
        let dir = tempdir().unwrap();
        let storage = Storage::new(dir.path().join("timeouts.redb")).unwrap();
        let store = storage.consensus();
        let t = |round, voter: AuthorityIndex| Timeout {
            round,
            voter,
            signature: Signature([voter as u8; 64]),
        };
        {
            let txn = storage.begin_write().unwrap();
            store.put_timeout(&txn, &t(12, 4)).unwrap();
            store.put_timeout(&txn, &t(12, 1)).unwrap();
            store.put_timeout(&txn, &t(15, 0)).unwrap();
            txn.commit().unwrap();
        }
        let txn = storage.begin_read().unwrap();
        assert_eq!(
            store.get_timeouts_for_round(&txn, 12).unwrap(),
            vec![t(12, 1), t(12, 4)]
        );
        assert_eq!(
            store.get_timeouts_for_round(&txn, 15).unwrap(),
            vec![t(15, 0)]
        );
        assert!(store.get_timeouts_for_round(&txn, 18).unwrap().is_empty());
    }

    // PRO-40 (b): a skipped round is decided with no leaders, and a skip
    // never overwrites a leader decision.
    #[test]
    fn mark_round_skipped_records_an_empty_decision_and_never_overrides_a_commit() {
        let dir = tempdir().unwrap();
        let storage = Storage::new(dir.path().join("skip.redb")).unwrap();
        let store = storage.consensus();
        let leader = Hash::new(b"kovanica-consensus-store-test/skip/leader");
        {
            let txn = storage.begin_write().unwrap();
            assert!(store.mark_round_skipped(&txn, 6).unwrap());
            assert!(store.mark_round_skipped(&txn, 6).unwrap(), "idempotent");
            store.mark_round_decided(&txn, 9, &leader).unwrap();
            assert!(!store.mark_round_skipped(&txn, 9).unwrap());
            txn.commit().unwrap();
        }
        let txn = storage.begin_read().unwrap();
        assert!(store.is_round_decided(&txn, 6).unwrap());
        assert!(store.get_decided_leaders(&txn, 6).unwrap().is_empty());
        assert_eq!(store.get_decided_leaders(&txn, 9).unwrap(), vec![leader]);
    }
}
