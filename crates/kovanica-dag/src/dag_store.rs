//! DAG store for Kovanica.
//!
#![allow(missing_docs)]
//! Provides high-level operations on the DAG structure using the storage layer.

use kovanica_storage::{hash_to_bytes, tables, BincodeSerialize, ConsensusStoreError, Storage};
use kovanica_types::{
    block::{BlockReference, StatementBlock},
    hash::Hash,
    AuthorityIndex, Round,
};
use redb::{
    CommitError, ReadTransaction, ReadableTable, TableDefinition, TableError, WriteTransaction,
};
use std::collections::{HashSet, VecDeque};
use std::sync::Arc;
use thiserror::Error;

/// Errors specific to DAG store operations.
#[derive(Error, Debug)]
pub enum DagStoreError {
    #[error("Block not found: {0}")]
    NotFound(String),
    #[error("Storage error: {0}")]
    Storage(#[from] kovanica_storage::StorageError),
    #[error("Consensus store error: {0}")]
    ConsensusStore(#[from] kovanica_storage::ConsensusStoreError),
    #[error("Block store error: {0}")]
    BlockStore(#[from] kovanica_storage::BlockStoreError),
    #[error("State store error: {0}")]
    StateStore(#[from] kovanica_storage::StateStoreError),
    #[error("Commit error: {0}")]
    Commit(#[from] CommitError),
    #[error("Table error: {0}")]
    Table(#[from] TableError),
    #[error("Redb storage error: {0}")]
    RedbStorage(#[from] redb::StorageError),
    #[error("Serialization error: {0}")]
    Serialization(#[from] bincode::Error),
    #[error(
        "Round {round} already decided for a different leader (existing {existing:?}, new {new})"
    )]
    ConflictingDecision {
        round: Round,
        existing: Vec<Hash>,
        new: Hash,
    },
}

/// Durable prune boundary: every DAG round strictly below the stored value
/// has been pruned. Written in the same redb write transaction as the pruning
/// itself, so the boundary and the deletion are atomic.
const DAG_PRUNE_BOUNDARY: TableDefinition<&str, u64> = TableDefinition::new("dag_prune_boundary");
const DAG_PRUNE_BOUNDARY_KEY: &str = "round";

/// Durable catch-up anchor: a leader round certified by a commit-seal quorum
/// or a verified state-sync checkpoint. The consensus engine advances a
/// lagging cursor to this round. Monotonic. Absent until one is noted.
const DAG_CATCHUP_ANCHOR: TableDefinition<&str, u64> = TableDefinition::new("dag_catchup_anchor");
const DAG_CATCHUP_ANCHOR_KEY: &str = "leader_round";

/// DAG store for high-level DAG operations.
#[derive(Clone)]
pub struct DagStore {
    storage: Arc<Storage>,
    /// Test-only instrumentation: number of `get_block` calls.
    #[cfg(test)]
    get_block_calls: Arc<std::sync::atomic::AtomicU64>,
}

impl DagStore {
    /// Create a new DAG store.
    pub fn new(storage: Storage) -> Result<Self, DagStoreError> {
        Ok(Self::from_storage(Arc::new(storage)))
    }

    /// Wrap an existing shared [`Storage`] handle.
    ///
    /// All stores (block, state, consensus) already share a single redb
    /// database, so a caller that already holds an `Arc<Storage>` can build a
    /// `DagStore` over it without reopening the database (handy for tests and
    /// for exposing the DAG view alongside the state view).
    pub fn from_storage(storage: Arc<Storage>) -> Self {
        Self {
            storage,
            #[cfg(test)]
            get_block_calls: Arc::default(),
        }
    }

    /// The shared storage handle this store reads and writes.
    ///
    /// The block, state and consensus tables all live in the same redb file,
    /// so a caller that needs a table the DAG API does not expose (the vote
    /// table, for example) reaches it through this handle. The returned
    /// handle is the same one the store was built from, so writes through it
    /// are visible to the store immediately.
    pub fn storage(&self) -> &Arc<Storage> {
        &self.storage
    }

    /// Test-only: number of `get_block` calls made so far.
    #[cfg(test)]
    pub(crate) fn get_block_calls(&self) -> u64 {
        self.get_block_calls
            .load(std::sync::atomic::Ordering::SeqCst)
    }

    /// Durable prune boundary: every round strictly below it has been pruned
    /// (0 if nothing was ever pruned). Survives restarts.
    pub fn prune_boundary(&self) -> Result<Round, DagStoreError> {
        let txn = self.storage.begin_read()?;
        let table = match txn.open_table(DAG_PRUNE_BOUNDARY) {
            Ok(table) => table,
            Err(TableError::TableDoesNotExist(_)) => return Ok(0),
            Err(e) => return Err(e.into()),
        };
        let boundary = table.get(DAG_PRUNE_BOUNDARY_KEY)?.map(|v| v.value());
        Ok(boundary.unwrap_or(0))
    }

    /// Raise (never lower) the prune boundary inside `txn`, i.e. in the same
    /// transaction as the pruning it describes.
    fn raise_prune_boundary(
        &self,
        txn: &WriteTransaction,
        boundary: Round,
    ) -> Result<(), DagStoreError> {
        let mut table = txn.open_table(DAG_PRUNE_BOUNDARY)?;
        let current = table
            .get(DAG_PRUNE_BOUNDARY_KEY)?
            .map(|v| v.value())
            .unwrap_or(0);
        if boundary > current {
            table.insert(DAG_PRUNE_BOUNDARY_KEY, boundary)?;
        }
        Ok(())
    }

    /// Leader round of a verified commit-seal quorum or state-sync checkpoint.
    ///
    /// `None` when no anchor has been noted. Survives restarts.
    pub fn certified_catchup_anchor(&self) -> Result<Option<Round>, DagStoreError> {
        let txn = self.storage.begin_read()?;
        let table = match txn.open_table(DAG_CATCHUP_ANCHOR) {
            Ok(table) => table,
            Err(TableError::TableDoesNotExist(_)) => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        Ok(table.get(DAG_CATCHUP_ANCHOR_KEY)?.map(|v| v.value()))
    }

    /// Raise (never lower) the certified catch-up anchor.
    ///
    /// Rounds that are not leader slots (`round % WAVE_LENGTH == 0`, and not
    /// genesis) are ignored. The engine refuses those too, so a caller cannot
    /// park the cursor in the middle of a wave.
    pub fn note_certified_catchup_anchor(&self, leader_round: Round) -> Result<(), DagStoreError> {
        if leader_round == 0 || !leader_round.is_multiple_of(kovanica_types::WAVE_LENGTH) {
            return Ok(());
        }
        let txn = self.storage.begin_write()?;
        {
            let mut table = txn.open_table(DAG_CATCHUP_ANCHOR)?;
            let current = table
                .get(DAG_CATCHUP_ANCHOR_KEY)?
                .map(|v| v.value())
                .unwrap_or(0);
            if leader_round > current {
                table.insert(DAG_CATCHUP_ANCHOR_KEY, leader_round)?;
            }
        }
        txn.commit()?;
        Ok(())
    }

    /// Get a block by hash.
    ///
    /// A missing block is reported as [`DagStoreError::NotFound`] (rather than
    /// the wrapped `ConsensusStoreError::NotFound`) so that every caller which
    /// tolerates a pruned/absent block can match on the same variant — the
    /// in-memory DAG implementations used in tests behave the same way.
    pub fn get_block(&self, hash: &Hash) -> Result<StatementBlock, DagStoreError> {
        #[cfg(test)]
        self.get_block_calls
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let txn = self.storage.begin_read()?;
        match self.storage.consensus().get_dag_block(&txn, hash) {
            Ok(block) => Ok(block),
            Err(ConsensusStoreError::NotFound(msg)) => Err(DagStoreError::NotFound(msg)),
            Err(e) => Err(e.into()),
        }
    }

    /// Get multiple blocks by their hashes.
    /// Returns only the blocks that are found (missing blocks are silently skipped).
    pub fn get_blocks(&self, hashes: &[Hash]) -> Result<Vec<StatementBlock>, DagStoreError> {
        let txn = self.storage.begin_read()?;
        let mut blocks = Vec::with_capacity(hashes.len());
        for hash in hashes {
            if let Ok(block) = self.storage.consensus().get_dag_block(&txn, hash) {
                blocks.push(block);
            }
        }
        Ok(blocks)
    }

    /// Check if a block exists.
    pub fn has_block(&self, hash: &Hash) -> Result<bool, DagStoreError> {
        let txn = self.storage.begin_read()?;
        Ok(self.storage.consensus().has_dag_block(&txn, hash)?)
    }

    /// Get parent hashes for a block.
    ///
    /// A missing parent list is reported as [`DagStoreError::NotFound`] for the
    /// same reason as [`Self::get_block`]: the M2 backstop treats a deleted
    /// block's parent edge as a leaf rather than a hard error.
    pub fn get_parents(&self, hash: &Hash) -> Result<Vec<Hash>, DagStoreError> {
        let txn = self.storage.begin_read()?;
        match self.storage.consensus().get_parents(&txn, hash) {
            Ok(parents) => Ok(parents),
            Err(ConsensusStoreError::NotFound(msg)) => Err(DagStoreError::NotFound(msg)),
            Err(e) => Err(e.into()),
        }
    }

    /// Get child hashes for a block.
    pub fn get_children(&self, hash: &Hash) -> Result<Vec<Hash>, DagStoreError> {
        let txn = self.storage.begin_read()?;
        // get_children requires a write transaction in the current implementation
        // For read-only access, we need to use a different approach
        // For now, we'll use a write transaction but only read
        let txn = self.storage.begin_write()?;
        let children = self.storage.consensus().get_children(&txn, hash)?;
        txn.commit()?;
        Ok(children)
    }

    /// Get all blocks for a given round.
    pub fn get_blocks_by_round(&self, round: Round) -> Result<Vec<StatementBlock>, DagStoreError> {
        let txn = self.storage.begin_read()?;
        Ok(self.storage.consensus().get_blocks_by_round(&txn, round)?)
    }

    /// Get block for a specific author and round.
    pub fn get_block_by_author_round(
        &self,
        author: AuthorityIndex,
        round: Round,
    ) -> Result<Option<StatementBlock>, DagStoreError> {
        let txn = self.storage.begin_read()?;
        Ok(self
            .storage
            .consensus()
            .get_block_by_author_round(&txn, author, round)?)
    }

    /// Get the committed leader height.
    pub fn get_committed_leader_height(&self) -> Result<u64, DagStoreError> {
        let txn = self.storage.begin_read()?;
        Ok(self.storage.consensus().get_committed_leader_height(&txn)?)
    }

    /// Get the last committed leader block hash.
    pub fn get_last_committed(&self) -> Result<Option<Hash>, DagStoreError> {
        let txn = self.storage.begin_read()?;
        Ok(self.storage.consensus().get_last_committed(&txn)?)
    }

    /// Check if a round is decided.
    pub fn is_round_decided(&self, round: Round) -> Result<bool, DagStoreError> {
        let txn = self.storage.begin_read()?;
        Ok(self.storage.consensus().is_round_decided(&txn, round)?)
    }

    /// Get decided leader hashes for a round.
    pub fn get_decided_leaders(&self, round: Round) -> Result<Vec<Hash>, DagStoreError> {
        let txn = self.storage.begin_read()?;
        Ok(self.storage.consensus().get_decided_leaders(&txn, round)?)
    }

    /// Get all decided rounds up to a maximum.
    pub fn get_decided_rounds(&self, max_round: Round) -> Result<Vec<Round>, DagStoreError> {
        let txn = self.storage.begin_read()?;
        Ok(self
            .storage
            .consensus()
            .get_decided_rounds(&txn, max_round)?)
    }

    /// Highest round that still has at least one stored DAG block.
    ///
    /// Returns `None` when the DAG is empty. Used by consensus to resume the
    /// round counter after a restart instead of replaying from round 0.
    pub fn max_dag_round(&self) -> Result<Option<Round>, DagStoreError> {
        let txn = self.storage.begin_read()?;
        Ok(self.storage.consensus().max_dag_round(&txn)?)
    }

    /// Get ancestors of a block up to a certain round (for parent selection).
    pub fn get_ancestors(&self, hash: &Hash, min_round: Round) -> Result<Vec<Hash>, DagStoreError> {
        let mut ancestors = Vec::new();
        let mut visited = HashSet::new();
        let mut queue = VecDeque::new();
        queue.push_back(*hash);

        while let Some(current) = queue.pop_front() {
            if visited.contains(&current) {
                continue;
            }
            visited.insert(current);

            // A parent list may be missing if the block was deleted during
            // pruning; treat it as a leaf rather than failing the whole walk.
            let parents = match self.get_parents(&current) {
                Ok(parents) => parents,
                Err(DagStoreError::NotFound(_)) => continue,
                Err(e) => return Err(e),
            };
            for parent in parents {
                if parent.0 == current.0 {
                    continue;
                }
                // A surviving child may still reference a parent that was
                // pruned away; skip that dangling edge instead of aborting the
                // traversal (M2 backstop).
                let block = match self.get_block(&parent) {
                    Ok(block) => block,
                    Err(DagStoreError::NotFound(_)) => continue,
                    Err(e) => return Err(e),
                };
                if block.round >= min_round {
                    ancestors.push(parent);
                    queue.push_back(parent);
                }
            }
        }

        Ok(ancestors)
    }

    /// Find blocks that can serve as parents for a new block at the given round.
    /// Returns up to `max_parents` blocks from the previous round that are valid parents.
    pub fn find_parents(
        &self,
        round: Round,
        max_parents: usize,
    ) -> Result<Vec<BlockReference>, DagStoreError> {
        if round == 0 {
            return Ok(Vec::new());
        }

        let prev_round = round - 1;
        let blocks = self.get_blocks_by_round(prev_round)?;

        // For now, return all blocks from previous round as parent references
        // In a full implementation, we'd filter by stake weight and validity
        let parents: Vec<BlockReference> = blocks
            .into_iter()
            .take(max_parents)
            .map(|b| BlockReference {
                author: b.author,
                round: b.round,
                digest: b.digest,
            })
            .collect();

        Ok(parents)
    }

    /// Store a new DAG block.
    pub fn put_block(&self, block: &StatementBlock) -> Result<(), DagStoreError> {
        if self.has_block(&block.digest)? {
            return Ok(());
        }
        let txn = self.storage.begin_write()?;
        self.storage.consensus().put_dag_block(&txn, block)?;
        txn.commit()?;
        Ok(())
    }

    /// Swap `existing` for `incoming` in one write transaction.
    ///
    /// Used only by the gated min-digest fork policy. Refuses unless both
    /// blocks share author and round, the existing digest has no children,
    /// the incoming digest is not already stored, and the round is not
    /// decided. A refused call commits nothing.
    pub fn replace_block(
        &self,
        existing: &StatementBlock,
        incoming: &StatementBlock,
    ) -> Result<(), DagStoreError> {
        if existing.author != incoming.author || existing.round != incoming.round {
            return Err(DagStoreError::NotFound(
                "replace requires the same author and round".into(),
            ));
        }
        if existing.digest == incoming.digest {
            return self.put_block(incoming);
        }

        let txn = self.storage.begin_write()?;
        {
            let table = txn.open_table(tables::DECIDED_ROUNDS)?;
            if table.get(existing.round)?.is_some() {
                return Err(DagStoreError::NotFound(format!(
                    "round {} is already decided",
                    existing.round
                )));
            }
        }
        {
            let table = txn.open_table(tables::DAG_BLOCKS)?;
            if table.get(hash_to_bytes(&existing.digest))?.is_none() {
                return Err(DagStoreError::NotFound(existing.digest.to_string()));
            }
            if table.get(hash_to_bytes(&incoming.digest))?.is_some() {
                return Err(DagStoreError::NotFound(
                    "incoming digest already stored".into(),
                ));
            }
        }
        if !self
            .storage
            .consensus()
            .get_children(&txn, &existing.digest)?
            .is_empty()
        {
            return Err(DagStoreError::NotFound(
                "existing leader digest already has children".into(),
            ));
        }

        self.delete_block_internal(&txn, &existing.digest)?;
        self.storage.consensus().put_dag_block(&txn, incoming)?;
        txn.commit()?;
        Ok(())
    }

    /// Mark a round as decided with a leader hash.
    pub fn mark_round_decided(
        &self,
        round: Round,
        leader_hash: &Hash,
    ) -> Result<(), DagStoreError> {
        if self
            .get_decided_leaders(round)?
            .iter()
            .any(|existing| existing == leader_hash)
        {
            return Ok(());
        }
        let txn = self.storage.begin_write()?;
        self.storage
            .consensus()
            .mark_round_decided(&txn, round, leader_hash)?;
        txn.commit()?;
        Ok(())
    }

    /// Record `round` as a certified skip (PRO-40 (b)): decided, no leader.
    ///
    /// Idempotent for a round that is already skipped. A round that already
    /// holds a leader decision is never overwritten:
    /// [`DagStoreError::ConflictingDecision`].
    pub fn mark_round_skipped(&self, round: Round) -> Result<(), DagStoreError> {
        let txn = self.storage.begin_write()?;
        if !self.storage.consensus().mark_round_skipped(&txn, round)? {
            drop(txn);
            return Err(DagStoreError::ConflictingDecision {
                round,
                existing: self.get_decided_leaders(round)?,
                new: Hash::zero(),
            });
        }
        txn.commit()?;
        Ok(())
    }

    /// Increment the committed leader height and set last committed.
    pub fn commit_leader(&self, leader_hash: &Hash) -> Result<u64, DagStoreError> {
        let txn = self.storage.begin_write()?;
        let height = self
            .storage
            .consensus()
            .increment_committed_leader_height(&txn)?;
        self.storage
            .consensus()
            .set_last_committed(&txn, leader_hash)?;
        txn.commit()?;
        Ok(height)
    }

    /// Atomically mark `round` decided for `leader_hash` and advance the
    /// committed leader height / last committed leader, in ONE redb write
    /// transaction: after a crash either both are durable or neither is.
    ///
    /// The "already decided" check runs inside the same write transaction:
    /// - round already decided with the SAME hash: no-op, returns the current
    ///   committed leader height (no increment);
    /// - round already decided with a DIFFERENT hash:
    ///   [`DagStoreError::ConflictingDecision`], nothing written.
    pub fn mark_decided_and_commit_leader(
        &self,
        round: Round,
        leader_hash: &Hash,
    ) -> Result<u64, DagStoreError> {
        let txn = self.storage.begin_write()?;
        let existing: Vec<Hash> = {
            let table = txn.open_table(tables::DECIDED_ROUNDS)?;
            let value = table.get(round)?;
            value
                .map(|v| {
                    let hashes: Vec<[u8; 32]> =
                        BincodeSerialize::from_bytes(&v.value()).unwrap_or_default();
                    hashes.into_iter().map(Hash).collect()
                })
                .unwrap_or_default()
        };
        if existing.contains(leader_hash) {
            let table = txn.open_table(tables::COMMITTED_LEADER_HEIGHT)?;
            let height = table.get("height")?.map(|v| v.value()).unwrap_or(0);
            drop(table);
            // Read-only use of the write transaction; nothing to persist.
            txn.abort()?;
            return Ok(height);
        }
        if !existing.is_empty() {
            txn.abort()?;
            return Err(DagStoreError::ConflictingDecision {
                round,
                existing,
                new: *leader_hash,
            });
        }
        self.storage
            .consensus()
            .mark_round_decided(&txn, round, leader_hash)?;
        #[cfg(test)]
        if fault::crash_between_steps() {
            // Simulated crash: the transaction is dropped uncommitted.
            return Err(DagStoreError::NotFound("injected crash".into()));
        }
        let height = self
            .storage
            .consensus()
            .increment_committed_leader_height(&txn)?;
        self.storage
            .consensus()
            .set_last_committed(&txn, leader_hash)?;
        txn.commit()?;
        Ok(height)
    }

    /// Prune DAG blocks below a certain round.
    pub fn prune_below(&self, min_round: Round) -> Result<u64, DagStoreError> {
        let txn = self.storage.begin_write()?;
        let pruned = self.storage.consensus().prune_dag_below(&txn, min_round)?;
        // `prune_dag_below` removes rounds <= min_round.
        self.raise_prune_boundary(&txn, min_round.saturating_add(1))?;
        txn.commit()?;
        Ok(pruned)
    }

    /// Prune non-blue blocks from a committed wave.
    ///
    /// Deletes all blocks from the committed wave that are NOT in the blue set.
    /// Keeps blue blocks and previous tips needed for future colouring.
    ///
    /// Deprecated (#13, variant A): the committer no longer calls this. Red
    /// blocks are reported in `CommittedSubDag::non_blue` and removed only by
    /// round pruning (`prune_waves_before`). Kept for compatibility; do not
    /// add new callers.
    pub fn prune_non_blue(
        &self,
        blue_hashes: &[Hash],
        committed_wave: u64,
    ) -> Result<u64, DagStoreError> {
        let txn = self.storage.begin_write()?;

        // Convert blue_hashes to a HashSet for O(1) lookup
        let blue_set: HashSet<Hash> = blue_hashes.iter().copied().collect();

        // Calculate round range for the committed wave
        let wave_length = kovanica_types::WAVE_LENGTH;
        let wave_start = committed_wave * wave_length;
        let wave_end = wave_start + wave_length - 1;

        // Blocks that must never be pruned even if not present in the blue set:
        // the last committed leader (`last_committed` must always resolve) and
        // every decided leader in this wave.
        //
        // The consensus helpers take a `&ReadTransaction` and redb's
        // `WriteTransaction` does not deref-coerce to it, so read the tables
        // directly from this transaction (same schema, same encoding).
        let mut protected: HashSet<Hash> = HashSet::new();
        let last_committed = {
            let last_table = txn.open_table(tables::LAST_COMMITED)?;
            let last = last_table.get("last")?.map(|v| Hash(v.value()));
            last
        };
        if let Some(h) = last_committed {
            protected.insert(h);
        }
        let decided_table = txn.open_table(tables::DECIDED_ROUNDS)?;
        for round in wave_start..=wave_end {
            let hashes: Vec<[u8; 32]> = decided_table
                .get(round)?
                .map(|v| BincodeSerialize::from_bytes(&v.value()).unwrap_or_default())
                .unwrap_or_default();
            for h in hashes {
                protected.insert(Hash(h));
            }
        }
        drop(decided_table);

        // Collect all blocks in the committed wave
        let round_table = txn.open_table(tables::DAG_BY_ROUND)?;
        let mut blocks_to_check = Vec::new();

        for entry in round_table.range((wave_start, 0u16)..=(wave_end, u16::MAX))? {
            let (_, block_hashes) = entry?;
            let hashes: Vec<[u8; 32]> = BincodeSerialize::from_bytes(&block_hashes.value())?;
            for hash in hashes {
                blocks_to_check.push(Hash(hash));
            }
        }
        // Drop the table to release the borrow on txn
        drop(round_table);

        // Determine which blocks to prune (those in the wave but not blue)
        let mut blocks_to_prune = Vec::new();
        for hash in blocks_to_check {
            if !blue_set.contains(&hash) {
                blocks_to_prune.push(hash);
            }
        }

        // Delete non-blue blocks and their links, never touching blue blocks or
        // protected leaders (last committed / decided leaders in this wave).
        let mut pruned = 0;
        for block_hash in blocks_to_prune {
            if blue_set.contains(&block_hash) || protected.contains(&block_hash) {
                continue;
            }
            self.delete_block_internal(&txn, &block_hash)?;
            pruned += 1;
        }

        txn.commit()?;
        Ok(pruned)
    }

    /// Prune all blocks from waves before the given wave minus the prune window.
    ///
    /// Deletes ALL blocks (blue and red) from waves < `wave - prune_window_waves`.
    /// Updates committed_leader_height accordingly.
    /// Must not break recovery (recover_committed_subdags only needs decided-round index).
    pub fn prune_waves_before(
        &self,
        wave: u64,
        prune_window_waves: u64,
    ) -> Result<u64, DagStoreError> {
        let txn = self.storage.begin_write()?;

        let wave_length = kovanica_types::WAVE_LENGTH;

        // Calculate the minimum wave to keep
        let min_wave_to_keep = wave.saturating_sub(prune_window_waves);

        // Calculate the maximum round to prune (last round of the wave before min_wave_to_keep)
        // If min_wave_to_keep is 0, we prune nothing (no waves before wave 0)
        let max_round_to_prune = if min_wave_to_keep == 0 {
            // No waves to prune - return 0 without calling prune_dag_below
            txn.commit()?;
            return Ok(0);
        } else {
            // Last round of wave (min_wave_to_keep - 1)
            min_wave_to_keep * wave_length - 1
        };

        // Prune all blocks below or equal to this round
        let pruned = self
            .storage
            .consensus()
            .prune_dag_below(&txn, max_round_to_prune)?;
        // Same transaction: rounds <= max_round_to_prune are gone.
        self.raise_prune_boundary(&txn, max_round_to_prune + 1)?;

        // The committed_leader_height counter is not changed here because
        // it represents the total number of committed leaders ever, not just recent ones.
        // The decided_rounds index is what recovery uses, and it's not touched by pruning.

        txn.commit()?;
        Ok(pruned)
    }

    /// Internal helper to delete a single block and all its links.
    fn delete_block_internal(
        &self,
        txn: &WriteTransaction,
        block_hash: &Hash,
    ) -> Result<(), DagStoreError> {
        let key = hash_to_bytes(block_hash);

        // Read the block's (round, author) before removing it so the round and
        // author indices can be cleaned up as well.
        let round_author: Option<(Round, AuthorityIndex)> = {
            let table = txn.open_table(tables::DAG_BLOCKS)?;
            let result = match table.get(key)? {
                Some(value) => {
                    let block = StatementBlock::from_bytes(&value.value())?;
                    Some((block.round, block.author))
                }
                None => None,
            };
            result
        };

        // Remove from dag_blocks
        {
            let mut table = txn.open_table(tables::DAG_BLOCKS)?;
            table.remove(key)?;
        }

        // Remove from dag_parents and get parents for child cleanup
        let parents: Vec<[u8; 32]> = {
            let mut table = txn.open_table(tables::DAG_PARENTS)?;
            let value = table.get(key)?;
            let parents = value
                .as_ref()
                .map(|v| BincodeSerialize::from_bytes(&v.value()).unwrap_or_default())
                .unwrap_or_default();
            // Drop the guard before removing
            drop(value);
            table.remove(key)?;
            parents
        };

        // Update parents' children lists
        for parent_hash in parents {
            let mut children: Vec<[u8; 32]> = {
                let table = txn.open_table(tables::DAG_CHILDREN)?;
                let value = table.get(parent_hash)?;
                value
                    .map(|v| BincodeSerialize::from_bytes(&v.value()).unwrap_or_default())
                    .unwrap_or_default()
            };
            children.retain(|h| *h != key);
            {
                let mut table = txn.open_table(tables::DAG_CHILDREN)?;
                table.insert(parent_hash, children.to_bytes()?)?;
            }
        }

        // Capture this block's children before its child link is removed so
        // each surviving child can drop the now-deleted block from its parent
        // list. Without this, a surviving child keeps a reference to a missing
        // parent and `get_ancestors`/`mergeset` fail with NotFound one wave
        // later.
        let children: Vec<[u8; 32]> = {
            let table = txn.open_table(tables::DAG_CHILDREN)?;
            let value = table.get(key)?;
            value
                .map(|v| BincodeSerialize::from_bytes(&v.value()).unwrap_or_default())
                .unwrap_or_default()
        };

        // Remove from dag_children
        {
            let mut table = txn.open_table(tables::DAG_CHILDREN)?;
            table.remove(key)?;
        }

        // Drop this block from each surviving child's parent list.
        for child_hash in children {
            let mut table = txn.open_table(tables::DAG_PARENTS)?;
            let existing: Vec<[u8; 32]> = table
                .get(child_hash)?
                .map(|v| BincodeSerialize::from_bytes(&v.value()).unwrap_or_default())
                .unwrap_or_default();
            let filtered: Vec<[u8; 32]> = existing.into_iter().filter(|h| *h != key).collect();
            if filtered.is_empty() {
                table.remove(child_hash)?;
            } else {
                table.insert(child_hash, filtered.to_bytes()?)?;
            }
        }

        // Remove from the round and author indices so a deleted block cannot
        // linger as a dangling index entry.
        if let Some((round, author)) = round_author {
            {
                let mut table = txn.open_table(tables::DAG_BY_ROUND)?;
                let existing: Vec<[u8; 32]> = table
                    .get((round, author))?
                    .map(|v| BincodeSerialize::from_bytes(&v.value()).unwrap_or_default())
                    .unwrap_or_default();
                let filtered: Vec<[u8; 32]> = existing.into_iter().filter(|h| *h != key).collect();
                if filtered.is_empty() {
                    table.remove((round, author))?;
                } else {
                    table.insert((round, author), filtered.to_bytes()?)?;
                }
            }
            {
                let mut table = txn.open_table(tables::DAG_BY_AUTHOR)?;
                let existing: Vec<[u8; 32]> = table
                    .get((author, round))?
                    .map(|v| BincodeSerialize::from_bytes(&v.value()).unwrap_or_default())
                    .unwrap_or_default();
                let filtered: Vec<[u8; 32]> = existing.into_iter().filter(|h| *h != key).collect();
                if filtered.is_empty() {
                    table.remove((author, round))?;
                } else {
                    table.insert((author, round), filtered.to_bytes()?)?;
                }
            }
        }

        Ok(())
    }

    /// Get the mergeset for a leader block.
    ///
    /// The mergeset is the set of all blocks reachable from the leader that
    /// have not yet been included in any previously committed sub-DAG.
    /// We compute this by BFS from the leader via parent links, stopping at
    /// blocks in [`Self::committed_before`] the leader's round (the actual
    /// committed set from the decided-leader index, not a round cutoff).
    pub fn mergeset(&self, leader: &Hash) -> Result<Vec<Hash>, DagStoreError> {
        let leader_round = match self.get_block(leader) {
            Ok(block) => block.round,
            Err(DagStoreError::NotFound(_)) => return Ok(Vec::new()),
            Err(e) => return Err(e),
        };
        // Cutoff = the actual committed set (decided leaders of lower rounds
        // and their histories), not the last committed leader's round: a
        // late block below that round that no earlier leader referenced is
        // still uncommitted and must enter this batch. Works when the last
        // committed block itself has been pruned.
        let committed = self.committed_before(leader_round)?;

        let mut result = Vec::new();
        let mut visited = HashSet::new();
        let mut queue = VecDeque::new();
        queue.push_back(*leader);
        visited.insert(*leader);

        while let Some(current) = queue.pop_front() {
            if current != *leader && committed.contains(&current) {
                // Already delivered; its history is committed too.
                continue;
            }
            // A pruned block can still be referenced by a surviving child's
            // parent list; skip the dangling edge instead of failing (M2).
            match self.get_block(&current) {
                Ok(_) => {}
                Err(DagStoreError::NotFound(_)) => continue,
                Err(e) => return Err(e),
            }

            result.push(current);

            let parents = match self.get_parents(&current) {
                Ok(parents) => parents,
                Err(DagStoreError::NotFound(_)) => continue,
                Err(e) => return Err(e),
            };
            for parent in parents {
                if visited.insert(parent) {
                    queue.push_back(parent);
                }
            }
        }

        Ok(result)
    }

    /// Blocks already delivered by commits of rounds strictly below `round`:
    /// every decided leader of such a round plus its (stored) causal history.
    /// Derived only from the durable decided-leader index, the same rule as
    /// `kovanica_consensus::uncommitted_history`, so it is identical live and
    /// after a restart. Relies on pruning being downward-closed by round.
    pub fn committed_before(&self, round: Round) -> Result<HashSet<Hash>, DagStoreError> {
        let mut committed = HashSet::new();
        if round == 0 {
            return Ok(committed);
        }
        for decided_round in self.get_decided_rounds(round - 1)? {
            if decided_round >= round {
                continue;
            }
            for prev in self.get_decided_leaders(decided_round)? {
                if !committed.insert(prev) {
                    continue;
                }
                committed.extend(self.get_ancestors(&prev, 0)?);
            }
        }
        Ok(committed)
    }
}

/// Test-only fault injection: simulate a process crash between the
/// decided-round mark and the committed-leader update.
#[cfg(test)]
pub(crate) mod fault {
    #![allow(clippy::missing_const_for_thread_local)]
    use std::cell::Cell;

    thread_local! {
        static CRASH_BETWEEN_STEPS: Cell<bool> = const { Cell::new(false) };
    }

    pub(crate) fn arm() {
        CRASH_BETWEEN_STEPS.with(|c| c.set(true));
    }

    /// Returns true (once) when a crash was armed.
    pub(crate) fn crash_between_steps() -> bool {
        CRASH_BETWEEN_STEPS.with(|c| c.replace(false))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kovanica_types::crypto::Signature;

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
            signature: Signature([0u8; 64]),
            digest: Hash::new(format!("kovanica-dag-store-test/{tag}").as_bytes()),
            merkle_root: Hash::zero(),
        }
    }

    fn block_ref(block: &StatementBlock) -> BlockReference {
        BlockReference {
            author: block.author,
            round: block.round,
            digest: block.digest,
        }
    }

    /// A real on-disk store backed by `kovanica-storage`. The returned `TempDir`
    /// must be kept alive for the store to remain usable.
    fn store() -> (tempfile::TempDir, DagStore) {
        let dir = tempfile::tempdir().expect("tempdir");
        let storage = Storage::new(dir.path().join("dag.redb")).expect("storage");
        let store = DagStore::new(storage).expect("dag store");
        (dir, store)
    }

    #[test]
    fn max_dag_round_reports_the_highest_stored_round_then_none_when_empty() {
        let (_dir, store) = store();
        assert_eq!(store.max_dag_round().unwrap(), None, "fresh store is empty");

        store
            .put_block(&make_block(0, 3, Vec::new(), "r3"))
            .unwrap();
        assert_eq!(store.max_dag_round().unwrap(), Some(3));

        // A deeper, differently authored round wins regardless of insertion order.
        store
            .put_block(&make_block(1, 11, Vec::new(), "r11"))
            .unwrap();
        store
            .put_block(&make_block(0, 7, Vec::new(), "r7"))
            .unwrap();
        assert_eq!(store.max_dag_round().unwrap(), Some(11));
    }

    #[test]
    fn replace_block_swaps_undecided_leader_and_refuses_children() {
        let (_dir, store) = store();
        let first = make_block(0, 3, Vec::new(), "larger");
        let second = make_block(0, 3, Vec::new(), "smaller");
        store.put_block(&first).unwrap();
        store.replace_block(&first, &second).unwrap();
        assert!(!store.has_block(&first.digest).unwrap());
        assert!(store.has_block(&second.digest).unwrap());
        assert_eq!(
            store
                .get_block_by_author_round(0, 3)
                .unwrap()
                .expect("replaced leader")
                .digest,
            second.digest
        );

        let child = make_block(1, 4, vec![block_ref(&second)], "child");
        store.put_block(&child).unwrap();
        let third = make_block(0, 3, Vec::new(), "after-child");
        let refused = store.replace_block(&second, &third);
        assert!(refused.is_err(), "a referenced leader must not be swapped");
        assert!(store.has_block(&second.digest).unwrap());
        assert!(!store.has_block(&third.digest).unwrap());
    }

    // #2: prune_non_blue keeps protected leaders (decided + last committed)
    // and deletes red blocks in the committed wave.
    #[test]
    fn prune_non_blue_keeps_decided_and_last_committed_and_removes_red() {
        let (_dir, store) = store();

        let leader = make_block(0, 3, vec![], "leader-3");
        let red = make_block(1, 4, vec![], "red-4");
        store.put_block(&leader).unwrap();
        store.put_block(&red).unwrap();

        store.mark_round_decided(3, &leader.digest).unwrap();
        store.commit_leader(&leader.digest).unwrap();

        // Wave 1 covers rounds 3..=5. The red block is deleted; the decided /
        // last-committed leader is protected even though it is not blue.
        let pruned = store.prune_non_blue(&[], 1).unwrap();
        assert_eq!(pruned, 1, "only the red block is pruned");
        assert!(store.get_block(&leader.digest).is_ok(), "leader survives");
        assert!(
            matches!(
                store.get_block(&red.digest),
                Err(DagStoreError::NotFound(_))
            ),
            "red block is gone"
        );

        // Empty waves delete nothing.
        assert_eq!(store.prune_non_blue(&[], 2).unwrap(), 0);
        assert_eq!(store.prune_non_blue(&[], 3).unwrap(), 0);
    }

    // #5a: a pruned sibling must be dropped from the (round, author) index, and
    // a stale index entry must not resurrect a missing block.
    #[test]
    fn prune_non_blue_removes_pruned_sibling_from_round_index() {
        let (_dir, store) = store();

        let sibling_a = make_block(0, 3, vec![], "sibling-a");
        let sibling_b = make_block(0, 3, vec![], "sibling-b");
        store.put_block(&sibling_a).unwrap();
        store.put_block(&sibling_b).unwrap();

        // Keep B (blue), delete A.
        let pruned = store.prune_non_blue(&[sibling_b.digest], 1).unwrap();
        assert_eq!(pruned, 1, "sibling A pruned");
        assert!(matches!(
            store.get_block(&sibling_a.digest),
            Err(DagStoreError::NotFound(_))
        ));
        assert_eq!(
            store
                .get_block_by_author_round(0, 3)
                .unwrap()
                .map(|block| block.digest),
            Some(sibling_b.digest),
            "round/author index resolves the surviving sibling"
        );

        // Inject a stale A-hash into the (round=3, author=0) index entry and
        // confirm the reader skips it instead of failing.
        {
            let txn = store.storage.begin_write().unwrap();
            let mut table = txn.open_table(tables::DAG_BY_ROUND).unwrap();
            let mut existing: Vec<[u8; 32]> = table
                .get((3u64, 0u16))
                .unwrap()
                .map(|v| BincodeSerialize::from_bytes(&v.value()).unwrap_or_default())
                .unwrap_or_default();
            existing.push(hash_to_bytes(&sibling_a.digest));
            table
                .insert((3u64, 0u16), existing.to_bytes().unwrap())
                .unwrap();
            drop(table);
            txn.commit().unwrap();
        }

        let blocks = store.get_blocks_by_round(3).unwrap();
        assert_eq!(blocks.len(), 1, "only the surviving sibling is returned");
        assert_eq!(blocks[0].digest, sibling_b.digest);
    }

    // #6 (M2 regression): deleting a block in the middle of a chain must not
    // leave a surviving child with a dangling parent edge that later makes
    // `get_ancestors`/`mergeset` fail.
    #[test]
    fn pruning_middle_block_leaves_surviving_child_traversable() {
        let (_dir, store) = store();

        let grandparent = make_block(0, 1, vec![], "grandparent-1");
        let parent = make_block(0, 3, vec![block_ref(&grandparent)], "parent-3");
        let child = make_block(0, 9, vec![block_ref(&parent)], "child-9");
        store.put_block(&grandparent).unwrap();
        store.put_block(&parent).unwrap();
        store.put_block(&child).unwrap();

        // Delete the middle parent through the non-blue wave prune...
        assert_eq!(store.prune_non_blue(&[], 1).unwrap(), 1);
        assert!(matches!(
            store.get_block(&parent.digest),
            Err(DagStoreError::NotFound(_))
        ));
        // ...and the grandparent through the wave prune.
        assert_eq!(store.prune_waves_before(3, 2).unwrap(), 1);

        // The surviving child must still be traversable: no dangling edge may
        // turn the walk into an error.
        assert!(store.get_block(&child.digest).is_ok(), "child survives");
        let ancestors = store
            .get_ancestors(&child.digest, 0)
            .expect("ancestry walk tolerates pruned parents");
        assert!(ancestors.is_empty(), "all ancestors were pruned");
        let mergeset = store
            .mergeset(&child.digest)
            .expect("mergeset walk tolerates pruned parents");
        assert_eq!(mergeset, vec![child.digest]);
    }

    #[test]
    fn mark_decided_and_commit_leader_is_atomic_across_crash_and_reopen() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("dag.redb");
        let leader = make_block(1, 3, Vec::new(), "atomic-leader");
        {
            let store = DagStore::new(Storage::new(&path).unwrap()).unwrap();
            store.put_block(&leader).unwrap();
            fault::arm();
            let res = store.mark_decided_and_commit_leader(3, &leader.digest);
            assert!(res.is_err(), "injected crash must surface");
        } // "process" dies here

        let store = DagStore::new(Storage::new(&path).unwrap()).unwrap();
        let decided = store.is_round_decided(3).unwrap();
        let height = store.get_committed_leader_height().unwrap();
        let last = store.get_last_committed().unwrap();
        let committed = height == 1 && last == Some(leader.digest);
        let not_committed = height == 0 && last.is_none();
        assert!(
            (decided && committed) || (!decided && not_committed),
            "inconsistent durable state after crash: decided={decided}, height={height}, last={last:?}"
        );

        // A retry after restart completes both steps exactly once.
        let h = store
            .mark_decided_and_commit_leader(3, &leader.digest)
            .unwrap();
        assert_eq!(h, 1);
        assert!(store.is_round_decided(3).unwrap());
        assert_eq!(store.get_last_committed().unwrap(), Some(leader.digest));
    }

    #[test]
    fn mark_decided_and_commit_leader_double_call_does_not_increase_height() {
        let (_dir, store) = store();
        let leader = make_block(1, 3, Vec::new(), "idem-leader");
        store.put_block(&leader).unwrap();
        assert_eq!(
            store
                .mark_decided_and_commit_leader(3, &leader.digest)
                .unwrap(),
            1
        );
        assert_eq!(
            store
                .mark_decided_and_commit_leader(3, &leader.digest)
                .unwrap(),
            1,
            "second call with the same hash must be a no-op"
        );
        assert_eq!(store.get_committed_leader_height().unwrap(), 1);
        assert_eq!(store.get_decided_leaders(3).unwrap(), vec![leader.digest]);
    }

    #[test]
    fn mark_decided_and_commit_leader_rejects_different_hash_for_decided_round() {
        let (_dir, store) = store();
        let a = make_block(1, 3, Vec::new(), "leader-a");
        let b = make_block(2, 3, Vec::new(), "leader-b");
        store.put_block(&a).unwrap();
        store.put_block(&b).unwrap();
        store.mark_decided_and_commit_leader(3, &a.digest).unwrap();
        let err = store
            .mark_decided_and_commit_leader(3, &b.digest)
            .expect_err("different hash for a decided round must fail");
        assert!(
            matches!(err, DagStoreError::ConflictingDecision { round: 3, .. }),
            "unexpected error: {err}"
        );
        assert_eq!(store.get_committed_leader_height().unwrap(), 1);
        assert_eq!(store.get_decided_leaders(3).unwrap(), vec![a.digest]);
        assert_eq!(store.get_last_committed().unwrap(), Some(a.digest));
    }

    // PRO-40 (b): a certified skip is a decided round without leaders, it
    // survives a reopen, and it never overrides a commit.
    #[test]
    fn mark_round_skipped_survives_reopen_and_never_overrides_a_commit() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("dag.redb");
        let leader = Hash::new(b"kovanica-dag-test/skip/leader");
        {
            let store = DagStore::new(Storage::new(&path).unwrap()).unwrap();
            store.mark_round_skipped(3).unwrap();
            store.mark_round_skipped(3).unwrap();
            store.mark_decided_and_commit_leader(6, &leader).unwrap();
            assert!(matches!(
                store.mark_round_skipped(6),
                Err(DagStoreError::ConflictingDecision { round: 6, .. })
            ));
        }
        let store = DagStore::new(Storage::new(&path).unwrap()).unwrap();
        assert_eq!(store.get_decided_rounds(u64::MAX).unwrap(), vec![3, 6]);
        assert!(store.get_decided_leaders(3).unwrap().is_empty());
        assert_eq!(store.get_decided_leaders(6).unwrap(), vec![leader]);
    }
}
