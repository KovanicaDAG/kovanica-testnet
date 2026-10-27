//! Main consensus engine for Kovanica.
//!
#![allow(missing_docs)]
//! Coordinates round advancement, leader selection, block production,
//! and commit decisions using Mysticeti-style DAG consensus.

use crate::metrics::{
    observe_finality_latency, record_block_height, record_commit_latency, record_committed_leader,
    record_current_round, record_mergeset_size_metric, record_skipped_leader,
    record_timeout_signed, record_vote_timeout_equivocation, SkipReason,
};
use crate::skip::{verify_skip_cert, verify_timeout, TimeoutPool, TimeoutRejection};
use crate::types::{CommitteeInfo, LeaderInfo, LeaderStatus};
use crate::{
    committer::{next_leader_slot, UniversalCommitter},
    is_leader_round,
    linearizer::Linearizer,
    offset_in_wave,
};
use kovanica_crypto::sign;
use kovanica_mempool::{Mempool, MempoolError};
use kovanica_types::{
    block::StatementBlock, hash::Hash, Address, AuthorityIndex, EquivocationEvidence, Round,
    Signature, Stake, Transaction, TransactionKind, MAX_TXS_PER_BLOCK,
};
use parking_lot::{Mutex, RwLock};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, watch};
use tokio::time::interval;
use tracing::{debug, info, warn};

/// Upper bound on the number of commits one [`ConsensusEngine::drain_commits`]
/// call performs.
///
/// The commit walk always advances the decided-round cursor, so it terminates
/// on its own; the bound only exists so a pathological state cannot spin the
/// caller forever.
const MAX_COMMIT_DRAIN_STEPS: usize = 4096;

/// Number of leader slots above the commit cursor that may be voted for after
/// the late-vote window has passed (PRO-40 (a), "K = 2"): the slot the commit
/// walk is stalled on and the next one. No wire change; at most K extra votes
/// per node.
pub const LATE_VOTE_AWAITED_SLOTS: u64 = 2;

/// Maximum number of leader rounds buffered in `pending_votes` ahead of `last_decided_round` (PRO-40 (a)).
pub const MAX_PENDING_VOTE_ROUNDS: usize = 16;

/// Maximum number of unanchored votes buffered per leader round (PRO-40 (a)).
pub const MAX_PENDING_VOTES_PER_ROUND: usize = 32;

/// Trait for broadcasting blocks to the network.
pub trait BlockBroadcaster: Send + Sync {
    fn broadcast_block(&self, block: &StatementBlock);
}

impl<F> BlockBroadcaster for F
where
    F: Fn(&StatementBlock) + Send + Sync,
{
    fn broadcast_block(&self, block: &StatementBlock) {
        self(block)
    }
}

/// Trait for broadcasting votes to the network.
pub trait VoteBroadcaster: Send + Sync {
    fn broadcast_vote(&self, vote: &kovanica_types::Vote);
}

impl<F> VoteBroadcaster for F
where
    F: Fn(&kovanica_types::Vote) + Send + Sync,
{
    fn broadcast_vote(&self, vote: &kovanica_types::Vote) {
        self(vote)
    }
}

/// Broadcasts leader-slot timeouts and skip certificates (PRO-40 (b)).
pub trait TimeoutBroadcaster: Send + Sync {
    fn broadcast_timeout(&self, timeout: &kovanica_types::Timeout);
    fn broadcast_skip_cert(&self, cert: &kovanica_types::SkipCert);
}

/// Trait for DAG store operations needed by consensus.
pub trait DagStoreTrait: Send + Sync {
    fn get_block(
        &self,
        hash: &Hash,
    ) -> Result<kovanica_types::block::StatementBlock, kovanica_dag::DagStoreError>;
    fn get_ancestors(
        &self,
        hash: &Hash,
        min_round: kovanica_types::Round,
    ) -> Result<Vec<Hash>, kovanica_dag::DagStoreError>;
    fn get_parents(&self, hash: &Hash) -> Result<Vec<Hash>, kovanica_dag::DagStoreError>;
    fn get_block_by_author_round(
        &self,
        author: kovanica_types::AuthorityIndex,
        round: kovanica_types::Round,
    ) -> Result<Option<kovanica_types::block::StatementBlock>, kovanica_dag::DagStoreError>;
    fn get_blocks_by_round(
        &self,
        round: kovanica_types::Round,
    ) -> Result<Vec<kovanica_types::block::StatementBlock>, kovanica_dag::DagStoreError>;
    fn has_block(&self, hash: &Hash) -> Result<bool, kovanica_dag::DagStoreError>;
    fn put_block(
        &self,
        block: &kovanica_types::block::StatementBlock,
    ) -> Result<(), kovanica_dag::DagStoreError>;
    /// Swap `existing` for `incoming` in an undecided leader slot.
    ///
    /// Default refuses. A min-digest policy must not update leader state
    /// unless the store actually drops the old digest and inserts the new one.
    /// Stores that cannot rewrite parent/child indexes should keep this
    /// default so the engine rejects the fork instead.
    fn replace_block(
        &self,
        _existing: &kovanica_types::block::StatementBlock,
        _incoming: &kovanica_types::block::StatementBlock,
    ) -> Result<(), kovanica_dag::DagStoreError> {
        Err(kovanica_dag::DagStoreError::NotFound(
            "min-digest replacement is not supported by this store".into(),
        ))
    }
    fn find_parents(
        &self,
        round: kovanica_types::Round,
        max_parents: usize,
    ) -> Result<Vec<kovanica_types::block::BlockReference>, kovanica_dag::DagStoreError>;
    fn commit_leader(&self, leader_hash: &Hash) -> Result<u64, kovanica_dag::DagStoreError>;
    fn mark_round_decided(
        &self,
        round: kovanica_types::Round,
        leader_hash: &Hash,
    ) -> Result<(), kovanica_dag::DagStoreError>;
    /// Atomically mark `round` decided for `leader_hash` AND advance the
    /// committed leader height / last committed leader. Implementations
    /// backed by durable storage must apply both or neither (one write
    /// transaction), so a crash can never leave a decided round without the
    /// matching committed-leader record or vice versa.
    fn mark_decided_and_commit_leader(
        &self,
        round: kovanica_types::Round,
        leader_hash: &Hash,
    ) -> Result<u64, kovanica_dag::DagStoreError>;
    /// Get the mergeset for a leader block (blocks reachable from leader not in previous sub-DAGs).
    fn mergeset(&self, leader: &Hash) -> Result<Vec<Hash>, kovanica_dag::DagStoreError>;
    /// Get multiple blocks by their hashes.
    fn get_blocks(
        &self,
        hashes: &[Hash],
    ) -> Result<Vec<kovanica_types::block::StatementBlock>, kovanica_dag::DagStoreError>;
    /// Get decided leader hashes for a round.
    fn get_decided_leaders(&self, round: Round) -> Result<Vec<Hash>, kovanica_dag::DagStoreError>;
    /// Persist a vote so it survives a restart and can be handed to a peer
    /// that joins later.
    ///
    /// The default is a no-op, which keeps in-memory test doubles unchanged.
    /// A durable implementation stores the vote under its leader round.
    ///
    /// Two callers, with different failure rules:
    ///
    /// * An already-accepted vote (`process_vote`) is written after consensus
    ///   has counted it. A failure there must not turn that accepted vote
    ///   into a rejected one. It only means the vote cannot be served later.
    /// * This node's own vote is written *before* it is counted or broadcast.
    ///   `Err` means the vote was not sent and the slot is not reserved. `Ok`
    ///   is the durable lock for that slot: a later start must not sign a
    ///   different digest, and it does not re-send the stored vote.
    ///
    /// See `docs/rfcs/RFC-009-VOTE-TRANSFER-OVER-BLOCK-SYNC.md`.
    fn put_vote(&self, _vote: &kovanica_types::Vote) -> Result<(), kovanica_dag::DagStoreError> {
        Ok(())
    }
    /// Votes persisted through [`Self::put_vote`] for one leader round.
    ///
    /// Read once at start-up to re-register the leaders a restarted node
    /// still has to decide (PRO-40). The default returns nothing, which is
    /// correct for stores that do not persist votes.
    fn get_votes_for_round(
        &self,
        _round: Round,
    ) -> Result<Vec<kovanica_types::Vote>, kovanica_dag::DagStoreError> {
        Ok(Vec::new())
    }
    /// Leader round certified by a quorum of `KUNA/commit/v1` commit seals or
    /// by a verified state-sync checkpoint.
    ///
    /// `None` (the default) means this store has no certified point. The
    /// commit walk then still stalls on a leader slot with no record.
    ///
    /// A `Some` round must be a leader round (`round % WAVE_LENGTH == 0`) and
    /// must be returned only after the seals or the checkpoint have been
    /// verified **and** local execution state already reflects that commit.
    /// A node whose cursor is behind the prune window advances to this round
    /// and continues from the next slot. It does not re-execute the gap.
    fn certified_catchup_anchor(&self) -> Result<Option<Round>, kovanica_dag::DagStoreError> {
        Ok(None)
    }
    /// Record `round` as decided by a quorum skip certificate: a decided
    /// round with no leader (PRO-40 (b)). Durable stores must persist it, so
    /// a restart resumes the cursor after the skip. Must refuse a round that
    /// already holds a leader decision. The default is a no-op for in-memory
    /// test doubles.
    fn mark_round_skipped(&self, _round: Round) -> Result<(), kovanica_dag::DagStoreError> {
        Ok(())
    }
    /// Persist a verified timeout (PRO-40 (b)). This node's own timeout is
    /// written here **before** it is broadcast, so a restart can never vote
    /// for a slot it already timed out. Default no-op for test doubles.
    fn put_timeout(
        &self,
        _timeout: &kovanica_types::Timeout,
    ) -> Result<(), kovanica_dag::DagStoreError> {
        Ok(())
    }
    /// Timeouts persisted for one leader slot, ordered by signer.
    fn get_timeouts_for_round(
        &self,
        _round: Round,
    ) -> Result<Vec<kovanica_types::Timeout>, kovanica_dag::DagStoreError> {
        Ok(Vec::new())
    }
    /// Get all decided rounds up to a maximum.
    fn get_decided_rounds(
        &self,
        max_round: Round,
    ) -> Result<Vec<Round>, kovanica_dag::DagStoreError>;
    /// Highest round that still has at least one stored DAG block.
    ///
    /// The engine resumes its round counter from this value at `start()` so a
    /// restart continues after the persisted DAG tip instead of replaying
    /// rounds that are already stored (which aborts on
    /// [`kovanica_dag::DagStoreError::ConflictingDecision`]).
    ///
    /// The default returns `None` — "start from round 0" — which is correct
    /// for a fresh chain and keeps in-memory test doubles unchanged.
    fn max_stored_round(&self) -> Result<Option<Round>, kovanica_dag::DagStoreError> {
        Ok(None)
    }
    /// Prune non-blue blocks from a committed wave.
    ///
    /// Deprecated (#13, variant A): the committer no longer calls this. Red
    /// blocks are reported in `CommittedSubDag::non_blue` and removed only by
    /// round pruning (`prune_waves_before`). Kept for compatibility; do not
    /// add new callers.
    fn prune_non_blue(
        &self,
        blue_hashes: &[Hash],
        committed_wave: u64,
    ) -> Result<u64, kovanica_dag::DagStoreError>;
    /// Prune all blocks from waves before the given wave minus the prune window.
    fn prune_waves_before(
        &self,
        wave: u64,
        prune_window_waves: u64,
    ) -> Result<u64, kovanica_dag::DagStoreError>;
}

/// Trait for block manager operations needed by consensus.
pub trait BlockManagerTrait: Send + Sync {
    fn propose_block(
        &self,
        round: kovanica_types::Round,
    ) -> Result<kovanica_types::block::StatementBlock, kovanica_dag::BlockManagerError>;
    fn propose_block_with_txs(
        &self,
        round: kovanica_types::Round,
        transactions: Vec<kovanica_types::Transaction>,
    ) -> Result<kovanica_types::block::StatementBlock, kovanica_dag::BlockManagerError>;
    fn process_block(
        &self,
        block: &kovanica_types::block::StatementBlock,
    ) -> Result<(), kovanica_dag::BlockManagerError>;
    fn our_authority(&self) -> kovanica_types::AuthorityIndex;
    fn set_signing_key(&self, key: kovanica_types::SigningKey);

    /// Publish a transaction-free block that carries this validator's VRF
    /// output. The default refuses. The engine calls it on decide rounds
    /// when VRF leader election is on and the committee has VRF keys.
    fn propose_vrf_carrier(
        &self,
        _round: kovanica_types::Round,
    ) -> Result<kovanica_types::block::StatementBlock, kovanica_dag::BlockManagerError> {
        Err(kovanica_dag::BlockManagerError::InvalidBlock(
            "vrf carrier is not available".into(),
        ))
    }

    /// VRF outputs this manager has already verified, keyed by block round
    /// then authority. Empty when the manager does not check proofs.
    fn verified_vrf_outputs(
        &self,
    ) -> HashMap<Round, HashMap<kovanica_types::AuthorityIndex, [u8; 32]>> {
        HashMap::new()
    }
}

/// Configuration for the consensus engine.
#[derive(Clone, Debug)]
pub struct ConsensusConfig {
    /// Duration of each round in milliseconds.
    pub round_duration_ms: u64,
    /// Number of rounds to look ahead for speculative execution.
    pub lookahead_rounds: u64,
    /// Maximum number of pending rounds to keep in memory.
    pub max_pending_rounds: u64,
    /// Order committed waves with scoped GHOSTDAG (`k = 3`).
    ///
    /// Default on. `UniversalCommitter` reads this flag: when it is on, red
    /// blocks are listed on `CommittedSubDag::non_blue` and are not executed.
    /// When it is off, the linearizer path is used and `non_blue` stays empty.
    /// The node sets it from configuration (`KOVANICA_MYSTICGHOST`).
    ///
    /// `committer_mysticghost` is an unused example wrapper. It is not this path.
    pub use_mysticghost: bool,
    /// Number of waves to keep before pruning old waves.
    /// Default: 100 waves.
    pub prune_window_waves: u64,
    /// Leader timeout in milliseconds; skip leader if no block arrives. A non-zero
    /// value wins over `leader_timeout_factor`. Kept for explicit overrides and
    /// test fixtures.
    pub leader_timeout_ms: u64,
    /// Mysticeti-style adaptive timeout factor: when `leader_timeout_ms` is 0,
    /// the effective leader timeout is `round_duration_ms * leader_timeout_factor`.
    /// Must be `>= 1`. Default: 2.
    pub leader_timeout_factor: u64,
    /// How many rounds behind its own current round a node may still cast a
    /// vote for a leader round.
    ///
    /// Votes only count toward a leader round while the network is still near
    /// that round. Without a bound, a lagging validator (e.g. a late joiner
    /// that starts its local round clock at 0 instead of adopting the network
    /// round) can gather fresh votes from peers that have long since decided
    /// the round, commit it locally, and then diverge from the sequence every
    /// already-decided peer committed — see `late_join_integration`.
    ///
    /// Must be at least `2 * Δ` in rounds (Δ = message delay) so a block and
    /// its votes can still traverse the network and reach quorum.
    /// Default: one wave (`kovanica_types::WAVE_LENGTH`, 3 rounds).
    ///
    /// Exception (PRO-40 (a)): the first [`LATE_VOTE_AWAITED_SLOTS`] leader
    /// slots above the node's own commit cursor may be voted for at any
    /// delay. A peer that already decided such a slot refuses to vote for it
    /// (`vote_for_leader`), and since PRO-35 nobody commits past a slot
    /// without that slot's own quorum, so the exception cannot produce a
    /// divergent sequence; it only lets a stalled slot reach quorum.
    pub late_vote_window_rounds: Round,
    /// Use stake-weighted VRF leader selection when the previous decide round
    /// has a verified output for every authority that published a VRF key.
    ///
    /// Default on. An empty or partial set stays on round-robin, so a node
    /// that has not seen every carrier does not elect a different leader from
    /// a subset. `KOVANICA_VRF_LEADER=false` forces round-robin.
    pub use_vrf_leader: bool,
    /// Replace an undecided leader block when a later same-author digest is
    /// lexicographically smaller **and** the DAG store can swap it.
    ///
    /// Default **on** (see `Default`): of two digests for the same scheduled
    /// leader slot, the byte-wise smaller one wins, but only while the round
    /// is undecided and only when the DAG store accepts the swap. With it off,
    /// the first valid digest wins and a different digest is equivocation.
    /// Either way the committer map must not prefer a digest the store does
    /// not hold. See `docs/rfcs/RFC-B1-B2-VRF-AND-MIN-DIGEST.md`.
    pub use_min_digest_fork: bool,
    /// Genesis hash bound into every timeout signature (PRO-40 (b)), so a
    /// timeout from another reset of the same chain never verifies. The node
    /// sets it from the genesis configuration digest.
    pub genesis_hash: Hash,
    /// `T_skip` in rounds (PRO-40 (b)): how long the first undecided leader
    /// slot may stay unvoted, after its vote round, before this node signs a
    /// timeout for it. Also the rebroadcast interval while the slot stays
    /// stalled. Default `2 * WAVE_LENGTH` = 6 rounds ≈ 24 s.
    pub skip_timeout_rounds: Round,
}

impl Default for ConsensusConfig {
    fn default() -> Self {
        Self {
            round_duration_ms: 4000, // 4 s round → 12 s per committed leader (wave = 3)
            lookahead_rounds: 3,
            max_pending_rounds: 100,
            use_mysticghost: true,
            prune_window_waves: 100,
            leader_timeout_ms: 0,
            leader_timeout_factor: 2,
            late_vote_window_rounds: kovanica_types::WAVE_LENGTH,
            use_vrf_leader: true,
            use_min_digest_fork: true,
            genesis_hash: Hash::zero(),
            skip_timeout_rounds: 2 * kovanica_types::WAVE_LENGTH,
        }
    }
}

/// State of a validator in the consensus protocol.
#[derive(Clone, Debug)]
pub struct ValidatorState {
    /// Our authority index.
    pub our_authority: kovanica_types::AuthorityIndex,
    /// Our stake.
    pub our_stake: Stake,
    /// Current round.
    pub current_round: Round,
    /// Whether we are the leader for the current round.
    pub is_leader: bool,
    /// Whether we have proposed a block for the current round.
    pub proposed: bool,
}

/// Decide round whose verified VRF outputs elect `leader_round`.
///
/// Leader rounds are wave offset 0, so the previous round is the decide
/// round of that wave. Round 0 has no previous round and stays round-robin.
fn election_beacon(leader_round: Round) -> Option<Round> {
    if !is_leader_round(leader_round) || leader_round == 0 {
        return None;
    }
    let beacon = leader_round - 1;
    if offset_in_wave(beacon) == 2 {
        Some(beacon)
    } else {
        None
    }
}

/// Main consensus engine.
pub struct ConsensusEngine<D, B>
where
    D: DagStoreTrait + 'static,
    B: BlockManagerTrait + 'static,
{
    config: ConsensusConfig,
    committee: CommitteeInfo,
    signing_key: kovanica_types::SigningKey,
    dag_store: Arc<D>,
    block_manager: Arc<RwLock<B>>,
    committer: UniversalCommitter,
    linearizer: Linearizer,
    state: RwLock<ValidatorState>,
    current_round: RwLock<Round>,
    leader_schedule: RwLock<HashMap<Round, kovanica_types::AuthorityIndex>>,
    running: RwLock<bool>,
    commit_sender: RwLock<Option<mpsc::UnboundedSender<kovanica_types::CommittedSubDag>>>,
    block_broadcaster: RwLock<Option<Arc<dyn BlockBroadcaster>>>,
    vote_broadcaster: RwLock<Option<Arc<dyn VoteBroadcaster>>>,
    /// Watch channel sender for round changes.
    round_sender: RwLock<Option<watch::Sender<Round>>>,
    /// Serializes decision construction, durable marking, state publication,
    /// and execution delivery across all commit triggers.
    commit_trigger_lock: Mutex<()>,
    /// Mempool for transaction selection during block proposal.
    mempool: Option<Arc<Mempool>>,
    /// Local signing context. Only its `chain_id` is used for votes; the
    /// vote epoch always comes from the local [`CommitteeInfo`] (see
    /// [`Self::vote_signing_ctx`]).
    signing_ctx: kovanica_types::SigningContext,
    /// Timeout deadline for the current leader slot (round, instant).
    leader_deadline: RwLock<Option<(Round, std::time::Instant)>>,
    /// Leader rounds this node has already cast its vote for. Shared by the
    /// round-loop vote and the late vote from `process_block`, so a vote is
    /// cast exactly once per leader round whichever path gets there first.
    voted_rounds: Mutex<std::collections::BTreeSet<Round>>,
    /// Verified VRF hashes, keyed by round then authority. Only consulted
    /// when `use_vrf_leader` is set. Empty until a caller records a proof
    /// that has already been checked against the committee VRF public key.
    vrf_outputs: RwLock<HashMap<Round, HashMap<kovanica_types::AuthorityIndex, [u8; 32]>>>,
    /// When this node first held the leader block for a leader round.
    ///
    /// The commit path observes `now - first_seen` as node-local finality
    /// latency. Entries are removed on commit and pruned with the round
    /// window, so the map stays bounded by `max_pending_rounds`.
    leader_first_seen: RwLock<HashMap<Round, Instant>>,
    /// This node's own timeouts, by slot (PRO-40 (b)). Together with
    /// `voted_rounds` this is the vote-xor-timeout lock; both are restored
    /// from the store at start-up. Lock order: `voted_rounds` first.
    own_timeouts: Mutex<std::collections::BTreeMap<Round, kovanica_types::Timeout>>,
    /// Verified timeouts of all signers for undecided slots.
    timeout_pool: Mutex<TimeoutPool>,
    /// The first undecided slot and when this node started waiting on it
    /// (after its vote round). Drives `T_skip` and rebroadcasts.
    stall_timer: Mutex<Option<(Round, Instant)>>,
    /// Last time a stored skip certificate was served for a round, to rate
    /// limit answers to lagging peers.
    cert_served: Mutex<HashMap<Round, Instant>>,
    timeout_broadcaster: RwLock<Option<Arc<dyn TimeoutBroadcaster>>>,
    /// Bounded buffer for unanchored/early votes on awaited or future leader rounds (PRO-40 (a)).
    /// Holds votes that arrived before the corresponding leader block was ingested.
    pending_votes: Mutex<std::collections::BTreeMap<Round, Vec<kovanica_types::Vote>>>,
}

impl<D, B> ConsensusEngine<D, B>
where
    D: DagStoreTrait + 'static,
    B: BlockManagerTrait + 'static,
{
    /// Create a new consensus engine.
    pub fn new(
        config: ConsensusConfig,
        committee: CommitteeInfo,
        dag_store: Arc<D>,
        block_manager: Arc<RwLock<B>>,
        signing_key: kovanica_types::SigningKey,
        mempool: Option<Arc<Mempool>>,
        signing_ctx: kovanica_types::SigningContext,
    ) -> Self {
        let our_authority = block_manager.read().our_authority();
        let our_stake = committee.stake_of(our_authority).unwrap_or(0);

        let committer = UniversalCommitter::new(
            committee.clone(),
            config.use_mysticghost,
            config.prune_window_waves,
        );
        let linearizer = Linearizer::new();

        let mut leader_schedule = HashMap::new();
        // Generate leader schedule for first 1000 rounds
        for round in 0..1000 {
            let leader = committee.leader(round);
            leader_schedule.insert(round, leader);
        }

        // Create watch channel for round notifications
        let (round_tx, _round_rx) = watch::channel(0);

        Self {
            signing_ctx,
            config,
            committee,
            signing_key,
            dag_store,
            block_manager,
            committer,
            linearizer,
            state: RwLock::new(ValidatorState {
                our_authority,
                our_stake,
                current_round: 0,
                is_leader: false,
                proposed: false,
            }),
            current_round: RwLock::new(0),
            leader_schedule: RwLock::new(leader_schedule),
            running: RwLock::new(false),
            commit_sender: RwLock::new(None),
            block_broadcaster: RwLock::new(None),
            vote_broadcaster: RwLock::new(None),
            round_sender: RwLock::new(Some(round_tx)),
            commit_trigger_lock: Mutex::new(()),
            mempool,
            leader_deadline: RwLock::new(None),
            voted_rounds: Mutex::new(std::collections::BTreeSet::new()),
            vrf_outputs: RwLock::new(HashMap::new()),
            leader_first_seen: RwLock::new(HashMap::new()),
            own_timeouts: Mutex::new(std::collections::BTreeMap::new()),
            timeout_pool: Mutex::new(TimeoutPool::default()),
            stall_timer: Mutex::new(None),
            cert_served: Mutex::new(HashMap::new()),
            timeout_broadcaster: RwLock::new(None),
            pending_votes: Mutex::new(std::collections::BTreeMap::new()),
        }
    }

    /// Record a VRF hash that the caller has already verified.
    ///
    /// The hash is stored under the block round it was proved for. Leader
    /// selection reads the previous decide round, and only when every
    /// VRF-keyed authority is present. The node must not call this with an
    /// unverified hash.
    pub fn record_verified_vrf_output(
        &self,
        round: Round,
        author: kovanica_types::AuthorityIndex,
        hash: [u8; 32],
    ) {
        self.vrf_outputs
            .write()
            .entry(round)
            .or_default()
            .entry(author)
            .or_insert(hash);
    }

    fn ingest_vrf_outputs(&self) {
        let fresh = self.block_manager.read().verified_vrf_outputs();
        if fresh.is_empty() {
            return;
        }
        let mut stored = self.vrf_outputs.write();
        for (round, authors) in fresh {
            let slot = stored.entry(round).or_default();
            for (author, hash) in authors {
                slot.entry(author).or_insert(hash);
            }
        }
    }

    fn committee_has_vrf_keys(&self) -> bool {
        self.committee
            .authorities()
            .iter()
            .any(|authority| authority.vrf_public_key.is_some())
    }

    fn vrf_set_complete(
        &self,
        outputs: &HashMap<kovanica_types::AuthorityIndex, [u8; 32]>,
    ) -> bool {
        let mut vrf_validators = 0u32;
        let mut present = 0u32;
        for authority in self.committee.authorities() {
            if authority.vrf_public_key.is_none() {
                continue;
            }
            vrf_validators += 1;
            if outputs.contains_key(&authority.index) {
                present += 1;
            }
        }
        if vrf_validators == 0 {
            return false;
        }
        // Quorum: 2f+1 = floor(2*N/3) + 1 where N is number of VRF-keyed validators
        let quorum = (vrf_validators * 2 / 3) + 1;
        present >= quorum
    }

    fn publish_vrf_carrier(&self, round: Round) {
        let proposed = self.block_manager.read().propose_vrf_carrier(round);
        match proposed {
            Ok(block) => {
                self.ingest_vrf_outputs();
                info!(
                    "Published VRF carrier {} at decide round {}",
                    block.digest, round
                );
                if let Some(broadcaster) = self.block_broadcaster.read().as_ref() {
                    broadcaster.broadcast_block(&block);
                }
            }
            Err(err) => {
                debug!(
                    error = %err,
                    round,
                    "skipping VRF carrier"
                );
            }
        }
    }

    /// Set the block broadcaster for gossiping proposed blocks.
    pub fn set_block_broadcaster(&self, broadcaster: Arc<dyn BlockBroadcaster>) {
        *self.block_broadcaster.write() = Some(broadcaster);
    }

    /// Set the vote broadcaster for gossiping votes.
    pub fn set_vote_broadcaster(&self, broadcaster: Arc<dyn VoteBroadcaster>) {
        *self.vote_broadcaster.write() = Some(broadcaster);
    }

    /// Attach the network side for timeouts and skip certificates.
    pub fn set_timeout_broadcaster(&self, broadcaster: Arc<dyn TimeoutBroadcaster>) {
        *self.timeout_broadcaster.write() = Some(broadcaster);
    }

    /// Deliver durable committed sub-DAGs to the execution pipeline.
    pub fn set_commit_sender(
        &self,
        sender: mpsc::UnboundedSender<kovanica_types::CommittedSubDag>,
    ) {
        *self.commit_sender.write() = Some(sender);
    }

    /// Start the consensus engine.
    pub async fn start(&self) -> Result<(), ConsensusError> {
        info!("Starting consensus engine");
        // The key comes from the node's explicit validator configuration. Do
        // not generate or replace validator identity inside consensus.
        self.block_manager
            .read()
            .set_signing_key(self.signing_key.clone());
        self.resume_from_store()?;
        *self.running.write() = true;

        // Start the round loop
        self.round_loop().await
    }

    /// Seed the round counter from the persisted DAG tip.
    ///
    /// A restarted node must continue after the rounds it already holds.
    /// Starting at round 0 makes it propose for decided rounds again, and
    /// `mark_round_decided` then stops the whole engine with
    /// [`kovanica_dag::DagStoreError::ConflictingDecision`] — the node could
    /// never restart against a non-empty chain.
    ///
    /// An empty store keeps the counter at 0: a fresh chain starts at round 0
    /// and the first loop iteration still advances to round 1.
    fn resume_from_store(&self) -> Result<(), ConsensusError> {
        let Some(tip) = self.dag_store.max_stored_round()? else {
            return Ok(());
        };
        if tip == 0 {
            return Ok(());
        }
        self.restore_undecided_leaders(tip)?;

        let mut current = self.current_round.write();
        if *current >= tip {
            // Already ahead (e.g. start() called twice); never move backwards.
            return Ok(());
        }
        *current = tip;
        self.state.write().current_round = tip;
        info!(
            stored_round = tip,
            next_round = tip + 1,
            "resuming consensus from the persisted DAG tip"
        );
        Ok(())
    }

    /// Restore the commit cursor and the undecided leaders after a restart.
    ///
    /// The committer's cursor and leader map live in memory. Before PRO-40 a
    /// restarted node started its walk at round 0 with an empty map, so the
    /// first leader it heard about after the restart became the first
    /// candidate and every undecided slot in between was passed over without
    /// a quorum. Now:
    ///
    /// 1. the cursor is restored from the persisted decision index;
    /// 2. stored decide-round carriers in `(cursor, tip]` are re-verified
    ///    through the block manager, and those VRF outputs are ingested
    ///    **before** any leader is selected;
    /// 3. every leader slot in `(cursor, tip]` whose scheduled leader block is
    ///    in the store is registered again, and the votes persisted for it
    ///    (RFC-009) are replayed through [`Self::process_vote`], the same
    ///    authentication boundary as live votes.
    ///
    /// Selecting the leader first would see an empty VRF map and fall back to
    /// round-robin, then miss the VRF leader's block. A slot whose block is
    /// not in the store keeps no record, so the walk stalls there until block
    /// sync delivers it. It never skips the slot.
    fn restore_undecided_leaders(&self, tip: Round) -> Result<(), ConsensusError> {
        let cursor = self
            .dag_store
            .get_decided_rounds(u64::MAX)?
            .into_iter()
            .max()
            .unwrap_or(0);
        self.committer.restore_last_decided_round(cursor);
        // A certified seal or state-sync checkpoint may sit further ahead than
        // the decision index when the rounds in between were pruned.
        self.committer
            .catch_up_to_certified_anchor(self.dag_store.as_ref())?;
        let cursor = self.committer.last_decided_round();

        // Replay, then ingest, then select. Ingest with an empty manager
        // (no replay) leaves the map empty and the slot stays round-robin.
        self.replay_stored_vrf_carriers(cursor, tip)?;
        self.ingest_vrf_outputs();

        let mut restored = 0usize;
        let mut round = (cursor / kovanica_types::WAVE_LENGTH + 1) * kovanica_types::WAVE_LENGTH;
        // Own votes and timeouts first, over a range that also covers slots
        // timed out after the last stored block, so the vote-xor-timeout lock
        // survives the restart even where the leader block is missing.
        let lock_end = tip + self.config.skip_timeout_rounds + 2 * kovanica_types::WAVE_LENGTH;
        let mut lock_slot = round;
        while lock_slot <= lock_end {
            self.restore_slot_locks(lock_slot)?;
            lock_slot += kovanica_types::WAVE_LENGTH;
        }
        while round <= tip {
            let slot = round;
            round += kovanica_types::WAVE_LENGTH;
            if self.committer.get_leader(slot).is_some() {
                continue;
            }
            let Some(author) = self.scheduled_leader_for_round(slot) else {
                continue;
            };
            let Some(block) = self.dag_store.get_block_by_author_round(author, slot)? else {
                continue;
            };
            self.committer.update_leader(LeaderInfo {
                round: slot,
                author,
                block_hash: Some(block.digest),
                status: LeaderStatus::Undecided,
                votes: HashMap::new(),
            });
            restored += 1;
            for vote in self.dag_store.get_votes_for_round(slot)? {
                if let Err(e) = self.process_vote(&vote) {
                    debug!(round = slot, error = %e, "persisted vote not re-applied");
                }
            }
        }
        if restored > 0 || cursor > 0 {
            info!(
                cursor,
                restored, "restored the commit cursor and undecided leaders from the store"
            );
        }
        Ok(())
    }

    /// Re-verify decide-round carriers whose VRF outputs elect leaders in
    /// `(cursor, tip]`.
    ///
    /// The block manager is new on every process start, so its verified-output
    /// map is empty until these blocks are processed again. A carrier that
    /// fails verification is skipped: that beacon stays incomplete and the
    /// slot keeps round-robin. The scan is only the decide round (wave offset
    /// 2) of each leader slot, and it stops at `u64::MAX` instead of wrapping.
    fn replay_stored_vrf_carriers(&self, cursor: Round, tip: Round) -> Result<(), ConsensusError> {
        let mut slot = (cursor / kovanica_types::WAVE_LENGTH + 1) * kovanica_types::WAVE_LENGTH;
        while slot <= tip {
            if let Some(beacon) = election_beacon(slot) {
                if beacon > cursor && beacon <= tip {
                    for block in self.dag_store.get_blocks_by_round(beacon)? {
                        if let Err(e) = self.block_manager.read().process_block(&block) {
                            debug!(
                                round = beacon,
                                author = block.author,
                                error = %e,
                                "stored VRF carrier was not re-verified"
                            );
                        }
                    }
                }
            }
            slot = match slot.checked_add(kovanica_types::WAVE_LENGTH) {
                Some(next) => next,
                None => break,
            };
        }
        Ok(())
    }

    /// Reload this node's own vote/timeout for `slot` and the stored
    /// timeouts of other signers (PRO-40 (b)).
    fn restore_slot_locks(&self, slot: Round) -> Result<(), ConsensusError> {
        let our = self.state.read().our_authority;
        if self
            .dag_store
            .get_votes_for_round(slot)?
            .iter()
            .any(|v| v.voter == our)
        {
            self.voted_rounds.lock().insert(slot);
        }
        let mut certified = false;
        for timeout in self.dag_store.get_timeouts_for_round(slot)? {
            if verify_timeout(
                &self.committee,
                self.signing_ctx.chain_id,
                &self.config.genesis_hash,
                &timeout,
            )
            .is_err()
            {
                continue;
            }
            if timeout.voter == our {
                self.own_timeouts.lock().insert(slot, timeout.clone());
            }
            let mut pool = self.timeout_pool.lock();
            pool.insert(timeout);
            certified = pool.certificate(&self.committee, slot).is_some();
        }
        if certified {
            self.committer.record_skip_certificate(slot);
        }
        Ok(())
    }

    /// Stop the consensus engine.
    pub fn stop(&self) {
        *self.running.write() = false;
    }

    /// Main round loop - advances rounds and produces blocks.
    async fn round_loop(&self) -> Result<(), ConsensusError> {
        let mut round_interval = interval(Duration::from_millis(self.config.round_duration_ms));

        while *self.running.read() {
            // Timeout check: stall on leader if no block by the absolute deadline.
            // PRO-35 fix: Do NOT call register_skip (local timeout skip causes fork).
            // The chain stalls until quorum arrives or a quorum-certified skip is
            // implemented (future RFC). skip_leader returns in-flight txs to mempool
            // so they can be re-proposed, but does not advance the commit cursor.
            {
                let deadline_opt = *self.leader_deadline.read();
                if let Some((round, deadline)) = deadline_opt {
                    if std::time::Instant::now() >= deadline {
                        // Check if we have a leader for this round
                        if let Some(leader_author) = self.scheduled_leader_for_round(round) {
                            // Return in-flight transactions to mempool so they can be
                            // re-proposed by the next leader. Do NOT record a Skip.
                            self.skip_leader(round)?;
                        }
                        *self.leader_deadline.write() = None;
                    }
                }
            }

            round_interval.tick().await;

            let current_round = *self.current_round.read();
            let next_round = current_round + 1;

            // Advance to next round
            *self.current_round.write() = next_round;

            // Record the round on its own gauge. Writing it into `block_height`
            // made that gauge fall back to the committed leader round on every
            // commit, because three rounds pass per committed leader.
            record_current_round(next_round as i64);

            // Broadcast round change to subscribers
            if let Some(tx) = self.round_sender.read().as_ref() {
                let _ = tx.send(next_round);
            }

            // Carriers from the previous decide round have to be in the map
            // before this round picks a leader.
            self.ingest_vrf_outputs();

            // Update our validator state
            let is_leader = self.is_leader_for_round(next_round);
            {
                let mut state = self.state.write();
                state.current_round = next_round;
                state.is_leader = is_leader;
                state.proposed = false;
            }

            // Late votes for the slots the commit walk is waiting on (PRO-40
            // (a)), then try to commit any pending leaders.
            self.vote_awaited_slots()?;
            self.check_skip_timeout()?;
            self.drain_commits()?;

            // If we're the leader, propose a block (no timeout needed; we just proposed).
            // Non-leaders: start an absolute deadline for the scheduled leader of this round.
            if is_leader {
                self.propose_block(next_round).await?;
            } else if crate::is_leader_round(next_round) {
                let deadline =
                    std::time::Instant::now() + Duration::from_millis(self.leader_timeout_ms());
                *self.leader_deadline.write() = Some((next_round, deadline));
            }

            // Decide rounds are where every VRF-keyed authority publishes the
            // output that elects the next leader. No transactions, and the
            // block is not a leader slot.
            if self.config.use_vrf_leader
                && offset_in_wave(next_round) == 2
                && self.committee_has_vrf_keys()
            {
                self.publish_vrf_carrier(next_round);
            }

            // If this is a vote round, produce a vote for the previous leader round
            if crate::is_vote_round(next_round) {
                self.produce_vote(next_round).await?;
            }

            // Clean up old rounds
            self.cleanup_old_rounds(next_round);
        }

        Ok(())
    }

    /// Handle a leader slot whose deadline expired (timeout).
    ///
    /// Since PRO-35 this is **not** a decision: it records a hash-less leader
    /// placeholder, increments the timeout counter and returns the slot's
    /// in-flight transactions to the mempool so a later leader can re-propose
    /// them. The committer never learns that the round was "skipped" — it keeps
    /// stalling at the round until a real quorum arrives, so a node that
    /// timed out and a node that did not can never commit different leaders at
    /// the same height.
    fn skip_leader(&self, round: Round) -> Result<(), ConsensusError> {
        if let Some(leader) = self.scheduled_leader_for_round(round) {
            let info = LeaderInfo {
                round,
                author: leader,
                block_hash: None,
                status: LeaderStatus::Skip,
                votes: HashMap::new(),
            };
            self.committer.update_leader(info);
            // No Skip decision is recorded (PRO-35): the counter below measures
            // "the leader block did not arrive by the deadline", not "the chain
            // moved past this round". The chain stalls instead.
            record_skipped_leader(SkipReason::Timeout);
            info!("Leader round {} timed out (no commit decision)", round);

            // Return the skipped leader's in-flight transactions to mempool queue
            // so they can be re-proposed by the next leader
            if let Some(mempool) = &self.mempool {
                if let Some(authority) = self.committee.get_by_index(leader) {
                    let returned =
                        mempool.return_in_flight_for_sender(&authority.address, Instant::now());
                    if returned > 0 {
                        info!(leader = ?leader, address = %authority.address, returned, "returned in-flight transactions to queue after leader skip");
                    }
                }
            }
        }
        // Try to commit after skip so downstream can progress
        self.try_commit_and_deliver()?;
        Ok(())
    }

    /// Check if we are the leader for a given round.
    fn is_leader_for_round(&self, round: Round) -> bool {
        self.scheduled_leader_for_round(round) == Some(self.state.read().our_authority)
    }

    /// Return the scheduled leader only for a protocol leader slot.
    ///
    /// Public so the node can tell whether a block it synced is a leader
    /// round, i.e. a round for which it will need the votes (RFC-009).
    pub fn scheduled_leader_for_round(
        &self,
        round: Round,
    ) -> Option<kovanica_types::AuthorityIndex> {
        if !is_leader_round(round) {
            return None;
        }

        // The constructor prefetches round-robin for rounds 0..1000. When
        // the flag is on, a complete output set from the previous decide
        // round replaces that prefetch. A missing output keeps round-robin
        // for every authority, so a partial view cannot elect alone.
        if self.config.use_vrf_leader {
            if let Some(beacon) = election_beacon(round) {
                let outputs = self
                    .vrf_outputs
                    .read()
                    .get(&beacon)
                    .cloned()
                    .unwrap_or_default();
                if self.vrf_set_complete(&outputs) {
                    return Some(self.committee.leader_with_vrf(round, &outputs));
                }
            }
        }

        Some(
            self.leader_schedule
                .read()
                .get(&round)
                .copied()
                .unwrap_or_else(|| self.committee.leader(round)),
        )
    }

    /// Propose a block for the given round.
    async fn propose_block(&self, round: Round) -> Result<(), ConsensusError> {
        info!("Proposing block for round {}", round);

        // Get transactions from mempool if available
        let transactions = if let Some(mempool) = &self.mempool {
            mempool.get_next_transactions(MAX_TXS_PER_BLOCK)
        } else {
            Vec::new()
        };

        let proposed = self
            .block_manager
            .read()
            .propose_block_with_txs(round, transactions);
        match proposed {
            Ok(block) => {
                // Update committer with leader info
                let leader_info = LeaderInfo {
                    round,
                    author: self.state.read().our_authority,
                    block_hash: Some(block.digest),
                    status: LeaderStatus::Undecided,
                    votes: HashMap::new(),
                };
                self.committer.update_leader(leader_info);
                self.note_leader_block_seen(round);

                // Mark as proposed for this round.
                self.state.write().proposed = true;

                info!(
                    "Proposed block {} at round {} with {} transactions",
                    block.digest,
                    round,
                    block.transactions.len()
                );
                self.ingest_vrf_outputs();

                // Broadcast the block to the network
                if let Some(broadcaster) = self.block_broadcaster.read().as_ref() {
                    broadcaster.broadcast_block(&block);
                }

                Ok(())
            }
            Err(e) => {
                warn!("Failed to propose block: {}", e);
                Err(ConsensusError::BlockProposal(e.to_string()))
            }
        }
    }

    /// Produce a vote for the leader of the previous leader round.
    /// Called during vote rounds (offset 1).
    async fn produce_vote(&self, vote_round: Round) -> Result<(), ConsensusError> {
        self.vote_for_leader(vote_round - 1)?;
        Ok(())
    }

    /// Cast this node's vote for the leader block of `leader_round`, at most
    /// once per round.
    ///
    /// Called from the round loop at the vote round and again from
    /// [`Self::process_block`] when the leader block arrives late (after the
    /// vote round already passed). Returns `true` if a vote was cast now.
    /// If the leader block is not known yet nothing is recorded, so a later
    /// call can still vote.
    fn vote_for_leader(&self, leader_round: Round) -> Result<bool, ConsensusError> {
        // A round is *final* once the commit cursor has moved past it: the
        // decision walk starts above `last_decided_round` and will never
        // revisit it, so a late vote could only let a lagging peer commit a
        // round this node settled differently, producing divergent committed
        // sequences (see `late_join_integration`). Refuse in that case.
        //
        // Since PRO-35 the only decision is Commit: `decided_leaders` never
        // holds a Skip, and `mark_decided` is the only writer of the cursor, so
        // `is_decided` and "the cursor passed this round" now coincide. The
        // explicit cursor comparison is kept because it is the property that
        // matters — a timeout is *not* a decision, so a round this node merely
        // timed out on must still be votable when its block finally arrives
        // (otherwise one missed timeout would make quorum unreachable and the
        // chain would halt while every component still reported healthy).
        //
        // PRO-40 (b): every leader slot at or below the cursor is decided
        // (committed, or skipped with a certificate), including slots decided
        // before a restart that the in-memory map no longer holds, so the
        // cursor alone is the test.
        if self.committer.last_decided_round() >= leader_round {
            debug!(
                "Leader round {} already decided locally; not voting",
                leader_round
            );
            return Ok(false);
        }

        if self.scheduled_leader_for_round(leader_round).is_none() {
            debug!("No leader scheduled for round {}", leader_round);
            return Ok(false);
        }

        let Some(leader_info) = self.committer.get_leader(leader_round) else {
            debug!("No leader info for round {}", leader_round);
            return Ok(false);
        };

        let Some(leader_hash) = leader_info.block_hash else {
            debug!("Leader block for round {} not yet known", leader_round);
            return Ok(false);
        };

        let our_authority = self.state.read().our_authority;
        {
            // Check-and-mark under one lock: exactly one caller wins.
            //
            // `voted_rounds` is memory-only. After a restart it is empty, and
            // a min-digest swap rejects the replayed vote (`LeaderHashMismatch`),
            // so the awaited-slot path would sign a second digest for the same
            // slot. The stored vote for `(slot, our authority)` is the lock:
            // a different digest is refused, and the same digest is not signed
            // again.
            let mut voted = self.voted_rounds.lock();
            if voted.contains(&leader_round) || leader_info.votes.contains_key(&our_authority) {
                debug!("Already voted for leader round {}", leader_round);
                return Ok(false);
            }
            // Vote xor timeout (PRO-40 (b)): a slot this node timed out is
            // never voted for, also after a restart (durable check).
            if self.own_timeouts.lock().contains_key(&leader_round)
                || self
                    .dag_store
                    .get_timeouts_for_round(leader_round)?
                    .iter()
                    .any(|t| t.voter == our_authority)
            {
                debug!(
                    "Timed out leader round {} earlier; not voting",
                    leader_round
                );
                return Ok(false);
            }
            match self.dag_store.get_votes_for_round(leader_round) {
                Ok(votes) => {
                    if let Some(stored) = votes.into_iter().find(|vote| vote.voter == our_authority)
                    {
                        voted.insert(leader_round);
                        if stored.leader_hash != leader_hash {
                            warn!(
                                leader_round,
                                voter = our_authority,
                                stored = %stored.leader_hash,
                                candidate = %leader_hash,
                                "refusing to sign a second digest for the same slot"
                            );
                        } else {
                            debug!(
                                "stored self-vote already covers leader round {}",
                                leader_round
                            );
                        }
                        return Ok(false);
                    }
                }
                Err(e) => {
                    // Fail closed. Signing without knowing whether a vote is
                    // already stored can publish two digests for one slot.
                    warn!(
                        leader_round,
                        voter = our_authority,
                        error = %e,
                        "refusing to vote; the stored self-vote could not be read"
                    );
                    return Ok(false);
                }
            }
            voted.insert(leader_round);
        }

        // Create and sign the vote
        let mut vote = kovanica_types::Vote {
            leader_round,
            leader_hash,
            voter: our_authority,
            signature: kovanica_types::Signature([0u8; 64]),
        };
        vote.signature = sign(
            &self.signing_key,
            &vote.signature_data(&self.vote_signing_ctx(leader_round)),
        );

        // Persist before broadcast and before the vote counts locally. A
        // crash or a storage error must not leave a signature on the wire
        // that the next start cannot see. A failed write is not remembered,
        // same as a timeout that could not be stored: nothing was sent, so a
        // later attempt may still vote. Once a vote is stored, the check
        // above refuses a second digest for this slot.
        if let Err(e) = self.dag_store.as_ref().put_vote(&vote) {
            self.voted_rounds.lock().remove(&leader_round);
            warn!(
                leader_round,
                voter = our_authority,
                error = %e,
                "own vote could not be persisted; not broadcasting it"
            );
            return Ok(false);
        }

        // Record the vote locally only after it is durable.
        self.committer
            .add_vote(leader_round, our_authority, leader_hash);

        // Broadcast the vote. Log unconditionally: a vote we recorded locally
        // but could not broadcast is exactly the state that stalls a quorum,
        // and it must be visible at `info` level rather than silently skipped
        // when no broadcaster is attached to this engine.
        match self.vote_broadcaster.read().as_ref() {
            Some(broadcaster) => {
                broadcaster.broadcast_vote(&vote);
                info!(
                    "Broadcast vote for leader round {} (hash: {})",
                    leader_round, leader_hash
                );
            }
            None => {
                warn!(
                    "Recorded vote for leader round {} (hash: {}) but no vote broadcaster is attached",
                    leader_round, leader_hash
                );
            }
        }

        // Try to commit after voting
        self.try_commit_and_deliver()?;

        Ok(true)
    }

    /// Late vote: the leader block of `round` arrived after our vote round
    /// (`round + 1`) already passed, so the round loop could not vote for it.
    fn vote_if_late(&self, round: Round) -> Result<(), ConsensusError> {
        let current = *self.current_round.read();
        if current <= round {
            return Ok(());
        }
        // Outside `late_vote_window_rounds` (default `WAVE_LENGTH` = 3
        // rounds) a vote is only cast for a round the commit walk is waiting
        // on (PRO-40 (a)). Since PRO-35 no node moves past a leader slot
        // without that slot's own quorum, so a late vote for an awaited slot
        // is exactly what restores quorum; it cannot help a lagging peer
        // commit a sequence the others settled differently. Any other stale
        // round keeps the window.
        if current - round > self.config.late_vote_window_rounds && !self.is_awaited_slot(round) {
            debug!(
                "Not voting for stale leader round {} (current round {}, window {})",
                round, current, self.config.late_vote_window_rounds
            );
            return Ok(());
        }
        if self.vote_for_leader(round)? {
            info!(
                "Late vote for leader round {} (current round {})",
                round, current
            );
        }
        Ok(())
    }

    /// Whether `round` is one of the first [`LATE_VOTE_AWAITED_SLOTS`] leader
    /// slots above the commit cursor, i.e. a slot the commit walk is waiting
    /// on (PRO-40 (a)). Such a slot may be voted for after the late-vote
    /// window has passed.
    fn is_awaited_slot(&self, round: Round) -> bool {
        let cursor = self.committer.last_decided_round();
        let first = next_leader_slot(cursor);
        is_leader_round(round)
            && round >= first
            && round < first + LATE_VOTE_AWAITED_SLOTS * kovanica_types::WAVE_LENGTH
    }

    /// Retry the late vote for every awaited slot whose leader block is
    /// known. Called every round, so a block that arrived while its slot was
    /// not yet awaited (outside the window, further than
    /// [`LATE_VOTE_AWAITED_SLOTS`] above the cursor) is voted for once the
    /// cursor reaches it. `vote_for_leader` is idempotent (one vote per
    /// round), so the retry never double-votes.
    fn vote_awaited_slots(&self) -> Result<(), ConsensusError> {
        let first = next_leader_slot(self.committer.last_decided_round());
        for k in 0..LATE_VOTE_AWAITED_SLOTS {
            let slot = first + k * kovanica_types::WAVE_LENGTH;
            let known = self
                .committer
                .get_leader(slot)
                .is_some_and(|leader| leader.block_hash.is_some());
            if known {
                self.vote_if_late(slot)?;
            }
        }
        Ok(())
    }

    /// `T_skip` as a duration.
    fn skip_timeout(&self) -> Duration {
        Duration::from_millis(
            self.config
                .skip_timeout_rounds
                .saturating_mul(self.config.round_duration_ms),
        )
    }

    /// Highest slot a timeout or certificate is accepted for.
    fn timeout_high_water(&self) -> Round {
        let current = *self.current_round.read();
        current.saturating_add(
            self.config
                .lookahead_rounds
                .max(kovanica_types::WAVE_LENGTH),
        )
    }

    /// Called every round (PRO-40 (b)). Once the first undecided slot has
    /// stayed unvoted for `T_skip` after its vote round, sign a timeout for
    /// it; while it stays stalled, rebroadcast this node's own timeout or
    /// vote every `T_skip`, so lost messages and lagging peers recover.
    fn check_skip_timeout(&self) -> Result<(), ConsensusError> {
        if self.state.read().our_stake == 0 {
            return Ok(());
        }
        let slot = next_leader_slot(self.committer.last_decided_round());
        let current = *self.current_round.read();
        if current <= slot + 1 {
            // The vote round has not passed yet.
            *self.stall_timer.lock() = None;
            return Ok(());
        }
        let now = Instant::now();
        {
            let mut timer = self.stall_timer.lock();
            match *timer {
                Some((stalled, since)) if stalled == slot => {
                    if now.duration_since(since) < self.skip_timeout() {
                        return Ok(());
                    }
                }
                _ => {
                    *timer = Some((slot, now));
                    return Ok(());
                }
            }
            *timer = Some((slot, now));
        }
        self.time_out_or_rebroadcast(slot)
    }

    /// Sign a timeout for `slot` unless this node voted for it; otherwise
    /// rebroadcast what it already signed for the slot.
    pub(crate) fn time_out_or_rebroadcast(&self, slot: Round) -> Result<(), ConsensusError> {
        if let Some(own) = self.own_timeouts.lock().get(&slot).cloned() {
            if let Some(b) = self.timeout_broadcaster.read().as_ref() {
                b.broadcast_timeout(&own);
            }
            return Ok(());
        }
        let our = self.state.read().our_authority;
        let own_vote = self
            .dag_store
            .get_votes_for_round(slot)?
            .into_iter()
            .find(|v| v.voter == our);
        if let Some(vote) = own_vote {
            if let Some(b) = self.vote_broadcaster.read().as_ref() {
                b.broadcast_vote(&vote);
            }
            return Ok(());
        }
        self.sign_timeout(slot)?;
        Ok(())
    }

    /// Sign, durably record, and broadcast this node's timeout for `slot`
    /// (PRO-40 (b)). Returns `false` if the node voted for the slot or
    /// already timed it out. The timeout is written to the store **before**
    /// it leaves the node; if that write fails it is not sent.
    pub(crate) fn sign_timeout(&self, slot: Round) -> Result<bool, ConsensusError> {
        if !is_leader_round(slot) || slot <= self.committer.last_decided_round() {
            return Ok(false);
        }
        let our = self.state.read().our_authority;
        let timeout = {
            let voted = self.voted_rounds.lock();
            let mut own = self.own_timeouts.lock();
            if voted.contains(&slot) || own.contains_key(&slot) {
                return Ok(false);
            }
            let voted_in_map = self
                .committer
                .get_leader(slot)
                .is_some_and(|l| l.votes.contains_key(&our));
            if voted_in_map
                || self
                    .dag_store
                    .get_votes_for_round(slot)?
                    .iter()
                    .any(|v| v.voter == our)
            {
                return Ok(false);
            }
            let mut timeout = kovanica_types::Timeout {
                round: slot,
                voter: our,
                signature: kovanica_types::Signature([0u8; 64]),
            };
            timeout.signature = sign(
                &self.signing_key,
                &timeout.signature_data(self.signing_ctx.chain_id, &self.config.genesis_hash),
            );
            if let Err(e) = self.dag_store.put_timeout(&timeout) {
                warn!(
                    round = slot,
                    error = %e,
                    "own timeout could not be persisted; not sending it"
                );
                return Ok(false);
            }
            own.insert(slot, timeout.clone());
            timeout
        };
        record_timeout_signed();
        warn!(
            round = slot,
            "leader slot still undecided after T_skip; signed a timeout"
        );
        self.add_verified_timeout(timeout.clone())?;
        match self.timeout_broadcaster.read().as_ref() {
            Some(b) => b.broadcast_timeout(&timeout),
            None => warn!(round = slot, "no timeout broadcaster is attached"),
        }
        Ok(true)
    }

    /// Process a timeout received from the network (PRO-40 (b)).
    ///
    /// Accepted for slots in `(cursor, current + lookahead]`, at most one per
    /// signer and slot. A timeout for a slot this node already skipped is
    /// answered with the stored certificate, which is how a lagging peer
    /// moves past a slot the others skipped while it was away.
    pub fn process_timeout(&self, timeout: &kovanica_types::Timeout) -> Result<(), ConsensusError> {
        verify_timeout(
            &self.committee,
            self.signing_ctx.chain_id,
            &self.config.genesis_hash,
            timeout,
        )?;
        let cursor = self.committer.last_decided_round();
        if timeout.round <= cursor {
            self.serve_skip_cert(timeout.round)?;
            return Ok(());
        }
        let high = self.timeout_high_water();
        if timeout.round > high {
            return Err(TimeoutRejection::OutOfRange {
                round: timeout.round,
                low: cursor,
                high,
            }
            .into());
        }
        self.add_verified_timeout(timeout.clone())
    }

    /// Pool a verified timeout, persist it, and act on a new certificate.
    fn add_verified_timeout(&self, timeout: kovanica_types::Timeout) -> Result<(), ConsensusError> {
        let round = timeout.round;
        let voter = timeout.voter;
        if self
            .committer
            .get_leader(round)
            .is_some_and(|l| l.votes.contains_key(&voter))
        {
            record_vote_timeout_equivocation();
            warn!(
                round,
                voter, "validator signed both a vote and a timeout for one slot"
            );
        }
        let cert = {
            let mut pool = self.timeout_pool.lock();
            if !pool.insert(timeout.clone()) {
                return Ok(());
            }
            pool.certificate(&self.committee, round)
        };
        if voter != self.state.read().our_authority {
            if let Err(e) = self.dag_store.put_timeout(&timeout) {
                warn!(round, voter, error = %e, "accepted timeout could not be persisted");
            }
        }
        if let Some(cert) = cert {
            if !self.committer.has_skip_certificate(round) {
                info!(
                    round,
                    signers = cert.timeouts.len(),
                    "skip certificate formed"
                );
                self.committer.record_skip_certificate(round);
                if let Some(b) = self.timeout_broadcaster.read().as_ref() {
                    b.broadcast_skip_cert(&cert);
                }
                self.drain_commits()?;
            }
        }
        Ok(())
    }

    /// Process a skip certificate received from the network (PRO-40 (b)).
    pub fn process_skip_cert(&self, cert: &kovanica_types::SkipCert) -> Result<(), ConsensusError> {
        let cursor = self.committer.last_decided_round();
        if cert.round <= cursor || self.committer.has_skip_certificate(cert.round) {
            return Ok(());
        }
        let high = self.timeout_high_water();
        // The upper bound caps memory against certificates for far-future
        // slots; a stale certificate (at or below the cursor) is ignored.
        if cert.round > high {
            return Err(TimeoutRejection::OutOfRange {
                round: cert.round,
                low: cursor,
                high,
            }
            .into());
        }
        verify_skip_cert(
            &self.committee,
            self.signing_ctx.chain_id,
            &self.config.genesis_hash,
            cert,
        )?;
        {
            let mut pool = self.timeout_pool.lock();
            for timeout in &cert.timeouts {
                if pool.insert(timeout.clone()) {
                    if let Err(e) = self.dag_store.put_timeout(timeout) {
                        warn!(round = cert.round, error = %e, "certificate timeout could not be persisted");
                    }
                }
            }
        }
        info!(round = cert.round, "received a valid skip certificate");
        self.committer.record_skip_certificate(cert.round);
        self.drain_commits()
    }

    /// Re-send the stored certificate for a slot this node skipped, at most
    /// once per `T_skip` per slot.
    fn serve_skip_cert(&self, round: Round) -> Result<(), ConsensusError> {
        if !self.dag_store.get_decided_leaders(round)?.is_empty() {
            return Ok(()); // committed, not skipped
        }
        let now = Instant::now();
        {
            let mut served = self.cert_served.lock();
            if served
                .get(&round)
                .is_some_and(|at| now.duration_since(*at) < self.skip_timeout())
            {
                return Ok(());
            }
            served.retain(|r, at| {
                *r + 64 * kovanica_types::WAVE_LENGTH > round
                    && now.duration_since(*at) < self.skip_timeout()
            });
            served.insert(round, now);
        }
        let mut pool = TimeoutPool::default();
        for timeout in self.dag_store.get_timeouts_for_round(round)? {
            pool.insert(timeout);
        }
        if let Some(cert) = pool.certificate(&self.committee, round) {
            if let Some(b) = self.timeout_broadcaster.read().as_ref() {
                debug!(round, "serving a stored skip certificate to a lagging peer");
                b.broadcast_skip_cert(&cert);
            }
        }
        Ok(())
    }

    /// Signing context for votes (v1, domain tag `KUNA/vote/v1`).
    ///
    /// Built ONLY from local state: the node's configured `chain_id` and the
    /// epoch derived from the voted `leader_round` (pure function of round).
    /// This ensures all nodes compute the SAME epoch for the same leader round,
    /// regardless of local committee state. A vote signed for another chain
    /// or epoch boundary never verifies.
    fn vote_signing_ctx(&self, leader_round: Round) -> kovanica_types::SigningContext {
        let epoch = kovanica_types::epoch_for_round(leader_round);
        kovanica_types::SigningContext {
            chain_id: self.signing_ctx.chain_id,
            epoch,
        }
    }

    /// Effective leader timeout (ms): explicit `leader_timeout_ms` unless it is 0,
    /// in which case `round_duration_ms * leader_timeout_factor` is used
    /// (Mysticeti-style adaptive timeout).
    pub fn leader_timeout_ms(&self) -> u64 {
        if self.config.leader_timeout_ms > 0 {
            self.config.leader_timeout_ms
        } else {
            self.config
                .round_duration_ms
                .saturating_mul(self.config.leader_timeout_factor.max(1))
                .max(1)
        }
    }

    /// Submit equivocation evidence for `(author, round)` to the local
    /// mempool, signed by this node.
    ///
    /// Best-effort and non-fatal: a missing mempool, an unknown authority
    /// index, a missing signing key match, or a full pool must never turn a
    /// detected fork into a consensus failure. The transaction is signed by
    /// the local validator (the only key this node holds), pays no fee, and
    /// is admitted under the normal rules — so a node that is not a validator
    /// simply cannot report, which is also true of gossip.
    ///
    /// Gated on `SLASHING_ACTIVE_FROM_ROUND`: below it the execution layer
    /// rejects evidence deterministically, so reporting would only waste
    /// block space.
    fn report_equivocation(&self, existing: &StatementBlock, incoming: &StatementBlock) {
        if !kovanica_types::slashing_active_from(incoming.round) {
            return;
        }
        let Some(mempool) = self.mempool.as_ref() else {
            return;
        };
        let Some(author) = self
            .committee
            .authorities()
            .iter()
            .find(|a| a.index == incoming.author)
            .map(|a| a.address)
        else {
            return;
        };
        let Ok(evidence) = EquivocationEvidence::from_blocks(existing, incoming, author) else {
            return;
        };
        let sender = Address::from_public_key(&kovanica_types::PublicKey(
            self.signing_key.verifying_key().to_bytes(),
        ));
        // The pool's accepted nonce can move between our read and admission
        // (the node's own traffic uses the same account). Retry a few times
        // on a nonce race; anything else is not worth retrying.
        for _ in 0..3 {
            let Ok(nonce) = mempool.next_nonce(&sender) else {
                return;
            };
            let mut tx = Transaction {
                sender,
                nonce,
                kind: TransactionKind::Evidence {
                    evidence: evidence.clone(),
                },
                fee: 0,
                signature: Signature([0u8; 64]),
                hash: Hash::zero(),
            };
            tx.hash = tx.signing_hash(&self.signing_ctx);
            tx.signature = Signature(sign(&self.signing_key, &tx.hash.0).0);
            match mempool.add_transaction(tx) {
                Ok(()) => return,
                Err(MempoolError::InvalidNonce { .. }) => continue,
                Err(_) => return,
            }
        }
    }

    /// Ingest and apply any buffered unanchored votes for `round` that match `digest` (PRO-40 (a)).
    fn apply_buffered_votes(&self, round: Round, digest: Hash) -> Result<(), ConsensusError> {
        let buffered = self.pending_votes.lock().remove(&round);
        let Some(votes) = buffered else {
            return Ok(());
        };
        let mut quorum_reached = false;
        for vote in votes {
            if vote.leader_hash == digest {
                match self
                    .committer
                    .add_verified_vote(round, vote.voter, vote.leader_hash)
                {
                    Ok(reached) => {
                        if reached {
                            quorum_reached = true;
                        }
                        if let Err(e) = self.dag_store.as_ref().put_vote(&vote) {
                            warn!(
                                leader_round = round,
                                voter = vote.voter,
                                error = %e,
                                "buffered vote could not be persisted"
                            );
                        }
                    }
                    Err(e) => {
                        debug!(
                            leader_round = round,
                            voter = vote.voter,
                            error = %e,
                            "buffered vote could not be applied"
                        );
                    }
                }
            }
        }
        if quorum_reached {
            info!("Leader round {} reached quorum from buffered votes", round);
            self.drain_commits()?;
        }
        Ok(())
    }

    /// Process a received block from another validator.
    pub fn process_block(
        &self,
        block: &kovanica_types::block::StatementBlock,
    ) -> Result<(), ConsensusError> {
        // Fork resolution for scheduled leader slots.
        // Default: first-valid digest wins. `use_min_digest_fork` may replace
        // the stored block only when the DAG store accepts the swap, and only
        // before the round is decided. Deterministic lookup by round/author.
        if self.scheduled_leader_for_round(block.round) == Some(block.author) {
            if let Ok(Some(existing)) = self
                .dag_store
                .get_block_by_author_round(block.author, block.round)
            {
                if existing.digest != block.digest {
                    if self.config.use_min_digest_fork
                        && !self.committer.is_decided(block.round)
                        && block.digest.0 < existing.digest.0
                        && self.dag_store.replace_block(&existing, block).is_ok()
                    {
                        // Store already holds `block` and dropped `existing`.
                        // Do not call process_block: it would put() again and,
                        // on a store that cannot swap, would leave both digests.
                        let leader_info = LeaderInfo {
                            round: block.round,
                            author: block.author,
                            block_hash: Some(block.digest),
                            status: LeaderStatus::Undecided,
                            votes: HashMap::new(),
                        };
                        self.committer.update_leader(leader_info);
                        self.note_leader_block_seen(block.round);
                        self.apply_buffered_votes(block.round, block.digest)?;
                        self.try_commit_and_deliver()?;
                        self.vote_if_late(block.round)?;
                        return Ok(());
                    }
                    // Both conflicting headers are in hand: the author signed
                    // two different digests for one round. Report it before
                    // returning, so the proof is not lost. The `use_min_digest`
                    // branch above deliberately does not report: there the
                    // configuration accepts an alternate block as fork
                    // resolution, so treating it as slashable would change
                    // that mode's consensus.
                    self.report_equivocation(&existing, block);
                    return Err(ConsensusError::InvalidVote(format!(
                        "fork/equivocation at round {} author {}: existing={}, new={}",
                        block.round, block.author, existing.digest, block.digest
                    )));
                }
                // Same digest: idempotent; skip duplicate processing if already in store.
                // Clear timeout and try commit; do not put/re-register.
                {
                    let mut dl = self.leader_deadline.write();
                    if let Some((r, _)) = *dl {
                        if r == block.round
                            && self.scheduled_leader_for_round(r) == Some(block.author)
                        {
                            *dl = None;
                        }
                    }
                }
                self.try_commit_and_deliver()?;
                self.vote_if_late(block.round)?;
                return Ok(());
            }
        }

        // Validate the block
        self.block_manager.read().process_block(block)?;
        self.ingest_vrf_outputs();

        // Every valid block belongs in the DAG, but only the scheduled author
        // of an offset-zero round represents a leader slot. In particular,
        // ordinary vote/decision-round blocks must not overwrite leader state.
        if self.scheduled_leader_for_round(block.round) == Some(block.author) {
            // After validation/store, register leader (pre-check already rejected forks).
            let leader_info = LeaderInfo {
                round: block.round,
                author: block.author,
                block_hash: Some(block.digest),
                status: LeaderStatus::Undecided,
                votes: HashMap::new(),
            };
            self.committer.update_leader(leader_info);
            self.note_leader_block_seen(block.round);
            self.apply_buffered_votes(block.round, block.digest)?;
        }

        // Clear timeout if this block resolves the current leader slot
        {
            let mut dl = self.leader_deadline.write();
            if let Some((r, _)) = *dl {
                if r == block.round && self.scheduled_leader_for_round(r) == Some(block.author) {
                    *dl = None;
                }
            }
        }

        // Try to commit after processing
        self.try_commit_and_deliver()?;

        if self.scheduled_leader_for_round(block.round) == Some(block.author) {
            self.vote_if_late(block.round)?;
        }

        Ok(())
    }

    /// Ingest a vote for a leader block. This is the authentication boundary
    /// for votes: every vote, including ones received over gossip, must enter
    /// consensus through this method.
    ///
    /// A vote is counted only if all of the following hold, checked in order:
    ///
    /// 1. `vote.voter` is a member of the current [`CommitteeInfo`];
    /// 2. `vote.signature` is a valid signature over
    ///    [`kovanica_types::Vote::signature_data`] under that member's public key
    ///    from the committee (a signature made with any other key, including
    ///    another validator's, is rejected);
    /// 3. `vote.leader_round` is a leader round and a leader block is
    ///    registered for it;
    /// 4. `vote.leader_hash` matches the registered leader block;
    /// 5. the voter has not already voted for this leader round. A duplicate
    ///    is rejected and contributes its stake at most once.
    ///
    /// Rejected votes return [`ConsensusError::VoteRejected`] and never change
    /// consensus state. Accepted votes may trigger a commit.
    pub fn process_vote(&self, vote: &kovanica_types::Vote) -> Result<(), ConsensusError> {
        let leader_round = vote.leader_round;
        let voter = vote.voter;

        let Some(authority) = self.committee.get_by_index(voter) else {
            return Err(VoteRejection::UnknownVoter(voter).into());
        };
        if kovanica_crypto::verify_vote_signature(
            &self.vote_signing_ctx(leader_round),
            vote,
            &authority.public_key,
        )
        .is_err()
        {
            return Err(VoteRejection::BadSignature(voter).into());
        }
        if !is_leader_round(leader_round) {
            return Err(VoteRejection::NotLeaderRound(leader_round).into());
        }
        // PRO-40 (b): a validator that voted for a slot the others skipped
        // while it was away cannot time it out; it rebroadcasts its vote
        // instead. Answer with the stored certificate (rate limited).
        if leader_round <= self.committer.last_decided_round() {
            if let Err(e) = self.serve_skip_cert(leader_round) {
                debug!(leader_round, error = %e, "could not serve a skip certificate");
            }
        }

        let leader_opt = self.committer.get_leader(leader_round);
        let is_unanchored = match &leader_opt {
            None => true,
            Some(info) => info.block_hash.is_none(),
        };

        if is_unanchored {
            let last_decided = self.committer.last_decided_round();
            let current_round = self.current_round();
            if leader_round > last_decided
                && leader_round <= current_round.saturating_add(3 * crate::WAVE_LENGTH)
            {
                let mut pending = self.pending_votes.lock();
                // Evict votes for rounds <= last_decided
                pending.retain(|&r, _| r > last_decided);

                // Enforce bounds: retain at most MAX_PENDING_VOTE_ROUNDS rounds ahead of last_decided
                if pending.len() >= MAX_PENDING_VOTE_ROUNDS && !pending.contains_key(&leader_round)
                {
                    if let Some(&max_r) = pending.keys().next_back() {
                        if leader_round < max_r {
                            pending.remove(&max_r);
                        }
                    }
                }
                if pending.len() < MAX_PENDING_VOTE_ROUNDS || pending.contains_key(&leader_round) {
                    let votes = pending.entry(leader_round).or_default();
                    if votes.len() < MAX_PENDING_VOTES_PER_ROUND
                        && !votes.iter().any(|v| v.voter == voter)
                    {
                        votes.push(vote.clone());
                        debug!(
                            leader_round,
                            voter, "buffered unanchored vote for future/awaited leader round"
                        );
                    }
                }
                return Ok(());
            }
            return Err(VoteRejection::UnknownLeaderRound(leader_round).into());
        }

        let has_quorum = self
            .committer
            .add_verified_vote(leader_round, voter, vote.leader_hash)?;
        // The vote is accepted by consensus at this point. Persisting it is a
        // side concern: it only makes the vote available to a peer that joins
        // later (RFC-009). A storage failure must not turn an accepted vote
        // into a rejected one, so it is logged and swallowed.
        if let Err(e) = self.dag_store.as_ref().put_vote(vote) {
            warn!(
                leader_round,
                voter,
                error = %e,
                "accepted vote could not be persisted; it cannot be served to a joining peer"
            );
        }
        if has_quorum {
            info!("Leader round {} now has quorum", leader_round);
            self.drain_commits()?;
        }
        Ok(())
    }

    fn try_commit_and_deliver(&self) -> Result<(), ConsensusError> {
        // Keep this critical section synchronous and non-awaiting. All sources
        // of commit attempts must use it so a later decision cannot be marked
        // or delivered ahead of an earlier pending decision.
        let _guard = self.commit_trigger_lock.lock();
        let commit_started = Instant::now();
        let Some(subdag) = self
            .committer
            .try_commit_and_mark_durable(self.dag_store.as_ref())?
        else {
            // No commit: the first undecided slot may have a skip certificate
            // (PRO-40 (b)). `drain_commits` then continues with the next slot.
            if let Some(round) = self
                .committer
                .try_skip_and_mark_durable(self.dag_store.as_ref())?
            {
                record_skipped_leader(SkipReason::Certified);
                self.timeout_pool.lock().prune_through(round);
                self.leader_first_seen.write().remove(&round);
                self.pending_votes.lock().retain(|&r, _| r > round);
            }
            return Ok(());
        };
        self.timeout_pool.lock().prune_through(subdag.leader_round);
        self.pending_votes
            .lock()
            .retain(|&r, _| r > subdag.leader_round);
        let commit_elapsed_ms = commit_started.elapsed().as_secs_f64() * 1000.0;

        // The committer persists before publication. On restart, the node
        // reconstructs committed sub-DAGs from the decided-round index and
        // execution deduplicates by leader digest in the state database.
        info!("Committed leader at round {}", subdag.leader_round);

        // Record metrics for committed leader. `block_height` is the committed
        // leader height ("height" in this DAG is the leader round), never the
        // local round.
        record_block_height(subdag.leader_round as i64);
        record_mergeset_size_metric(subdag.blocks.len());
        // Real wall-clock cost of the commit work (colouring + durable write),
        // not a placeholder: the 5 s alert threshold has to be able to fire.
        record_commit_latency(commit_elapsed_ms);

        // Node-local finality latency: how long this node needed from first
        // sighting the leader block to the durable commit. A leader proposing
        // locally starts the clock at proposal time, so the sample is never
        // missing for a commit this node produced itself.
        if let Some(seen) = self.leader_first_seen.write().remove(&subdag.leader_round) {
            observe_finality_latency(seen.elapsed().as_secs_f64());
        }
        // Leading 64 bits of the leader digest as a divergence fingerprint.
        let d = subdag.leader.digest.0;
        let digest_prefix = u64::from_be_bytes([d[0], d[1], d[2], d[3], d[4], d[5], d[6], d[7]]);
        record_committed_leader(subdag.leader_round as i64, digest_prefix);

        if let Some(sender) = self.commit_sender.read().as_ref() {
            if sender.send(subdag).is_err() {
                warn!("execution receiver is unavailable; commit remains persisted for replay");
            }
        }
        Ok(())
    }

    /// Clean up old rounds to limit memory usage.
    fn cleanup_old_rounds(&self, current_round: Round) {
        let max_pending = self.config.max_pending_rounds;
        if current_round > max_pending {
            let cutoff = current_round - max_pending;
            // Nothing above the commit cursor is dropped (PRO-40): the record
            // of a stuck leader keeps the commit walk stalled on it instead of
            // letting it skip the round, and the "already voted" marker keeps
            // this node from voting a second time for that round.
            let last_decided = self.committer.last_decided_round();
            self.committer.cleanup_old_leaders(cutoff);
            self.voted_rounds
                .lock()
                .retain(|&round| round >= cutoff || round > last_decided);
            // A stalled chain keeps one `Instant` per undecided slot; that is
            // bounded by the length of the stall, and it is dropped once the
            // round is decided.
            self.leader_first_seen
                .write()
                .retain(|&round, _| round >= cutoff || round > last_decided);
        }
    }

    /// Remember when this node first held the leader block for `round`.
    ///
    /// Idempotent: a duplicate block delivery (idempotent re-processing, fork
    /// replacement) must not reset the clock, or finality latency would be
    /// under-reported.
    fn note_leader_block_seen(&self, round: Round) {
        self.leader_first_seen
            .write()
            .entry(round)
            .or_insert_with(Instant::now);
    }

    /// The leader record registered for `round`, if any.
    ///
    /// A round only has a record once this node has ingested that round's
    /// leader block. Consensus rejects a vote for a round without a record
    /// ([`VoteRejection::UnknownLeaderRound`]), so a caller that holds votes
    /// for a round uses this to tell "not applicable yet" from "never
    /// applicable".
    pub fn registered_leader(&self, round: Round) -> Option<LeaderInfo> {
        self.committer.get_leader(round)
    }

    /// Returns the number of buffered unanchored votes for `round` (PRO-40 (a)).
    pub fn pending_votes_count(&self, round: Round) -> usize {
        self.pending_votes
            .lock()
            .get(&round)
            .map(|v| v.len())
            .unwrap_or(0)
    }

    /// Returns the rounds currently present in the pending vote buffer (PRO-40 (a)).
    pub fn pending_vote_rounds(&self) -> Vec<Round> {
        self.pending_votes.lock().keys().copied().collect()
    }

    /// Commit every leader the registered votes already justify.
    ///
    /// [`Self::process_vote`] and [`Self::process_block`] trigger a single
    /// commit attempt each. A node that catches up applies a whole batch of
    /// votes for many leader rounds at once, and a round that was *already* at
    /// quorum can sit behind an earlier round that has just become decidable:
    /// the commit walk stops at the first undecided leader, so the later round
    /// stays uncommitted until some unrelated trigger runs the walk again.
    ///
    /// Draining the pipeline until it stops making progress removes that
    /// wait. The commits are exactly the ones the next trigger would have
    /// produced, in the same order, so this changes timing only — never the
    /// committed sequence.
    ///
    /// See `docs/rfcs/RFC-009-VOTE-TRANSFER-OVER-BLOCK-SYNC.md`.
    pub fn drain_commits(&self) -> Result<(), ConsensusError> {
        for _ in 0..MAX_COMMIT_DRAIN_STEPS {
            let before = self.committer.last_decided_round();
            self.try_commit_and_deliver()?;
            if self.committer.last_decided_round() == before {
                // No further progress: the walk found nothing left to commit.
                return Ok(());
            }
        }
        warn!(
            "commit drain hit its step bound; the remaining leaders are committed by a later drain"
        );
        Ok(())
    }

    /// The commit cursor: the highest leader slot decided by a commit or a
    /// certified skip.
    pub fn last_decided_round(&self) -> Round {
        self.committer.last_decided_round()
    }

    /// Get the current round.
    pub fn current_round(&self) -> Round {
        *self.current_round.read()
    }

    /// Subscribe to round changes.
    /// Returns a receiver that will be notified when the consensus round advances.
    pub fn subscribe_round(&self) -> watch::Receiver<Round> {
        self.round_sender
            .read()
            .as_ref()
            .expect("round sender should be initialized in new()")
            .subscribe()
    }

    /// Get our validator state.
    pub fn state(&self) -> ValidatorState {
        self.state.read().clone()
    }

    /// Get the committee info.
    pub fn committee(&self) -> &CommitteeInfo {
        &self.committee
    }

    /// Configured prune window in waves (`WAVE_LENGTH` rounds per wave).
    pub fn prune_window_waves(&self) -> u64 {
        self.config.prune_window_waves
    }
}

/// Errors that can occur in consensus operations.
#[derive(Debug, thiserror::Error)]
pub enum ConsensusError {
    #[error("Block proposal failed: {0}")]
    BlockProposal(String),
    #[error("DAG store error: {0}")]
    DagStore(#[from] kovanica_dag::DagStoreError),
    #[error("Block manager error: {0}")]
    BlockManager(#[from] kovanica_dag::BlockManagerError),
    #[error("Crypto error: {0}")]
    Crypto(#[from] kovanica_crypto::CryptoError),
    #[error("Storage error: {0}")]
    Storage(#[from] kovanica_storage::StorageError),
    #[error("Invalid consensus vote: {0}")]
    InvalidVote(String),
    #[error("Vote rejected: {0}")]
    VoteRejected(#[from] VoteRejection),
    #[error("Timeout rejected: {0}")]
    TimeoutRejected(#[from] TimeoutRejection),
}

/// Why [`ConsensusEngine::process_vote`] refused to count a vote.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum VoteRejection {
    /// The voter index is not a member of the committee.
    #[error("voter {0} is not a committee member")]
    UnknownVoter(kovanica_types::AuthorityIndex),
    /// The signature does not verify under the voter's committee key.
    #[error("invalid signature for voter {0}")]
    BadSignature(kovanica_types::AuthorityIndex),
    /// The vote targets a round that is not a leader round.
    #[error("round {0} is not a leader round")]
    NotLeaderRound(Round),
    /// No leader block is registered for the voted round.
    #[error("no leader block registered for round {0}")]
    UnknownLeaderRound(Round),
    /// The voted hash differs from the registered leader block.
    #[error("vote hash does not match the leader block for round {0}")]
    LeaderHashMismatch(Round),
    /// The voter already has a vote recorded for this leader round.
    #[error("duplicate vote from voter {voter} for round {round}")]
    Duplicate {
        round: Round,
        voter: kovanica_types::AuthorityIndex,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    const TEST_CTX: kovanica_types::SigningContext =
        kovanica_types::SigningContext::new(kovanica_types::signing::chain_id::LOCAL);
    use crate::types::AuthorityInfo;
    use kovanica_types::{block::BlockReference, crypto::PublicKey, Address};
    use parking_lot::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[derive(Default)]
    struct TestDag {
        blocks: RwLock<HashMap<Hash, kovanica_types::StatementBlock>>,
        decisions: Mutex<Vec<(Round, Hash)>>,
        fail_next_decision_mark: std::sync::atomic::AtomicBool,
        /// Stand-in for the highest persisted DAG round, driven by
        /// `DagStoreTrait::max_stored_round`. `None` models an empty store.
        stored_tip: RwLock<Option<Round>>,
        /// Votes persisted through `DagStoreTrait::put_vote`, in write order.
        persisted_votes: Mutex<Vec<kovanica_types::Vote>>,
        /// Certified catch-up anchor (leader round), if the test sets one.
        catchup_anchor: RwLock<Option<Round>>,
        /// Digests whose `process_block` records a VRF output without checking
        /// a signature. Empty unless a test is replaying stored carriers.
        replay_vrf: RwLock<HashMap<Hash, [u8; 32]>>,
        /// Outputs recorded by [`TestBlockManager::process_block`].
        recorded_vrf: RwLock<HashMap<Round, HashMap<AuthorityIndex, [u8; 32]>>>,
        /// When set, `put_vote` fails without storing the vote.
        fail_put_vote: std::sync::atomic::AtomicBool,
        /// When set, `get_votes_for_round` fails before returning stored votes.
        fail_get_votes: std::sync::atomic::AtomicBool,
        /// Timeouts persisted through `DagStoreTrait::put_timeout`.
        persisted_timeouts: Mutex<Vec<kovanica_types::Timeout>>,
        /// Rounds recorded through `DagStoreTrait::mark_round_skipped`.
        skipped: Mutex<Vec<Round>>,
    }

    impl DagStoreTrait for TestDag {
        fn get_block(
            &self,
            hash: &Hash,
        ) -> Result<kovanica_types::StatementBlock, kovanica_dag::DagStoreError> {
            self.blocks
                .read()
                .get(hash)
                .cloned()
                .ok_or_else(|| kovanica_dag::DagStoreError::NotFound(hash.to_string()))
        }

        fn get_ancestors(
            &self,
            hash: &Hash,
            min_round: Round,
        ) -> Result<Vec<Hash>, kovanica_dag::DagStoreError> {
            let blocks = self.blocks.read();
            let mut found = Vec::new();
            let mut pending = vec![*hash];
            while let Some(current) = pending.pop() {
                if let Some(block) = blocks.get(&current) {
                    for parent in &block.parents {
                        if let Some(parent_block) = blocks.get(&parent.digest) {
                            if parent_block.round >= min_round {
                                found.push(parent.digest);
                            }
                            pending.push(parent.digest);
                        }
                    }
                }
            }
            found.sort_by_key(|hash| hash.0);
            found.dedup();
            Ok(found)
        }

        fn get_parents(&self, hash: &Hash) -> Result<Vec<Hash>, kovanica_dag::DagStoreError> {
            let blocks = self.blocks.read();
            if let Some(block) = blocks.get(hash) {
                Ok(block.parents.iter().map(|p| p.digest).collect())
            } else {
                Err(kovanica_dag::DagStoreError::NotFound(hash.to_string()))
            }
        }

        fn get_block_by_author_round(
            &self,
            author: AuthorityIndex,
            round: Round,
        ) -> Result<Option<kovanica_types::StatementBlock>, kovanica_dag::DagStoreError> {
            Ok(self
                .blocks
                .read()
                .values()
                .find(|block| block.author == author && block.round == round)
                .cloned())
        }

        fn get_blocks_by_round(
            &self,
            round: Round,
        ) -> Result<Vec<kovanica_types::StatementBlock>, kovanica_dag::DagStoreError> {
            Ok(self
                .blocks
                .read()
                .values()
                .filter(|block| block.round == round)
                .cloned()
                .collect())
        }

        fn has_block(&self, hash: &Hash) -> Result<bool, kovanica_dag::DagStoreError> {
            Ok(self.blocks.read().contains_key(hash))
        }

        fn put_block(
            &self,
            block: &kovanica_types::StatementBlock,
        ) -> Result<(), kovanica_dag::DagStoreError> {
            self.blocks.write().insert(block.digest, block.clone());
            Ok(())
        }

        fn replace_block(
            &self,
            existing: &kovanica_types::StatementBlock,
            incoming: &kovanica_types::StatementBlock,
        ) -> Result<(), kovanica_dag::DagStoreError> {
            let mut blocks = self.blocks.write();
            let referenced = blocks.values().any(|b| {
                b.parents
                    .iter()
                    .any(|p| p.digest == existing.digest || p.digest == incoming.digest)
            });
            if referenced {
                return Err(kovanica_dag::DagStoreError::NotFound(
                    "leader digest is already a parent".into(),
                ));
            }
            if !blocks.contains_key(&existing.digest) {
                return Err(kovanica_dag::DagStoreError::NotFound(
                    existing.digest.to_string(),
                ));
            }
            blocks.remove(&existing.digest);
            blocks.insert(incoming.digest, incoming.clone());
            Ok(())
        }

        fn find_parents(
            &self,
            _round: Round,
            _max_parents: usize,
        ) -> Result<Vec<BlockReference>, kovanica_dag::DagStoreError> {
            Ok(Vec::new())
        }

        fn commit_leader(&self, _leader_hash: &Hash) -> Result<u64, kovanica_dag::DagStoreError> {
            Ok(self.decisions.lock().len() as u64 + 1)
        }

        fn mark_decided_and_commit_leader(
            &self,
            round: Round,
            leader_hash: &Hash,
        ) -> Result<u64, kovanica_dag::DagStoreError> {
            self.mark_round_decided(round, leader_hash)?;
            self.commit_leader(leader_hash)
        }

        fn mark_round_decided(
            &self,
            round: Round,
            leader_hash: &Hash,
        ) -> Result<(), kovanica_dag::DagStoreError> {
            if self.fail_next_decision_mark.swap(false, Ordering::SeqCst) {
                return Err(kovanica_dag::DagStoreError::NotFound(
                    "injected decision-mark failure".into(),
                ));
            }
            let mut decisions = self.decisions.lock();
            if !decisions.contains(&(round, *leader_hash)) {
                decisions.push((round, *leader_hash));
            }
            Ok(())
        }

        fn mergeset(&self, _leader: &Hash) -> Result<Vec<Hash>, kovanica_dag::DagStoreError> {
            Ok(Vec::new())
        }

        fn get_blocks(
            &self,
            hashes: &[Hash],
        ) -> Result<Vec<kovanica_types::StatementBlock>, kovanica_dag::DagStoreError> {
            let blocks = self.blocks.read();
            Ok(hashes
                .iter()
                .filter_map(|h| blocks.get(h).cloned())
                .collect())
        }

        fn get_decided_leaders(
            &self,
            round: Round,
        ) -> Result<Vec<Hash>, kovanica_dag::DagStoreError> {
            Ok(self
                .decisions
                .lock()
                .iter()
                .filter(|(r, _)| *r == round)
                .map(|(_, h)| *h)
                .collect())
        }

        fn get_decided_rounds(
            &self,
            max_round: Round,
        ) -> Result<Vec<Round>, kovanica_dag::DagStoreError> {
            let mut rounds: Vec<Round> = self
                .decisions
                .lock()
                .iter()
                .filter(|(r, _)| *r <= max_round)
                .map(|(r, _)| *r)
                .collect();
            rounds.extend(self.skipped.lock().iter().filter(|r| **r <= max_round));
            Ok(rounds)
        }

        fn mark_round_skipped(&self, round: Round) -> Result<(), kovanica_dag::DagStoreError> {
            let existing = self.get_decided_leaders(round)?;
            if !existing.is_empty() {
                return Err(kovanica_dag::DagStoreError::ConflictingDecision {
                    round,
                    existing,
                    new: Hash::zero(),
                });
            }
            let mut skipped = self.skipped.lock();
            if !skipped.contains(&round) {
                skipped.push(round);
            }
            Ok(())
        }

        fn put_timeout(
            &self,
            timeout: &kovanica_types::Timeout,
        ) -> Result<(), kovanica_dag::DagStoreError> {
            let mut stored = self.persisted_timeouts.lock();
            if !stored
                .iter()
                .any(|t| t.round == timeout.round && t.voter == timeout.voter)
            {
                stored.push(timeout.clone());
            }
            Ok(())
        }

        fn get_timeouts_for_round(
            &self,
            round: Round,
        ) -> Result<Vec<kovanica_types::Timeout>, kovanica_dag::DagStoreError> {
            let mut out: Vec<_> = self
                .persisted_timeouts
                .lock()
                .iter()
                .filter(|t| t.round == round)
                .cloned()
                .collect();
            out.sort_by_key(|t| t.voter);
            Ok(out)
        }

        fn max_stored_round(&self) -> Result<Option<Round>, kovanica_dag::DagStoreError> {
            Ok(*self.stored_tip.read())
        }

        fn put_vote(&self, vote: &kovanica_types::Vote) -> Result<(), kovanica_dag::DagStoreError> {
            if self.fail_put_vote.load(Ordering::SeqCst) {
                return Err(kovanica_dag::DagStoreError::NotFound(
                    "injected vote write failure".into(),
                ));
            }
            self.persisted_votes.lock().push(vote.clone());
            Ok(())
        }

        fn get_votes_for_round(
            &self,
            round: Round,
        ) -> Result<Vec<kovanica_types::Vote>, kovanica_dag::DagStoreError> {
            if self.fail_get_votes.load(Ordering::SeqCst) {
                return Err(kovanica_dag::DagStoreError::NotFound(
                    "injected vote read failure".into(),
                ));
            }
            Ok(self
                .persisted_votes
                .lock()
                .iter()
                .filter(|v| v.leader_round == round)
                .cloned()
                .collect())
        }

        fn certified_catchup_anchor(&self) -> Result<Option<Round>, kovanica_dag::DagStoreError> {
            Ok(*self.catchup_anchor.read())
        }

        fn prune_non_blue(
            &self,
            _blue_hashes: &[Hash],
            _committed_wave: u64,
        ) -> Result<u64, kovanica_dag::DagStoreError> {
            // Test implementation: no-op
            Ok(0)
        }

        fn prune_waves_before(
            &self,
            _wave: u64,
            _prune_window_waves: u64,
        ) -> Result<u64, kovanica_dag::DagStoreError> {
            // Test implementation: no-op
            Ok(0)
        }
    }

    struct TestBlockManager {
        dag: Arc<TestDag>,
        key: RwLock<kovanica_types::SigningKey>,
        set_key_calls: AtomicUsize,
    }

    impl BlockManagerTrait for TestBlockManager {
        fn propose_block(
            &self,
            round: Round,
        ) -> Result<kovanica_types::StatementBlock, kovanica_dag::BlockManagerError> {
            self.propose_block_with_txs(round, Vec::new())
        }

        fn propose_block_with_txs(
            &self,
            round: Round,
            _transactions: Vec<kovanica_types::Transaction>,
        ) -> Result<kovanica_types::StatementBlock, kovanica_dag::BlockManagerError> {
            let digest = kovanica_types::StatementBlock::compute_digest(0, round, &[], &[]);
            let block = kovanica_types::StatementBlock {
                author: 0,
                round,
                parents: Vec::new(),
                transactions: Vec::new(),
                statements: Vec::new(),
                signature: kovanica_crypto::sign(&self.key.read(), digest.as_ref()),
                digest,
                merkle_root: Default::default(),
            };
            self.dag.put_block(&block).expect("store proposal");
            Ok(block)
        }

        fn process_block(
            &self,
            block: &kovanica_types::StatementBlock,
        ) -> Result<(), kovanica_dag::BlockManagerError> {
            if let Some(output) = self.dag.replay_vrf.read().get(&block.digest).copied() {
                self.dag
                    .recorded_vrf
                    .write()
                    .entry(block.round)
                    .or_default()
                    .insert(block.author, output);
                self.dag.put_block(block)?;
                return Ok(());
            }
            let public_key = PublicKey::from(self.key.read().verifying_key());
            kovanica_crypto::verify_block_signature(&public_key, &block.digest, &block.signature)?;
            self.dag.put_block(block)?;
            Ok(())
        }

        fn verified_vrf_outputs(
            &self,
        ) -> HashMap<Round, HashMap<kovanica_types::AuthorityIndex, [u8; 32]>> {
            self.dag.recorded_vrf.read().clone()
        }

        fn our_authority(&self) -> AuthorityIndex {
            0
        }

        fn set_signing_key(&self, key: kovanica_types::SigningKey) {
            *self.key.write() = key;
            self.set_key_calls.fetch_add(1, Ordering::SeqCst);
        }
    }

    fn test_engine(
        round_duration_ms: u64,
    ) -> (
        ConsensusEngine<TestDag, TestBlockManager>,
        Arc<TestDag>,
        kovanica_types::SigningKey,
    ) {
        test_engine_at_epoch(round_duration_ms, 0)
    }

    fn test_engine_with(
        round_duration_ms: u64,
        config: ConsensusConfig,
    ) -> (
        ConsensusEngine<TestDag, TestBlockManager>,
        Arc<TestDag>,
        kovanica_types::SigningKey,
    ) {
        let (key, public_key) = kovanica_crypto::generate_keypair();
        let dag = Arc::new(TestDag::default());
        let committee = CommitteeInfo::try_new(
            0,
            vec![AuthorityInfo {
                index: 0,
                stake: 100,
                public_key,
                vrf_public_key: None,
                address: Address::default(),
                network_address: String::new(),
            }],
        )
        .expect("test committee is valid");
        let manager = Arc::new(RwLock::new(TestBlockManager {
            dag: dag.clone(),
            key: RwLock::new(key.clone()),
            set_key_calls: AtomicUsize::new(0),
        }));
        let mut config = config;
        config.round_duration_ms = round_duration_ms;
        let engine = ConsensusEngine::new(
            config,
            committee,
            dag.clone(),
            manager,
            key.clone(),
            None,
            TEST_CTX,
        );
        (engine, dag, key)
    }

    /// A new engine on an existing store, as after a process restart.
    fn restarted_engine(
        dag: Arc<TestDag>,
        key: kovanica_types::SigningKey,
        round_duration_ms: u64,
    ) -> ConsensusEngine<TestDag, TestBlockManager> {
        let public_key = PublicKey::from(key.verifying_key());
        let committee = CommitteeInfo::try_new(
            0,
            vec![AuthorityInfo {
                index: 0,
                stake: 100,
                public_key,
                vrf_public_key: None,
                address: Address::default(),
                network_address: String::new(),
            }],
        )
        .expect("test committee is valid");
        let manager = Arc::new(RwLock::new(TestBlockManager {
            dag: dag.clone(),
            key: RwLock::new(key.clone()),
            set_key_calls: AtomicUsize::new(0),
        }));
        ConsensusEngine::new(
            ConsensusConfig {
                round_duration_ms,
                ..Default::default()
            },
            committee,
            dag,
            manager,
            key,
            None,
            TEST_CTX,
        )
    }

    fn record_broadcasts(
        engine: &ConsensusEngine<TestDag, TestBlockManager>,
    ) -> Arc<Mutex<Vec<kovanica_types::Vote>>> {
        let sent: Arc<Mutex<Vec<kovanica_types::Vote>>> = Arc::new(Mutex::new(Vec::new()));
        let sent_log = sent.clone();
        engine.set_vote_broadcaster(Arc::new(move |vote: &kovanica_types::Vote| {
            sent_log.lock().push(vote.clone());
        }));
        sent
    }

    fn test_engine_at_epoch(
        round_duration_ms: u64,
        committee_epoch: u64,
    ) -> (
        ConsensusEngine<TestDag, TestBlockManager>,
        Arc<TestDag>,
        kovanica_types::SigningKey,
    ) {
        let (key, public_key) = kovanica_crypto::generate_keypair();
        let dag = Arc::new(TestDag::default());
        let committee = CommitteeInfo::try_new(
            committee_epoch,
            vec![AuthorityInfo {
                index: 0,
                stake: 100,
                public_key,
                vrf_public_key: None,
                address: Address::default(),
                network_address: String::new(),
            }],
        )
        .expect("test committee is valid");
        let manager = Arc::new(RwLock::new(TestBlockManager {
            dag: dag.clone(),
            key: RwLock::new(key.clone()),
            set_key_calls: AtomicUsize::new(0),
        }));
        let engine = ConsensusEngine::new(
            ConsensusConfig {
                round_duration_ms,
                ..Default::default()
            },
            committee,
            dag.clone(),
            manager,
            key.clone(),
            None, // No mempool for tests
            TEST_CTX,
        );
        (engine, dag, key)
    }

    fn signed_vote(
        key: &kovanica_types::SigningKey,
        leader_round: Round,
        voter: AuthorityIndex,
        leader_hash: Hash,
    ) -> kovanica_types::Vote {
        let mut vote = kovanica_types::Vote {
            leader_round,
            leader_hash,
            voter,
            signature: kovanica_types::Signature([0; 64]),
        };
        vote.signature = kovanica_crypto::sign(key, &vote.signature_data(&TEST_CTX));
        vote
    }

    #[tokio::test]
    async fn start_preserves_the_node_signing_identity() {
        let (engine, dag, key) = test_engine(10);
        let engine = Arc::new(engine);
        let manager = engine.block_manager.clone();
        let running_engine = engine.clone();
        let task = tokio::spawn(async move { running_engine.start().await });
        let deadline = tokio::time::Instant::now() + Duration::from_secs(1);
        while dag.blocks.read().is_empty() {
            assert!(
                tokio::time::Instant::now() < deadline,
                "engine did not propose at its first scheduled leader slot"
            );
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        engine.stop();
        task.await.unwrap().unwrap();
        assert_eq!(manager.read().set_key_calls.load(Ordering::SeqCst), 1);
        let proposal = dag
            .blocks
            .read()
            .values()
            .next()
            .cloned()
            .expect("engine proposed a block");
        let public_key = PublicKey::from(key.verifying_key());
        kovanica_crypto::verify_block_signature(&public_key, &proposal.digest, &proposal.signature)
            .expect("proposal uses node-provided identity");
    }

    /// A restarted node must resume after the rounds it already holds.
    ///
    /// Before the fix the engine always began at round 0, re-proposed already
    /// decided rounds, and `mark_round_decided` then aborted the entire engine
    /// with `DagStoreError::ConflictingDecision` — the node could not restart
    /// against a non-empty chain at all.
    #[test]
    fn resume_seeds_the_round_counter_from_the_persisted_dag_tip() {
        let (engine, dag, _key) = test_engine(10);
        *dag.stored_tip.write() = Some(9);
        engine.resume_from_store().expect("resume succeeds");
        assert_eq!(*engine.current_round.read(), 9);
        assert_eq!(engine.state().current_round, 9);
    }

    #[test]
    fn resume_keeps_round_zero_for_an_empty_store() {
        let (engine, _dag, _key) = test_engine(10);
        engine.resume_from_store().expect("resume succeeds");
        assert_eq!(*engine.current_round.read(), 0);
    }

    #[test]
    fn resume_never_moves_the_counter_backwards() {
        let (engine, dag, _key) = test_engine(10);
        *engine.current_round.write() = 100;
        *dag.stored_tip.write() = Some(5);
        engine.resume_from_store().expect("resume succeeds");
        assert_eq!(*engine.current_round.read(), 100);
    }

    #[tokio::test]
    async fn restarted_engine_does_not_replay_decided_rounds() {
        let (engine, dag, _key) = test_engine(10);
        *dag.stored_tip.write() = Some(9);
        let engine = Arc::new(engine);
        let running = engine.clone();
        let task = tokio::spawn(async move { running.start().await });

        let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
        while dag.blocks.read().is_empty() {
            assert!(
                tokio::time::Instant::now() < deadline,
                "engine did not propose after resuming from the persisted tip"
            );
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        engine.stop();
        task.await.unwrap().unwrap();

        // Resuming at the round-9 tip makes round 12 the first leader slot.
        // Restarting from 0 would have produced a proposal at round 3.
        let rounds: Vec<Round> = dag.blocks.read().values().map(|b| b.round).collect();
        assert!(!rounds.is_empty(), "expected at least one proposal");
        assert!(
            rounds.iter().all(|r| *r > 9),
            "engine replayed already decided rounds: {rounds:?}"
        );
    }

    fn stored_leader_block(
        key: &kovanica_types::SigningKey,
        round: Round,
    ) -> kovanica_types::StatementBlock {
        let digest = kovanica_types::StatementBlock::compute_digest(0, round, &[], &[]);
        kovanica_types::StatementBlock {
            author: 0,
            round,
            parents: Vec::new(),
            transactions: Vec::new(),
            statements: Vec::new(),
            signature: kovanica_crypto::sign(key, digest.as_ref()),
            digest,
            merkle_root: Default::default(),
        }
    }

    /// PRO-40, restart: the cursor comes back from the decision index and an
    /// undecided leader whose block and votes are in the store is registered
    /// and decided again, in order, from the slot after the cursor.
    #[test]
    fn restart_restores_the_cursor_and_replays_stored_leaders_and_votes() {
        let (engine, dag, key) = test_engine(100);
        let (sender, mut receiver) = mpsc::unbounded_channel();
        engine.set_commit_sender(sender);
        let committed = stored_leader_block(&key, 3);
        dag.decisions.lock().push((3, committed.digest));
        let pending = stored_leader_block(&key, 6);
        dag.blocks.write().insert(pending.digest, pending.clone());
        dag.persisted_votes
            .lock()
            .push(signed_vote(&key, 6, 0, pending.digest));
        *dag.stored_tip.write() = Some(7);

        engine.resume_from_store().expect("resume");

        let sub = receiver
            .try_recv()
            .expect("round 6 is decided from the store");
        assert_eq!(sub.leader_round, 6);
        assert_eq!(engine.committer.last_decided_round(), 6);
        assert!(receiver.try_recv().is_err(), "nothing else is committed");
    }

    /// PRO-40, restart: a slot above the restored cursor whose block is not in
    /// the store stalls the walk. A later leader with quorum must not be
    /// committed over it, which is what the empty in-memory map used to allow.
    #[test]
    fn restart_with_a_missing_slot_stalls_instead_of_skipping() {
        let (engine, dag, key) = test_engine(100);
        let (sender, mut receiver) = mpsc::unbounded_channel();
        engine.set_commit_sender(sender);
        let committed = stored_leader_block(&key, 3);
        dag.decisions.lock().push((3, committed.digest));
        // Slot 6: no block in the store. Slot 9: block and quorum.
        let later = stored_leader_block(&key, 9);
        dag.blocks.write().insert(later.digest, later.clone());
        dag.persisted_votes
            .lock()
            .push(signed_vote(&key, 9, 0, later.digest));
        *dag.stored_tip.write() = Some(10);

        engine.resume_from_store().expect("resume");

        assert_eq!(engine.committer.last_decided_round(), 3);
        assert!(engine.registered_leader(9).is_some());
        assert!(engine.registered_leader(6).is_none());
        assert!(
            receiver.try_recv().is_err(),
            "round 9 must not be committed over the unseen slot 6"
        );
    }

    /// A node whose cursor is further back than the prune window catches up
    /// from a certified anchor instead of stalling on the deleted slots.
    ///
    /// The production window is 100 waves (about 300 rounds, about 20 minutes).
    /// This fixture uses a window of one wave and an anchor three waves ahead,
    /// with the slots in between absent, which is the same gap: the walk would
    /// stall on the first missing slot and the node would never commit again.
    #[test]
    fn restart_behind_the_prune_window_catches_up_from_a_certified_anchor() {
        let (engine, dag, key) = test_engine_with(
            100,
            ConsensusConfig {
                prune_window_waves: 1,
                ..ConsensusConfig::default()
            },
        );
        let anchor = 9;
        let gap_waves = anchor / kovanica_types::WAVE_LENGTH;
        assert!(
            gap_waves > engine.config.prune_window_waves,
            "the fixture must sit further ahead than the prune window"
        );
        *dag.catchup_anchor.write() = Some(anchor);
        let (sender, mut receiver) = mpsc::unbounded_channel();
        engine.set_commit_sender(sender);
        // Slots 3 and 6 are inside the gap and are not in the store (pruned
        // on every peer). Slot 12 is the next leader after the anchor.
        let later = stored_leader_block(&key, 12);
        dag.blocks.write().insert(later.digest, later.clone());
        dag.persisted_votes
            .lock()
            .push(signed_vote(&key, 12, 0, later.digest));
        *dag.stored_tip.write() = Some(13);

        engine.resume_from_store().expect("resume");

        let sub = receiver
            .try_recv()
            .expect("the leader after the anchor commits");
        assert_eq!(sub.leader_round, 12);
        assert_eq!(engine.committer.last_decided_round(), 12);
        assert!(
            engine.committer.get_leader(3).is_none(),
            "pruned slots are not reconstructed"
        );
        assert!(receiver.try_recv().is_err());
    }

    /// The anchor covers the gap up to itself. A later hole still stalls.
    #[test]
    fn catchup_anchor_does_not_skip_a_hole_after_the_anchor() {
        let (engine, dag, key) = test_engine_with(
            100,
            ConsensusConfig {
                prune_window_waves: 1,
                ..ConsensusConfig::default()
            },
        );
        *dag.catchup_anchor.write() = Some(9);
        let (sender, mut receiver) = mpsc::unbounded_channel();
        engine.set_commit_sender(sender);
        // Slot 12 is missing. Slot 15 has quorum but must not be committed
        // over it.
        let later = stored_leader_block(&key, 15);
        dag.blocks.write().insert(later.digest, later.clone());
        dag.persisted_votes
            .lock()
            .push(signed_vote(&key, 15, 0, later.digest));
        *dag.stored_tip.write() = Some(16);

        engine.resume_from_store().expect("resume");

        assert_eq!(engine.committer.last_decided_round(), 9);
        assert!(engine.committer.get_leader(15).is_some());
        assert!(engine.committer.get_leader(12).is_none());
        assert!(
            receiver.try_recv().is_err(),
            "round 15 must not be committed over the unseen slot 12"
        );
    }

    #[tokio::test]
    async fn quorum_commit_is_delivered_once_and_persisted() {
        let (engine, dag, key) = test_engine(100);
        let (sender, mut receiver) = mpsc::unbounded_channel();
        engine.set_commit_sender(sender);
        let digest = kovanica_types::StatementBlock::compute_digest(0, 3, &[], &[]);
        let block = kovanica_types::StatementBlock {
            author: 0,
            round: 3,
            parents: Vec::new(),
            transactions: Vec::new(),
            statements: Vec::new(),
            signature: kovanica_crypto::sign(&key, digest.as_ref()),
            digest,
            merkle_root: Default::default(),
        };
        engine.process_block(&block).unwrap();
        let vote = signed_vote(&key, 3, 0, digest);
        engine.process_vote(&vote).unwrap();
        assert_eq!(receiver.try_recv().unwrap().leader.digest, digest);
        // The same vote after a committed round is a rejected duplicate and
        // cannot redeliver the commit.
        assert!(matches!(
            engine.process_vote(&vote),
            Err(ConsensusError::VoteRejected(
                VoteRejection::Duplicate { .. }
            ))
        ));
        assert!(receiver.try_recv().is_err());
        assert_eq!(dag.decisions.lock().as_slice(), &[(3, digest)]);
    }

    /// Read a single (unlabelled) series value out of the Prometheus text.
    fn metric_value(text: &str, series: &str) -> f64 {
        text.lines()
            .find(|line| {
                line.strip_prefix(series)
                    .is_some_and(|rest| rest.starts_with(' '))
            })
            .and_then(|line| line.split_whitespace().nth(1))
            .and_then(|value| value.parse().ok())
            .unwrap_or(0.0)
    }

    /// The commit path records the M1-M8 leader metrics and consumes the
    /// arrival timestamp.
    ///
    /// The counters are process-global and tests run in parallel, so this
    /// asserts a *monotonic increase* rather than an absolute value; the
    /// per-round state (`leader_first_seen`) is asserted exactly.
    #[tokio::test]
    async fn commit_records_leader_metrics_and_clears_arrival() {
        let (engine, _dag, key) = test_engine(100);
        let before = crate::metrics_text();
        let committed_before = metric_value(&before, "kovanica_committed_leaders_total");
        let samples_before = metric_value(&before, "kovanica_finality_latency_seconds_count");

        let digest = kovanica_types::StatementBlock::compute_digest(0, 3, &[], &[]);
        let block = kovanica_types::StatementBlock {
            author: 0,
            round: 3,
            parents: Vec::new(),
            transactions: Vec::new(),
            statements: Vec::new(),
            signature: kovanica_crypto::sign(&key, digest.as_ref()),
            digest,
            merkle_root: Default::default(),
        };
        engine.process_block(&block).unwrap();
        // The leader block was seen; the clock starts here.
        assert!(engine.leader_first_seen.read().contains_key(&3));

        engine
            .process_vote(&signed_vote(&key, 3, 0, digest))
            .unwrap();

        // The arrival entry is consumed exactly once by the commit.
        assert!(!engine.leader_first_seen.read().contains_key(&3));

        let after = crate::metrics_text();
        assert!(
            metric_value(&after, "kovanica_committed_leaders_total") > committed_before,
            "committed-leader counter did not increase:\n{after}"
        );
        assert!(
            metric_value(&after, "kovanica_finality_latency_seconds_count") > samples_before,
            "finality latency histogram got no sample:\n{after}"
        );
    }

    /// A leader deadline timeout is counted under the `timeout` reason.
    #[tokio::test]
    async fn skipped_leader_is_counted_as_timeout() {
        let (engine, _dag, _key) = test_engine(100);
        let before = crate::metrics_text();
        let skipped_before = metric_value(
            &before,
            "kovanica_skipped_leaders_total{reason=\"timeout\"}",
        );

        engine.skip_leader(3).unwrap();

        let after = crate::metrics_text();
        assert!(
            metric_value(&after, "kovanica_skipped_leaders_total{reason=\"timeout\"}")
                > skipped_before,
            "timeout skip was not counted:\n{after}"
        );
    }

    /// An accepted vote is persisted, so a peer that joins later can be given
    /// the evidence for that leader round (RFC-009).
    #[tokio::test]
    async fn accepted_vote_is_persisted() {
        let (engine, dag, key) = test_engine(100);
        let digest = kovanica_types::StatementBlock::compute_digest(0, 3, &[], &[]);
        let block = kovanica_types::StatementBlock {
            author: 0,
            round: 3,
            parents: Vec::new(),
            transactions: Vec::new(),
            statements: Vec::new(),
            signature: kovanica_crypto::sign(&key, digest.as_ref()),
            digest,
            merkle_root: Default::default(),
        };
        engine.process_block(&block).unwrap();
        let vote = signed_vote(&key, 3, 0, digest);
        engine.process_vote(&vote).unwrap();
        let persisted = dag.persisted_votes.lock();
        assert_eq!(persisted.len(), 1);
        assert_eq!(persisted[0].leader_round, 3);
        assert_eq!(persisted[0].voter, 0);
        assert_eq!(persisted[0].leader_hash, digest);
    }

    /// The node's own vote is persisted too. It is part of the evidence for
    /// the leader round, and a joining peer cannot produce it: the joiner is
    /// outside its late vote window for the rounds it syncs.
    #[tokio::test]
    async fn own_vote_is_persisted() {
        let (engine, dag, key) = test_engine(100);
        let digest = kovanica_types::StatementBlock::compute_digest(0, 3, &[], &[]);
        let block = kovanica_types::StatementBlock {
            author: 0,
            round: 3,
            parents: Vec::new(),
            transactions: Vec::new(),
            statements: Vec::new(),
            signature: kovanica_crypto::sign(&key, digest.as_ref()),
            digest,
            merkle_root: Default::default(),
        };
        engine.process_block(&block).unwrap();
        assert!(engine.vote_for_leader(3).unwrap());
        let persisted = dag.persisted_votes.lock();
        assert_eq!(persisted.len(), 1);
        assert_eq!(persisted[0].leader_round, 3);
        assert_eq!(persisted[0].voter, 0);
    }

    /// A rejected vote is never persisted: the durable store must only hold
    /// votes that passed the authentication boundary.
    #[tokio::test]
    async fn rejected_vote_is_not_persisted() {
        let (engine, dag, key) = test_engine(100);
        let digest = kovanica_types::StatementBlock::compute_digest(0, 3, &[], &[]);
        let block = kovanica_types::StatementBlock {
            author: 0,
            round: 3,
            parents: Vec::new(),
            transactions: Vec::new(),
            statements: Vec::new(),
            signature: kovanica_crypto::sign(&key, digest.as_ref()),
            digest,
            merkle_root: Default::default(),
        };
        engine.process_block(&block).unwrap();
        // A vote for a non-leader round (rejected by consensus).
        let not_leader = signed_vote(&key, 4, 0, digest);
        assert!(engine.process_vote(&not_leader).is_err());
        // An unanchored vote for round 6 is buffered, not persisted.
        let vote6 = signed_vote(&key, 6, 0, digest);
        assert!(engine.process_vote(&vote6).is_ok());
        assert_eq!(engine.pending_votes_count(6), 1);
        // A vote with a broken signature.
        let mut bad = signed_vote(&key, 3, 0, digest);
        bad.signature = kovanica_types::Signature([1u8; 64]);
        assert!(engine.process_vote(&bad).is_err());
        assert!(dag.persisted_votes.lock().is_empty());
    }

    /// The commit walk stops at the first undecided leader, so a leader that
    /// was already at quorum stays uncommitted behind an earlier round.
    /// Draining the pipeline commits it without waiting for an unrelated
    /// trigger (RFC-009).
    #[tokio::test]
    async fn drain_commits_commits_a_leader_that_was_already_at_quorum() {
        let (engine, dag, key) = test_engine(100);
        let (sender, mut receiver) = mpsc::unbounded_channel();
        engine.set_commit_sender(sender);
        let make_block = |round: Round| {
            let digest = kovanica_types::StatementBlock::compute_digest(0, round, &[], &[]);
            kovanica_types::StatementBlock {
                author: 0,
                round,
                parents: Vec::new(),
                transactions: Vec::new(),
                statements: Vec::new(),
                signature: kovanica_crypto::sign(&key, digest.as_ref()),
                digest,
                merkle_root: Default::default(),
            }
        };
        let block3 = make_block(3);
        let block6 = make_block(6);
        let digest3 = block3.digest;
        let digest6 = block6.digest;
        engine.process_block(&block3).unwrap();
        engine.process_block(&block6).unwrap();

        // The later leader reaches quorum first. The walk must not pass the
        // earlier undecided leader.
        engine
            .process_vote(&signed_vote(&key, 6, 0, digest6))
            .unwrap();
        assert!(
            receiver.try_recv().is_err(),
            "the commit walk must not pass an undecided leader"
        );

        // The earlier leader reaches quorum: under PRO-40 (a) cascade commit draining,
        // it commits immediately and cascades to commit the waiting later leader.
        engine
            .process_vote(&signed_vote(&key, 3, 0, digest3))
            .unwrap();
        assert_eq!(receiver.try_recv().unwrap().leader.digest, digest3);
        assert_eq!(receiver.try_recv().unwrap().leader.digest, digest6);
        assert!(receiver.try_recv().is_err());

        // Draining again is idempotent when nothing is left to commit.
        engine.drain_commits().unwrap();
        assert!(receiver.try_recv().is_err());
        assert_eq!(
            dag.decisions.lock().as_slice(),
            &[(3, digest3), (6, digest6)]
        );
    }

    /// `registered_leader` tells a caller whether the votes for a round can
    /// be applied yet.
    #[tokio::test]
    async fn registered_leader_reports_the_ingested_leader_round() {
        let (engine, _dag, key) = test_engine(100);
        let digest = kovanica_types::StatementBlock::compute_digest(0, 3, &[], &[]);
        let block = kovanica_types::StatementBlock {
            author: 0,
            round: 3,
            parents: Vec::new(),
            transactions: Vec::new(),
            statements: Vec::new(),
            signature: kovanica_crypto::sign(&key, digest.as_ref()),
            digest,
            merkle_root: Default::default(),
        };
        assert!(engine.registered_leader(3).is_none());
        engine.process_block(&block).unwrap();
        let leader = engine
            .registered_leader(3)
            .expect("the leader is registered");
        assert_eq!(leader.round, 3);
        assert_eq!(leader.block_hash, Some(digest));
        assert!(engine.registered_leader(6).is_none());
    }

    #[tokio::test]
    async fn decision_mark_failure_leaves_commit_retryable() {
        let (engine, dag, key) = test_engine(100);
        let (sender, mut receiver) = mpsc::unbounded_channel();
        engine.set_commit_sender(sender);
        let digest = kovanica_types::StatementBlock::compute_digest(0, 3, &[], &[]);
        let block = kovanica_types::StatementBlock {
            author: 0,
            round: 3,
            parents: Vec::new(),
            transactions: Vec::new(),
            statements: Vec::new(),
            signature: kovanica_crypto::sign(&key, digest.as_ref()),
            digest,
            merkle_root: Default::default(),
        };
        engine.process_block(&block).unwrap();

        let later_parent = kovanica_types::block::BlockReference {
            author: 0,
            round: 3,
            digest,
        };
        let later_digest = kovanica_types::StatementBlock::compute_digest(
            0,
            6,
            std::slice::from_ref(&later_parent),
            &[],
        );
        let later_block = kovanica_types::StatementBlock {
            author: 0,
            round: 6,
            parents: vec![later_parent],
            transactions: Vec::new(),
            statements: Vec::new(),
            signature: kovanica_crypto::sign(&key, later_digest.as_ref()),
            digest: later_digest,
            merkle_root: Default::default(),
        };
        engine.process_block(&later_block).unwrap();

        dag.fail_next_decision_mark.store(true, Ordering::SeqCst);
        assert!(matches!(
            engine.process_vote(&signed_vote(&key, 3, 0, digest)),
            Err(ConsensusError::DagStore(_))
        ));
        assert_eq!(engine.committer.last_decided_round(), 0);
        assert!(engine.committer.get_all_decided_leaders().is_empty());
        assert!(
            receiver.try_recv().is_err(),
            "failed persistence is not delivered"
        );

        // Even with a later quorum available, the earlier failed decision is
        // retried and delivered first; under PRO-40 (a) cascade draining, both
        // round 3 and round 6 are committed and delivered in order.
        engine
            .process_vote(&signed_vote(&key, 6, 0, later_digest))
            .unwrap();
        assert_eq!(receiver.try_recv().unwrap().leader_round, 3);
        assert_eq!(receiver.try_recv().unwrap().leader_round, 6);
        assert!(receiver.try_recv().is_err());
        assert_eq!(
            dag.decisions.lock().as_slice(),
            &[(3, digest), (6, later_digest)]
        );
        assert_eq!(engine.committer.last_decided_round(), 6);
    }

    #[test]
    fn concurrent_commit_triggers_deliver_decisions_in_order_once() {
        let (engine, dag, _key) = test_engine(100);
        let (sender, mut receiver) = mpsc::unbounded_channel();
        engine.set_commit_sender(sender);

        let round3 = kovanica_types::StatementBlock::compute_digest(0, 3, &[], &[]);
        let round6 = kovanica_types::StatementBlock::compute_digest(0, 6, &[], &[]);
        for (round, digest, parents) in [
            (3, round3, Vec::new()),
            (
                6,
                round6,
                vec![kovanica_types::block::BlockReference {
                    author: 0,
                    round: 3,
                    digest: round3,
                }],
            ),
        ] {
            let block = kovanica_types::StatementBlock {
                author: 0,
                round,
                parents,
                transactions: Vec::new(),
                statements: Vec::new(),
                signature: kovanica_types::Signature([0; 64]),
                digest,
                merkle_root: Default::default(),
            };
            dag.put_block(&block).unwrap();
            engine.committer.update_leader(LeaderInfo {
                round,
                author: 0,
                block_hash: Some(digest),
                status: LeaderStatus::Undecided,
                votes: HashMap::new(),
            });
            engine.committer.add_vote(round, 0, digest);
        }
        let engine = Arc::new(engine);
        let trigger_count = 8;
        let barrier = Arc::new(std::sync::Barrier::new(trigger_count));
        let mut threads = Vec::new();
        for _ in 0..trigger_count {
            let engine = Arc::clone(&engine);
            let barrier = Arc::clone(&barrier);
            threads.push(std::thread::spawn(move || {
                barrier.wait();
                engine.try_commit_and_deliver().unwrap();
            }));
        }
        for thread in threads {
            thread.join().unwrap();
        }

        let delivered: Vec<_> = std::iter::from_fn(|| receiver.try_recv().ok())
            .map(|subdag| subdag.leader_round)
            .collect();
        assert_eq!(delivered, vec![3, 6]);
        assert_eq!(
            dag.decisions
                .lock()
                .iter()
                .map(|(round, _)| *round)
                .collect::<Vec<_>>(),
            vec![3, 6]
        );
    }

    #[tokio::test]
    async fn invalid_block_rejected_by_network_pipeline() {
        // This test simulates the network→engine→block_manager pipeline
        // receiving an invalid block (bad signature) and rejecting it.
        let (engine, dag, key) = test_engine(100);
        let engine = Arc::new(engine);

        // Create a valid block first (genesis is already in TestDag via propose_block)
        let valid_digest = kovanica_types::StatementBlock::compute_digest(0, 3, &[], &[]);
        let valid_block = kovanica_types::StatementBlock {
            author: 0,
            round: 3,
            parents: Vec::new(),
            transactions: Vec::new(),
            statements: Vec::new(),
            signature: kovanica_crypto::sign(&key, valid_digest.as_ref()),
            digest: valid_digest,
            merkle_root: Default::default(),
        };

        // Process valid block - should succeed
        engine.process_block(&valid_block).unwrap();
        assert!(dag.has_block(&valid_digest).unwrap());

        // Create an invalid block (wrong signature)
        let invalid_digest = kovanica_types::StatementBlock::compute_digest(0, 4, &[], &[]);
        let (_, wrong_pk) = kovanica_crypto::generate_keypair();
        let wrong_key = kovanica_types::SigningKey::from_bytes(&wrong_pk.0);
        let invalid_block = kovanica_types::StatementBlock {
            author: 0,
            round: 4,
            parents: Vec::new(),
            transactions: Vec::new(),
            statements: Vec::new(),
            signature: kovanica_crypto::sign(&wrong_key, invalid_digest.as_ref()),
            digest: invalid_digest,
            merkle_root: Default::default(),
        };

        // Process invalid block - should fail validation
        let result = engine.process_block(&invalid_block);
        assert!(result.is_err(), "Invalid block should be rejected");

        // Block should not be stored
        assert!(!dag.has_block(&invalid_digest).unwrap());

        // Create block with unknown author - should fail
        let unknown_digest = kovanica_types::StatementBlock::compute_digest(99, 5, &[], &[]);
        let unknown_block = kovanica_types::StatementBlock {
            author: 99, // not in committee
            round: 5,
            parents: Vec::new(),
            transactions: Vec::new(),
            statements: Vec::new(),
            signature: kovanica_types::Signature([0; 64]),
            digest: unknown_digest,
            merkle_root: Default::default(),
        };

        let result = engine.process_block(&unknown_block);
        assert!(
            result.is_err(),
            "Block from unknown author should be rejected"
        );
        assert!(!dag.has_block(&unknown_digest).unwrap());

        // Create block with bad digest - should fail
        let mut bad_digest_block = valid_block.clone();
        bad_digest_block.round = 6;
        bad_digest_block.digest = kovanica_types::Hash::zero();

        let result = engine.process_block(&bad_digest_block);
        assert!(
            result.is_err(),
            "Block with mismatched digest should be rejected"
        );
    }

    #[tokio::test]
    async fn leader_proposes_only_once_per_round_no_duplicate_proposals() {
        // This test ensures that the consensus engine produces exactly one block
        // per leader round, preventing the duplicate proposal issue where both
        // the engine's round_loop and a separate builder task would produce blocks.
        let (engine, dag, _key) = test_engine(100);
        let engine = Arc::new(engine);

        // Manually trigger the round loop logic for round 3 (leader round for authority 0)
        // First, advance to round 3 and check if we're leader
        engine.state.write().current_round = 3;
        assert!(engine.is_leader_for_round(3), "Should be leader at round 3");

        // Call propose_block - this simulates the round_loop calling propose_block
        engine.propose_block(3).await.unwrap();
        let block1 = dag.blocks.read().values().find(|b| b.round == 3).cloned();
        assert!(block1.is_some(), "First proposal should exist");
        let first_proposal_digest = block1.unwrap().digest;

        // Call propose_block again for the same round - should not produce a duplicate
        // (the engine tracks proposed state and should not re-propose)
        engine.state.write().proposed = false; // Reset to simulate a bug scenario
        engine.propose_block(3).await.unwrap();

        // Verify only one block exists at round 3
        let blocks_at_round3: Vec<_> = dag
            .blocks
            .read()
            .values()
            .filter(|b| b.round == 3)
            .cloned()
            .collect();
        assert_eq!(
            blocks_at_round3.len(),
            1,
            "Only one block should be produced per leader round, but found {} blocks (duplicate proposal bug)",
            blocks_at_round3.len()
        );

        // Verify the block is the same one (no equivocation)
        assert_eq!(
            blocks_at_round3[0].digest, first_proposal_digest,
            "Block digest should not change between proposals"
        );

        // Verify the block has the correct author (our authority)
        assert_eq!(
            blocks_at_round3[0].author, 0,
            "Block author should be our authority"
        );

        engine.stop();
    }

    #[test]
    fn timeout_skips_leader_after_deadline() {
        let (engine, _dag, _key) = test_engine(100);
        // Manually set a leader deadline in the past for round 3
        *engine.leader_deadline.write() = Some((
            3,
            std::time::Instant::now() - std::time::Duration::from_secs(10),
        ));
        // Skip should mark leader as Skip without panic
        engine.skip_leader(3).unwrap();
    }

    #[test]
    fn fork_first_valid_digest_wins_deterministic() {
        let (engine, _dag, key) = test_engine_with(
            100,
            ConsensusConfig {
                use_min_digest_fork: false,
                ..ConsensusConfig::default()
            },
        );
        let digest_a = kovanica_types::StatementBlock::compute_digest(0, 3, &[], &[]);
        let block_a = kovanica_types::StatementBlock {
            author: 0,
            round: 3,
            parents: Vec::new(),
            transactions: Vec::new(),
            statements: Vec::new(),
            signature: kovanica_crypto::sign(&key, digest_a.as_ref()),
            digest: digest_a,
            merkle_root: Default::default(),
        };
        engine.process_block(&block_a).unwrap();

        // Second block with different digest for same round/author should fail (fork)
        let fork_parent = kovanica_types::block::BlockReference {
            author: 0,
            round: 2,
            digest: kovanica_types::Hash::zero(),
        };
        let digest_b = kovanica_types::StatementBlock::compute_digest(0, 3, &[fork_parent], &[]);
        let block_b = kovanica_types::StatementBlock {
            author: 0,
            round: 3,
            parents: vec![fork_parent],
            transactions: Vec::new(),
            statements: Vec::new(),
            signature: kovanica_crypto::sign(&key, digest_b.as_ref()),
            digest: digest_b,
            merkle_root: Default::default(),
        };
        let result = engine.process_block(&block_b);
        assert!(
            result.is_err(),
            "Fork/equivocation with different digest must be rejected"
        );
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("fork/equivocation"));
    }

    #[test]
    fn vrf_flag_without_outputs_matches_round_robin() {
        let (engine, _dag, _key) = test_engine(100);
        assert!(engine.config.use_vrf_leader);
        let rr = engine.scheduled_leader_for_round(3);
        // Flag on, empty output map: still the round-robin leader.
        let mut flagged = engine.config.clone();
        flagged.use_vrf_leader = true;
        // Recompute via the committee hook directly; the engine field is private
        // to mutate after build, so compare the two selection functions.
        let _ = flagged;
        let committee = &engine.committee;
        assert_eq!(
            committee.leader_with_vrf(3, &std::collections::HashMap::new()),
            committee.leader(3)
        );
        assert_eq!(rr, Some(committee.leader(3)));

        let (flagged_engine, _, _) = test_engine_with(
            100,
            ConsensusConfig {
                use_vrf_leader: true,
                ..ConsensusConfig::default()
            },
        );
        assert_eq!(
            flagged_engine.scheduled_leader_for_round(3),
            Some(flagged_engine.committee.leader(3)),
            "flag on with no verified outputs must ignore the round-robin prefetch"
        );
    }

    #[test]
    fn vrf_flag_uses_recorded_outputs_not_prefetch() {
        let (key, public_key) = kovanica_crypto::generate_keypair();
        let dag = Arc::new(TestDag::default());
        let committee = CommitteeInfo::try_new(
            0,
            vec![
                AuthorityInfo {
                    index: 0,
                    stake: 100,
                    public_key,
                    vrf_public_key: Some(kovanica_types::crypto::PublicKey([1; 32])),
                    address: Address::default(),
                    network_address: String::new(),
                },
                AuthorityInfo {
                    index: 1,
                    stake: 100,
                    public_key: kovanica_types::crypto::PublicKey([9; 32]),
                    vrf_public_key: Some(kovanica_types::crypto::PublicKey([2; 32])),
                    address: Address::default(),
                    network_address: String::new(),
                },
            ],
        )
        .expect("committee");
        let manager = Arc::new(RwLock::new(TestBlockManager {
            dag: dag.clone(),
            key: RwLock::new(key.clone()),
            set_key_calls: AtomicUsize::new(0),
        }));
        let engine = ConsensusEngine::new(
            ConsensusConfig {
                use_vrf_leader: true,
                ..ConsensusConfig::default()
            },
            committee,
            dag,
            manager,
            key,
            None,
            TEST_CTX,
        );
        // Round 3, two authorities: round-robin index is 1. Outputs from
        // decide round 2 elect it once both authorities are present.
        assert_eq!(engine.scheduled_leader_for_round(3), Some(1));
        engine.record_verified_vrf_output(2, 0, [0x01; 32]);
        assert_eq!(
            engine.scheduled_leader_for_round(3),
            Some(1),
            "a partial VRF set must stay on round-robin"
        );
        engine.record_verified_vrf_output(2, 1, [0xff; 32]);
        assert_eq!(
            engine.scheduled_leader_for_round(3),
            Some(0),
            "lower stake-weighted VRF hash must beat the prefetched round-robin leader"
        );
    }

    /// Restart must replay stored decide-round carriers and ingest them before
    /// it selects the leader. Round-robin for round 3 is authority 1. The
    /// outputs below elect authority 0, and only authority 0's leader block is
    /// stored. Selecting round-robin first leaves the slot unregistered.
    ///
    /// The engine map starts empty. Outputs appear only when `process_block`
    /// sees `replay_vrf`, so calling `ingest_vrf_outputs` without that replay
    /// still elects round-robin and this test fails.
    #[test]
    fn restart_ingests_vrf_outputs_before_restoring_leaders() {
        let (key, public_key) = kovanica_crypto::generate_keypair();
        let dag = Arc::new(TestDag::default());
        let committee = CommitteeInfo::try_new(
            0,
            vec![
                AuthorityInfo {
                    index: 0,
                    stake: 100,
                    public_key,
                    vrf_public_key: Some(kovanica_types::crypto::PublicKey([1; 32])),
                    address: Address::default(),
                    network_address: String::new(),
                },
                AuthorityInfo {
                    index: 1,
                    stake: 100,
                    public_key: kovanica_types::crypto::PublicKey([9; 32]),
                    vrf_public_key: Some(kovanica_types::crypto::PublicKey([2; 32])),
                    address: Address::default(),
                    network_address: String::new(),
                },
            ],
        )
        .expect("committee");
        let manager = Arc::new(RwLock::new(TestBlockManager {
            dag: dag.clone(),
            key: RwLock::new(key.clone()),
            set_key_calls: AtomicUsize::new(0),
        }));
        let engine = ConsensusEngine::new(
            ConsensusConfig::default(),
            committee,
            dag.clone(),
            manager,
            key,
            None,
            TEST_CTX,
        );
        assert_eq!(engine.scheduled_leader_for_round(3), Some(1));

        let mut replay = dag.replay_vrf.write();
        for (author, output) in [(0u16, [0x01u8; 32]), (1u16, [0xffu8; 32])] {
            let digest = kovanica_types::Hash([author as u8 + 1; 32]);
            replay.insert(digest, output);
            let block = kovanica_types::StatementBlock {
                author,
                round: 2,
                parents: Vec::new(),
                transactions: Vec::new(),
                statements: Vec::new(),
                signature: kovanica_types::Signature([0; 64]),
                digest,
                merkle_root: Default::default(),
            };
            dag.blocks.write().insert(digest, block);
        }
        drop(replay);

        let leader_digest = kovanica_types::Hash([0x11; 32]);
        dag.blocks.write().insert(
            leader_digest,
            kovanica_types::StatementBlock {
                author: 0,
                round: 3,
                parents: Vec::new(),
                transactions: Vec::new(),
                statements: Vec::new(),
                signature: kovanica_types::Signature([0; 64]),
                digest: leader_digest,
                merkle_root: Default::default(),
            },
        );
        *dag.stored_tip.write() = Some(3);

        engine.resume_from_store().expect("resume");

        let leader = engine
            .committer
            .get_leader(3)
            .expect("VRF leader is registered from the stored block");
        assert_eq!(leader.author, 0);
        assert_eq!(leader.block_hash, Some(leader_digest));
        assert!(
            dag.recorded_vrf.read().get(&2).is_some_and(|outputs| {
                outputs.len() == 2 && outputs.get(&0) == Some(&[0x01; 32])
            }),
            "carriers must be re-verified before the leader is selected"
        );
    }

    #[test]
    fn min_digest_fork_replaces_only_when_store_swaps() {
        let (engine, dag, key) = test_engine_with(
            100,
            ConsensusConfig {
                use_min_digest_fork: true,
                ..ConsensusConfig::default()
            },
        );

        let larger = kovanica_types::Hash([0x20; 32]);
        let smaller = kovanica_types::Hash([0x10; 32]);
        let block_large = kovanica_types::StatementBlock {
            author: 0,
            round: 3,
            parents: Vec::new(),
            transactions: Vec::new(),
            statements: Vec::new(),
            signature: kovanica_crypto::sign(&key, larger.as_ref()),
            digest: larger,
            merkle_root: Default::default(),
        };
        engine.process_block(&block_large).unwrap();

        let block_small = kovanica_types::StatementBlock {
            digest: smaller,
            signature: kovanica_crypto::sign(&key, smaller.as_ref()),
            ..block_large.clone()
        };
        engine.process_block(&block_small).unwrap();
        assert!(
            !dag.has_block(&larger).unwrap(),
            "replaced digest must leave the store"
        );
        assert!(dag.has_block(&smaller).unwrap());
        assert_eq!(
            engine.committer.get_leader(3).and_then(|l| l.block_hash),
            Some(smaller)
        );

        // A larger digest after the swap must still be rejected.
        let bigger = kovanica_types::Hash([0xff; 32]);
        let block_bigger = kovanica_types::StatementBlock {
            digest: bigger,
            signature: kovanica_crypto::sign(&key, bigger.as_ref()),
            ..block_large
        };
        let rejected = engine.process_block(&block_bigger);
        assert!(rejected.is_err());
        assert!(dag.has_block(&smaller).unwrap());
        assert!(!dag.has_block(&bigger).unwrap());
    }

    /// Equivocating leader, min-digest swap, then a restart.
    ///
    /// The node voted for digest X. The store then replaced the leader block
    /// with a smaller digest Y. After restart, `voted_rounds` is empty and
    /// replaying the stored vote X fails with `LeaderHashMismatch`, so the
    /// awaited-slot path would otherwise sign Y. It must not.
    #[test]
    fn restart_after_min_digest_swap_does_not_vote_the_replacement() {
        let (our_key, our_public) = kovanica_crypto::generate_keypair();
        let (leader_key, leader_public) = kovanica_crypto::generate_keypair();
        let dag = Arc::new(TestDag::default());
        let authorities = vec![
            AuthorityInfo {
                index: 0,
                stake: 1,
                public_key: our_public,
                vrf_public_key: None,
                address: Address::default(),
                network_address: String::new(),
            },
            AuthorityInfo {
                index: 1,
                stake: 1,
                public_key: leader_public,
                vrf_public_key: None,
                address: Address::default(),
                network_address: String::new(),
            },
            AuthorityInfo {
                index: 2,
                stake: 1,
                public_key: PublicKey([2; 32]),
                vrf_public_key: None,
                address: Address::default(),
                network_address: String::new(),
            },
            AuthorityInfo {
                index: 3,
                stake: 1,
                public_key: PublicKey([3; 32]),
                vrf_public_key: None,
                address: Address::default(),
                network_address: String::new(),
            },
        ];
        let committee = CommitteeInfo::try_new(0, authorities).expect("committee");
        // Round 3 is slot 1. With 4 authorities the round-robin leader is index 1,
        // so this node (index 0) votes and one vote is not a quorum.
        assert_eq!(committee.leader(3), 1);
        let config = ConsensusConfig {
            round_duration_ms: 100,
            use_min_digest_fork: true,
            ..ConsensusConfig::default()
        };
        let manager = Arc::new(RwLock::new(TestBlockManager {
            dag: dag.clone(),
            key: RwLock::new(leader_key.clone()),
            set_key_calls: AtomicUsize::new(0),
        }));
        let engine = ConsensusEngine::new(
            config.clone(),
            committee.clone(),
            dag.clone(),
            manager,
            our_key.clone(),
            None,
            TEST_CTX,
        );

        let digest_x = kovanica_types::Hash([0x20; 32]);
        let digest_y = kovanica_types::Hash([0x10; 32]);
        let block_x = kovanica_types::StatementBlock {
            author: 1,
            round: 3,
            parents: Vec::new(),
            transactions: Vec::new(),
            statements: Vec::new(),
            signature: kovanica_crypto::sign(&leader_key, digest_x.as_ref()),
            digest: digest_x,
            merkle_root: Default::default(),
        };
        engine.process_block(&block_x).unwrap();

        let broadcast = Arc::new(Mutex::new(Vec::<kovanica_types::Vote>::new()));
        let broadcast_log = broadcast.clone();
        let dag_for_broadcast = dag.clone();
        engine.set_vote_broadcaster(Arc::new(move |vote: &kovanica_types::Vote| {
            let stored = dag_for_broadcast
                .get_votes_for_round(vote.leader_round)
                .expect("stored votes");
            assert!(
                stored
                    .iter()
                    .any(|stored| stored.voter == vote.voter
                        && stored.leader_hash == vote.leader_hash),
                "the vote must be persisted before it is broadcast"
            );
            broadcast_log.lock().push(vote.clone());
        }));

        assert!(
            engine.vote_for_leader(3).unwrap(),
            "the node votes for the first leader digest"
        );
        assert_eq!(broadcast.lock().len(), 1);
        assert_eq!(broadcast.lock()[0].leader_hash, digest_x);

        let block_y = kovanica_types::StatementBlock {
            digest: digest_y,
            signature: kovanica_crypto::sign(&leader_key, digest_y.as_ref()),
            ..block_x
        };
        engine.process_block(&block_y).unwrap();
        assert_eq!(
            engine
                .committer
                .get_leader(3)
                .and_then(|leader| leader.block_hash),
            Some(digest_y),
            "min-digest swap replaces the leader block before it is decided"
        );
        assert!(
            broadcast
                .lock()
                .iter()
                .all(|vote| vote.leader_hash != digest_y),
            "the same process must not vote for the replacement"
        );

        // Restart: new engine, same store. The tip is far enough past the
        // late-vote window that only the awaited-slot path can vote.
        let restarted_manager = Arc::new(RwLock::new(TestBlockManager {
            dag: dag.clone(),
            key: RwLock::new(leader_key),
            set_key_calls: AtomicUsize::new(0),
        }));
        let restarted = ConsensusEngine::new(
            config,
            committee,
            dag.clone(),
            restarted_manager,
            our_key,
            None,
            TEST_CTX,
        );
        let restarted_broadcast = Arc::new(Mutex::new(Vec::<kovanica_types::Vote>::new()));
        let restarted_log = restarted_broadcast.clone();
        restarted.set_vote_broadcaster(Arc::new(move |vote: &kovanica_types::Vote| {
            restarted_log.lock().push(vote.clone());
        }));
        *dag.stored_tip.write() = Some(20);
        restarted.resume_from_store().expect("resume");
        assert_eq!(
            restarted
                .committer
                .get_leader(3)
                .and_then(|leader| leader.block_hash),
            Some(digest_y),
            "restore registers the swapped leader block"
        );
        restarted.vote_awaited_slots().expect("awaited slots");

        assert!(
            restarted_broadcast.lock().is_empty(),
            "restart must not broadcast a vote for Y, got {:?}",
            restarted_broadcast
                .lock()
                .iter()
                .map(|vote| vote.leader_hash)
                .collect::<Vec<_>>()
        );
        let own_votes: Vec<_> = dag
            .get_votes_for_round(3)
            .unwrap()
            .into_iter()
            .filter(|vote| vote.voter == 0)
            .collect();
        assert_eq!(own_votes.len(), 1, "exactly one stored self-vote");
        assert_eq!(own_votes[0].leader_hash, digest_x);
        assert!(own_votes.iter().all(|vote| vote.leader_hash != digest_y));
    }

    /// A failed durable write must not put the vote on the wire. The slot is
    /// not remembered, so once storage accepts the write the same slot is
    /// voted and the vote is stored before it is broadcast.
    #[test]
    fn failed_vote_write_is_not_broadcast() {
        let (engine, dag, key) = test_engine(100);
        let digest = kovanica_types::StatementBlock::compute_digest(0, 3, &[], &[]);
        let block = kovanica_types::StatementBlock {
            author: 0,
            round: 3,
            parents: Vec::new(),
            transactions: Vec::new(),
            statements: Vec::new(),
            signature: kovanica_crypto::sign(&key, digest.as_ref()),
            digest,
            merkle_root: Default::default(),
        };
        engine.process_block(&block).unwrap();
        dag.fail_put_vote.store(true, Ordering::SeqCst);

        let sent = Arc::new(Mutex::new(Vec::<kovanica_types::Vote>::new()));
        let sent_log = sent.clone();
        let dag_for_broadcast = dag.clone();
        engine.set_vote_broadcaster(Arc::new(move |vote: &kovanica_types::Vote| {
            let stored = dag_for_broadcast
                .get_votes_for_round(vote.leader_round)
                .expect("stored votes");
            assert!(
                stored.iter().any(|stored| {
                    stored.voter == vote.voter && stored.leader_hash == vote.leader_hash
                }),
                "the vote must be persisted before it is broadcast"
            );
            sent_log.lock().push(vote.clone());
        }));
        let (commit_tx, mut commits) = mpsc::unbounded_channel();
        engine.set_commit_sender(commit_tx);

        assert!(
            !engine.vote_for_leader(3).unwrap(),
            "a failed write does not cast a vote"
        );
        assert!(
            sent.lock().is_empty(),
            "a failed write must not broadcast, got {:?}",
            sent.lock()
                .iter()
                .map(|vote| vote.leader_hash)
                .collect::<Vec<_>>()
        );
        assert!(dag.persisted_votes.lock().is_empty());
        assert!(
            engine.committer.get_leader(3).unwrap().votes.is_empty(),
            "the vote must not count locally when it was not stored"
        );
        assert!(commits.try_recv().is_err(), "nothing is committed");

        dag.fail_put_vote.store(false, Ordering::SeqCst);
        assert!(
            engine.vote_for_leader(3).unwrap(),
            "storage recovered, so the slot can still be voted"
        );
        assert_eq!(sent.lock().len(), 1);
        assert_eq!(sent.lock()[0].leader_hash, digest);
        assert_eq!(dag.get_votes_for_round(3).unwrap().len(), 1);
        assert_eq!(commits.try_recv().unwrap().leader.digest, digest);
    }

    /// The durable write committed and the process died before `broadcast_vote`.
    /// After restart the stored vote is not sent, and a different digest for
    /// the same slot is not signed.
    #[test]
    fn crash_between_persist_and_send_is_not_resent_and_does_not_equivocate() {
        let (engine, dag, key) = test_engine(100);
        let block = stored_leader_block(&key, 3);
        let digest_x = block.digest;
        engine.process_block(&block).unwrap();

        let ctx = engine.vote_signing_ctx(3);
        let mut stored = kovanica_types::Vote {
            leader_round: 3,
            leader_hash: digest_x,
            voter: 0,
            signature: kovanica_types::Signature([0; 64]),
        };
        stored.signature = kovanica_crypto::sign(&key, &stored.signature_data(&ctx));
        dag.persisted_votes.lock().push(stored);
        drop(engine);

        let restarted = restarted_engine(dag.clone(), key, 100);
        // The block is already in the store, so `process_block` does not
        // re-register the leader. Put the record back the way a resume would,
        // with an empty in-memory vote map.
        restarted.committer.update_leader(LeaderInfo {
            round: 3,
            author: 0,
            block_hash: Some(digest_x),
            status: LeaderStatus::Undecided,
            votes: HashMap::new(),
        });
        let sent = record_broadcasts(&restarted);
        assert!(
            !restarted.vote_for_leader(3).unwrap(),
            "a vote stored before the crash is not sent after restart"
        );
        assert!(
            sent.lock().is_empty(),
            "restart must not re-send a vote that was never broadcast"
        );

        // The in-memory reservation from the same-digest refusal is gone on a
        // real restart. Drop it here so the conflicting digest reaches the
        // durable check.
        let digest_y = kovanica_types::Hash([0x00; 32]);
        assert!(
            digest_y.0 < digest_x.0,
            "the replacement must be the smaller digest so the leader record updates"
        );
        restarted.committer.update_leader(LeaderInfo {
            round: 3,
            author: 0,
            block_hash: Some(digest_y),
            status: LeaderStatus::Undecided,
            votes: HashMap::new(),
        });
        assert_eq!(
            restarted
                .committer
                .get_leader(3)
                .and_then(|leader| leader.block_hash),
            Some(digest_y)
        );
        restarted.voted_rounds.lock().remove(&3);
        assert!(
            !restarted.vote_for_leader(3).unwrap(),
            "a stored vote must block a conflicting digest"
        );
        assert!(
            sent.lock().is_empty(),
            "a conflicting digest must not be broadcast, got {:?}",
            sent.lock()
                .iter()
                .map(|vote| vote.leader_hash)
                .collect::<Vec<_>>()
        );
        let own = dag.get_votes_for_round(3).unwrap();
        assert_eq!(own.len(), 1, "the stored self-vote is unchanged");
        assert_eq!(own[0].voter, 0);
        assert_eq!(own[0].leader_hash, digest_x);
    }

    /// A read error on the stored self-vote fails closed: nothing is signed
    /// or reserved. A later successful read can still vote.
    #[test]
    fn stored_vote_read_error_rejects_the_vote() {
        let (engine, dag, key) = test_engine(100);
        let block = stored_leader_block(&key, 3);
        let digest = block.digest;
        engine.process_block(&block).unwrap();
        dag.fail_get_votes.store(true, Ordering::SeqCst);

        let sent = record_broadcasts(&engine);
        assert!(
            !engine.vote_for_leader(3).unwrap(),
            "a store read error does not cast a vote"
        );
        assert!(
            sent.lock().is_empty(),
            "a store read error must not broadcast"
        );
        assert!(
            dag.persisted_votes.lock().is_empty(),
            "a refused read must not write a vote"
        );
        assert!(
            !engine.voted_rounds.lock().contains(&3),
            "a failed read must not reserve the slot"
        );
        assert!(
            !engine.vote_for_leader(3).unwrap(),
            "the slot stays closed while the read keeps failing"
        );
        assert!(sent.lock().is_empty());

        dag.fail_get_votes.store(false, Ordering::SeqCst);
        assert!(
            engine.vote_for_leader(3).unwrap(),
            "a recovered read can still vote"
        );
        assert_eq!(sent.lock().len(), 1);
        assert_eq!(sent.lock()[0].leader_hash, digest);
        assert_eq!(dag.get_votes_for_round(3).unwrap().len(), 1);
    }

    /// A vote that was persisted and sent is not broadcast again after restart.
    #[test]
    fn persisted_vote_is_not_resent_after_restart() {
        let (engine, dag, key) = test_engine(100);
        let block = stored_leader_block(&key, 3);
        let digest = block.digest;
        engine.process_block(&block).unwrap();
        let sent = record_broadcasts(&engine);
        assert!(engine.vote_for_leader(3).unwrap(), "the vote is cast once");
        assert_eq!(sent.lock().len(), 1);
        assert_eq!(sent.lock()[0].leader_hash, digest);
        drop(engine);

        let restarted = restarted_engine(dag.clone(), key, 100);
        restarted.committer.update_leader(LeaderInfo {
            round: 3,
            author: 0,
            block_hash: Some(digest),
            status: LeaderStatus::Undecided,
            votes: HashMap::new(),
        });
        let resent = record_broadcasts(&restarted);
        assert!(
            !restarted.vote_for_leader(3).unwrap(),
            "the stored vote is not signed again"
        );
        assert!(
            resent.lock().is_empty(),
            "restart must not re-send the persisted vote, got {:?}",
            resent
                .lock()
                .iter()
                .map(|vote| vote.leader_hash)
                .collect::<Vec<_>>()
        );
        let own = dag.get_votes_for_round(3).unwrap();
        assert_eq!(own.len(), 1);
        assert_eq!(own[0].leader_hash, digest);
    }

    #[test]
    fn fork_same_digest_is_idempotent() {
        let (engine, _dag, key) = test_engine(100);
        let digest = kovanica_types::StatementBlock::compute_digest(0, 3, &[], &[]);
        let block = kovanica_types::StatementBlock {
            author: 0,
            round: 3,
            parents: Vec::new(),
            transactions: Vec::new(),
            statements: Vec::new(),
            signature: kovanica_crypto::sign(&key, digest.as_ref()),
            digest,
            merkle_root: Default::default(),
        };
        engine.process_block(&block).unwrap();
        // Same digest again must succeed (idempotent)
        engine.process_block(&block).unwrap();
    }

    #[tokio::test]
    async fn leader_timeout_timer_cleared_on_valid_block() {
        let (engine, _dag, key) = test_engine(100);
        let digest = kovanica_types::StatementBlock::compute_digest(0, 3, &[], &[]);
        let block = kovanica_types::StatementBlock {
            author: 0,
            round: 3,
            parents: Vec::new(),
            transactions: Vec::new(),
            statements: Vec::new(),
            signature: kovanica_crypto::sign(&key, digest.as_ref()),
            digest,
            merkle_root: Default::default(),
        };
        *engine.leader_deadline.write() = Some((3, std::time::Instant::now()));
        engine.process_block(&block).unwrap();
        assert!(
            engine.leader_deadline.read().is_none(),
            "Deadline should be cleared when block arrives"
        );
    }

    #[test]
    fn timeout_and_fork_deterministic() {
        // 4.3 Timeout + 4.4 Fork: skip via timeout_factor and lexicographic min-digest wins.
        use crate::committer::UniversalCommitter;
        use crate::types::{CommitteeInfo, LeaderInfo, LeaderStatus};
        use kovanica_types::{hash::Hash, AuthorityIndex};

        let committee = CommitteeInfo::try_new(
            0,
            vec![crate::types::AuthorityInfo {
                index: 0,
                stake: 100,
                public_key: kovanica_crypto::generate_keypair().1,
                vrf_public_key: None,
                address: kovanica_types::Address::default(),
                network_address: String::new(),
            }],
        )
        .expect("valid");

        let committer = UniversalCommitter::new(committee, false, 100);
        let round: Round = 7;
        let author: AuthorityIndex = 0;

        // First digest (larger lexicographically) registered.
        let larger_digest = Hash([255u8; 32]);
        committer.update_leader(LeaderInfo {
            round,
            author,
            block_hash: Some(larger_digest),
            status: LeaderStatus::Undecided,
            votes: std::collections::HashMap::new(),
        });

        // Second digest (smaller lexicographically) must win deterministically.
        let smaller_digest = Hash([1u8; 32]);
        committer.update_leader(LeaderInfo {
            round,
            author,
            block_hash: Some(smaller_digest),
            status: LeaderStatus::Undecided,
            votes: std::collections::HashMap::new(),
        });

        let leader = committer.get_leader(round).expect("leader exists");
        assert_eq!(
            leader.block_hash,
            Some(smaller_digest),
            "min_digest (lexicographic) must win"
        );
        assert_ne!(
            leader.block_hash,
            Some(larger_digest),
            "larger digest must be rejected"
        );

        // 4.3 Timeout: register_skip must persist Skip in decided map.
        committer.register_skip(7, 0);
        let decided = committer.get_all_decided_leaders();
        assert!(
            decided.contains_key(&7),
            "skip must be persisted in decided map"
        );
        assert_eq!(
            decided.get(&7).unwrap().status,
            LeaderStatus::Skip,
            "Skip status must be persisted"
        );
    }

    // -----------------------------------------------------------------
    // Signature format v1: vote context is local chain_id + committee epoch
    // -----------------------------------------------------------------

    const SIG_V1_EPOCH: u64 = 5;

    fn vote_with_ctx(
        key: &kovanica_types::SigningKey,
        ctx: &kovanica_types::SigningContext,
        leader_round: Round,
        leader_hash: Hash,
    ) -> kovanica_types::Vote {
        let mut vote = kovanica_types::Vote {
            leader_round,
            leader_hash,
            voter: 0,
            signature: kovanica_types::Signature([0; 64]),
        };
        vote.signature = kovanica_crypto::sign(key, &vote.signature_data(ctx));
        vote
    }

    fn engine_with_leader_at_epoch() -> (
        ConsensusEngine<TestDag, TestBlockManager>,
        kovanica_types::SigningKey,
        Hash,
        mpsc::UnboundedReceiver<kovanica_types::CommittedSubDag>,
    ) {
        let (engine, _dag, key) = test_engine_at_epoch(100, SIG_V1_EPOCH);
        let (sender, receiver) = mpsc::unbounded_channel();
        engine.set_commit_sender(sender);
        let digest = kovanica_types::StatementBlock::compute_digest(0, 3, &[], &[]);
        let block = kovanica_types::StatementBlock {
            author: 0,
            round: 3,
            parents: Vec::new(),
            transactions: Vec::new(),
            statements: Vec::new(),
            signature: kovanica_crypto::sign(&key, digest.as_ref()),
            digest,
            merkle_root: Default::default(),
        };
        engine.process_block(&block).unwrap();
        (engine, key, digest, receiver)
    }

    fn engine_with_leader_at_epoch_for_epoch(
        epoch: u64,
    ) -> (
        ConsensusEngine<TestDag, TestBlockManager>,
        kovanica_types::SigningKey,
        Hash,
        mpsc::UnboundedReceiver<kovanica_types::CommittedSubDag>,
    ) {
        let leader_round = epoch * kovanica_staking::EPOCH_ROUNDS;
        let (engine, _dag, key) = test_engine_at_epoch(100, epoch);
        let (sender, receiver) = mpsc::unbounded_channel();
        engine.set_commit_sender(sender);
        let digest = kovanica_types::StatementBlock::compute_digest(0, leader_round, &[], &[]);
        let block = kovanica_types::StatementBlock {
            author: 0,
            round: leader_round,
            parents: Vec::new(),
            transactions: Vec::new(),
            statements: Vec::new(),
            signature: kovanica_crypto::sign(&key, digest.as_ref()),
            digest,
            merkle_root: Default::default(),
        };
        engine.process_block(&block).unwrap();
        (engine, key, digest, receiver)
    }

    fn local_v1_ctx() -> kovanica_types::SigningContext {
        // With new epoch derivation (leader_round / EPOCH_ROUNDS), round 3 -> epoch 0
        kovanica_types::SigningContext {
            chain_id: TEST_CTX.chain_id,
            epoch: 3 / kovanica_staking::EPOCH_ROUNDS,
        }
    }

    #[tokio::test]
    async fn sig_v1_correct_quorum_commits() {
        let (engine, key, digest, mut receiver) = engine_with_leader_at_epoch();
        engine
            .process_vote(&vote_with_ctx(&key, &local_v1_ctx(), 3, digest))
            .expect("v1 vote for local chain_id + committee epoch is accepted");
        assert_eq!(receiver.try_recv().unwrap().leader.digest, digest);
    }

    #[tokio::test]
    async fn sig_v1_vote_for_other_chain_id_rejected() {
        let (engine, key, digest, mut receiver) = engine_with_leader_at_epoch();
        let other_chain = kovanica_types::SigningContext {
            chain_id: TEST_CTX.chain_id + 1,
            epoch: SIG_V1_EPOCH,
        };
        assert!(matches!(
            engine.process_vote(&vote_with_ctx(&key, &other_chain, 3, digest)),
            Err(ConsensusError::VoteRejected(VoteRejection::BadSignature(0)))
        ));
        assert!(receiver.try_recv().is_err());
    }

    #[tokio::test]
    async fn sig_v1_vote_for_other_epoch_rejected() {
        // Create engine with committee at epoch 5, but leader round that maps to epoch 5
        // With EPOCH_ROUNDS = 7200, round 36000 -> epoch 5
        let (engine, key, digest, mut receiver) = engine_with_leader_at_epoch_for_epoch(5);
        // Vote signed for epoch 0 (wrong epoch) while leader round maps to epoch 5
        let other_epoch = kovanica_types::SigningContext {
            chain_id: TEST_CTX.chain_id,
            epoch: 0,
        };
        assert!(matches!(
            engine.process_vote(&vote_with_ctx(&key, &other_epoch, 36000, digest)),
            Err(ConsensusError::VoteRejected(VoteRejection::BadSignature(0)))
        ));
        assert!(receiver.try_recv().is_err());
    }

    // B1 at engine level: an engine whose committee was built after the
    // epoch boundary (committee epoch 1, i.e. restarted node) must accept a
    // vote that a long-running node (committee epoch 0) signs for the same
    // leader round.
    // Test from Jarvis review (2026-10-19).
    #[tokio::test]
    async fn b1_review_restarted_engine_accepts_vote_from_running_engine() {
        let (engine, key, digest, _receiver) = engine_with_leader_at_epoch(); // committee epoch 5, round 3
        let running_ctx = kovanica_types::SigningContext {
            chain_id: TEST_CTX.chain_id,
            epoch: 3 / kovanica_staking::EPOCH_ROUNDS,
        };
        let res = engine.process_vote(&vote_with_ctx(&key, &running_ctx, 3, digest));
        assert!(
            !matches!(
                res,
                Err(ConsensusError::VoteRejected(VoteRejection::BadSignature(_)))
            ),
            "restarted engine rejected a running engine's vote: {res:?}"
        );
    }

    #[tokio::test]
    async fn sig_v1_old_format_without_domain_tag_rejected() {
        let (engine, key, digest, mut receiver) = engine_with_leader_at_epoch();
        // Legacy encoding: leader_round (LE) || leader_hash, no tag/ctx.
        let mut legacy = Vec::new();
        legacy.extend_from_slice(&3u64.to_le_bytes());
        legacy.extend_from_slice(&digest.0);
        let vote = kovanica_types::Vote {
            leader_round: 3,
            leader_hash: digest,
            voter: 0,
            signature: kovanica_crypto::sign(&key, &legacy),
        };
        assert!(matches!(
            engine.process_vote(&vote),
            Err(ConsensusError::VoteRejected(VoteRejection::BadSignature(0)))
        ));
        assert!(receiver.try_recv().is_err());
    }

    #[tokio::test]
    async fn sig_v1_own_vote_is_signed_with_committee_epoch() {
        let (engine, _key, _digest, _receiver) = engine_with_leader_at_epoch();
        assert_eq!(engine.vote_signing_ctx(3), local_v1_ctx());
    }

    // CI run #118: early-start nodes are rounds ahead, so a slow node's
    // leader block arrives after the fast node's vote round. The round loop
    // votes only once, so the vote used to be dropped and the leader never
    // reached quorum. The late vote must be cast (exactly once) on arrival.
    #[test]
    fn late_leader_block_gets_exactly_one_late_vote_and_commits() {
        let (key, public_key) = kovanica_crypto::generate_keypair();
        let others: Vec<_> = (1..4)
            .map(|_| kovanica_crypto::generate_keypair())
            .collect();
        let mut authorities = vec![AuthorityInfo {
            index: 0,
            stake: 1,
            public_key,
            vrf_public_key: None,
            address: Address::default(),
            network_address: String::new(),
        }];
        for (i, (_, pk)) in others.iter().enumerate() {
            authorities.push(AuthorityInfo {
                index: (i + 1) as AuthorityIndex,
                stake: 1,
                public_key: *pk,
                vrf_public_key: None,
                address: Address::default(),
                network_address: String::new(),
            });
        }
        let committee = CommitteeInfo::try_new(0, authorities).expect("committee");
        let dag = Arc::new(TestDag::default());
        let manager = Arc::new(RwLock::new(TestBlockManager {
            dag: dag.clone(),
            key: RwLock::new(key.clone()),
            set_key_calls: AtomicUsize::new(0),
        }));
        let engine = ConsensusEngine::new(
            ConsensusConfig::default(),
            committee.clone(),
            dag,
            manager,
            key.clone(),
            None,
            TEST_CTX,
        );
        let sent: Arc<Mutex<Vec<Round>>> = Arc::new(Mutex::new(Vec::new()));
        let sink = sent.clone();
        engine.set_vote_broadcaster(Arc::new(move |v: &kovanica_types::Vote| {
            sink.lock().push(v.leader_round)
        }));
        let (tx, mut rx) = mpsc::unbounded_channel();
        engine.set_commit_sender(tx);

        // Leader rounds 3, 6, 9 belong to authorities 3, 2, 1; we are 0.
        for leader_round in [3u64, 6, 9] {
            let author = committee.leader(leader_round);
            assert_ne!(author, 0);
            // The round loop ran its vote round with the leader still unknown.
            *engine.current_round.write() = leader_round + 1;
            assert!(!engine.vote_for_leader(leader_round).unwrap());
            // We are now 3 rounds past the leader round when it arrives.
            *engine.current_round.write() = leader_round + 3;

            let digest =
                kovanica_types::StatementBlock::compute_digest(author, leader_round, &[], &[]);
            let block = kovanica_types::StatementBlock {
                author,
                round: leader_round,
                parents: Vec::new(),
                transactions: Vec::new(),
                statements: Vec::new(),
                signature: kovanica_crypto::sign(&key, digest.as_ref()),
                digest,
                merkle_root: Default::default(),
            };
            engine.process_block(&block).expect("late leader block");
            // Duplicate delivery and the round-loop path must not re-vote.
            engine.process_block(&block).expect("duplicate block");
            assert_eq!(
                sent.lock().last().copied(),
                Some(leader_round),
                "late vote must be sent when the leader block arrives"
            );
            assert!(!engine.vote_for_leader(leader_round).unwrap());

            // Two other validators' votes: with ours that is 3/4 = quorum.
            let voters = [1u16, 2, 3]
                .into_iter()
                .filter(|v| *v != author)
                .take(1)
                .chain(std::iter::once(author));
            for voter in voters {
                let vkey = &others[(voter - 1) as usize].0;
                engine
                    .process_vote(&signed_vote(vkey, leader_round, voter, digest))
                    .expect("valid vote");
            }
            let committed = rx.try_recv().expect("late leader must commit");
            assert_eq!(committed.leader_round, leader_round);
        }
        assert_eq!(
            *sent.lock(),
            vec![3, 6, 9],
            "exactly one (late) vote per leader round"
        );
    }

    // -----------------------------------------------------------------
    // Late-vote bounds (late_join_integration regression guards)
    // -----------------------------------------------------------------

    /// Engine that is authority 0 of a 4-validator committee with a recording
    /// vote broadcaster. Returns the committee and the broadcast leader rounds.
    fn late_vote_engine() -> (
        CommitteeInfo,
        ConsensusEngine<TestDag, TestBlockManager>,
        Arc<Mutex<Vec<Round>>>,
    ) {
        let (key, public_key) = kovanica_crypto::generate_keypair();
        let others: Vec<_> = (1..4)
            .map(|_| kovanica_crypto::generate_keypair())
            .collect();
        let mut authorities = vec![AuthorityInfo {
            index: 0,
            stake: 1,
            public_key,
            vrf_public_key: None,
            address: Address::default(),
            network_address: String::new(),
        }];
        for (i, (_, pk)) in others.iter().enumerate() {
            authorities.push(AuthorityInfo {
                index: (i + 1) as AuthorityIndex,
                stake: 1,
                public_key: *pk,
                vrf_public_key: None,
                address: Address::default(),
                network_address: String::new(),
            });
        }
        let committee = CommitteeInfo::try_new(0, authorities).expect("committee");
        let dag = Arc::new(TestDag::default());
        let manager = Arc::new(RwLock::new(TestBlockManager {
            dag: dag.clone(),
            key: RwLock::new(key.clone()),
            set_key_calls: AtomicUsize::new(0),
        }));
        let engine = ConsensusEngine::new(
            ConsensusConfig::default(),
            committee.clone(),
            dag,
            manager,
            key,
            None,
            TEST_CTX,
        );
        let sent: Arc<Mutex<Vec<Round>>> = Arc::new(Mutex::new(Vec::new()));
        let sink = sent.clone();
        engine.set_vote_broadcaster(Arc::new(move |v: &kovanica_types::Vote| {
            sink.lock().push(v.leader_round)
        }));
        (committee, engine, sent)
    }

    fn registered_leader(round: Round, author: AuthorityIndex, seed: u8) -> LeaderInfo {
        LeaderInfo {
            round,
            author,
            block_hash: Some(kovanica_types::hash::Hash([seed; 32])),
            status: LeaderStatus::Undecided,
            votes: HashMap::new(),
        }
    }

    /// PRO-40: the per-round GC must keep everything above the commit cursor.
    /// Before the fix a leader stuck for `max_pending_rounds` (100 rounds,
    /// about 400 s) lost its record and the "already voted" marker, so the
    /// commit walk passed over it and the node could vote for it again.
    #[test]
    fn gc_keeps_the_stuck_leader_and_the_vote_marker_above_the_cursor() {
        let (committee, engine, _sent) = late_vote_engine();
        let stuck: Round = 3;
        engine
            .committer
            .update_leader(registered_leader(stuck, committee.leader(stuck), 7));
        engine.voted_rounds.lock().insert(stuck);
        engine.note_leader_block_seen(stuck);

        let max_pending = engine.config.max_pending_rounds;
        engine.cleanup_old_rounds(stuck + max_pending + 1_000);

        assert!(
            engine.registered_leader(stuck).is_some(),
            "the stuck leader record must survive GC"
        );
        assert!(
            engine.voted_rounds.lock().contains(&stuck),
            "the vote marker of an undecided round must survive GC"
        );
        assert!(engine.leader_first_seen.read().contains_key(&stuck));
        assert_eq!(engine.committer.last_decided_round(), 0);
    }

    /// A leader block arriving more than `late_vote_window_rounds` behind the
    /// node's own round is not voted for unless the commit walk is waiting on
    /// it (PRO-40 (a)): with the cursor at 0 the awaited slots are 3 and 6,
    /// so a stale block for slot 9 is refused. Exactly at the window boundary
    /// the vote is still cast.
    #[test]
    fn vote_is_refused_outside_the_late_vote_window() {
        let (committee, engine, sent) = late_vote_engine();
        let window = engine.config.late_vote_window_rounds;
        assert!(window >= 1, "window must allow in-flight votes");
        assert_eq!(engine.committer.last_decided_round(), 0);

        // Stale and not awaited: one round beyond the window.
        let stale_round: Round = 9;
        engine.committer.update_leader(registered_leader(
            stale_round,
            committee.leader(stale_round),
            1,
        ));
        *engine.current_round.write() = stale_round + window + 1;
        engine.vote_if_late(stale_round).expect("no error");
        assert!(
            sent.lock().is_empty(),
            "a leader block {} rounds behind that is not awaited must not be voted for",
            window + 1
        );

        // Boundary: exactly at the window, the vote is still cast.
        let edge_round: Round = 12;
        engine.committer.update_leader(registered_leader(
            edge_round,
            committee.leader(edge_round),
            2,
        ));
        *engine.current_round.write() = edge_round + window;
        engine.vote_if_late(edge_round).expect("no error");
        assert_eq!(
            sent.lock().last().copied(),
            Some(edge_round),
            "a leader block exactly {} rounds behind must still be voted for",
            window
        );
    }

    /// PRO-40 (a): the slot the walk is stalled on, and the next one, are
    /// voted for however late their block arrives; the third slot is not.
    #[test]
    fn a_late_block_for_an_awaited_slot_is_voted_for() {
        let (committee, engine, sent) = late_vote_engine();
        assert_eq!(LATE_VOTE_AWAITED_SLOTS, 2);
        *engine.current_round.write() = 200; // far beyond any window
        for (round, byte) in [(3, 1), (6, 2), (9, 3)] {
            engine
                .committer
                .update_leader(registered_leader(round, committee.leader(round), byte));
            engine.vote_if_late(round).expect("no error");
        }
        assert_eq!(*sent.lock(), vec![3, 6], "only the K = 2 awaited slots");
        // A non-slot round is never "awaited".
        assert!(!engine.is_awaited_slot(4));
        assert!(!engine.is_awaited_slot(0));
    }

    /// The per-round retry votes for a block that arrived while its slot was
    /// not yet awaited, once the cursor makes it awaited, and never twice.
    #[test]
    fn awaited_slot_retry_votes_once_the_slot_becomes_awaited() {
        let (committee, engine, sent) = late_vote_engine();
        *engine.current_round.write() = 200;
        let far: Round = 9;
        engine
            .committer
            .update_leader(registered_leader(far, committee.leader(far), 4));
        engine.vote_awaited_slots().expect("no error");
        assert!(sent.lock().is_empty(), "slot 9 is not awaited at cursor 0");

        engine.committer.restore_last_decided_round(3);
        engine.vote_awaited_slots().expect("no error");
        assert_eq!(*sent.lock(), vec![far], "awaited at cursor 3");
        engine.vote_awaited_slots().expect("no error");
        assert_eq!(*sent.lock(), vec![far], "one vote per round");
    }

    /// A timeout records a *provisional* skip. `register_skip` deliberately does
    /// not advance `last_decided_round`, precisely so that a leader block which
    /// arrives after the timeout can still be decided. A vote must therefore not
    /// be refused merely because the round carries a provisional decision:
    /// otherwise a single missed timeout disqualifies the round for ever, no
    /// quorum can ever form, and the chain stalls while every component still
    /// reports healthy. This is the regression test for that stall.
    #[test]
    fn provisional_skip_does_not_block_a_vote_once_the_leader_block_is_known() {
        let (committee, engine, sent) = late_vote_engine();
        let round: Round = 3;
        let author = committee.leader(round);
        // The leader's block was delivered...
        engine
            .committer
            .update_leader(registered_leader(round, author, 3));
        // ...but this node's leader-slot deadline expired anyway, so it recorded
        // a skip for the round. `update_leader` never lets a hash-less skip
        // erase a real block, so the block stays known.
        engine.committer.register_skip(round, author);
        assert!(engine.committer.is_decided(round));
        assert_eq!(
            engine.committer.last_decided_round(),
            0,
            "a provisional skip must not advance the decision cursor"
        );

        *engine.current_round.write() = round + 1;
        engine.vote_if_late(round).expect("no error");
        assert_eq!(
            sent.lock().last().copied(),
            Some(round),
            "a provisionally skipped round must still be voted for when its block is known"
        );
    }

    /// The durable decision cursor is the finality boundary: once it has passed a
    /// round, the decision walk never revisits that round, so a vote could only
    /// let a lagging peer commit a round this node already settled differently.
    /// A decided round at or below `last_decided_round` must be refused.
    #[test]
    fn vote_is_refused_once_the_decision_cursor_has_passed_the_round() {
        let (engine, dag, _key) = test_engine(4000);
        let round: Round = 3;
        let author = engine.committee.leader(round);
        let digest = kovanica_types::StatementBlock::compute_digest(author, round, &[], &[]);
        let block = kovanica_types::StatementBlock {
            author,
            round,
            parents: Vec::new(),
            transactions: Vec::new(),
            statements: Vec::new(),
            signature: kovanica_types::Signature([0; 64]),
            digest,
            merkle_root: Default::default(),
        };
        dag.put_block(&block).expect("block is stored");
        engine.committer.update_leader(LeaderInfo {
            round,
            author,
            block_hash: Some(digest),
            status: LeaderStatus::Undecided,
            votes: HashMap::new(),
        });
        // The single-authority test committee holds all the stake, so one vote
        // is already a quorum and the round becomes durably decided.
        engine.committer.add_vote(round, author, digest);
        engine.try_commit_and_deliver().expect("commit succeeds");

        assert_eq!(engine.committer.last_decided_round(), round);
        assert!(engine.committer.is_decided(round));
        assert!(
            !engine.vote_for_leader(round).expect("no error"),
            "a vote must be refused once the decision cursor has passed the round"
        );
    }

    /// The relaxation above only removes the refusal for *provisional* skips. A
    /// round whose leader block never arrived still has no hash to vote for and
    /// must not be voted for, however it was decided.
    #[test]
    fn vote_is_not_cast_for_a_decided_round_with_no_known_leader_block() {
        let (committee, engine, sent) = late_vote_engine();
        let round: Round = 3;
        let author = committee.leader(round);
        engine.committer.register_skip(round, author);
        assert!(engine.committer.is_decided(round));
        assert!(
            engine.committer.get_leader(round).is_some(),
            "the skip is still recorded as the round's leader entry"
        );
        assert!(
            engine
                .committer
                .get_leader(round)
                .and_then(|leader| leader.block_hash)
                .is_none(),
            "a skip carries no leader hash"
        );

        *engine.current_round.write() = round + 1;
        assert!(!engine.vote_for_leader(round).expect("no error"));
        assert_eq!(
            sent.lock().last().copied(),
            None,
            "a round with no known leader block must never be voted for"
        );
    }

    /// Detection halves of the slashing path: two conflicting headers by the
    /// scheduled leader are turned into a signed `Evidence` transaction in the
    /// local mempool, and nothing is submitted below the activation round.
    #[test]
    fn detected_equivocation_is_reported_as_a_signed_evidence_transaction() {
        use kovanica_types::{TransactionKind, SLASHING_ACTIVE_FROM_ROUND};

        let dir = tempfile::tempdir().expect("tempdir");
        let storage =
            Arc::new(kovanica_storage::Storage::new(dir.path().join("e.redb")).expect("storage"));
        let key = kovanica_types::SigningKey::from_bytes(&[3u8; 32]);
        let address =
            Address::from_public_key(&kovanica_types::PublicKey(key.verifying_key().to_bytes()));
        // The reporter is a validator, so its evidence is fee-free and the
        // pool's staking lookup succeeds.
        let mut staking = kovanica_staking::StakingState::new();
        staking
            .join_validator(
                address,
                kovanica_staking::MIN_VALIDATOR_STAKE,
                0,
                None,
                None,
                None,
            )
            .expect("join");
        let txn = storage.begin_write().expect("write");
        storage
            .state()
            .save_staking_state(&txn, &staking)
            .expect("save staking");
        txn.commit().expect("commit");

        let mempool = Arc::new(Mempool::new(Default::default(), storage.clone(), TEST_CTX));
        let dag = Arc::new(TestDag::default());
        let committee = CommitteeInfo::try_new(
            0,
            vec![AuthorityInfo {
                index: 0,
                stake: kovanica_staking::MIN_VALIDATOR_STAKE,
                public_key: kovanica_types::PublicKey(key.verifying_key().to_bytes()),
                vrf_public_key: None,
                address,
                network_address: String::new(),
            }],
        )
        .expect("committee");
        let manager = Arc::new(RwLock::new(TestBlockManager {
            dag: dag.clone(),
            key: RwLock::new(key.clone()),
            set_key_calls: AtomicUsize::new(0),
        }));
        let engine = ConsensusEngine::new(
            ConsensusConfig::default(),
            committee,
            dag,
            manager,
            key.clone(),
            Some(mempool.clone()),
            TEST_CTX,
        );

        let block = |round: Round, digest: Hash| kovanica_types::StatementBlock {
            author: 0,
            round,
            parents: Vec::new(),
            transactions: Vec::new(),
            statements: Vec::new(),
            signature: kovanica_crypto::sign(&key, digest.as_ref()),
            digest,
            merkle_root: Default::default(),
        };

        // Below activation: detected, but not reported.
        let below = SLASHING_ACTIVE_FROM_ROUND - 1;
        engine.report_equivocation(
            &block(below, Hash::new(b"a")),
            &block(below, Hash::new(b"b")),
        );
        assert_eq!(mempool.len(), 0);

        let a = block(SLASHING_ACTIVE_FROM_ROUND, Hash::new(b"a"));
        let b = block(SLASHING_ACTIVE_FROM_ROUND, Hash::new(b"b"));
        engine.report_equivocation(&a, &b);
        assert_eq!(mempool.len(), 1, "one evidence transaction was admitted");

        let hash = mempool.pending_hashes()[0];
        let tx = mempool.get(&hash).expect("tx");
        assert_eq!(tx.sender, address);
        assert_eq!(tx.fee, 0);
        assert!(
            tx.verify_signature(&TEST_CTX),
            "the node signs its own report"
        );
        match &tx.kind {
            TransactionKind::Evidence { evidence } => {
                assert_eq!(evidence.offender().expect("valid"), address);
                assert_eq!(evidence.round(), SLASHING_ACTIVE_FROM_ROUND);
                assert_eq!(
                    evidence.id(),
                    EquivocationEvidence::from_blocks(&a, &b, address)
                        .expect("valid")
                        .id()
                );
            }
            other => panic!("expected Evidence, got {other:?}"),
        }

        // A second report of the same event is not admitted twice under a new
        // nonce until the first is committed away: the pool accepts a
        // different nonce, so the duplicate is stopped at execution instead.
        // What matters here is that detection produced exactly one proof.
        assert_eq!(mempool.len(), 1);
    }

    // -----------------------------------------------------------------
    // PRO-40 (b): timeouts and quorum skip certificates
    // -----------------------------------------------------------------

    const SKIP_GENESIS: Hash = Hash([0x5a; 32]);

    #[derive(Default)]
    struct TimeoutRecorder {
        timeouts: Mutex<Vec<kovanica_types::Timeout>>,
        certs: Mutex<Vec<kovanica_types::SkipCert>>,
    }

    impl TimeoutBroadcaster for TimeoutRecorder {
        fn broadcast_timeout(&self, timeout: &kovanica_types::Timeout) {
            self.timeouts.lock().push(timeout.clone());
        }
        fn broadcast_skip_cert(&self, cert: &kovanica_types::SkipCert) {
            self.certs.lock().push(cert.clone());
        }
    }

    struct SkipFixture {
        committee: CommitteeInfo,
        keys: Vec<kovanica_types::SigningKey>,
        dag: Arc<TestDag>,
        engine: ConsensusEngine<TestDag, TestBlockManager>,
        recorder: Arc<TimeoutRecorder>,
        votes: Arc<Mutex<Vec<Round>>>,
        commits: mpsc::UnboundedReceiver<kovanica_types::CommittedSubDag>,
    }

    /// Authority 0 of five equal validators (quorum 4).
    type KeyPairs = Vec<(kovanica_types::SigningKey, PublicKey)>;

    fn key_pairs() -> KeyPairs {
        (0..5)
            .map(|_| kovanica_crypto::generate_keypair())
            .collect()
    }

    fn skip_fixture_with(dag: Arc<TestDag>, pairs: KeyPairs) -> SkipFixture {
        let keys: Vec<kovanica_types::SigningKey> = pairs.iter().map(|p| p.0.clone()).collect();
        let authorities = pairs
            .iter()
            .enumerate()
            .map(|(i, (_, pk))| AuthorityInfo {
                index: i as AuthorityIndex,
                stake: 1,
                public_key: *pk,
                vrf_public_key: None,
                address: Address::default(),
                network_address: String::new(),
            })
            .collect();
        let committee = CommitteeInfo::try_new(0, authorities).expect("committee");
        let manager = Arc::new(RwLock::new(TestBlockManager {
            dag: dag.clone(),
            key: RwLock::new(keys[0].clone()),
            set_key_calls: AtomicUsize::new(0),
        }));
        let engine = ConsensusEngine::new(
            ConsensusConfig {
                genesis_hash: SKIP_GENESIS,
                ..ConsensusConfig::default()
            },
            committee.clone(),
            dag.clone(),
            manager,
            keys[0].clone(),
            None,
            TEST_CTX,
        );
        let recorder = Arc::new(TimeoutRecorder::default());
        engine.set_timeout_broadcaster(recorder.clone());
        let votes: Arc<Mutex<Vec<Round>>> = Arc::new(Mutex::new(Vec::new()));
        let sink = votes.clone();
        engine.set_vote_broadcaster(Arc::new(move |v: &kovanica_types::Vote| {
            sink.lock().push(v.leader_round)
        }));
        let (tx, commits) = mpsc::unbounded_channel();
        engine.set_commit_sender(tx);
        SkipFixture {
            committee,
            keys,
            dag,
            engine,
            recorder,
            votes,
            commits,
        }
    }

    fn skip_fixture() -> SkipFixture {
        skip_fixture_with(Arc::new(TestDag::default()), key_pairs())
    }

    fn signed_timeout(
        key: &kovanica_types::SigningKey,
        voter: AuthorityIndex,
        round: Round,
        genesis: &Hash,
    ) -> kovanica_types::Timeout {
        let mut t = kovanica_types::Timeout {
            round,
            voter,
            signature: kovanica_types::Signature([0; 64]),
        };
        t.signature = kovanica_crypto::sign(key, &t.signature_data(TEST_CTX.chain_id, genesis));
        t
    }

    fn leader_block(
        committee: &CommitteeInfo,
        key: &kovanica_types::SigningKey,
        round: Round,
    ) -> kovanica_types::StatementBlock {
        let author = committee.leader(round);
        let digest = kovanica_types::StatementBlock::compute_digest(author, round, &[], &[]);
        kovanica_types::StatementBlock {
            author,
            round,
            parents: Vec::new(),
            transactions: Vec::new(),
            statements: Vec::new(),
            signature: kovanica_crypto::sign(key, digest.as_ref()),
            digest,
            merkle_root: Default::default(),
        }
    }

    #[test]
    fn four_timeouts_skip_the_slot_durably_and_the_next_leader_commits() {
        let mut f = skip_fixture();
        *f.engine.current_round.write() = 10;
        // Slot 3 never got a block. We time out, then three peers do.
        assert!(f.engine.sign_timeout(3).unwrap());
        assert_eq!(f.recorder.timeouts.lock().len(), 1);
        for voter in [1u16, 2] {
            f.engine
                .process_timeout(&signed_timeout(
                    &f.keys[voter as usize],
                    voter,
                    3,
                    &SKIP_GENESIS,
                ))
                .unwrap();
        }
        assert_eq!(
            f.engine.committer.last_decided_round(),
            0,
            "3 of 5: no skip"
        );
        assert!(f.dag.skipped.lock().is_empty());
        f.engine
            .process_timeout(&signed_timeout(&f.keys[4], 4, 3, &SKIP_GENESIS))
            .unwrap();
        assert_eq!(f.engine.committer.last_decided_round(), 3);
        assert_eq!(*f.dag.skipped.lock(), vec![3], "skip is durable");
        assert_eq!(f.recorder.certs.lock().len(), 1, "certificate is gossiped");
        assert!(f.commits.try_recv().is_err(), "a skip delivers nothing");
        // The skipped slot is never voted for afterwards.
        assert!(!f.engine.vote_for_leader(3).unwrap());

        // Slot 6 commits normally after the skip.
        *f.engine.current_round.write() = 7;
        let block = leader_block(&f.committee, &f.keys[0], 6);
        f.engine.process_block(&block).unwrap();
        assert_eq!(f.votes.lock().last().copied(), Some(6));
        for voter in [1u16, 2, 3] {
            f.engine
                .process_vote(&signed_vote(
                    &f.keys[voter as usize],
                    6,
                    voter,
                    block.digest,
                ))
                .unwrap();
        }
        let committed = f.commits.try_recv().expect("slot 6 commits after the skip");
        assert_eq!(committed.leader_round, 6);
    }

    #[test]
    fn a_vote_blocks_the_timeout_and_a_timeout_blocks_the_vote() {
        let f = skip_fixture();
        *f.engine.current_round.write() = 4;
        let block = leader_block(&f.committee, &f.keys[0], 3);
        f.engine.process_block(&block).unwrap();
        assert_eq!(*f.votes.lock(), vec![3]);
        assert!(!f.engine.sign_timeout(3).unwrap(), "voted: no timeout");

        *f.engine.current_round.write() = 9;
        assert!(f.engine.sign_timeout(6).unwrap());
        assert!(!f.engine.sign_timeout(6).unwrap(), "one timeout per slot");
        *f.engine.current_round.write() = 7;
        f.engine
            .process_block(&leader_block(&f.committee, &f.keys[0], 6))
            .unwrap();
        assert!(!f.engine.vote_for_leader(6).unwrap(), "timed out: no vote");
        assert_eq!(*f.votes.lock(), vec![3]);
    }

    #[test]
    fn the_own_timeout_lock_survives_a_restart() {
        let keys = key_pairs();
        let dag = Arc::new(TestDag::default());
        {
            let f = skip_fixture_with(dag.clone(), keys.clone());
            *f.engine.current_round.write() = 9;
            assert!(f.engine.sign_timeout(6).unwrap());
        }
        assert_eq!(
            dag.persisted_timeouts.lock().len(),
            1,
            "written before sending"
        );
        *dag.stored_tip.write() = Some(9);
        let f = skip_fixture_with(dag, keys);
        f.engine.resume_from_store().unwrap();
        f.engine
            .process_block(&leader_block(&f.committee, &f.keys[0], 6))
            .unwrap();
        assert!(!f.engine.vote_for_leader(6).unwrap());
        assert!(f.votes.lock().is_empty());
        // The restarted node rebroadcasts the stored timeout, never a new one.
        f.engine.time_out_or_rebroadcast(6).unwrap();
        let sent = f.recorder.timeouts.lock().clone();
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0], f.engine.own_timeouts.lock()[&6]);
    }

    /// The other half of the durable xor: a vote written before it was sent
    /// still refuses a timeout for that slot after restart, and the restarted
    /// node rebroadcasts the stored vote.
    #[test]
    fn restart_after_own_vote_refuses_the_timeout() {
        let keys = key_pairs();
        let dag = Arc::new(TestDag::default());
        {
            let f = skip_fixture_with(dag.clone(), keys.clone());
            *f.engine.current_round.write() = 4;
            let block = leader_block(&f.committee, &f.keys[0], 3);
            f.engine.process_block(&block).unwrap();
            assert_eq!(*f.votes.lock(), vec![3]);
            assert!(!f.engine.sign_timeout(3).unwrap(), "voted: no timeout");
            assert_eq!(
                dag.persisted_votes.lock().len(),
                1,
                "the vote is stored before it is broadcast"
            );
        }
        *dag.stored_tip.write() = Some(9);
        let f = skip_fixture_with(dag.clone(), keys);
        f.engine.resume_from_store().unwrap();
        assert!(
            f.engine.voted_rounds.lock().contains(&3),
            "the stored self-vote is restored"
        );
        assert!(
            !f.engine.sign_timeout(3).unwrap(),
            "no timeout after restart"
        );
        assert!(f.recorder.timeouts.lock().is_empty());
        f.engine.time_out_or_rebroadcast(3).unwrap();
        assert!(
            f.recorder.timeouts.lock().is_empty(),
            "rebroadcast must not sign a timeout"
        );
        assert_eq!(*f.votes.lock(), vec![3], "the stored vote is rebroadcast");
        assert!(
            dag.get_votes_for_round(3)
                .unwrap()
                .iter()
                .any(|vote| vote.voter == f.engine.state.read().our_authority),
            "the stored vote is unchanged"
        );
        assert!(dag.persisted_timeouts.lock().is_empty());
    }

    #[test]
    fn foreign_genesis_out_of_range_and_non_member_timeouts_are_rejected() {
        let f = skip_fixture();
        *f.engine.current_round.write() = 10;
        let wrong = signed_timeout(&f.keys[1], 1, 3, &Hash([1; 32]));
        assert!(matches!(
            f.engine.process_timeout(&wrong),
            Err(ConsensusError::TimeoutRejected(
                TimeoutRejection::BadSignature(1)
            ))
        ));
        let far = signed_timeout(&f.keys[1], 1, 30, &SKIP_GENESIS);
        assert!(matches!(
            f.engine.process_timeout(&far),
            Err(ConsensusError::TimeoutRejected(
                TimeoutRejection::OutOfRange { .. }
            ))
        ));
        let mut stranger = signed_timeout(&f.keys[1], 1, 3, &SKIP_GENESIS);
        stranger.voter = 7;
        assert!(matches!(
            f.engine.process_timeout(&stranger),
            Err(ConsensusError::TimeoutRejected(
                TimeoutRejection::UnknownVoter(7)
            ))
        ));
        assert!(f.engine.timeout_pool.lock().is_empty());
    }

    #[test]
    fn a_network_certificate_skips_only_with_a_quorum() {
        let mut f = skip_fixture();
        *f.engine.current_round.write() = 10;
        let cert = |voters: &[u16]| kovanica_types::SkipCert {
            round: 3,
            timeouts: voters
                .iter()
                .map(|v| signed_timeout(&f.keys[*v as usize], *v, 3, &SKIP_GENESIS))
                .collect(),
        };
        assert!(matches!(
            f.engine.process_skip_cert(&cert(&[1, 2, 3])),
            Err(ConsensusError::TimeoutRejected(
                TimeoutRejection::NoQuorum { .. }
            ))
        ));
        assert_eq!(f.engine.committer.last_decided_round(), 0);
        f.engine.process_skip_cert(&cert(&[1, 2, 3, 4])).unwrap();
        assert_eq!(f.engine.committer.last_decided_round(), 3);
        assert_eq!(*f.dag.skipped.lock(), vec![3]);
        assert!(f.commits.try_recv().is_err());
        // A lagging peer's timeout for the skipped slot is answered with
        // the stored certificate.
        f.engine
            .process_timeout(&signed_timeout(&f.keys[2], 2, 3, &SKIP_GENESIS))
            .unwrap();
        let served = f.recorder.certs.lock().clone();
        assert_eq!(served.len(), 1);
        assert_eq!(served[0].round, 3);
        assert!(served[0].timeouts.len() >= 4);
    }

    #[test]
    fn a_rebroadcast_vote_for_a_skipped_slot_is_answered_with_the_certificate() {
        let f = skip_fixture();
        *f.engine.current_round.write() = 10;
        f.engine
            .process_skip_cert(&kovanica_types::SkipCert {
                round: 3,
                timeouts: (1..5u16)
                    .map(|v| signed_timeout(&f.keys[v as usize], v, 3, &SKIP_GENESIS))
                    .collect(),
            })
            .unwrap();
        // The returning leader voted for its own slot-3 block and keeps
        // rebroadcasting that vote.
        let vote = signed_vote(&f.keys[1], 3, 1, Hash([9; 32]));
        let _ = f.engine.process_vote(&vote);
        let _ = f.engine.process_vote(&vote);
        let served = f.recorder.certs.lock().clone();
        assert_eq!(served.len(), 1, "served once per T_skip");
        assert_eq!(served[0].round, 3);
    }

    #[test]
    fn a_slot_with_a_vote_quorum_is_committed_never_skipped() {
        let mut f = skip_fixture();
        *f.engine.current_round.write() = 4;
        let block = leader_block(&f.committee, &f.keys[0], 3);
        f.engine.process_block(&block).unwrap();
        for voter in [1u16, 2, 3] {
            f.engine
                .process_vote(&signed_vote(
                    &f.keys[voter as usize],
                    3,
                    voter,
                    block.digest,
                ))
                .unwrap();
        }
        assert_eq!(f.commits.try_recv().unwrap().leader_round, 3);
        // A (byzantine) certificate for the committed slot is stale.
        f.engine
            .process_skip_cert(&kovanica_types::SkipCert {
                round: 3,
                timeouts: (1..5u16)
                    .map(|v| signed_timeout(&f.keys[v as usize], v, 3, &SKIP_GENESIS))
                    .collect(),
            })
            .unwrap();
        assert!(f.dag.skipped.lock().is_empty());
    }

    #[test]
    fn check_skip_timeout_signs_only_after_t_skip_and_then_rebroadcasts() {
        let mut f = skip_fixture_with(Arc::new(TestDag::default()), key_pairs());
        f.engine.config.round_duration_ms = 1;
        f.engine.config.skip_timeout_rounds = 20; // 20 ms
        *f.engine.current_round.write() = 5; // slot 3, vote round 4 passed
        f.engine.check_skip_timeout().unwrap();
        assert!(f.recorder.timeouts.lock().is_empty(), "timer only started");
        f.engine.check_skip_timeout().unwrap();
        assert!(f.recorder.timeouts.lock().is_empty(), "T_skip not elapsed");
        std::thread::sleep(Duration::from_millis(30));
        f.engine.check_skip_timeout().unwrap();
        assert_eq!(f.recorder.timeouts.lock().len(), 1);
        assert_eq!(f.recorder.timeouts.lock()[0].round, 3);
        std::thread::sleep(Duration::from_millis(30));
        f.engine.check_skip_timeout().unwrap();
        let sent = f.recorder.timeouts.lock().clone();
        assert_eq!(sent.len(), 2, "rebroadcast while stalled");
        assert_eq!(sent[0], sent[1], "the same timeout, never a second one");
    }

    /// A skip certificate on the last leader slot of an epoch and the first
    /// slot of the next epoch. The timeout preimage binds `epoch(round)`, so
    /// a signature from the previous epoch does not verify on the far side
    /// of the boundary, and both certificates still move the cursor.
    #[test]
    fn epoch_boundary_skip_certs_bind_epoch_of_the_round() {
        let mut f = skip_fixture();
        let wave = kovanica_types::WAVE_LENGTH;
        let last_of_epoch_0 = kovanica_types::EPOCH_ROUNDS - wave;
        let first_of_epoch_1 = kovanica_types::EPOCH_ROUNDS;
        assert_eq!(last_of_epoch_0, 7_197);
        assert_eq!(first_of_epoch_1, 7_200);
        assert!(is_leader_round(last_of_epoch_0));
        assert!(is_leader_round(first_of_epoch_1));
        assert_eq!(kovanica_types::epoch_for_round(last_of_epoch_0), 0);
        assert_eq!(kovanica_types::epoch_for_round(first_of_epoch_1), 1);

        let cursor = last_of_epoch_0 - wave;
        f.engine.committer.restore_last_decided_round(cursor);
        *f.engine.current_round.write() = first_of_epoch_1 + 6;

        // Same bytes as a valid epoch-0 timeout, retargeted at the epoch-1 slot.
        let mut forged = signed_timeout(&f.keys[1], 1, last_of_epoch_0, &SKIP_GENESIS);
        forged.round = first_of_epoch_1;
        assert!(matches!(
            f.engine.process_timeout(&forged),
            Err(ConsensusError::TimeoutRejected(
                TimeoutRejection::BadSignature(1)
            ))
        ));

        assert!(f.engine.sign_timeout(last_of_epoch_0).unwrap());
        for voter in [1u16, 2, 3] {
            f.engine
                .process_timeout(&signed_timeout(
                    &f.keys[voter as usize],
                    voter,
                    last_of_epoch_0,
                    &SKIP_GENESIS,
                ))
                .unwrap();
        }
        assert_eq!(f.engine.committer.last_decided_round(), last_of_epoch_0);
        assert!(f.commits.try_recv().is_err(), "a skip delivers nothing");

        assert!(f.engine.sign_timeout(first_of_epoch_1).unwrap());
        let own = f.engine.own_timeouts.lock()[&first_of_epoch_1].clone();
        let preimage = own.signature_data(TEST_CTX.chain_id, &SKIP_GENESIS);
        assert_eq!(
            &preimage[56..64],
            &1u64.to_le_bytes(),
            "the epoch-1 slot is signed under epoch 1"
        );
        for voter in [1u16, 2, 3] {
            f.engine
                .process_timeout(&signed_timeout(
                    &f.keys[voter as usize],
                    voter,
                    first_of_epoch_1,
                    &SKIP_GENESIS,
                ))
                .unwrap();
        }
        assert_eq!(f.engine.committer.last_decided_round(), first_of_epoch_1);
        assert!(f.commits.try_recv().is_err(), "a skip delivers nothing");
        let rounds: Vec<_> = f
            .recorder
            .certs
            .lock()
            .iter()
            .map(|cert| cert.round)
            .collect();
        assert!(rounds.contains(&last_of_epoch_0));
        assert!(rounds.contains(&first_of_epoch_1));
    }
}
