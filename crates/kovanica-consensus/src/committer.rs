//! Commit logic (Base + Universal Committer).
//!
#![allow(missing_docs)]
//! Implements Mysticeti-style committer with direct/indirect commit rules
//! for wave-based uncertified DAG consensus.

use crate::engine::{DagStoreTrait, VoteRejection};
use crate::ghostdag_scoped::ColouringResult;
use crate::is_leader_round;
use crate::metrics::{record_pruned_blocks, record_pruned_waves};
use crate::mysticghost::{order_committed_wave, MysticGhostConfig, MysticGhostOrder};
use crate::types::{CommitResult, CommitteeInfo, LeaderInfo, LeaderStatus};
use kovanica_types::{
    block::StatementBlock, hash::Hash, AuthorityIndex, CommittedSubDag, Round, WAVE_LENGTH,
};
use parking_lot::{Mutex, RwLock};
use std::collections::{BTreeSet, HashMap, HashSet};
use std::sync::Arc;
use tracing::{debug, info, warn};

/// Basic committer that tracks leader decisions.
pub struct BaseCommitter {
    committee: CommitteeInfo,
}

impl BaseCommitter {
    /// Create a new base committer.
    pub fn new(committee: CommitteeInfo) -> Self {
        Self { committee }
    }

    /// Try to make a direct decision on a leader round.
    ///
    /// In Mysticeti, a leader is directly decided if it receives votes from
    /// a quorum (2f+1 stake) of validators in the next round.
    pub fn try_direct_decide(
        &self,
        dag_store: &dyn DagStoreTrait,
        leader_info: &LeaderInfo,
    ) -> LeaderStatus {
        if leader_info.round == 0 {
            return LeaderStatus::Undecided;
        }

        let votes = &leader_info.votes;
        let leader_hash = leader_info.block_hash.as_ref();

        // Check if we have quorum (2f+1 stake) of votes *for the leader block*
        if self.committee.has_quorum(votes, leader_hash) {
            debug!(
                "Direct commit: leader round {} author {} has quorum ({} votes)",
                leader_info.round,
                leader_info.author,
                votes.len()
            );
            return LeaderStatus::Commit;
        }

        // Check if we have validity threshold but not quorum - could be skip
        if self.committee.has_validity(votes, leader_hash) {
            debug!(
                "Leader round {} author {} has validity but not quorum",
                leader_info.round, leader_info.author
            );
        }

        LeaderStatus::Undecided
    }

    /// Try to make an indirect decision on a leader round.
    ///
    /// In Mysticeti, a leader can be indirectly decided if a later leader
    /// in the same wave is directly committed, or if a leader is skipped
    /// by a later committed leader.
    pub fn try_indirect_decide(
        &self,
        dag_store: &dyn DagStoreTrait,
        leader_info: &LeaderInfo,
        decided_leaders: &HashMap<Round, LeaderInfo>,
    ) -> LeaderStatus {
        let wave = self.wave_of(leader_info.round);
        let wave_start = wave * kovanica_types::WAVE_LENGTH;
        let wave_end = wave_start + kovanica_types::WAVE_LENGTH - 1;

        // Check leaders in the same wave after this one
        for round in (leader_info.round + 1)..=wave_end {
            if let Some(later_leader) = decided_leaders.get(&round) {
                if later_leader.status == LeaderStatus::Commit {
                    // If a later leader in the same wave is committed,
                    // this leader is indirectly decided (skip or commit based on connectivity)
                    if self.has_path(dag_store, leader_info, later_leader) {
                        debug!(
                            "Indirect commit: leader round {} connected to committed leader round {}",
                            leader_info.round, later_leader.round
                        );
                        return LeaderStatus::Commit;
                    } else {
                        debug!(
                            "Indirect skip: leader round {} not connected to committed leader round {}",
                            leader_info.round, later_leader.round
                        );
                        return LeaderStatus::Skip;
                    }
                }
            }
        }

        LeaderStatus::Undecided
    }

    /// Check if there's a causal path from one leader to another.
    pub(crate) fn has_path(
        &self,
        dag_store: &dyn DagStoreTrait,
        from: &LeaderInfo,
        to: &LeaderInfo,
    ) -> bool {
        if let Some(from_hash) = from.block_hash {
            if let Some(to_hash) = to.block_hash {
                match dag_store.get_ancestors(&to_hash, from.round) {
                    Ok(ancestors) => ancestors.contains(&from_hash),
                    Err(_) => false,
                }
            } else {
                false
            }
        } else {
            false
        }
    }

    fn wave_of(&self, round: Round) -> u64 {
        round / kovanica_types::WAVE_LENGTH
    }
}

/// The first leader slot strictly above `round`.
///
/// Leader slots are the rounds at offset 0 of a wave (`round % WAVE_LENGTH ==
/// 0`), and round 0 is genesis, so the first slot is `WAVE_LENGTH`.
pub(crate) fn next_leader_slot(round: Round) -> Round {
    (round / WAVE_LENGTH + 1).saturating_mul(WAVE_LENGTH)
}

/// Helper: registered leaders strictly after `round`, in round order.
trait RangeAfter {
    fn range_after(&self, round: Round) -> Vec<LeaderInfo>;
}

impl RangeAfter for HashMap<Round, LeaderInfo> {
    fn range_after(&self, round: Round) -> Vec<LeaderInfo> {
        let mut later: Vec<LeaderInfo> =
            self.values().filter(|l| l.round > round).cloned().collect();
        later.sort_unstable_by_key(|l| l.round);
        later
    }
}

/// Causal history of `leader` that has NOT been delivered by an earlier
/// commit.
///
/// "Already committed" is derived only from the durable decided-leader index:
/// a block is committed iff it is a decided leader of a round strictly below
/// `leader.round`, or in such a leader's causal history. The result therefore
/// depends only on the persisted DAG + decided index, so the live committer
/// and restart recovery (kovanica-node `recover_committed_subdags`) produce the
/// same batch and no block is delivered twice across commits.
///
/// Returned in `get_ancestors` order (the linearizer canonicalises order);
/// excludes `leader` itself.
///
/// Correctness condition (pruning): pruning must be downward-closed by round.
/// If any block of round `r` is deleted, every block of round `<= r` must be
/// deleted too (as `prune_waves_before` / `prune_below` do). Then every
/// still-stored ancestor of an earlier decided leader is reachable from that
/// leader via stored parent edges, or that leader's whole stored history is
/// gone. A deletion that leaves a gap (e.g. `prune_non_blue` removing a block
/// while lower-round blocks of the same history remain) can hide still-stored
/// committed blocks behind the gap; they would then be re-delivered.
///
/// Note (follow-up): caching the committed set incrementally (in-memory or
/// persisted) would avoid re-walking earlier leaders' histories on each
/// commit (O(sum of earlier histories)); correctness currently relies on the
/// deterministic decided-index walk above.
pub fn uncommitted_history<D: DagStoreTrait + ?Sized>(
    dag_store: &D,
    leader: &StatementBlock,
) -> Result<Vec<StatementBlock>, kovanica_dag::DagStoreError> {
    let mut committed: HashSet<Hash> = HashSet::new();
    if leader.round > 0 {
        for round in dag_store.get_decided_rounds(leader.round - 1)? {
            if round >= leader.round {
                continue;
            }
            for prev in dag_store.get_decided_leaders(round)? {
                if prev == leader.digest || !committed.insert(prev) {
                    continue;
                }
                // NotFound-tolerant: a pruned previous leader contributes
                // nothing (its history is pruned too).
                committed.extend(dag_store.get_ancestors(&prev, 0)?);
            }
        }
    }

    // A certified catch-up anchor means execution state already includes every
    // block at or below that leader round. Those ancestors must not be
    // delivered again when the next leader after the anchor commits.
    let anchor_round = dag_store.certified_catchup_anchor()?;

    let mut history = Vec::new();
    for hash in dag_store.get_ancestors(&leader.digest, 0)? {
        if hash == leader.digest || committed.contains(&hash) {
            continue;
        }
        let block = dag_store.get_block(&hash)?;
        if anchor_round.is_some_and(|anchor| block.round <= anchor) {
            continue;
        }
        history.push(block);
    }
    Ok(history)
}

/// Universal committer that also handles indirect decisions.
pub struct UniversalCommitter {
    base: BaseCommitter,
    /// Whether to use MysticGhost (scoped GHOSTDAG) ordering for committed waves.
    use_mysticghost: bool,
    /// Number of waves to keep before pruning old waves.
    prune_window_waves: u64,
    /// Last decided round.
    last_decided_round: RwLock<Round>,
    /// Map of leader info by round.
    leaders: RwLock<HashMap<Round, LeaderInfo>>,
    /// Map of decided leaders.
    decided_leaders: RwLock<HashMap<Round, LeaderInfo>>,
    /// Serializes durable commit attempts and their in-memory publication.
    durable_commit_lock: Mutex<()>,
    /// Leader slots above the cursor with a verified skip certificate
    /// (PRO-40 (b)). Applied in slot order by
    /// [`Self::try_skip_and_mark_durable`].
    skip_certified: RwLock<BTreeSet<Round>>,
}

impl UniversalCommitter {
    /// Create a new universal committer.
    pub fn new(committee: CommitteeInfo, use_mysticghost: bool, prune_window_waves: u64) -> Self {
        Self {
            base: BaseCommitter::new(committee),
            use_mysticghost,
            prune_window_waves,
            last_decided_round: RwLock::new(0),
            leaders: RwLock::new(HashMap::new()),
            decided_leaders: RwLock::new(HashMap::new()),
            durable_commit_lock: Mutex::new(()),
            skip_certified: RwLock::new(BTreeSet::new()),
        }
    }

    /// Explicitly register a skip for a leader (timeout resolution).
    ///
    /// **Test-only since PRO-35.** The node no longer records Skip decisions: a
    /// node-local skip let other nodes commit the same round, so two nodes
    /// produced different committed-leader sequences at the same height (fork).
    /// `try_commit_with_leader` now stalls instead. Kept so the regression
    /// tests can still build the "a skip was decided" state and prove the
    /// properties the removed paths violated.
    #[cfg(test)]
    pub fn register_skip(&self, round: Round, author: AuthorityIndex) {
        let info = LeaderInfo {
            round,
            author,
            block_hash: None,
            status: LeaderStatus::Skip,
            votes: HashMap::new(),
        };
        self.update_leader(info.clone());
        // Ensure decided map reflects Skip (persisted in decided map per spec).
        //
        // Deliberately does NOT advance `last_decided_round`: a timeout skip is
        // provisional and must not move the commit cursor past earlier pending
        // leaders or permanently disqualify a later block that reaches quorum
        // for the same round.
        //
        // Never overwrite an already-committed decision for this round: the
        // timeout can fire after the round was durably committed and must not
        // rewrite history to `Skip`.
        let mut decided = self.decided_leaders.write();
        decided.entry(round).or_insert(info);
    }

    /// Update leader information for a round.
    /// Deterministic tie-break (fork): same (round, author) with different
    /// digest keeps the lexicographically smaller digest; larger rejected.
    ///
    /// A hash-less record (a timeout placeholder) never replaces a record that
    /// already carries a leader block, whichever author it names. Otherwise a
    /// node whose leader schedule diverges from its peers (PRO-7) could erase a
    /// block it already holds when its own slot deadline for that round expires,
    /// and — now that `try_commit_with_leader` stalls at the first undecided
    /// round instead of skipping it (PRO-35) — it could never commit again.
    pub fn update_leader(&self, leader_info: LeaderInfo) {
        let mut leaders = self.leaders.write();
        let key = leader_info.round;
        if let Some(existing) = leaders.get(&key) {
            if leader_info.block_hash.is_none() && existing.block_hash.is_some() {
                return;
            }
            if existing.author == leader_info.author {
                match (
                    existing.block_hash.as_ref(),
                    leader_info.block_hash.as_ref(),
                ) {
                    (Some(old_hash), Some(new_hash)) => {
                        if new_hash.0 < old_hash.0 {
                            leaders.insert(key, leader_info);
                        }
                        return;
                    }
                    (None, Some(_)) => {
                        leaders.insert(key, leader_info);
                        return;
                    }
                    (Some(_), None) => return,
                    (None, None) => {
                        if leader_info.status == LeaderStatus::Skip
                            && existing.status != LeaderStatus::Skip
                        {
                            leaders.insert(key, leader_info);
                        }
                        return;
                    }
                }
            }
        }
        leaders.insert(key, leader_info);
    }

    /// Mark a leader as decided.
    fn mark_decided(&self, round: Round, leader_info: LeaderInfo) {
        // S5: Assert that we only advance the commit cursor on Commit.
        // Skip decisions do NOT advance last_decided_round — they are only
        // recorded in the decided map. This prevents the fork where a local
        // timeout skip on round R and a later commit on round R+3 end up at
        // the same committed_leader_height (PRO-35).
        debug_assert!(
            leader_info.status == LeaderStatus::Commit,
            "mark_decided must only be called with Commit status; Skip does not advance the cursor"
        );
        let mut decided = self.decided_leaders.write();
        decided.insert(round, leader_info);
        let mut last = self.last_decided_round.write();
        if round > *last {
            *last = round;
        }
    }

    /// Get the last decided round.
    pub fn last_decided_round(&self) -> Round {
        *self.last_decided_round.read()
    }

    /// Get leader info for a round.
    pub fn get_leader(&self, round: Round) -> Option<LeaderInfo> {
        self.leaders.read().get(&round).cloned()
    }

    /// Whether `round` already has a decision recorded locally (committed or
    /// skipped).
    ///
    /// A decided round is final on this node: once the committer has written a
    /// decision, the commit cursor will never revisit that round. Nodes must
    /// therefore not cast fresh votes for a decided round — doing so can only
    /// mint a certificate that some lagging peer will act on while this node
    /// (and every other already-decided node) will not, producing divergent
    /// committed sequences. See `late_join_integration`.
    pub fn is_decided(&self, round: Round) -> bool {
        self.decided_leaders.read().contains_key(&round)
    }

    /// Get all decided leaders.
    pub fn get_decided_leaders(&self) -> HashMap<Round, LeaderInfo> {
        self.decided_leaders.read().clone()
    }

    /// Get all leader info.
    pub fn get_all_leaders(&self) -> HashMap<Round, LeaderInfo> {
        self.leaders.read().clone()
    }

    /// Get all decided leaders.
    pub fn get_all_decided_leaders(&self) -> HashMap<Round, LeaderInfo> {
        self.decided_leaders.read().clone()
    }

    /// Add a vote to a leader.
    pub fn add_vote(&self, leader_round: Round, voter: AuthorityIndex, vote_hash: Hash) -> bool {
        let mut leaders = self.leaders.write();
        if let Some(leader_info) = leaders.get_mut(&leader_round) {
            leader_info.votes.insert(voter, vote_hash);

            // Check if we now have quorum of votes *for the leader block*
            if self
                .base
                .committee
                .has_quorum(&leader_info.votes, leader_info.block_hash.as_ref())
            {
                leader_info.status = LeaderStatus::Commit;
                return true;
            }
        }
        false
    }

    /// Record an already-authenticated vote, rejecting it if no leader block
    /// is registered for `leader_round`, if `vote_hash` does not match that
    /// block, or if `voter` has already voted for the round. The checks and
    /// the insert happen under one write lock, so concurrent duplicates are
    /// counted at most once. Returns whether the leader now has a quorum.
    pub fn add_verified_vote(
        &self,
        leader_round: Round,
        voter: AuthorityIndex,
        vote_hash: Hash,
    ) -> Result<bool, VoteRejection> {
        let mut leaders = self.leaders.write();
        let leader_info = leaders
            .get_mut(&leader_round)
            .ok_or(VoteRejection::UnknownLeaderRound(leader_round))?;
        if leader_info.block_hash != Some(vote_hash) {
            return Err(VoteRejection::LeaderHashMismatch(leader_round));
        }
        if leader_info.votes.contains_key(&voter) {
            return Err(VoteRejection::Duplicate {
                round: leader_round,
                voter,
            });
        }
        leader_info.votes.insert(voter, vote_hash);
        if self
            .base
            .committee
            .has_quorum(&leader_info.votes, leader_info.block_hash.as_ref())
        {
            leader_info.status = LeaderStatus::Commit;
            return Ok(true);
        }
        Ok(false)
    }

    /// Decide (commit or skip) any still-undecided leaders *earlier in the
    /// same wave* as `commit_round`, using the indirect rule.
    ///
    /// In Mysticeti a leader that is committed (directly or indirectly) makes
    /// the earlier leaders of its wave decidable: each is committed when it is
    /// causally connected to the committed leader, skipped otherwise. Without
    /// this sweep the indirect rule is unreachable, because the main
    /// `try_commit` walk only ever looks at rounds *after* the last decided
    /// round and `try_indirect_decide` only finds *later* decided leaders in
    /// the wave.
    ///
    /// **PRO-35 fix**: With WAVE_LENGTH=3 there is exactly one leader per wave,
    /// so this sweep is a no-op (there are no earlier leaders in the same wave).
    /// The cross-wave skip path was removed from `try_commit_with_leader`. This
    /// function is kept as a no-op for API compatibility.
    fn decide_earlier_in_wave<D: DagStoreTrait>(&self, _dag_store: &D, _commit_round: Round) {
        // No-op: WAVE_LENGTH=3 ⇒ exactly one leader per wave.
        // The cross-wave skip was removed to eliminate the fork (PRO-35).
    }

    /// Clean up old leader info to limit memory usage.
    ///
    /// Only records at or below the commit cursor may be dropped. A leader
    /// above `last_decided_round` is still undecided: the commit walk stalls on
    /// it, and dropping its record would turn the stall into a silent skip
    /// (the walk would then commit a later leader over a round that never got
    /// a quorum, at a moment that depends on this node's clock — the PRO-35
    /// fork class, PRO-40). Memory stays bounded by the length of a stall.
    pub fn cleanup_old_leaders(&self, cutoff: Round) {
        let last_decided = self.last_decided_round();
        let mut leaders = self.leaders.write();
        leaders.retain(|&round, _| round >= cutoff || round > last_decided);
    }

    /// Restore the commit cursor from the persisted decision index.
    ///
    /// The in-memory cursor starts at 0 on every boot. Without this a
    /// restarted node walks from round 0 with an empty leader map, so the
    /// first leader it hears about after the restart is the first candidate
    /// and every undecided slot in between is passed over silently. The
    /// cursor only moves forward.
    pub fn restore_last_decided_round(&self, round: Round) {
        let mut last = self.last_decided_round.write();
        if round > *last {
            *last = round;
        }
    }

    /// Advance the cursor to a certified catch-up anchor when one is ahead.
    ///
    /// Peers delete DAG blocks older than `prune_window_waves` (default 100
    /// waves, about 20 minutes). A node whose cursor is further back must
    /// otherwise hold a record for every leader slot from the cursor up
    /// ([`Self::try_commit_with_leader`]), and those blocks are gone, so it
    /// can never commit again. The anchor is a leader round a quorum of
    /// `KUNA/commit/v1` seals or a verified state-sync checkpoint has already
    /// committed. Slots at or below it are not walked.
    ///
    /// The cursor only moves forward. A round that is not a leader slot is
    /// ignored, so a bad anchor cannot land in the middle of a wave.
    pub fn catch_up_to_certified_anchor<D: DagStoreTrait>(
        &self,
        dag_store: &D,
    ) -> Result<bool, kovanica_dag::DagStoreError> {
        let Some(anchor) = dag_store.certified_catchup_anchor()? else {
            return Ok(false);
        };
        if anchor == 0 || !crate::is_leader_round(anchor) {
            return Ok(false);
        }
        let cursor = self.last_decided_round();
        if anchor <= cursor {
            return Ok(false);
        }
        info!(
            anchor,
            cursor, "catch-up anchor advances the commit cursor past pruned history"
        );
        self.restore_last_decided_round(anchor);
        Ok(true)
    }

    /// Record that `round` has a verified skip certificate (PRO-40 (b)).
    ///
    /// The caller has verified the certificate (`crate::skip`). Nothing moves
    /// here: the skip is applied by [`Self::try_skip_and_mark_durable`] once
    /// `round` is the first undecided slot, so skips and commits stay in slot
    /// order. A round at or below the cursor is ignored.
    pub fn record_skip_certificate(&self, round: Round) {
        if is_leader_round(round) && round > self.last_decided_round() {
            self.skip_certified.write().insert(round);
        }
    }

    /// Whether a verified skip certificate is held for `round`.
    pub fn has_skip_certificate(&self, round: Round) -> bool {
        self.skip_certified.read().contains(&round)
    }

    /// Durably skip the first undecided leader slot if it has a skip
    /// certificate (PRO-40 (b)). Returns the skipped round.
    ///
    /// This is the only path besides a commit that moves the cursor, and it
    /// needs a quorum certificate: no node passes over a slot on a local
    /// timeout. A slot that has its own vote quorum is committed, never
    /// skipped (with honest signers both cannot exist; this is defensive).
    ///
    /// The skip is written to the decided-round index as a decision with no
    /// leaders before the cursor moves, so a restart resumes after it and
    /// replay commits nothing for it. The skipped leader block, if any, stays
    /// in the DAG and is ordered into the next committed leader's sub-DAG.
    pub fn try_skip_and_mark_durable<D: DagStoreTrait>(
        &self,
        dag_store: &D,
    ) -> Result<Option<Round>, kovanica_dag::DagStoreError> {
        let _guard = self.durable_commit_lock.lock();
        let slot = next_leader_slot(self.last_decided_round());
        if !self.skip_certified.read().contains(&slot) {
            return Ok(None);
        }
        let existing = self.leaders.read().get(&slot).cloned();
        if let Some(info) = existing.as_ref() {
            if self.base.try_direct_decide(dag_store, info) == LeaderStatus::Commit {
                warn!(
                    round = slot,
                    "slot has both a vote quorum and a skip certificate; committing, not skipping"
                );
                return Ok(None);
            }
        }
        dag_store.mark_round_skipped(slot)?;
        let author = existing.as_ref().map(|l| l.author).unwrap_or_default();
        self.decided_leaders.write().insert(
            slot,
            LeaderInfo {
                round: slot,
                author,
                block_hash: existing.and_then(|l| l.block_hash),
                status: LeaderStatus::Skip,
                votes: HashMap::new(),
            },
        );
        {
            let mut last = self.last_decided_round.write();
            if slot > *last {
                *last = slot;
            }
        }
        {
            let mut certified = self.skip_certified.write();
            *certified = certified.split_off(&(slot + 1));
        }
        info!(
            round = slot,
            "leader slot skipped with a quorum certificate"
        );
        Ok(Some(slot))
    }

    /// Construct the next committed sub-DAG candidate without publishing it.
    /// Use [`Self::try_commit_and_mark_durable`] to persist and publish it.
    pub fn try_commit<D: DagStoreTrait>(&self, dag_store: &D) -> Option<CommittedSubDag> {
        self.try_commit_with_leader(dag_store)
            .map(|(subdag, _, _)| subdag)
    }

    /// Construct the next committed sub-DAG together with the registered
    /// leader record that established its eligibility and, on the MysticGhost
    /// path, the colouring result produced while building the sub-DAG.
    fn try_commit_with_leader<D: DagStoreTrait>(
        &self,
        dag_store: &D,
    ) -> Option<(CommittedSubDag, LeaderInfo, Option<ColouringResult>)> {
        // A joiner that learned a certified anchor while running (state sync
        // or a seal quorum) has to move the cursor before this walk. An
        // unreadable anchor fails closed: return nothing rather than commit
        // over a gap that should have been anchored.
        if let Err(e) = self.catch_up_to_certified_anchor(dag_store) {
            warn!(error = %e, "certified catch-up anchor unreadable; not committing");
            return None;
        }
        let last_decided = self.last_decided_round();
        let leaders = self.leaders.read().clone();
        let decided = self.decided_leaders.read().clone();

        // Walk the expected leader slots in round order, starting at the
        // first slot above the cursor. The walk stops at the first slot that
        // is not decided by its own quorum, and also at the first slot that
        // has **no record at all** (PRO-40): a missing record means this node
        // has not seen that leader yet (it restarted, joined late, or the
        // block never arrived), not that the round may be passed over.
        // Previously the candidates were `leaders.keys()`, so a round without
        // a record was skipped silently and a later leader with quorum was
        // committed over it.
        //
        // The walk visits at most the run of consecutive slots that have
        // records, so its cost stays proportional to the number of known
        // leaders, and there is no fixed look-ahead cap.
        let max_checked = leaders.keys().copied().max().unwrap_or(last_decided);
        let mut round = next_leader_slot(last_decided);
        while round <= max_checked {
            let slot = round;
            round = round.saturating_add(WAVE_LENGTH);

            // A round already decided must not be re-processed. A provisional
            // Skip entry, however, must not permanently disqualify a round
            // whose leader block later reaches quorum (register_skip no longer
            // advances the cursor), so only skip when no live block-bearing
            // leader is registered for that round.
            if decided.contains_key(&slot)
                && !leaders
                    .get(&slot)
                    .map(|l| l.block_hash.is_some())
                    .unwrap_or(false)
            {
                continue;
            }

            let Some(leader_info) = leaders.get(&slot) else {
                // Expected leader slot without any record: stall here.
                break;
            };

            // Try direct decision
            let direct_status = self.base.try_direct_decide(dag_store, leader_info);

            if direct_status == LeaderStatus::Commit {
                // Construct only; candidate-only callers do not publish it.
                return self
                    .build_committed_subdag(dag_store, leader_info)
                    .map(|(subdag, colouring)| (subdag, leader_info.clone(), colouring));
            }

            // `try_direct_decide` only ever returns Commit or Undecided (a
            // validity threshold without quorum is not a decision). The old
            // `direct_status == Skip` branch that called `mark_decided(Skip)`
            // was removed with PRO-35: it is the exact primitive that advanced
            // the commit cursor without a certificate. If a Skip ever appears
            // here it must stall like Undecided, never fall through.

            // Still undecided. A leader without its OWN direct quorum is never
            // committed (votes are not DAG references, so causal history is
            // not certificate proof). No commit may ever pass over an undecided
            // round leader — the chain stalls until quorum arrives.
            // Cross-wave skip and local timeout skip are REMOVED to eliminate
            // the fork (PRO-35). Liveness restoration requires a quorum-certified
            // skip (Tendermint-style timeout certificate), feasible at chain-4 reset.
            break;
        }

        None
    }

    /// Durably commit and publish the next eligible leader, if one is ready.
    ///
    /// The decision index is persisted before in-memory state is advanced. If
    /// persistence fails, the eligible leader remains available for retry.
    pub fn try_commit_and_mark_durable<D: DagStoreTrait>(
        &self,
        dag_store: &D,
    ) -> Result<Option<CommittedSubDag>, kovanica_dag::DagStoreError> {
        let _guard = self.durable_commit_lock.lock();
        let Some((subdag, mut decided_leader, colouring)) = self.try_commit_with_leader(dag_store)
        else {
            return Ok(None);
        };

        let leader_block = &subdag.leader;
        let metadata_matches = decided_leader.round == subdag.leader_round
            && decided_leader.author == subdag.leader_author
            && decided_leader.block_hash == Some(leader_block.digest)
            && leader_block.round == subdag.leader_round
            && leader_block.author == subdag.leader_author;
        if !metadata_matches {
            warn!(
                registered_round = decided_leader.round,
                registered_author = decided_leader.author,
                registered_digest = ?decided_leader.block_hash,
                subdag_round = subdag.leader_round,
                subdag_author = subdag.leader_author,
                subdag_digest = %leader_block.digest,
                block_round = leader_block.round,
                block_author = leader_block.author,
                "refusing to persist mismatched committed leader metadata"
            );
            return Ok(None);
        }

        // Persist the exact eligible leader selected above; never synthesize a
        // leader record from a caller-provided sub-DAG.
        // The decided-round mark and the committed leader height / last
        // committed leader are written atomically (both or neither), so a
        // crash between them cannot leave inconsistent durable state.
        dag_store.mark_decided_and_commit_leader(subdag.leader_round, &subdag.leader.digest)?;
        decided_leader.status = LeaderStatus::Commit;
        self.mark_decided(subdag.leader_round, decided_leader);

        // This existing same-wave bookkeeping is committed only after the
        // later leader's durable mark succeeded.
        self.decide_earlier_in_wave(dag_store, subdag.leader_round);

        // Pruning after successful commit
        let leader_wave = subdag.leader_round / kovanica_types::WAVE_LENGTH;

        // #13 (variant A): red mergeset blocks are NOT pruned here any more.
        // They are reported in `subdag.non_blue` (their transactions go back
        // to the mempool via `non_blue_transactions`) and are removed only by
        // the round-based pruning below.
        if self.use_mysticghost {
            if let Some(c) = colouring.as_ref() {
                crate::metrics::record_mergeset_size(c.blue.len());
            }
        }

        // Prune old waves (both MysticGhost and linearizer paths)
        match dag_store.prune_waves_before(leader_wave, self.prune_window_waves) {
            Ok(pruned) => {
                if pruned > 0 {
                    info!("Pruned {} blocks from waves before {}", pruned, leader_wave);
                    record_pruned_blocks(pruned);
                    record_pruned_waves(1); // One wave pruning event
                }
            }
            Err(e) => {
                warn!("Failed to prune old waves: {}", e);
            }
        }

        Ok(Some(subdag))
    }

    /// Build a committed sub-DAG from a leader and its causal history.
    ///
    /// On the MysticGhost path the colouring result produced while building
    /// the sub-DAG is returned alongside it so the caller can prune using the
    /// exact same blue set. The linearizer path returns `None` colouring.
    fn build_committed_subdag<D: DagStoreTrait>(
        &self,
        dag_store: &D,
        leader_info: &LeaderInfo,
    ) -> Option<(CommittedSubDag, Option<ColouringResult>)> {
        let leader_hash = leader_info.block_hash?;
        let leader_block = dag_store.get_block(&leader_hash).ok()?;

        if self.use_mysticghost {
            // MysticGhost path: use scoped GHOSTDAG colouring
            self.build_committed_subdag_mysticghost(dag_store, &leader_block, leader_info.round)
        } else {
            // Original linearizer path (bit-identical to current behaviour)
            self.build_committed_subdag_linearizer(dag_store, &leader_block)
                .map(|subdag| (subdag, None))
        }
    }

    /// Original linearizer path (Mysticeti).
    fn build_committed_subdag_linearizer<D: DagStoreTrait>(
        &self,
        dag_store: &D,
        leader_block: &StatementBlock,
    ) -> Option<CommittedSubDag> {
        // Only the not-yet-committed part of the leader's causal history.
        let history = uncommitted_history(dag_store, leader_block).ok()?;

        // Linearize the sub-DAG
        let linearizer = crate::linearizer::Linearizer::new();
        let subdag = linearizer.linearize(leader_block.clone(), history);

        Some(subdag)
    }

    /// MysticGhost path: scoped GHOSTDAG colouring of the mergeset.
    fn build_committed_subdag_mysticghost<D: DagStoreTrait>(
        &self,
        dag_store: &D,
        leader_block: &StatementBlock,
        leader_round: Round,
    ) -> Option<(CommittedSubDag, Option<ColouringResult>)> {
        // 1. Get mergeset hashes
        let mergeset_hashes = dag_store.mergeset(&leader_block.digest).ok()?;

        // 2. Get mergeset blocks
        let mergeset_blocks = dag_store.get_blocks(&mergeset_hashes).ok()?;

        // Record mergeset size metric
        crate::metrics::record_mergeset_size(mergeset_blocks.len());

        // 3. Get previous tips (decided leaders' blocks that are not ancestors
        //    of this leader and not the leader itself)
        let previous_tips = self
            .get_previous_tips(dag_store, &leader_block.digest)
            .ok()?;

        // 4. Configure MysticGhost
        let mg_config = MysticGhostConfig {
            enabled: true,
            k: 3,
            max_mergeset_blocks: 2_000,
        };

        // 5. Run MysticGhost ordering with timing
        let colouring_start = std::time::Instant::now();
        let result = order_committed_wave(&mg_config, &mergeset_blocks, &previous_tips);
        let colouring_duration = colouring_start.elapsed().as_secs_f64() * 1000.0;

        match result {
            MysticGhostOrder::Ghost { colouring } => {
                crate::metrics::record_colouring_duration_ms(colouring_duration, "success");
                // Use the blue-set order from GHOSTDAG
                let blue_ordered = colouring.blue_ordered();

                // Red mergeset blocks: reported, never executed as blocks.
                let non_blue = crate::non_blue::non_blue_refs(
                    &mergeset_blocks,
                    &colouring.blue,
                    &leader_block.digest,
                );

                // Build blocks in blue order, filtering to only those in mergeset
                let block_map: std::collections::HashMap<Hash, StatementBlock> =
                    mergeset_blocks.into_iter().map(|b| (b.digest, b)).collect();

                let mut ordered_blocks = Vec::new();
                for hash in blue_ordered {
                    if let Some(block) = block_map.get(&hash) {
                        ordered_blocks.push(block.clone());
                    }
                }

                // Ensure leader is included (should be blue)
                if !ordered_blocks
                    .iter()
                    .any(|b| b.digest == leader_block.digest)
                {
                    ordered_blocks.push(leader_block.clone());
                }

                Some((
                    CommittedSubDag {
                        blocks: ordered_blocks,
                        leader: leader_block.clone(),
                        leader_round,
                        leader_author: leader_block.author,
                        non_blue,
                    },
                    Some(colouring),
                ))
            }
            MysticGhostOrder::Fallback => {
                crate::metrics::record_colouring_duration_ms(colouring_duration, "fallback");
                // Fall back to original linearizer (no scoped colouring)
                self.build_committed_subdag_linearizer(dag_store, leader_block)
                    .map(|subdag| (subdag, None))
            }
        }
    }

    /// Get previous committed tips for MysticGhost colouring.
    ///
    /// Returns the decided leaders that are neither the leader being coloured
    /// nor ancestors of it. Leaders that are already in the leader's causal
    /// history must not be seeded as tips: doing so would count the leader
    /// against its own past and drive the scoped colouring to an empty blue
    /// set.
    ///
    /// M3: the ancestry walk is intentionally unbounded (`min_round = 0`).
    /// `prune_waves_before` deletes old waves, so the walk may encounter a
    /// parent whose block is gone; `DagStore::get_ancestors` is NotFound
    /// tolerant (it skips dangling edges) so pruning cannot turn this into an
    /// error. The same choice is mirrored in the node's
    /// `recover_committed_subdags` recovery path.
    fn get_previous_tips<D: DagStoreTrait>(
        &self,
        dag_store: &D,
        leader_hash: &Hash,
    ) -> Result<Vec<Hash>, kovanica_dag::DagStoreError> {
        let ancestors: HashSet<Hash> = dag_store
            .get_ancestors(leader_hash, 0)?
            .into_iter()
            .collect();
        let decided_rounds = dag_store.get_decided_rounds(u64::MAX)?;
        let mut tips = Vec::new();

        for round in decided_rounds {
            let leaders = dag_store.get_decided_leaders(round)?;
            for leader in leaders {
                if leader == *leader_hash || ancestors.contains(&leader) {
                    continue;
                }
                // Verify the leader block exists and matches
                if let Ok(block) = dag_store.get_block(&leader) {
                    if block.round == round && block.digest == leader {
                        tips.push(leader);
                    }
                }
            }
        }

        Ok(tips)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::AuthorityInfo;
    use kovanica_types::block::BlockReference;
    use kovanica_types::{Address, PublicKey, Signature};
    use parking_lot::Mutex;

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
            digest: Hash::new(format!("kovanica-test/{tag}").as_bytes()),
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

    fn committee(validators: u16) -> CommitteeInfo {
        let authorities = (0..validators)
            .map(|index| AuthorityInfo {
                index,
                stake: 1,
                public_key: PublicKey([index as u8; 32]),
                vrf_public_key: None,
                address: Address([index as u8; 32]),
                network_address: String::new(),
            })
            .collect();
        CommitteeInfo::try_new(0, authorities).expect("valid committee")
    }

    fn leader(round: Round, author: AuthorityIndex, block_hash: Option<Hash>) -> LeaderInfo {
        LeaderInfo {
            round,
            author,
            block_hash,
            status: LeaderStatus::Undecided,
            votes: HashMap::new(),
        }
    }

    /// In-memory DAG store with a configurable mergeset/ancestry and pruning
    /// recorded for assertions. It exists because `kovanica-storage`'s real store is
    /// not reachable from this crate without a temp DB, and the shared
    /// integration-test `MockDag` cannot record prune arguments.
    #[derive(Default)]
    struct RecordingDag {
        blocks: HashMap<Hash, StatementBlock>,
        mergesets: HashMap<Hash, Vec<Hash>>,
        ancestors: HashMap<Hash, Vec<Hash>>,
        decided: HashMap<Round, Vec<Hash>>,
        prune_calls: Mutex<Vec<(Vec<Hash>, u64)>>,
    }

    impl RecordingDag {
        fn insert(&mut self, block: StatementBlock) {
            self.blocks.insert(block.digest, block);
        }

        fn set_mergeset(&mut self, leader: Hash, hashes: Vec<Hash>) {
            self.mergesets.insert(leader, hashes);
        }

        fn set_ancestors(&mut self, hash: Hash, ancestors: Vec<Hash>) {
            self.ancestors.insert(hash, ancestors);
        }

        fn decide(&mut self, round: Round, hash: Hash) {
            self.decided.entry(round).or_default().push(hash);
        }

        fn prune_calls(&self) -> Vec<(Vec<Hash>, u64)> {
            self.prune_calls.lock().clone()
        }
    }

    impl DagStoreTrait for RecordingDag {
        fn get_block(&self, hash: &Hash) -> Result<StatementBlock, kovanica_dag::DagStoreError> {
            self.blocks
                .get(hash)
                .cloned()
                .ok_or_else(|| kovanica_dag::DagStoreError::NotFound(hash.to_string()))
        }

        fn get_ancestors(
            &self,
            hash: &Hash,
            _min_round: Round,
        ) -> Result<Vec<Hash>, kovanica_dag::DagStoreError> {
            Ok(self.ancestors.get(hash).cloned().unwrap_or_default())
        }

        fn get_parents(&self, hash: &Hash) -> Result<Vec<Hash>, kovanica_dag::DagStoreError> {
            self.blocks
                .get(hash)
                .map(|b| b.parents.iter().map(|p| p.digest).collect())
                .ok_or_else(|| kovanica_dag::DagStoreError::NotFound(hash.to_string()))
        }

        fn get_block_by_author_round(
            &self,
            author: AuthorityIndex,
            round: Round,
        ) -> Result<Option<StatementBlock>, kovanica_dag::DagStoreError> {
            Ok(self
                .blocks
                .values()
                .find(|b| b.author == author && b.round == round)
                .cloned())
        }

        fn get_blocks_by_round(
            &self,
            round: Round,
        ) -> Result<Vec<StatementBlock>, kovanica_dag::DagStoreError> {
            Ok(self
                .blocks
                .values()
                .filter(|b| b.round == round)
                .cloned()
                .collect())
        }

        fn has_block(&self, hash: &Hash) -> Result<bool, kovanica_dag::DagStoreError> {
            Ok(self.blocks.contains_key(hash))
        }

        fn put_block(&self, _block: &StatementBlock) -> Result<(), kovanica_dag::DagStoreError> {
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
            Ok(1)
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
            _round: Round,
            _leader_hash: &Hash,
        ) -> Result<(), kovanica_dag::DagStoreError> {
            Ok(())
        }

        fn mergeset(&self, leader: &Hash) -> Result<Vec<Hash>, kovanica_dag::DagStoreError> {
            Ok(self.mergesets.get(leader).cloned().unwrap_or_default())
        }

        fn get_blocks(
            &self,
            hashes: &[Hash],
        ) -> Result<Vec<StatementBlock>, kovanica_dag::DagStoreError> {
            Ok(hashes
                .iter()
                .filter_map(|h| self.blocks.get(h).cloned())
                .collect())
        }

        fn get_decided_leaders(
            &self,
            round: Round,
        ) -> Result<Vec<Hash>, kovanica_dag::DagStoreError> {
            Ok(self.decided.get(&round).cloned().unwrap_or_default())
        }

        fn get_decided_rounds(
            &self,
            max_round: Round,
        ) -> Result<Vec<Round>, kovanica_dag::DagStoreError> {
            let mut rounds: Vec<Round> = self
                .decided
                .keys()
                .copied()
                .filter(|r| *r <= max_round)
                .collect();
            rounds.sort_unstable();
            Ok(rounds)
        }

        fn prune_non_blue(
            &self,
            blue_hashes: &[Hash],
            committed_wave: u64,
        ) -> Result<u64, kovanica_dag::DagStoreError> {
            self.prune_calls
                .lock()
                .push((blue_hashes.to_vec(), committed_wave));
            Ok(0)
        }

        fn prune_waves_before(
            &self,
            _wave: u64,
            _prune_window_waves: u64,
        ) -> Result<u64, kovanica_dag::DagStoreError> {
            Ok(0)
        }
    }

    // -----------------------------------------------------------------
    // #1: build_committed_subdag colouring vs linearizer/Fallback
    // -----------------------------------------------------------------

    #[test]
    fn mysticghost_build_returns_colouring_with_leader_blue_and_does_not_prune() {
        let genesis = make_block(0, 0, vec![], "genesis");
        let leader_block = make_block(0, 3, vec![block_ref(&genesis)], "leader-3");
        let mut dag = RecordingDag::default();
        dag.insert(genesis.clone());
        dag.insert(leader_block.clone());
        dag.set_mergeset(
            leader_block.digest,
            vec![genesis.digest, leader_block.digest],
        );

        let committer = UniversalCommitter::new(committee(4), true, 100);
        let info = leader(3, 0, Some(leader_block.digest));

        // Direct construction yields a colouring whose blue set has the leader.
        let (subdag, colouring) = committer
            .build_committed_subdag(&dag, &info)
            .expect("mysticghost subdag");
        let colouring = colouring.expect("mysticghost produced a colouring");
        assert!(
            colouring.blue.contains(&leader_block.digest),
            "leader digest must be blue, got {:?}",
            colouring.blue
        );
        assert_eq!(subdag.leader.digest, leader_block.digest);

        // The commit path must prune with that exact blue set.
        committer.update_leader(info.clone());
        for voter in [0u16, 1, 2] {
            committer.add_vote(3, voter, leader_block.digest);
        }
        let committed = committer
            .try_commit_and_mark_durable(&dag)
            .expect("no storage error")
            .expect("quorum + present leader commits");
        assert_eq!(committed.leader_round, 3);

        // #13 variant A: red blocks are reported in `non_blue`, never pruned
        // by the committer (only round pruning removes them).
        assert!(
            dag.prune_calls().is_empty(),
            "mysticghost path must no longer call prune_non_blue"
        );
    }

    #[test]
    fn linearizer_build_returns_no_colouring_and_does_not_prune() {
        let genesis = make_block(0, 0, vec![], "genesis");
        let leader_block = make_block(0, 3, vec![block_ref(&genesis)], "leader-3");
        let mut dag = RecordingDag::default();
        dag.insert(genesis.clone());
        dag.insert(leader_block.clone());
        dag.set_ancestors(leader_block.digest, vec![genesis.digest]);

        let committer = UniversalCommitter::new(committee(4), false, 100);
        let info = leader(3, 0, Some(leader_block.digest));

        let (_subdag, colouring) = committer
            .build_committed_subdag(&dag, &info)
            .expect("linearizer subdag");
        assert!(colouring.is_none(), "linearizer path has no colouring");

        committer.update_leader(info.clone());
        for voter in [0u16, 1, 2] {
            committer.add_vote(3, voter, leader_block.digest);
        }
        committer
            .try_commit_and_mark_durable(&dag)
            .expect("no storage error")
            .expect("commits");
        assert!(
            dag.prune_calls().is_empty(),
            "linearizer path must never call prune_non_blue"
        );
    }

    #[test]
    fn mysticghost_fallback_yields_no_colouring_and_does_not_prune() {
        let leader_block = make_block(0, 3, vec![], "leader-3");
        let mut dag = RecordingDag::default();
        dag.insert(leader_block.clone());

        // Exceed the 2000-block guard so `order_committed_wave` returns Fallback.
        let mut mergeset_hashes = vec![leader_block.digest];
        for i in 0..2_001u32 {
            let extra = make_block(1, 3, vec![], &format!("extra-{i}"));
            dag.insert(extra.clone());
            mergeset_hashes.push(extra.digest);
        }
        dag.set_mergeset(leader_block.digest, mergeset_hashes);
        dag.set_ancestors(leader_block.digest, Vec::new());

        let committer = UniversalCommitter::new(committee(4), true, 100);
        let info = leader(3, 0, Some(leader_block.digest));

        let (_subdag, colouring) = committer
            .build_committed_subdag(&dag, &info)
            .expect("fallback subdag");
        assert!(colouring.is_none(), "fallback has no colouring");

        committer.update_leader(info.clone());
        for voter in [0u16, 1, 2] {
            committer.add_vote(3, voter, leader_block.digest);
        }
        committer
            .try_commit_and_mark_durable(&dag)
            .expect("no storage error")
            .expect("commits");
        assert!(
            dag.prune_calls().is_empty(),
            "fallback path must never call prune_non_blue"
        );
    }

    // -----------------------------------------------------------------
    // #3: get_previous_tips filters ancestors and the leader itself
    // -----------------------------------------------------------------

    #[test]
    fn get_previous_tips_excludes_ancestors_and_leader_keeps_fork() {
        let ancestor = make_block(0, 3, vec![], "ancestor");
        let fork = make_block(1, 5, vec![], "fork");
        let leader_block = make_block(2, 6, vec![block_ref(&ancestor)], "leader-6");

        let mut dag = RecordingDag::default();
        dag.insert(ancestor.clone());
        dag.insert(fork.clone());
        dag.insert(leader_block.clone());
        dag.decide(3, ancestor.digest);
        dag.decide(5, fork.digest);
        dag.decide(6, leader_block.digest);
        // The leader descends from `ancestor`, so it must not be seeded as a tip.
        dag.set_ancestors(leader_block.digest, vec![ancestor.digest]);

        let committer = UniversalCommitter::new(committee(4), true, 100);
        let tips = committer
            .get_previous_tips(&dag, &leader_block.digest)
            .expect("tips");

        assert_eq!(
            tips,
            vec![fork.digest],
            "ancestor and leader excluded, genuine fork tip kept"
        );
    }

    // -----------------------------------------------------------------
    // #4: register_skip cursor semantics + no fixed look-ahead cap
    // -----------------------------------------------------------------

    #[test]
    fn register_skip_does_not_advance_cursor_and_later_quorum_commits() {
        let genesis = make_block(0, 0, vec![], "genesis");
        let leader_block = make_block(1, 3, vec![block_ref(&genesis)], "leader-3");
        let mut dag = RecordingDag::default();
        dag.insert(genesis.clone());
        dag.insert(leader_block.clone());
        dag.set_ancestors(leader_block.digest, vec![genesis.digest]);

        let committer = UniversalCommitter::new(committee(4), false, 100);
        committer.register_skip(3, 1);
        assert_eq!(
            committer.last_decided_round(),
            0,
            "a provisional skip must not advance the commit cursor"
        );

        // A later quorum at the same round R still commits R.
        committer.update_leader(leader(3, 1, Some(leader_block.digest)));
        for voter in [0u16, 1, 2] {
            committer.add_vote(3, voter, leader_block.digest);
        }
        let committed = committer
            .try_commit_and_mark_durable(&dag)
            .expect("no storage error")
            .expect("round 3 commits after an earlier skip");
        assert_eq!(committed.leader_round, 3);
        assert_eq!(committer.last_decided_round(), 3);
    }

    #[test]
    fn register_skip_does_not_overwrite_a_committed_decision() {
        let genesis = make_block(0, 0, vec![], "genesis");
        let leader_block = make_block(1, 3, vec![block_ref(&genesis)], "leader-3");
        let mut dag = RecordingDag::default();
        dag.insert(genesis.clone());
        dag.insert(leader_block.clone());
        dag.set_ancestors(leader_block.digest, vec![genesis.digest]);

        let committer = UniversalCommitter::new(committee(4), false, 100);
        committer.update_leader(leader(3, 1, Some(leader_block.digest)));
        for voter in [0u16, 1, 2] {
            committer.add_vote(3, voter, leader_block.digest);
        }
        committer
            .try_commit_and_mark_durable(&dag)
            .expect("no storage error")
            .expect("round 3 commits");

        // A late timeout skip must not rewrite the committed decision (m1).
        committer.register_skip(3, 1);
        let decided = committer.get_all_decided_leaders();
        assert_eq!(
            decided.get(&3).map(|l| l.status),
            Some(LeaderStatus::Commit)
        );
        assert_eq!(committer.last_decided_round(), 3);
    }

    #[test]
    fn is_decided_reports_skips_and_commits_but_not_undecided_rounds() {
        let genesis = make_block(0, 0, vec![], "genesis");
        let leader_block = make_block(1, 3, vec![block_ref(&genesis)], "leader-3");
        let leader_block_6 = make_block(1, 6, vec![block_ref(&genesis)], "leader-6");
        let mut dag = RecordingDag::default();
        dag.insert(genesis.clone());
        dag.insert(leader_block.clone());
        dag.insert(leader_block_6.clone());
        dag.set_ancestors(leader_block.digest, vec![genesis.digest]);
        dag.set_ancestors(leader_block_6.digest, vec![genesis.digest]);

        let committer = UniversalCommitter::new(committee(4), false, 100);
        // Nothing is decided yet.
        assert!(!committer.is_decided(3));
        assert!(!committer.is_decided(6));

        // A provisional skip still counts as decided: the timeout already
        // resolved the round locally.
        committer.register_skip(3, 1);
        assert!(committer.is_decided(3));
        assert!(!committer.is_decided(6));

        // A commit at another round is decided too.
        committer.update_leader(leader(6, 1, Some(leader_block_6.digest)));
        for voter in [0u16, 1, 2] {
            committer.add_vote(6, voter, leader_block_6.digest);
        }
        let committed = committer
            .try_commit_and_mark_durable(&dag)
            .expect("no storage error");
        assert!(committed.is_some(), "round 6 must commit");
        assert!(committer.is_decided(6));
    }

    /// PRO-40: a leader with quorum far above the cursor is NOT committed
    /// while the slots in between have no record. Before the fix the walk
    /// only visited `leaders.keys()`, so it jumped straight to the far leader.
    #[test]
    fn a_far_leader_is_not_committed_over_empty_slots() {
        let genesis = make_block(0, 0, vec![], "genesis");
        let far_round: Round = 249; // a leader slot far above the cursor
        let far_block = make_block(0, far_round, vec![block_ref(&genesis)], "far-leader");
        let mut dag = RecordingDag::default();
        dag.insert(genesis.clone());
        dag.insert(far_block.clone());
        dag.set_ancestors(far_block.digest, vec![genesis.digest]);

        let committer = UniversalCommitter::new(committee(4), false, 100);
        committer.update_leader(leader(far_round, 0, Some(far_block.digest)));
        for voter in [0u16, 1, 2] {
            committer.add_vote(far_round, voter, far_block.digest);
        }

        assert!(
            committer.try_commit(&dag).is_none(),
            "slots 3..=246 have no record: the walk must stall at slot 3"
        );
        assert_eq!(committer.last_decided_round(), 0);
    }

    /// The walk is not capped: a run of consecutive leader slots with quorum
    /// commits all the way up, however far it reaches.
    #[test]
    fn consecutive_leaders_commit_without_a_lookahead_cap() {
        let genesis = make_block(0, 0, vec![], "genesis");
        let mut dag = RecordingDag::default();
        dag.insert(genesis.clone());
        let committer = UniversalCommitter::new(committee(4), false, 100);
        let mut parent = genesis.clone();
        let mut expected = Vec::new();
        for slot in 1..=40u64 {
            let round = slot * WAVE_LENGTH;
            let block = make_block(
                (slot % 4) as u16,
                round,
                vec![block_ref(&parent)],
                &format!("l{round}"),
            );
            dag.insert(block.clone());
            dag.set_ancestors(block.digest, vec![parent.digest]);
            committer.update_leader(leader(round, (slot % 4) as u16, Some(block.digest)));
            for voter in [0u16, 1, 2] {
                committer.add_vote(round, voter, block.digest);
            }
            expected.push(round);
            parent = block;
        }
        let mut seen = Vec::new();
        for _ in 0..64 {
            match committer
                .try_commit_and_mark_durable(&dag)
                .expect("no storage error")
            {
                Some(sub) => seen.push(sub.leader_round),
                None => break,
            }
        }
        assert_eq!(seen, expected);
        assert_eq!(committer.last_decided_round(), 120);
    }

    // -----------------------------------------------------------------
    // #3: commit order — never commit over an undecided earlier leader
    // -----------------------------------------------------------------

    /// Earlier leader (round 3, wave 1) has no quorum, later leader (round 6,
    /// wave 2) has quorum. Crossing a wave boundary means the same-wave sweep
    /// cannot rescue the earlier leader. Returns (dag, committer, earlier block, later block).
    fn gap_fixture(
        earlier_in_history: bool,
    ) -> (
        RecordingDag,
        UniversalCommitter,
        StatementBlock,
        StatementBlock,
    ) {
        let genesis = make_block(0, 0, vec![], "genesis");
        let earlier = make_block(1, 3, vec![block_ref(&genesis)], "earlier-3");
        let later_parents = if earlier_in_history {
            vec![block_ref(&earlier)]
        } else {
            vec![block_ref(&genesis)]
        };
        let later = make_block(2, 6, later_parents, "later-6");
        let mut dag = RecordingDag::default();
        dag.insert(genesis.clone());
        dag.insert(earlier.clone());
        dag.insert(later.clone());
        dag.set_ancestors(earlier.digest, vec![genesis.digest]);
        let later_anc = if earlier_in_history {
            vec![earlier.digest, genesis.digest]
        } else {
            vec![genesis.digest]
        };
        dag.set_ancestors(later.digest, later_anc);

        let committer = UniversalCommitter::new(committee(4), false, 100);
        committer.update_leader(leader(3, 1, Some(earlier.digest)));
        committer.update_leader(leader(6, 2, Some(later.digest)));
        // Only one vote for the earlier leader: Undecided on its own.
        committer.add_vote(3, 0, earlier.digest);
        for voter in [0u16, 1, 2] {
            committer.add_vote(6, voter, later.digest);
        }
        (dag, committer, earlier, later)
    }

    /// PRO-40 (Jarvis probe 1, inverted): GC must not drop the record of a
    /// stuck leader. Before the fix `cleanup_old_leaders` removed it and the
    /// next walk committed round 6 over the unconfirmed round 3.
    #[test]
    fn pro40_cleanup_keeps_the_stalled_leader_and_the_walk_stays_stalled() {
        let (dag, committer, earlier, _later) = gap_fixture(true);
        assert!(committer.try_commit(&dag).is_none(), "stalls at 3");
        committer.cleanup_old_leaders(6);
        committer.cleanup_old_leaders(1_000);
        assert!(
            committer.get_leader(3).is_some(),
            "the undecided leader record survives GC"
        );
        assert!(
            committer.try_commit(&dag).is_none(),
            "GC must not let the walk pass the stuck round 3"
        );
        // Quorum for 3 still resolves the stall in order.
        committer.add_vote(3, 1, earlier.digest);
        committer.add_vote(3, 2, earlier.digest);
        assert_eq!(drain(&committer, &dag), vec![3, 6]);
        // Decided records may be collected again.
        committer.cleanup_old_leaders(1_000);
        assert!(committer.get_all_leaders().is_empty());
    }

    /// PRO-40 (Jarvis probe 2, inverted): an expected leader slot without
    /// any record is a stall, not a skip. This is the restart / late-join
    /// case: the node never heard of round 3.
    #[test]
    fn pro40_missing_record_for_an_expected_slot_is_a_stall() {
        let (dag, _c, _earlier, later) = gap_fixture(true);
        let committer = UniversalCommitter::new(committee(4), false, 100);
        committer.update_leader(leader(6, 2, Some(later.digest)));
        for voter in [0u16, 1, 2] {
            committer.add_vote(6, voter, later.digest);
        }
        assert!(
            committer.try_commit(&dag).is_none(),
            "round 6 must not commit while slot 3 has no record"
        );
        assert_eq!(committer.last_decided_round(), 0);
    }

    /// A restarted node restores its cursor from the decision index; the walk
    /// then resumes at the next slot instead of slot 3.
    #[test]
    fn pro40_restored_cursor_resumes_at_the_next_slot() {
        let (dag, _c, _earlier, later) = gap_fixture(true);
        let committer = UniversalCommitter::new(committee(4), false, 100);
        committer.restore_last_decided_round(3);
        committer.restore_last_decided_round(0); // never moves backwards
        assert_eq!(committer.last_decided_round(), 3);
        committer.update_leader(leader(6, 2, Some(later.digest)));
        for voter in [0u16, 1, 2] {
            committer.add_vote(6, voter, later.digest);
        }
        let c = committer
            .try_commit(&dag)
            .expect("slot 6 follows the restored cursor");
        assert_eq!(c.leader_round, 6);
    }

    #[test]
    fn next_leader_slot_is_the_next_wave_start() {
        assert_eq!(next_leader_slot(0), WAVE_LENGTH);
        assert_eq!(next_leader_slot(1), WAVE_LENGTH);
        assert_eq!(next_leader_slot(WAVE_LENGTH), 2 * WAVE_LENGTH);
        assert_eq!(next_leader_slot(2 * WAVE_LENGTH - 1), 2 * WAVE_LENGTH);
    }

    fn drain(committer: &UniversalCommitter, dag: &RecordingDag) -> Vec<Round> {
        let mut out = Vec::new();
        for _ in 0..16 {
            match committer
                .try_commit_and_mark_durable(dag)
                .expect("no storage error")
            {
                Some(sub) => out.push(sub.leader_round),
                None => break,
            }
        }
        out
    }

    /// Regression test for PRO-35: no fork when nodes see commits in different order.
    ///
    /// With the fix, the chain STALLS at the first leader without quorum.
    /// Both nodes must produce an empty commit sequence until the missing quorum arrives.
    #[test]
    fn regression_no_fork_different_arrival_order() {
        for in_history in [true, false] {
            let (dag, committer, earlier, _) = gap_fixture(in_history);
            // No commit should pass over the undecided round 3.
            let first = committer
                .try_commit_and_mark_durable(&dag)
                .expect("no storage error");
            assert!(first.is_none(), "chain must stall at round 3 (no quorum)");
            assert_eq!(committer.last_decided_round(), 0);
            assert!(!committer.is_decided(3), "round 3 must remain undecided");

            // Now give round 3 its quorum.
            committer.add_vote(3, 1, earlier.digest);
            committer.add_vote(3, 2, earlier.digest);
            let seq = drain(&committer, &dag);
            // After quorum on round 3, both nodes must commit the same sequence.
            assert_eq!(seq, vec![3, 6], "identical commit sequence after quorum");
            let decided = committer.get_all_decided_leaders();
            assert_eq!(
                decided.get(&3).map(|l| l.status),
                Some(LeaderStatus::Commit)
            );
            assert_eq!(
                decided.get(&6).map(|l| l.status),
                Some(LeaderStatus::Commit)
            );
        }
    }

    #[test]
    fn commit_order_no_commit_over_undecided_gap_without_anchor() {
        // Later leader has no quorum either: nothing may commit at all.
        let (dag, committer, _, later) = gap_fixture(true);
        let fresh = UniversalCommitter::new(committee(4), false, 100);
        for l in committer.get_all_leaders().into_values() {
            let mut l = l;
            l.votes.clear();
            l.status = LeaderStatus::Undecided;
            fresh.update_leader(l);
        }
        fresh.add_vote(6, 0, later.digest);
        assert!(drain(&fresh, &dag).is_empty());
        assert_eq!(fresh.last_decided_round(), 0);
    }
}
