# Design: Multi-proposer DAG (#2)

Status: draft (Consensus). Code state: `origin/main` 8170a82.

## 1. Goal

Move from "one leader proposes per leader round + separate signed votes" to a
Mysticeti-style uncertified DAG where **every validator proposes a block every
round**, each block references **at least 2f+1 (by stake) blocks of the previous
round**, and **votes are DAG references** rather than separate `Vote` messages.
This raises throughput (all validators carry transactions) and removes the
separate vote gossip path.

Also decide **when indirect Commit may come back**. Owner rule today (PR #18):
*a leader without its own direct quorum is always Skip*, because votes are not
DAG references and causal history is not a certificate. That rule stays until the
conditions in §3.5 hold.

## 2. Current state (grounded in code)

- Rounds and waves: `WAVE_LENGTH = 3`, offsets leader / vote / decide
  (`kovanica-consensus/src/lib.rs` `is_leader_round`, `is_vote_round`).
- Proposing: engine `propose_block` runs only when `is_leader_for_round`
  (`engine.rs:417`); leader from `CommitteeInfo::leader(round)` or `leader_schedule`.
- Votes: `vote_for_leader(leader_round)` signs a `Vote { leader_round, leader_hash, voter, signature }`
  (v1 ctx). It is called by the round loop at the vote round (`produce_vote`) and,
  since #43, again from `process_block` when the leader block arrives after the
  vote round (late vote). The in-memory `voted_rounds` set makes it exactly once
  per round (not persisted across restarts). `process_vote` verifies and
  accumulates stake in `LeaderInfo.votes`.
- Commit: `committer.rs` `try_commit_with_leader` stops at the first Undecided
  leader; Commit requires the leader's own vote quorum; earlier undecided
  leaders get explicit Skip when a later one decides (#18).
- Batch: `uncommitted_history` (#11) for the linearizer, `mergeset` with the
  decided-index cutoff (#12) for MysticGhost.
- Parents: `BlockManager::select_parents` walks back up to
  `MAX_PARENT_ROUND_GAP = 300`, filtered by committee and stake.
- Validation: `validate_block` is bounded (#4): direct parents exist,
  `parent.round < block.round`, gap ≤ `MAX_PARENT_ROUND_GAP`, below the durable
  prune boundary accepted.
- MysticGhost red blocks (#47): reported in `CommittedSubDag::non_blue`
  (`non_blue_refs`: round order, digest tie-break), never executed as blocks;
  their transactions come from `non_blue_transactions` (deduped, blue txs
  excluded).
- Pruning: only `prune_waves_before` (round-based, durable boundary). The
  committer no longer calls `prune_non_blue` (deprecated), so red blocks are
  removed only by round pruning.

## 3. Model

### 3.1 Proposing

Every authority in `committee_for_round(r)` proposes exactly one block per round
`r` once it has seen blocks of round `r-1` from ≥ 2f+1 stake. Leader slots
remain (one or more leader authorities per leader round, schedule unchanged
initially); non-leader blocks carry transactions too.

### 3.2 Parents

A block at round `r > 0` must include references to blocks of round `r-1` with
total stake ≥ `quorum_threshold`, at most one per author, plus optional weak
links to older blocks (≤ `MAX_PARENT_ROUND_GAP`). Its own previous block must be
among the parents (chain per author → equivocation is detectable).

### 3.3 Votes as references

- A block `B` at round `r+1` **votes** for leader `L` at `r` iff `L ∈ parents(B)`.
- A block `C` at round `r+2` **certifies** `L` iff `C`'s parents include ≥ 2f+1
  stake of round-`r+1` blocks that vote for `L`.
- **Direct commit** of `L`: ≥ 2f+1 stake of round-`r+2` blocks certify `L`.
- **Direct skip** of `L`: ≥ 2f+1 stake of round-`r+1` blocks do *not* reference `L`.
- Otherwise Undecided.
- Signatures: the block signature (v1 ctx `chain_id`, plus epoch per
  `epoch-rotation.md`) authenticates its parent list, so a reference is a signed
  vote. The separate `Vote` type and gossip topic become unnecessary (kept for a
  transition period, see migration).

### 3.4 Commit sequence

Unchanged ordering rule from #18: process leader rounds in increasing order,
stop at the first Undecided leader. Decisions come only from the DAG (§3.3),
not from out-of-band vote counts.

### 3.5 When indirect Commit may return

Indirect rule (Mysticeti): for an Undecided leader `L`, find the next later
leader `L'` that is directly committed; if `L'`'s causal history contains a
**certificate** for `L` (some block certifying `L` per §3.3) → Commit `L`,
otherwise Skip.

It is safe again **only when all hold**:
1. votes are DAG references (§3.3), so a certificate is a set of signed blocks,
   not an assertion;
2. blocks carry ≥ 2f+1 parents of the previous round (quorum intersection makes
   any direct commit visible to every later certified leader);
3. per-author chains + equivocation handling so a certificate cannot be forged
   with two blocks from one author;
4. the check is "certificate in history", **not** "leader in history" — plain
   ancestry is exactly what #18 rejected and stays rejected.

Until then the owner rule stays: no own quorum → Skip. Re-enabling requires a
separate owner decision and PR (feature flag in `UniversalCommitter`).

## 4. Impact per component

- **Linearizer / `uncommitted_history` (consensus)**: batch is still "history
  of committed leader minus everything already delivered". With many proposers
  the history per commit is ~n× larger; order inside the batch must stay
  deterministic (round, then author, then digest). The TODO for an incremental
  committed set (#27) becomes necessary for performance.
- **Mergeset / MysticGhost (dag + consensus)**: mergeset sizes grow with n;
  blue/red classification (GHOSTDAG `k`) must be re-tuned for n blocks per round.
  Red blocks are already returned as `non_blue` (#47, not executed as blocks),
  and `non_blue_transactions` dedups their transactions against the blue ones.
  Expect more overlap, because all proposers pull from the same mempool.
- **Pruning (dag)**: `prune_waves_before` remains round-based. The prune window
  must keep at least the rounds needed for the indirect rule (leaders up to the
  next committed leader + 2 rounds) and anything an undelivered batch needs
  (correctness condition already documented at `uncommitted_history`), including
  red blocks until their sub-DAG's `non_blue_transactions` have been read. Storage
  per round grows n×; window may need to shrink in rounds.
- **`validate_block` (dag)**: add checks — parents of round `r-1` sum to
  ≥ quorum stake; at most one parent per author per round; own previous block
  present; author in `committee_for_round(r)`; at most one block per
  (author, round) stored (equivocation evidence kept). Stays bounded (direct
  parents only); the quorum check needs parent stake, which is local.
  Note: a parent below the prune boundary cannot be stake-counted; require the
  quorum parents (round `r-1`) to be above the boundary — true by construction
  when the window ≫ 1 round.
- **Engine**: proposal loop for every round, wait-for-quorum of `r-1` with
  timeout; `vote_for_leader` (round-loop and late-vote paths, `voted_rounds`)
  and `process_vote` replaced by DAG-derived decisions. A late leader block
  then simply gets referenced by later blocks, so the late-vote path disappears;
  leader timeout still produces Skip only through §3.3 rules (or a timeout path
  kept as today).
- **Network/mempool (Network)**: block gossip volume ×n; vote topic retired;
  mempool must avoid every proposer taking the same txs (sharding by sender
  hash or author) — Network decision.

## 5. Interface changes per crate

- **kovanica-types (Foundation)**: none required for blocks (parents already a
  list); maybe `BlockReference` ordering helper; later remove `Vote` (or keep for
  compatibility).
- **kovanica-dag**: `validate_block` quorum/uniqueness checks; `select_parents`
  returns all r-1 blocks (≥ quorum) + own chain; `DagStore` index
  `(round, author) → digest` with equivocation flag; mergeset re-tune.
- **kovanica-consensus**: decision rule from DAG (`direct_decide(L)`, later
  `indirect_decide(L)` behind a flag); engine proposes every round; remove vote
  accumulation from `LeaderInfo` once migrated.
- **kovanica-node / network / mempool (Network)**: proposal timing, gossip,
  mempool partitioning.

## 6. Migration

1. Dual mode: all validators propose, but decisions still from `Vote` messages
   (no protocol change in commit rule). Measure throughput/DAG size.
2. Compute DAG-reference decisions in shadow, compare with vote-based decisions
   (metric + test), no effect on commits.
3. Switch the commit rule to DAG-reference direct decisions (owner gate);
   stop producing `Vote`s.
4. Optional, separate owner decision: enable certificate-based indirect Commit
   (§3.5).
Each step is a config/genesis flag, testnet first; no stored-data migration
beyond the new `(round, author)` index.

## 7. Risks

- Safety regression if "in history" is used instead of "certificate in
  history" (exactly the #18 bug class).
- Equivocation: two blocks per (author, round) can double-vote; needs detection
  and a rule (first-seen is not deterministic — use "any equivocating block does
  not count").
- Liveness: waiting for 2f+1 parents each round adds a round trip; slow
  validators fall behind (weak links up to `MAX_PARENT_ROUND_GAP`).
- Storage and CPU ×n; `uncommitted_history` cost without the incremental set.
- Mempool duplication across proposers; dedup at execution (same mechanism as
  #13 `non_blue_transactions`).
- Pruning too aggressive vs. indirect rule lookback.

## 8. Test plan

- Unit (dag): `validate_block` rejects < quorum parents, duplicate author
  parents, missing own previous block, author outside committee; accepts pruned
  older weak links.
- Unit (consensus): direct commit / direct skip / undecided from synthetic DAGs;
  no Commit without certificate; commit order strictly increasing, stops at
  Undecided (reuse `commit_order_*` tests).
- Property: random DAGs with ≤ f Byzantine authors (incl. equivocators) — all
  honest nodes produce the same commit sequence; no block delivered twice;
  no tx lost (with #13).
- Shadow-mode test: vote-based and DAG-based decisions agree on honest runs.
- Integration (Network-owned): 4 and 7 nodes, sustained liveness, one crashed
  node, restart recovery equality (`committed_subdag_recovery_*`).
