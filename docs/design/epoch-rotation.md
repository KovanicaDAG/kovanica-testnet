# Design: Epoch rotation

Status: implemented (Consensus PRO-37). Baseline: `origin/main` 8170a82.

## 1. Goal

Make the committee epoch real. Today every committee is epoch 0
(`kovanica-node/src/main.rs` builds `CommitteeInfo::try_new(0, ..)`), so the
`epoch` field of the v1 vote signing context (`SigningContext { chain_id, epoch }`,
`docs/SIGNATURE_FORMAT.md`) never changes. We want:

- a deterministic epoch boundary that every honest node agrees on;
- committee (and stake) changes that take effect only at that boundary;
- votes and signatures from the previous epoch handled explicitly (accepted only
  where the old committee is still authoritative, rejected everywhere else);
- **Consensus as the single source of the current epoch** for the node, Network
  (gossip edge validation) and Execution (evidence verification). The types and
  the pure context function live in `kovanica-types` (Foundation); Consensus fills
  the schedule.

Non-goals: staking/reward logic for choosing the next committee (Execution),
state sync across epochs (handled via DAG/state sync protocol), key rotation inside an epoch.

## 2. Current state (grounded in code)

| Item | Where | Today |
|---|---|---|
| Committee + epoch | `kovanica-consensus/src/types.rs` `CommitteeInfo { epoch, authorities, .. }`, `epoch()` | set once at startup, always 0 |
| Vote ctx | `kovanica-consensus/src/engine.rs` `vote_signing_ctx()` | `chain_id` from local ctx + `self.committee.epoch()`; never from the message |
| Own votes | engine `vote_for_leader` (round loop + late vote from `process_block`, #43) | exactly once per leader round via the in-memory `voted_rounds` |
| Red blocks | `CommittedSubDag::non_blue`, `non_blue_refs` / `non_blue_transactions` (#47) | not executed as blocks; removed only by round pruning |
| Vote bytes | `kovanica-types/src/vote.rs` `Vote::signature_data(ctx)` | 74 bytes, `KUNA/vote/v1` + chain_id + epoch + voter + leader_round + leader_hash. `Vote` itself has **no epoch field** |
| Tx ctx | `kovanica-types/src/transaction.rs` | `chain_id` only; epoch is NOT part of tx hash (test `epoch_is_not_part_of_tx_hash`) |
| Node ctx | `kovanica-node/src/main.rs:447` | `SigningContext::new(chain_id).with_epoch(committee.epoch())` |
| Network edge | `kovanica-network/src/validation.rs` `VoteVerifier`, `AuthorityKeys` | one static key map, ctx injected at startup |
| Leader schedule | `CommitteeInfo::leader(round)`, engine `leader_schedule` | round-robin over one committee |
| Rounds | `kovanica-types` `WAVE_LENGTH = 3`, leader/vote/decide offsets | global round counter, not reset per epoch |

Consequence: the engine holds one immutable `CommitteeInfo`; there is no API to
replace it, and Network has its own copy of the key map.

## 3. Model

### 3.1 Epoch boundary

- Epoch `e` covers a contiguous range of **leader waves**. The boundary is
  defined by consensus output, not wall-clock: epoch `e` ends at the first
  committed leader whose round `>= end_round(e)`, where
  `end_round(e) = start_round(e) + EPOCH_LENGTH_ROUNDS` (a multiple of
  `WAVE_LENGTH`; proposed constant in `kovanica-types`).
- The **closing commit** is the `CommittedSubDag` that crosses `end_round(e)`.
  It is delivered in epoch `e` and executed under epoch `e` rules.
- The next committee `C(e+1)` must be fixed by state that is final **before**
  the closing commit (e.g. computed by Execution/staking at a commit at least one
  wave earlier and recorded in the committed state). Consensus only consumes it.
- `start_round(e+1) = leader_round(closing commit) + WAVE_LENGTH` (the next
  leader round). Rounds are not reset; the global round counter keeps increasing,
  so `(round)` alone still identifies a slot and existing indices
  (`decided`, `prune_boundary`) need no epoch dimension.

### 3.2 Source of truth: `EpochSchedule` (kovanica-types) filled by Consensus

The schedule type and the context derivation are shared, pure and owned by
Foundation in `kovanica-types`, so every crate computes the same context:

```text
// kovanica-types (Foundation)
struct EpochEntry   { epoch: u64, start_round: Round, committee: Committee }
struct EpochSchedule { entries: Vec<EpochEntry> }      // sorted, contiguous
impl EpochSchedule {
    fn epoch_for_round(&self, r: Round) -> Option<u64>;
    fn committee_for_round(&self, r: Round) -> Option<&Committee>;
}
/// Pure: no I/O, no clock, no network input.
fn signing_ctx_for_round(s: &EpochSchedule, chain_id: u64, r: Round)
    -> Option<SigningContext>;     // None = round outside the schedule
```

- **Consensus fills it.** The engine appends `EpochEntry(e+1)` when it commits
  the closing sub-DAG of epoch `e`. Nothing else writes the schedule.
- **Durable and part of committed state per height.** The schedule change is
  written in the **same redb transaction** as the commit closing the epoch
  (`mark_decided_and_commit_leader` extended, as in #14: both or neither). So
  for every committed height `h` there is exactly one schedule `S(h)`, and a
  restart or replay reads the same `S(h)`.
- **Readers:**
  - **Consensus** (votes, blocks, quorum): its in-memory copy of the latest
    committed schedule.
  - **Gossip edge (Network)**: the node's live `Arc<RwLock<EpochSchedule>>`,
    updated by the node right after Consensus persists a change (event
    `EpochChanged { epoch, start_round }`). This edge is a best-effort filter
    only; Consensus re-verifies.
  - **Execution** (e.g. `DoubleSignProof` evidence): reads `S(h)` for the
    **height of the sub-DAG being executed**, never the live copy. That keeps
    execution deterministic across nodes at different live positions and on
    replay.
- `vote_signing_ctx()` and block verification become
  `signing_ctx_for_round(schedule, local chain_id, round)`. Only local state
  is used, never the message, so the v1 rule still holds.
- Own votes: `vote_for_leader(r)` signs with `ctx(r)` of the **leader round**,
  not the current epoch. That matters for a late vote (#43) cast after the
  boundary for a leader of `e-1`; it uses `C(e-1)`'s epoch, consistent with
  the votes table below. `voted_rounds` stays keyed by round (rounds are
  global), so no epoch dimension is needed.

### 3.3 Context per round: blocks and votes alike

For a round `r`, **blocks and votes use the same context**:
`ctx(r) = signing_ctx_for_round(S, chain_id, r)`. For a vote, `r` is
`vote.leader_round`; for a block, `r` is `block.round`. `Vote` carries no
epoch, so the epoch is derived from the round. A signature made for the wrong
epoch never verifies, because the epoch is in the signed bytes. That is the
replay protection across epochs.

#### Votes across the boundary

| Vote for leader round in | Accepted? | Key set / ctx |
|---|---|---|
| current epoch `e` | yes | `C(e)`, ctx(r) |
| previous epoch `e-1`, round `<= end_round(e-1)`, leader not yet decided locally | yes (late votes can still finish the closing wave) | `C(e-1)`, ctx(r) |
| `e-1` but already decided / below `last_decided_round` | dropped (no effect, no penalty) | — |
| `<= e-2` | rejected | — |
| outside the schedule (future epoch not yet known locally) | gossip: **Ignore** (no peer penalty); Consensus: bounded buffer, re-checked on `EpochChanged`, else dropped | — |

#### Blocks across the boundary

| Block round `r` in | Accepted? | Key set / ctx |
|---|---|---|
| current epoch `e` | yes | `C(e)`, ctx(r) |
| previous epoch `e-1` (block arrives after the boundary), `r >= prune_boundary` | yes, stored as DAG history (it can be a parent or part of the closing wave's history); it is never a leader for `e` | `C(e-1)`, ctx(r) |
| `e-1` but `r < prune_boundary` | dropped (already pruned; not needed) | — |
| `<= e-2` and above the prune boundary | accepted only as history under `C(epoch_of(r))` while that epoch is still in the schedule; otherwise dropped | ctx(r) |
| outside the schedule (future epoch) | gossip: **Ignore**; Consensus: held in the pending-block buffer, re-validated on `EpochChanged`, else dropped | — |

`validate_block` stays bounded (#4). It checks the author against
`committee_for_round(block.round)` and parent rounds as today. A parent from
an earlier epoch is accepted if it is stored or below the prune boundary.

#### Transactions and evidence in execution

- Transaction ctx stays `chain_id` only (epoch not in the tx hash), so mempool
  content survives a rotation.
- Evidence (e.g. `DoubleSignProof`) is checked with `ctx(r)` from `S(h)`, where
  `h` is the height of the executing sub-DAG. If `r` is **outside** `S(h)`, the
  transaction **fails deterministically**: no state effect from the proof, but
  the **fee is charged and the nonce is incremented** (same as any other failed
  transaction). So a node can't make execution diverge by gossiping
  out-of-schedule evidence.

### 3.4 Quorum across the boundary

All quorum checks (`quorum_threshold`, `validity_threshold`, commit rule in
`committer.rs`) use `committee_for_round(leader_round)`. A wave never mixes two
committees: the boundary is at a leader round, and the vote/decide rounds of a
wave belong to the leader's epoch.

## 4. Interface changes per crate

- **kovanica-types (Foundation)**: `EpochEntry`, `EpochSchedule` (with
  `epoch_for_round`, `committee_for_round`) and the pure
  `signing_ctx_for_round(schedule, chain_id, round) -> Option<SigningContext>`;
  `EPOCH_LENGTH_ROUNDS`; `EpochChanged` event type. No change to `Vote` bytes
  or the v1 format.
- **kovanica-consensus (Consensus)**: fills the schedule; the engine holds the
  latest committed `EpochSchedule` instead of one `CommitteeInfo`; vote and
  block ctx via `signing_ctx_for_round`; emits `EpochChanged` after the
  durable commit; per-epoch leader schedule; committer quorum per round;
  removes the `TODO(owner)` at `engine.rs:240`; pending buffers for
  out-of-schedule votes/blocks.
- **kovanica-dag (Consensus)**: new redb table `DAG_EPOCHS` (height → schedule
  change). `mark_decided_and_commit_leader` gains an optional
  `schedule_change` that is written in the **same** transaction. A reader
  `schedule_at(height)` returns `S(h)`. The `BlockManager` key map and
  `select_parents` become per-round via `committee_for_round`.
- **kovanica-network (Network)**: `AuthorityKeys` / `VoteVerifier` read the node's
  live `Arc<RwLock<EpochSchedule>>` and verify with `ctx(r)`. A round outside
  the schedule gives `Ignore` (no penalty, no relay). It keeps `C(e-1)` until
  `end_round(e-1)` is decided.
- **kovanica-node (Network)**: owns the live `Arc<RwLock<EpochSchedule>>` (built
  from genesis plus `DAG_EPOCHS` on start), updates it on `EpochChanged`, and
  stops building ctx from a static committee (`main.rs:447`).
- **kovanica-execution / staking (Execution)**: produce `C(e+1)` from committed
  state at least one wave before the boundary. `DoubleSignProof` (and any
  signed-evidence tx) verifies with `signing_ctx_for_round(S(h), ...)` for
  the sub-DAG height. Outside the schedule it fails deterministically, but the
  fee and nonce are still charged.
- **kovanica-mempool (Network)**: none (tx ctx has no epoch); only remove the
  `TODO(owner)` epoch note.

## 5. Migration

1. Foundation lands `EpochSchedule` and `signing_ctx_for_round` in kovanica-types.
   It has a single entry `(epoch 0, start_round 0, genesis committee)`, and
   `signing_ctx_for_round` returns today's ctx for every round, so behaviour
   is identical.
2. Consensus switches vote and block ctx to `signing_ctx_for_round` and adds
   `DAG_EPOCHS`, written atomically with the commit. A DB without the table is
   read as the single epoch-0 entry.
3. Network wires the live `Arc<RwLock<EpochSchedule>>` into the gossip edge
   (Ignore outside the schedule). Execution reads `S(h)` for evidence.
4. Enable rotation behind a genesis/config flag (`EPOCH_LENGTH_ROUNDS`),
   testnet first.
5. Only then let Execution feed real committee changes.

No change to the v1 byte format, so no new signature version is needed.

## 6. Risks

- **Non-deterministic boundary**: if `C(e+1)` depends on anything not final
  before the closing commit, nodes diverge. Mitigation: the one-wave lag rule.
- **Execution reading the live schedule** instead of `S(h)` would make
  evidence results depend on node timing. Mitigation: the API only exposes
  `schedule_at(height)` to execution.
- **Liveness at the boundary**: the old committee must finish the closing
  wave. If `C(e-1)` keys are dropped too early, the last wave stalls.
  Mitigation: keep `C(e-1)` until `end_round(e-1)` is decided.
- **Crash between commit and schedule write**: avoided by the single redb
  transaction (same lesson as #14). A test covers it.
- **Live copy lagging** (`Arc<RwLock<EpochSchedule>>` updated after the
  event): the gossip edge may Ignore valid new-epoch messages briefly. That
  costs latency, not safety, because Consensus re-verifies.
- **Late blocks from `e-1`** accepted as history could be used to grow the
  DAG. Bounded by the prune boundary and `MAX_PARENT_ROUND_GAP`.
- **Leader schedule churn**: `leader_schedule` overrides keyed by round must
  not leak across epochs.
- **Pruning**: `prune_waves_before` must not remove the closing wave before the
  next epoch's first commit (recovery needs it). `DAG_EPOCHS` is never pruned.
  Red blocks (`non_blue`, #47) are removed only by round pruning, so the
  same window must cover them until the closing sub-DAG's
  `non_blue_transactions` are read.

## 7. Test plan

- **Unit (kovanica-types, Foundation):** `signing_ctx_for_round` is pure and total
  over the schedule. It returns `None` outside the schedule, and boundary
  rounds map to the right epoch.
- **Unit (consensus):**
  - Vote and block for the same round use the identical ctx.
  - Vote for `e-1` is accepted only while undecided; `e-2` is rejected.
  - A vote or block with the correct key but the wrong epoch fails (extends
    the `sig_v1_*` tests).
  - Out-of-schedule votes and blocks are buffered, then accepted on
    `EpochChanged`.
- **Unit (consensus, blocks table):**
  - A late `e-1` block above the prune boundary is stored as history and is
    never a leader in `e`.
  - A late block below the prune boundary is dropped.
- **Unit (dag):**
  - The closing commit and the `DAG_EPOCHS` row are atomic (fault injection
    as in `dag_store::fault`; reopen gives both or neither).
  - `schedule_at(h)` survives a reopen.
- **Execution (Execution-owned):**
  - `DoubleSignProof` verifies against `S(h)`.
  - A proof for a round outside `S(h)` fails deterministically and still
    charges the fee and increments the nonce. Replaying it gives the same
    result.
- **Network (Network-owned):** the gossip edge gives Ignore (no penalty)
  outside the live schedule, and Accept after the live schedule updates.
- **Property:** random epoch lengths; no commit uses the quorum of the wrong
  committee; the same `S(h)` on every node for every height.
- **Integration (node, Network-owned):**
  - 4 nodes rotate to a different committee at round N; liveness continues
    with the same committed leaders on all nodes.
  - A restart in the middle of the boundary works.
