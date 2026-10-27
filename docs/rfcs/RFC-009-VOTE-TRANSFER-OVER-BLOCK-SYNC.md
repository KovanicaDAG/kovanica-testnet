# RFC-009 — Vote Transfer Over Block Sync (Late-Join Catch-Up)

- **Status:** Implemented (2026-10-22)
- **Crate Scope:** `kovanica-network`, `kovanica-consensus`, `kovanica-storage`
- **Primary References:**
  - Network block sync: [`crates/kovanica-network/src/block_sync.rs`](file:///crates/kovanica-network/src/block_sync.rs)
  - Committer logic: [`crates/kovanica-consensus/src/committer.rs`](file:///crates/kovanica-consensus/src/committer.rs)
  - Vote storage: [`crates/kovanica-storage/src/consensus_store.rs`](file:///crates/kovanica-storage/src/consensus_store.rs)
  - Related RFCs:
    - [`RFC-002-MYSTICETI-DAG-CONSENSUS-AND-LEADER-LOGIC.md`](file:///docs/rfcs/RFC-002-MYSTICETI-DAG-CONSENSUS-AND-LEADER-LOGIC.md)
    - [`RFC-005-STATE-COMMITMENT-PRUNING-AND-VERIFIABLE-STATE-SYNC.md`](file:///docs/rfcs/RFC-005-STATE-COMMITMENT-PRUNING-AND-VERIFIABLE-STATE-SYNC.md)
    - [`RFC-006-P2P-NETWORK-PROTOCOL-AND-MEMPOOL.md`](file:///docs/rfcs/RFC-006-P2P-NETWORK-PROTOCOL-AND-MEMPOOL.md)

---

## Sažetak (Executive Summary)

RFC-009 rješava problem zaustavljanja sinkronizacije (stall) kod čvorova koji se naknadno priključuju pokrenutoj mreži (late-joiners). U originalnoj verziji protokola, konsenzusni glasovi (`Vote`) prenosili su se isključivo preko nepostojanog Gossipsub kanala "votes" i nisu bili trajno pohranjeni niti dostupni preko sinkronizacijskog protokola `block-sync`.

Kako committer odbija prijeći preko neodlučenog lidera bez kvoruma glasova ($2f+1$), čvor koji se naknadno priključi zaprimio bi blokove lidera, ali nikada ne bi mogao prikupiti kvorum glasova za njih, što bi trajno zaledilo visinu potvrđenog lanca na nuli (`committed_height = 0`).

Ovaj RFC definira trajno čuvanje glasova u tablici `VOTES` unutar `kovanica-storage`, proširenje protokola `block-sync/1.1.0` novim varijantama `VotesForRound` i `Votes`, te automatsko povlačenje nedostajućih glasova tijekom sinkronizacije liderskih blokova.

---

## 1. Root cause

Three facts combine into a permanent stall.

**(a) Votes have exactly one transport, and it is live-only.**
A vote is published once over the gossipsub `votes` topic
(`kovanica-network/src/service.rs`) at cast time. It is never persisted
(`put_vote`/`get_vote` do not exist anywhere in the tree) and never carried in
a block-sync response (`BlockSyncResponse` has no vote variant). Gossipsub does
not replay. A vote cast before a node connects is therefore gone for good.

**(b) The commit walk refuses to pass over an undecided leader.**
`Committer::try_commit_with_leader` walks candidate leader rounds in ascending
order and, on the first round that is still `Undecided`, breaks out
(`kovanica-consensus/src/committer.rs`). The comment is explicit:

> *"No commit may ever pass over an undecided round leader — the chain stalls
> until quorum arrives."*

This is deliberate (PRO-35 removed the cross-wave and local-timeout skip paths
that used to cause a committed-chain fork), and it is correct **as long as the
node holds every vote for the rounds it has registered**.

**(c) A late joiner registers old leader rounds it can never decide.**
Synced leader blocks are registered via
`ConsensusEngine::process_block` → `Committer::update_leader` with status
`Undecided`. So the joiner's `leaders` map contains, say, rounds 3, 6, 9, 12 —
but not the votes for them. `try_direct_decide` needs a stake quorum of votes
*for that leader hash* (`CommitteeInfo::has_quorum`), so every one of those
rounds stays `Undecided`, the walk breaks at round 3, and the committed height
never leaves `0`.

The asymmetry that makes this a *join-only* bug: a node that **restarts** does
not re-register old leaders (the `leaders` map is in-memory and is not
rehydrated at startup), so the walk simply finds no candidate for old rounds
and continues forward. A late joiner fills the map with undecidable rounds and
wedges itself.

**Observed signature** (from the failing test's preserved logs): the late node
receives blocks (`block received over gossip`, 30 of them), has 3 peers, and
logs `Leader round N skipped (timeout/fork)` for every round, while its
`kovanica_blockNumber` stays `0` and its peers reach `35`.

## 2. Goal

A late joiner must reach the same committed height as its peers **by applying
the same consensus rule to the same evidence**, not by trusting a peer's word.

Concretely: the joiner must be able to obtain the votes for the leader rounds
it synced, verify them with the existing authentication boundary, and let the
existing commit rule decide them.

## 3. Design

### 3.1 Votes become durable consensus data

`kovanica-storage` gains a `votes` table, keyed by `(leader_round, voter)`,
holding the bincode-encoded `Vote`.

The invariant is: **if a node can serve a block for round R, it can serve the
votes for round R.** Today that invariant is violated — blocks are durable,
votes are not — which is exactly the asymmetry that produces the bug.

Retention follows the block-pruning policy: votes for rounds below the
DAG-prune cutoff are removed with the blocks they belong to. A vote is bounded
(~130 bytes encoded), and only leader rounds carry votes.

### 3.2 Votes are transferred over the existing block-sync protocol

Two additive variants:

```rust
BlockSyncRequest::VotesForRound { round: Round }
BlockSyncResponse::Votes { votes: Vec<Vote> }
```

`VotesForRound` asks a peer for every vote it holds for one leader round. The
responder reads its durable vote store; it does **not** consult the in-memory
committer, so a peer that has restarted can still serve history.

Bounds: at most `MAX_VOTES_PER_ROUND` votes per response (the committee size,
capped), so one response stays far under the 1 MiB frame cap.

### 3.3 The joiner requests votes for the leader rounds it synced

When the node ingests a **synced** block whose round is a leader round for the
local leader schedule, it asks the peer that served the block for that round's
votes. When the response arrives, every vote goes through
`ConsensusEngine::process_vote` — the single authentication boundary that
already gates live gossiped votes.

**Ordering.** `Committer::add_verified_vote` rejects a vote whose leader round
is not yet registered (`VoteRejection::UnknownLeaderRound`). The request is
therefore issued *after* the leader block has been ingested, which guarantees
the leader is registered before the response can be applied. A response that
arrives for a round the node has not registered is dropped and re-requested on
the next catch-up tick rather than being applied out of order.

### 3.4 The decision rule does not change

The joiner commits leader `H` for round `R` only when it holds a stake quorum
of **authenticated** votes for `H`:

- each vote's signature is verified against the committee member's public key
  (`verify_vote_signature`);
- the vote's `leader_hash` must match the leader block the joiner itself
  registered for `R`;
- a voter contributes its stake at most once.

This is exactly `try_direct_decide`'s existing rule. A peer cannot make the
joiner commit a different leader than the one it synced: votes for any other
hash fail the `LeaderHashMismatch` check. The evidence arrives later; the rule
is unchanged.

### 3.5 Historical votes verify correctly

`Vote::signature_data` commits to the committee epoch
(`docs/SIGNATURE_FORMAT.md` §1), and the epoch is a pure function of the round
(`kovanica_types::epoch_for_round`, `EPOCH_ROUNDS = 7_200` DAG rounds ≈ 8 h; the
height-based staking epoch `epoch_for_height` is a different counter and is
not used for vote signing). The engine already
derives the verification context from the *leader round*, not from wall-clock
now (`ConsensusEngine::vote_signing_ctx`). A vote cast in epoch 3 therefore
verifies correctly when replayed in epoch 9.

## 4. What this change does not do

- **It does not change any consensus rule.** No new commit condition, no new
  skip condition, no digest change, no tokenomics change. The wire format
  grows two variants; every existing variant is untouched.
- **It does not implement the quorum-certified skip.** PRO-35 deferred liveness
  restoration to a Tendermint-style timeout certificate. That remains a
  separate, chain-4 RFC. This RFC does not reintroduce any skip path, and in
  particular does not reintroduce the local-timeout skip that caused the
  committed-chain fork.
- **It does not give a node the authority to skip a round.** A joiner that
  cannot obtain the votes for a round still stalls at that round. That is the
  safe behaviour: "I lack evidence" is not "the round was skipped".
- **It does not solve cross-epoch committee history.** `process_vote` resolves
  the voter's public key from the *current* committee. A joiner catching up
  across an epoch boundary in which the committee changed cannot verify votes
  cast under the old committee. Resolving the committee per epoch (via the
  existing `EPOCH_COMMITTEE` snapshot) is follow-up work, tracked in §6.
- **It does not give a joining node the committee.** A node still needs the
  genesis validator set (or another authority source) to build a committee and
  compute the leader schedule. Without one it builds a one-member committee
  and rejects every other validator's block. Out of scope here.

## 5. Alternatives considered

**(a) Quorum-certified skip (PRO-35's promised fix).** Rejected for this
change: it is a consensus rule change, it requires every node to upgrade, and
upstream scoped it to a chain-4 reset. It also answers a different question —
"may a node decide a round it has no evidence for?" — whereas the bug here is
"can a node obtain the evidence it is entitled to?".

**(b) Serve votes from the in-memory committer only.** Rejected: the
committer prunes leader records below `current_round - max_pending_rounds`
(100 rounds), and the map is lost on restart. A peer that restarts could no
longer serve the history it still holds blocks for, reproducing the same stall
at a different boundary.

**(c) Trust the peer's "round R was decided with leader H".** Rejected: this
replaces the consensus rule with a peer's assertion. There is no signature
over a decided round that a joining node could verify — `CommitSeal` is a
*post-execution* seal over a `LeaderHeader`, produced after the commit, and is
not a pre-commit certificate.

**(d) Put votes in `StatementBlock::statements`.** Rejected: `statements` is
already covered by `compute_digest_statements` (the VRF framing), so adding
votes there changes the block digest and splits the chain.

## 6. Follow-ups

1. **Per-epoch committee resolution for historical votes** — resolve the
   committee from the `EPOCH_COMMITTEE` snapshot when verifying a vote whose
   leader round is in an earlier epoch, so a joiner can cross epoch boundaries.
2. **Joiner round clock** — a joining node's `current_round` starts at its
   local tip and is never advanced to the network's tip, so it proposes for
   rounds the network already decided and its votes are refused. Adopting a
   peer's advertised tip (as a fetch trigger and clock hint only) is a separate
   change.
3. **Catch-up session re-arming** — a catch-up session that completes or times
   out is never re-created for a still-connected peer, and `catch_up.tick` is
   driven only by network events rather than a timer.
4. **Committee bootstrap for joining nodes** — see §4.

## 7. File map

| File | Change |
|---|---|
| `crates/kovanica-storage/src/lib.rs` | `tables::VOTES` table definition |
| `crates/kovanica-storage/src/consensus_store.rs` | `put_vote`, `get_votes_for_round`, `has_vote`, `prune_votes_below` |
| `crates/kovanica-consensus/src/engine.rs` | `DagStoreTrait::put_vote` (default no-op); `process_vote` **and** `vote_for_leader` persist; `drain_commits`, `registered_leader`, `pub scheduled_leader_for_round` |
| `crates/kovanica-dag/src/dag_store.rs` | `DagStore::storage()` accessor |
| `crates/kovanica-network/src/block_sync.rs` | `BlockSyncRequest::VotesForRound`, `BlockSyncResponse::Votes`, `VoteSource` |
| `crates/kovanica-network/src/service.rs` | serve `VotesForRound` from the durable vote store (`set_vote_source`), validate the response |
| `crates/kovanica-node/src/main.rs` | `NodeVoteSource`, `NodeDagStore::put_vote`, `VoteSync` tracker; request votes for synced leader rounds; apply responses through `process_vote` |
| `crates/kovanica-node/tests/late_join_integration.rs` | existing test becomes the regression test |

## 8. Outcome (implementation notes, 2026-10-22)

Implemented as specified. The regression test `late_join_integration` passes
again: the joining validator reaches the peers' committed height (target `14`,
join height `10`) instead of staying at `0`.

### 8.1 A second root cause, found while implementing

§1(a) was incomplete. Votes were not only *not persisted* — **the node did not
persist its own vote either**. `ConsensusEngine::vote_for_leader` recorded the
local vote through `Committer::add_vote`, bypassing `process_vote`, so the
persistence hook added to `process_vote` never saw it. A serving peer that had
voted `n` times therefore stored only `n - (its own votes)` — for a 4-validator
committee with the local node as one voter, `2` of `4`, i.e. **one short of
`quorum_threshold = floor(2T/3)+1 = 3`**.

The joiner cannot close that gap itself: `late_vote_window_rounds` defaults to
`WAVE_LENGTH` (`3`), so `vote_if_late` refuses to vote for the older synced
rounds. The fix is to persist the local vote at cast time
(`vote_for_leader` now calls `put_vote` in addition to `add_vote`). Without
this, transferring votes alone would have moved the joiner from "no votes" to
"one vote short" and the stall would have remained.

### 8.2 What the implementation added beyond §3

| Addition | Why |
|---|---|
| `DagStoreTrait::put_vote` (default no-op) | consensus crate cannot depend on a concrete store; the node overrides it |
| `ConsensusEngine::drain_commits` (bounded by `MAX_COMMIT_DRAIN_STEPS = 4096`) | votes can arrive for several rounds at once; one `try_commit_and_deliver` only advances one leader, so the buffered rounds must be drained until `last_decided_round` stops advancing |
| `ConsensusEngine::registered_leader` / `pub scheduled_leader_for_round` | the node must know whether a synced block is a leader round **and** whether its leader is already registered before asking for votes |
| `VoteSync` tracker in `kovanica-node` | buffers votes that arrive before their leader block, bounds outstanding requests (`64`), retries on a `2s` interval with `8` attempts, and reassigns a request when its peer disconnects |
| `BlockSyncResponse::MAX_VOTES_PER_ROUND = 64` | bounds a response well under the 1 MiB frame cap |

### 8.3 Safety properties, re-checked

- **No consensus-rule change.** The commit walk still breaks on the first
  `Undecided` leader; no skip path was reintroduced (PRO-35 stays intact).
- **Single authentication boundary.** Synced votes go through
  `ConsensusEngine::process_vote`, exactly like gossiped votes.
- **Leader binding.** `LeaderHashMismatch` still rejects a vote for a leader
  hash other than the locally registered one.
- **Ordering.** Votes are requested only after the leader block is ingested
  (`UnknownLeaderRound` otherwise).
- **Wire compatibility.** Both variants are *appended* to their enums, so the
  bincode variant indices of existing variants are unchanged.
- **Historical signature validity.** `vote_signing_ctx(leader_round)` derives
  the epoch from the round via `epoch_for_round` (`EPOCH_ROUNDS = 7200` DAG
  rounds ≈ 8 h), not from committed height and not
  from wall clock, so a vote cast in an earlier epoch still verifies.

### 8.4 New tests

- `kovanica-storage`: 4 tests for the `VOTES` table (`put_vote`,
  `get_votes_for_round` ordering, `has_vote`, `prune_votes_below`).
- `kovanica-network`: round-trip, bincode variant-index preservation,
  frame-cap fit, `votes_for_round_are_served_from_the_vote_source`,
  `votes_response_must_answer_the_vote_request`.
- `kovanica-consensus`: `accepted_vote_is_persisted`, `own_vote_is_persisted`,
  `rejected_vote_is_not_persisted`,
  `drain_commits_commits_a_leader_that_was_already_at_quorum`,
  `registered_leader_reports_the_ingested_leader_round`.
- `kovanica-node`: `vote_sync_requests_the_votes_of_a_synced_leader_round`,
  `vote_sync_requests_nothing_without_a_peer`,
  `vote_sync_reassigns_the_request_of_a_disconnected_peer`,
  `vote_sync_applies_buffered_votes_once_the_leader_is_known`.
- `late_join_integration` (existing) is the end-to-end regression test.

### 8.5 Known limitation (unchanged from §4)

`process_vote` resolves the voter's public key from the **current** committee.
A vote from an earlier epoch is applied only if that voter is still in the
current committee; otherwise the vote is rejected as non-member. Cross-epoch
catch-up therefore needs per-epoch committee resolution (follow-up 1). This is
why `late_join_integration` covers a within-epoch join.

### 8.6 Retention — wired, and a pre-existing bug found while wiring it

`ConsensusStore::prune_votes_below` is now called from `run_retention_pass`
with the **same cutoff as the DAG prune**, and takes a `limit` so a pass stays
bounded. Votes are pruned *after* the blocks are committed: a joining node asks
for a round's votes after syncing that round's leader block, so a vote that is
gone while its block is still served would turn a catch-up back into a stall.
A crash between the two leaves extra votes, never votes missing for a servable
block. When the block window is not configured, no vote is pruned — every
block, and therefore every vote, remains servable.

Wiring this exposed a **pre-existing bug**: `run_retention_pass` read the
committed leader height and the latest block from the *state* DB, while both
live in the *consensus* DB (`data_dir/state.redb` vs `data_dir/consensus.redb`,
separate redb files). On a real node the tip was always `None` and the
committed height `0`, so `retention_floor` returned `None` and every
configured window — blocks, receipts and state roots alike — silently deleted
nothing. Tests had masked it by passing one handle for both stores. The pass
now takes the consensus handle and reads both from there, and the new tests use
two separate DB files like production does.
