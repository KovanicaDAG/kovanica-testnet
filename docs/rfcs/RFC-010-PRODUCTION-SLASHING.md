# RFC-010 — Production Slashing: Verifiable Evidence and Unbonding Coverage

- **Status:** Accepted & Implemented (2026-10-22, gated behind `SLASHING_ACTIVE_FROM_ROUND = u64::MAX`)
- **Crate Scope:** `kovanica-staking`, `kovanica-types`, `kovanica-consensus`, `kovanica-execution`
- **Tracks:** TASKLIST item 8, Linear PRO-12, PRO-19
- **Primary References:**
  - Staking slashing logic: [`crates/kovanica-staking/src/lib.rs`](file:///crates/kovanica-staking/src/lib.rs)
  - Equivocation evidence: [`crates/kovanica-types/src/evidence.rs`](file:///crates/kovanica-types/src/evidence.rs)
  - Engine equivocation check: [`crates/kovanica-consensus/src/engine.rs`](file:///crates/kovanica-consensus/src/engine.rs)
  - Execution processing: [`crates/kovanica-execution/src/lib.rs`](file:///crates/kovanica-execution/src/lib.rs)
  - Related RFCs:
    - [`RFC-002-MYSTICETI-DAG-CONSENSUS-AND-LEADER-LOGIC.md`](file:///docs/rfcs/RFC-002-MYSTICETI-DAG-CONSENSUS-AND-LEADER-LOGIC.md)
    - [`RFC-003-STAKING-EPOCHS-AND-VALIDATOR-LIFECYCLE.md`](file:///docs/rfcs/RFC-003-STAKING-EPOCHS-AND-VALIDATOR-LIFECYCLE.md)

---

## Sažetak (Executive Summary)

RFC-010 definira produkcijski sustav kažnjavanja (slashing) za validatore koji dokazano equivociraju (potpišu dva različita bloka za istu rundu). Kazna se provodi deterministički na svim čvorovima u mreži kroz fiksni odbitak od 5% uloga (`SLASH_PCT_BPS = 500`), preusmjeravanje oduzetih sredstava u riznicu, trenutnu deaktivaciju validatora i smještanje u zatvor (jail) na 7 200 visina lidera (~24h).

Kako bi se spriječilo izbjegavanje kazne pokretanjem unbonding procesa prije detekcije prekršaja, unbonding red čeka 100 000 blokova lidera i ostaje podložan retroaktivnom rezanju ako je prekršaj počinjen dok su sredstva bila aktivna.

---

## 1. Goal

A validator that provably equivocates (signs two different blocks for the same
round) is slashed on every node, deterministically, and cannot escape the slash
by unbonding first.

## 2. What exists today (verified against main @ `b15f77c`)

| Piece | State |
|---|---|
| `DoubleSignEvidence { validator, height }` (`kovanica-staking/src/lib.rs:402`) | **No proof.** Anyone could construct one; nothing constructs it in production. |
| `StakingState::slash` (`lib.rs:1229`) | Cuts 5 % (`SLASH_PCT_BPS`) of self-stake and delegations, sets `slashed = true`. Does **not** touch `unbonding_queue` (H2). |
| `evidence_id` (`lib.rs:1254`) | `validator ‖ height_le`, 40 bytes. |
| `PROCESSED_EVIDENCE` table (`kovanica-execution/src/lib.rs:77`) | `[u8; 40] -> u8`, replay guard. |
| `apply_double_sign_evidence` (`execution/lib.rs:1088`) | Slashes, credits treasury, bumps `slashed_to_treasury`, marks the id. **Opens its own write txn**, so it cannot run inside a sub-DAG apply as-is. Called only from tests. |
| Engine equivocation check (`consensus/engine.rs:1019-1056`) | Detects a second, different-digest block for the same `(round, author)` when that author is the **scheduled leader**, then returns `InvalidVote`. It has both blocks in hand — the exact evidence needed — and discards it. |
| `SignedBlockHeader` | Does not exist. `StatementBlock` carries `author, round, digest, signature, merkle_root`, … |
| `EVIDENCE_MAX_AGE_ROUNDS`, `JAIL_ROUNDS` | Do not exist. |
| Slashed validator deactivation | Missing. `slash()` leaves `active = true`; a 5 % cut leaves 95 % of stake, above `MIN_VALIDATOR_STAKE`, so the offender stays in the committee. This is PRO-19's scope (`slashed` flag + `ValidatorSlashed` already block re-entry). |

`StatementBlock` is signed over its `digest`
(`kovanica_crypto::verify_block_signature(pubkey, digest, signature)`), so a
block's signature is a signature over `(author, round, parents, txs)`.

## 3. Evidence type

PRO-12 proposes `EquivocationEvidence { header_a: SignedBlockHeader, header_b:
SignedBlockHeader }` with verification "under the author's committee key for
that epoch". That requirement cannot be implemented as written: **no historical
committee is stored**. Committees are rebuilt from the *current* active set via
`build_committee_for_round`, and `epoch = epoch_for_round(round)`; asking for
epoch *e*'s membership after the set changed is not answerable from state.

Proposal — a self-contained proof that needs no historical committee:

```rust
// kovanica-types
pub struct SignedBlockHeader {
    pub author: Address,   // the validator's on-chain address (= pubkey)
    pub round: Round,
    pub digest: Hash,
    pub signature: Signature,
}

pub struct EquivocationEvidence {
    pub header_a: SignedBlockHeader,
    pub header_b: SignedBlockHeader,
}
```

Rules (`EquivocationEvidence::verify` — pure, no storage):

1. `header_a.author == header_b.author` — same offender.
2. `header_a.round == header_b.round` — same slot.
3. `header_a.digest != header_b.digest` — actually two different blocks.
4. Both signatures verify over their digest under `author` (block domain tag).
5. Neither digest is the zero hash.

Soundness: only the holder of the validator key can produce both signatures, so
evidence cannot be forged against an honest validator. Advisory invalidity
(evidence about a block from before the validator joined) is not proven, but
slashing is only applied when `author` is a validator in state — and a
non-validator equivocating harms nobody and yields `NotValidator`.

**Decision D1:** accept the "no historical committee proof" model, or store
per-epoch committee snapshots (a much larger change). Recommendation: accept
for v1 and document the limitation. The spec's intent — prove the offender
signed both — is satisfied.

`evidence_id = blake3("KUNA/evidence/equivocation/v1" ‖ author ‖ round_le)`
(32 bytes). This changes `PROCESSED_EVIDENCE`'s key type from `[u8; 40]`.
Because the table is only written by an inert test-only path today, no live
data migration is needed — but confirm with PRO-19's store-versioning work
before shipping.

## 4. Detection

Hook: `engine.rs:1019`, the branch that already fetches `existing` by
`(author, round)` and compares digests. On `existing.digest != block.digest`
and after the block's own signature has been validated:

1. Build `EquivocationEvidence` from `(existing, block)`.
2. `mempool.add_transaction(evidence_tx)` if a mempool is configured.
3. Keep the existing rejection of the second block.

Detection is local and non-consensus: a node that misses the second block simply
does not report, and the network needs only one honest reporter.

**Open:** the current check runs only when `scheduled_leader_for_round(round) ==
Some(author)`. That is the leader-equivocation case the spec targets. Whether
non-scheduled authors can even produce competing blocks (and should be slashed)
is a consensus question — see D2.

## 5. Transport

New `TransactionKind::Evidence { evidence: EquivocationEvidence }`, sighash tag
**12** (next free; 11 is `ClaimTreasury`). Gate production of this kind on
`SLASHING_ACTIVE_FROM_ROUND`; before activation the executor rejects it as
unsupported, and no node creates one.

Reporter semantics:

- The reporter signs the tx like any other (sender = reporter address, nonce,
  fee). Any account may report; no reward (tokenomics unchanged).
- **Fee floor must be bypassed.** `Mempool::add_transaction` rejects
  `fee_rate < min_fee_rate` (`mempool/src/lib.rs:375`). `min_fee_rate` defaults
  to 0 but is operator-settable, so a fee floor could silently drop all
  evidence. Options: exempt `Evidence` from the floor, or require the reporter
  to pay. Recommendation: exempt it and document that evidence is a protocol
  message carried in a block.
- Mempool must dedup by `evidence_id`. It dedups by tx hash today; a second
  reporter's byte-different tx would still occupy the pool. Add an
  `evidence_id` index or reject duplicates at execution (execution already does,
  via `PROCESSED_EVIDENCE`).

**Decision D3:** evidence as a transaction (spec) vs. a first-class gossip
message (like votes). Recommendation: transaction, because it gets replicated,
ordered, and executed by the existing path — and it avoids new network protocol
work. Accept the oddity of a reporter-signed, fee-exempt protocol tx.

## 6. Execution

On `TransactionKind::Evidence`:

1. Reject unless `round >= SLASHING_ACTIVE_FROM_ROUND`.
2. `evidence.verify()` — reject on any failure.
3. Age bound: let `L` be the enclosing sub-DAG's `leader_round` (thread it into
   the executor alongside `committed_height`). Require
   `evidence.header_a.round <= L` and `L - round <= EVIDENCE_MAX_AGE_ROUNDS`.
4. `PROCESSED_EVIDENCE` lookup by `evidence_id` → `EvidenceProcessed`.
5. Apply in the **same write txn** as the sub-DAG: snapshot staking, `slash()`,
   credit treasury, bump `slashed_to_treasury`, mark id — i.e. the body of
   `apply_double_sign_evidence` with its `begin_write`/`commit` removed and a
   savepoint/rollback on failure, matching the other staking executors. The
   existing method stays for tests until the refactor lands.

`EVIDENCE_MAX_AGE_ROUNDS` must be shorter than the unbonding window in
comparable units, so an unbond cannot mature before evidence can be applied.
Current unbonding is `committed_leader_height + UNBONDING_ROUNDS (100_000)` —
**heights, despite the name** (the PRO-37 unit mismatch). Rounds and heights
differ by the leader stride (`WAVE_LENGTH = 3`), so pick the constant
deliberately: recommendation `EVIDENCE_MAX_AGE_ROUNDS = 30_000` rounds ≈ 10 000
leader heights ≈ 1.4 days, comfortably inside 100 000 heights.

**Decision D4:** the exact constant. It is economic policy; needs owner sign-off.

## 7. H2 — unbonding coverage

`slash()` must also cut pending unbonding entries of the offender:

```
for entry in unbonding_queue where entry.validator == offender:
    cut = entry.amount * SLASH_PCT_BPS / 10_000
    entry.amount -= cut
    total += cut
```

`unbond_validator` already subtracts the amount from `total_staked` at unbond
time, so H2 must **not** subtract again; it reduces what will be withdrawable
and adds the cut to the returned total (which execution credits to treasury).
Supply is unchanged: the funds exist in the treasury account afterwards.

**Decision D5 — the window.** Comparing `evidence.round` to
`entry.release_height` mixes rounds and heights. Two honest options:

- (a) Cut **every entry still pending at execution time**. Simple, fully
  deterministic, impossible to game with a forged height. The unbonding period
  is the escape hatch; while funds are pending they are slashable. This makes
  `EVIDENCE_MAX_AGE_ROUNDS` purely an anti-stale-evidence bound, not the
  security boundary.
- (b) Cut only entries with `release_height > height_of(evidence.round)`,
  requiring a round→height reverse lookup that does not exist.

Recommendation: (a). It satisfies PRO-12's acceptance test (unbond 100 %, then
evidence lands → entry reduced by 5 %) and removes the unit trap. Note the
residual: once an unbond **matures and is withdrawn**, there is nothing left to
slash. That is why the evidence age bound must stay well inside the unbonding
window.

## 8. Decisions needed

> **Accepted 2026-10-22 (owner): all five as recommended.** D4 is therefore
> `EVIDENCE_MAX_AGE_ROUNDS = 30_000`; D5 slashes every entry still pending in
> `unbonding_queue` at execution time.

| # | Question | Recommendation |
|---|---|---|
| D1 | Historical committee proof for evidence | Accept self-contained evidence (no per-epoch snapshots) |
| D2 | Slash only scheduled-leader equivocation, or any author? | Start with scheduled leader (what the engine detects today) |
| D3 | Evidence as tx vs gossip message | Transaction, fee-floor exempt |
| D4 | `EVIDENCE_MAX_AGE_ROUNDS` | 30 000 rounds (~1.4 days) |
| D5 | Unbonding window rule | Cut all entries pending at execution |

Also unresolved and **not** in this RFC's scope: the offender must leave the
committee. `slash()` sets `slashed = true` but leaves `active = true`; with a
5 % cut the validator stays above the minimum and keeps its seat. PRO-19
(#80, merged 2026-10-23) adds immediate deactivation and a jail of
`JAIL_ROUNDS = 7 200` committed leaders (about 1 day; 3 epochs of 8 h once the
staking epoch is 2 400 leaders, PRO-37). After the jail the validator returns
only through an explicit stake transaction. The feature stays gated off
(`SLASHING_ACTIVE_FROM_ROUND`).

## 9. Activation

- `pub const SLASHING_ACTIVE_FROM_ROUND: u64 = u64::MAX;` in `kovanica-types`,
  with `slashing_active_from(round)` as the single predicate (same shape as
  `GAS_HARDENING_ACTIVE_FROM_ROUND`, `CONTRACT_HARDENING_ACTIVE_FROM_ROUND`,
  `SIZE_LIMITS_ACTIVE_FROM_ROUND`).
- Set to `0` at the chain 4 genesis reset, together with the other three gates.
- Chain 2 must not activate it: adding a `TransactionKind` variant changes the
  wire enum, so an activated evidence tx would be undecodable by old nodes.

## 10. Test plan

Unit (types): forged evidence (bad signature), different authors, identical
digests, different rounds, zero digest → rejected.

Unit (staking): valid evidence cuts exactly 5 % of self-stake, each delegation,
and each pending unbonding entry; `total_staked` and `unbonding_queue` stay
consistent; treasury credit equals the total; supply unchanged.

Unit (execution): a second submission returns `EvidenceProcessed`; failure rolls
back staking and balances together; evidence older than the age bound is
rejected; everything is rejected below `SLASHING_ACTIVE_FROM_ROUND`.

Integration (`crates/kovanica-node/tests/`): node A signs two blocks for one
round → within 2 waves every honest node commits the evidence tx; identical
stake via `kovanica_getStake` and identical state root; replay after restart
gives the same root.

Regression: with the gate at `u64::MAX`, an `Evidence` tx is rejected and no
existing behaviour changes; the full workspace suite must stay green.

## 11. Out of scope

Downtime/liveness slashing; governance-controlled slash parameters; reporter
rewards; slashing past a matured, withdrawn unbond.

## 11. Implementation (2026-10-22)

Shipped behind `SLASHING_ACTIVE_FROM_ROUND = u64::MAX`, so chain 2 behaviour is
bit-identical until the chain 4 reset.

| Layer | Change |
|---|---|
| `kovanica-types` | New `evidence` module: `SignedBlockHeader { author, round, digest, signature }` (`from_block`, `verify` via `Signature::verify_strict`), `EquivocationEvidence { header_a, header_b }` (`from_blocks`, `offender`, `round`, `id`, `is_fresh_at`), `EvidenceError`, `EVIDENCE_MAX_AGE_ROUNDS = 30_000`. `Hash::DOMAIN_EVIDENCE` + `Hash::new_keyed`. `TransactionKind::Evidence` (sighash tag 12). `SLASHING_ACTIVE_FROM_ROUND` + `slashing_active_from`. |
| `kovanica-staking` | `slash_validator(Address) -> Result<u64>`: cuts self-stake, all delegations and every pending unbonding entry; the queued cut was never counted in `total_staked`, so it is not subtracted again. Legacy `slash(DoubleSignEvidence)` delegates. `evidence_id` is now `[u8; 32]` (`Hash::new_keyed(DOMAIN_EVIDENCE, author ‖ round_le)`). |
| `kovanica-execution` | `PROCESSED_EVIDENCE: [u8; 32] -> ()`. `execute_transaction` takes `leader_round` + `slashing_active`; new `Evidence` arm: gate → offender → freshness → active validator → dedup → treasury credit → in-memory slash → marker insert (before the credit, so a storage failure cannot mint). `slashed_to_treasury` counter unchanged. |
| `kovanica-mempool` | `immediate_value` arm (`0`); `evidence_is_free(sender)` — fee-free only when the sender is an active validator (matches the gossip rule that only committee keys may publish evidence); public `next_nonce`. |
| `kovanica-consensus` | `report_equivocation(existing, incoming)` builds and signs the evidence tx (nonce from the pool, up to 3 retries) and submits it. Called from the equivocation reject branch only — the `use_min_digest_fork` swap branch is convergence, not proof, and stays silent. Gated on `slashing_active_from(round)`. |
| `kovanica-network` | `verify_transaction` exempts `Evidence` from the zero-fee rejection. This is safe because the same function already requires the sender key to be a current committee key — the gossip-edge equivalent of the mempool's active-validator check. Without it, a node's own report could never reach its peers (only the reporter would slash). |
| `kovanica-rpc` | `kind_to_json` renders `{"type":"evidence", author, round, digest_a, digest_b}`. |

Tests: 8 in `kovanica-types`, 3 in `kovanica-staking` (incl. H2 end-to-end),
4 in `kovanica-execution` (gate off; slash + treasury + dedup; stale /
non-validator / forged; H2 observed through `withdraw_unbonded`), 1 in
`kovanica-consensus` (detection → signed evidence tx in the pool, nothing below
the gate), 3 in `kovanica-network` (fee floor still applies to transfers;
fee-free evidence from a committee member is accepted; non-committee senders
are rejected).

### 11.1 PRO-19 part 2 — jail (2026-10-23)

Shipped live (no activation gate): `slash_validator` now sets `active = false`
and `jailed_until_height = committed_leader_height + JAIL_ROUNDS`
(`JAIL_ROUNDS = 7_200` committed leaders, ≈1 day at 12 s/leader — Toni's
2026-10-23 decision, replacing the earlier `21_600` ≈3 days). A slashed
validator therefore leaves the committee in the same sub-DAG that carries the
evidence.

| Layer | Change |
|---|---|
| `kovanica-types` | `STAKING_STATE_VERSION` 1 → 2; new `STAKING_STATE_VERSION_PREVIOUS = 1`. |
| `kovanica-staking` | `ValidatorInfo.jailed_until_height` (`serde(default)`). `slash_validator` deactivates + jails (never converting a legacy `jailed_until_height == 0` permanent-exclusion marker into a finite jail). `reactivate_validator` refuses `ValidatorSlashed` while `jailed_until_height == 0` or `committed_leader_height < jailed_until_height`; after the jail it requires an explicit stake that leaves the record at/above `MIN_VALIDATOR_STAKE` with room under `MAX_ACTIVE_VALIDATORS`. A served jail clears `slashed` + `jailed_until_height`; nothing reactivates automatically. `on_leader_committed_forfeited` shares `commit_leader` bookkeeping with the paid path. |
| `kovanica-staking` (decode) | `from_bytes` ladder: v2 → current; v1 → 11-field `ValidatorInfo` lifted with jail 0; untagged → try 12/11/10 fields newest-first; unknown version → `Err`. All branches use `Options::deserialize` with `reject_trailing_bytes`. |
| `kovanica-execution` | `execute_evidence` checks `PROCESSED_EVIDENCE` before the active-validator check, so a replay stays `EvidenceProcessed` after the offender is deactivated. An unresolvable leader forfeits the reward (`amount = 0`) instead of aborting; height, liveness and treasury vesting still advance. |

Tests: 5 new staking tests (jail lifecycle, mid-jail stake rejection, legacy
permanent row, v1 decode, v2 round-trip) plus reworked execution/node tests.
Workspace suite: 1035 passed, 1 ignored.

Leader identity resolution (fixed 2026-10-23). Execution no longer resolves
`subdag.leader_author` by position in the **live** `committee_order()`.
Before running a sub-DAG's transactions it freezes the `EPOCH_COMMITTEE`
snapshot for `epoch_for_round(leader_round)` from the **pre-sub-DAG** staking
state (first writer wins, and `publish_local_seal` reuses the same row), then
maps the authority index through that snapshot's public key to the validator
address. This makes the index stable for the whole epoch: joins, unbonds,
slashes and liveness evictions cannot shift who index *N* names.

The paid/forfeited decision is still made **after** the transactions: the
resolved validator must still be an active committee member with
`stake >= MIN_VALIDATOR_STAKE`. Otherwise the reward is forfeited — a validator
slashed or fully unbonded inside its own sub-DAG is not paid, and whoever now
occupies the shifted live index is not paid by accident. Liveness uses the same
identity, so a shifted order cannot reset the wrong validator's miss counter or
charge the leader with a miss. Idempotent replays skip the freeze, so a restart
cannot write a snapshot for a past epoch from the current state. Direct
execution-layer callers with no snapshot, and a node that starts executing
mid-epoch without one, fall back to the live order and freeze the set they see
(stable from then on).

Remaining, orthogonal: the consensus engine's `CommitteeInfo` is fixed when the
process boots, so a node that runs across an epoch boundary keeps using its boot
committee's indices. Epoch-scoped engine committees are tracked with the
per-epoch vote resolution work (RFC-009 §8.5). `release_height` remains measured
in committed-leader heights (PRO-37).
