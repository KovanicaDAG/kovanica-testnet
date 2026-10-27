# Kovanica External Security Audit — Scope Document

**Version:** 1.0  
**Date:** 2026-10-14  
**Codebase:** `kovanica` (Mysticeti-style DAG, account-based, Wasmi execution)  
**Commit:** `main` @ `dd3aff9` (Baseline: `98d88cc`)  
**Crates:** 27 workspace members, ~90.5k LOC Rust (crates) / ~95.5k repo

---

## 1. Executive Summary

Kovanica is a from-scratch Layer-1 blockchain with a Mysticeti-style uncertified DAG consensus (wave length = 3), account-based execution with staked validators (15–21 active, min 50,000 KUNA), and deterministic Wasmi WebAssembly smart contracts. Native token: **KUNA** (9 decimals, 90.2M total supply).

This document defines the scope for an external security audit covering consensus-critical paths, cryptographic primitives, P2P networking, execution sandbox, staking/tokenomics, and RPC surface.

---

## 2. In-Scope Components

### 2.1 Consensus — `kovanica-consensus` (CRITICAL)

| Module | Risk | Description |
|--------|------|-------------|
| `mysticghost.rs` | **Critical** | Wave-based commit logic, VRF leader election (ecvrf), GHOSTDAG-scoped colouring (k=3), min-digest fork resolution, late-vote window bounds |
| `engine.rs` | **Critical** | Round loop, leader timeout (adaptive `round_duration_ms * factor`), block proposal, vote production/processing, commit trigger serialization (`commit_trigger_lock`), duplicate proposal prevention |
| `committer.rs` / `committer_mysticghost.rs` | **Critical** | Direct/indirect commit rules, 2f+1 quorum, decided-round cursor, skip persistence, non-blue tracking |
| `ghostdag_scoped.rs` | **Critical** | Scoped GHOSTDAG (k=3) colouring of mergeset, blue-set ordering, previous-tip seeding |
| `linearizer.rs` | **High** | Fallback topological sort when MysticGhost disabled or mergeset too large |
| `types.rs` | **High** | `CommitteeInfo` (stake-weighted thresholds, leader schedule), `AuthorityInfo` (VRF keys), `CommitResult`, `CommittedSubDag` |

**Specific consensus invariants to verify:**
- No two honest nodes commit different leader blocks at the same height
- Late-vote window (`late_vote_window_rounds = WAVE_LENGTH = 3`) prevents divergent commits from late-joining nodes
- Vote durability (RFC-009): every accepted vote **and the node's own vote** are persisted (`tables::VOTES`); a node that can serve a block for round R can serve the votes for R. Votes fetched from a peer are re-verified by `process_vote` before use — block-sync is a transport, never a trust boundary.
- VRF leader election: quorum = `floor(2*N/3)+1` of VRF-keyed validators; partial set → round-robin
- Min-digest fork: only replaces when store accepts swap AND round undecided
- Skip registration persists in decided map with `LeaderStatus::Skip`
- `mark_decided_and_commit_leader` atomicity (both or neither on crash)
- Block/transaction size limits: `MAX_BLOCK_BYTES` (960 KiB) and `MAX_TX_BYTES` (512 KiB) are checked in block-manager validation on the **bincode encoding**, so the bound applies on every ingest path (gossip, block sync, proposal, local assembly), not just at the P2P edge. Gated by `SIZE_LIMITS_ACTIVE_FROM_ROUND` (currently `u64::MAX` → inert until the next genesis reset, because a node without the limits would accept a block an upgraded node rejects).

#### 2.1.1 KNOWN CRITICAL FINDING — committed-chain fork via node-local skip (PRO-35)

**This is a pre-existing safety defect in the current tree, not a hypothetical. It
must be treated as the top audit item and it blocks the VRF C1 work (PRO-7).**

`crates/kovanica-consensus/src/committer.rs` can mark a leader round as **Skip**
based on **node-local** information, while another node **commits** that same
round. Because the committed height is a plain counter, the two nodes then
assign the **same height to different blocks** and derive **different state
roots**.

Three independent paths reach the fork:

1. **Local timeout skip (routine).** `register_skip` (`:238-259`) records
   `LeaderStatus::Skip` with `block_hash: None`. The walk guard
   (`:507-514`) then `continue`s over that round **without** `mark_decided`, so
   the round is silently dropped from the committed sequence while the cursor
   stays put. Node B (missed the L-6 block) commits **L-9** at the height where
   node A commits **L-6**. This happens *every time a node misses a leader
   block* — it is not a corner case.
2. **Cross-wave skip (the normal path).** The `has_later_commit` branch
   (`:544-561`) marks an earlier round Skip when a *later* round has a commit.
   Votes for round `r` are cast in round `r+1`, so the L-3 certificate exists in
   wall-clock time *before* the L-6 certificate — nodes routinely observe a
   later certificate first.
3. **Missing-block conflation.** `has_path` (`:109-127`) cannot distinguish
   "block absent locally" from "block present but not causally connected", so
   `try_indirect_decide` (`:72-106`) can return Skip. With `WAVE_LENGTH = 3`
   there is exactly one leader per wave, so this path always returns
   `Undecided` and `decide_earlier_in_wave` (`:411-450`) is effectively dead
   code — meaning **no skip path in the tree is safe**.

**Why the height model makes it fatal:** `STATE_ROOT` is keyed by
`committed_leader_height` (`crates/kovanica-storage/src/lib.rs:150`), a counter
incremented once per committed leader
(`crates/kovanica-storage/src/consensus_store.rs:257-267`). A skipped round
consumes no height slot, and the two nodes' committed-leader *sequences*
differ — so the per-leader subsidy minting and the epoch boundaries diverge as
well. Even a per-block height would not be enough: the **set of committed
leaders must be identical on every node**.

**Known-safe direction (no protocol change):** a node-local skip is unsafe
because it removes a round from the committed sequence; a node that merely
**waits** is only *behind*, never forked, and commits the same leader once the
block and quorum arrive. Removing the local timeout skip and the cross-wave
skip therefore converts a fork into a stall. Restoring liveness (a crashed
leader) requires a quorum-certified timeout certificate — a protocol change,
feasible in the pending chain-4 reset.

**Auditor asks:** confirm the three paths above, assess the fork's blast
radius on the live chain, and review the chosen remedy (stall vs. timeout
certificate) against the subsidy/epoch invariants in §2.5.

### 2.2 Mempool — `kovanica-mempool` (HIGH)

| Area | Risk | Description |
|------|------|-------------|
| Admission pipeline | **High** | Size, gas, fee floor, hash-binding (`tx.hash == tx.signing_hash()`), Ed25519 strict verify, nonce window, per-sender limit, cumulative balance, RBF (10% bump), capacity eviction (strictly cheaper only) |
| In-flight lifecycle | **High** | `get_next_transactions` → in-flight (15s timeout) → re-queue on timeout; `return_in_flight_for_sender` on leader skip |
| Re-insertion (red blocks) | **High** | `reinsert_returned`: full re-admission, sorted by `(sender, nonce)`, no gossip by default, no peer penalty |
| Fee policy | **Medium** | `min_fee_rate` default 0 (operator choice); stake/delegate fee-free |

### 2.3 Network / P2P — `kovanica-network` (HIGH)

| Component | Risk | Description |
|-----------|------|-------------|
| `service.rs` | **High** | `NetworkService` wrapping libp2p Swarm; gossipsub topics `kovanica/<tag>/{blocks, transactions, votes, sync, state_sync, seals}` (`<tag>` = `<chain_id>-<genesis prefix>`, `network_id.rs`); Kademlia `/kovanica/<tag>/kad/1.0.0` + ping + identify `/kovanica/<tag>/1.0.0` (a peer with another tag is disconnected); serves `VotesForRound` from the durable vote store via `VoteSource` and validates the answer against the request |
| `validation.rs` | **Critical** | Edge validation before gossip: block digest/merkle/author/signature; vote signature + committee membership + leader round/hash match; seal signature + header match |
| `scoring.rs` | **High** | Peer scoring: topic mesh delivery, validation rejects, behaviour penalties; ban threshold |
| `block_sync.rs` | **High** | Request-response block sync (protocol `/kovanica/<chain_id>-<genesis prefix>/block-sync/1.1.0`; every protocol id and topic is chain-scoped, `network_id.rs`); carries block history **and** (since RFC-009) per-round vote history, bounded to `MAX_VOTES_PER_ROUND = 64` |
| `state_sync.rs` | **High** | Request-response state sync (protocol `/kovanica/<tag>/state-sync/2.0.0`) |
| `identity.rs` | **Medium** | Persistent node identity (Ed25519 transport key, `0600` file perms), no hard-coded bootstrap nodes |

**Configuration defaults:** listen `/ip4/0.0.0.0/tcp/8000`, max 50 peers, ping 10s. Gossip frames are capped at `MAX_TRANSMIT_SIZE` (1 MiB); the consensus block cap sits 64 KiB below it so a valid block is always relayable in one message (asserted by `consensus_block_cap_fits_the_gossip_frame`). Bootstrap nodes supplied at deploy via DNS names (no external project infra).

### 2.4 Execution / WASM — `kovanica-execution` + `kovanica-runtime` (HIGH)

| Component | Risk | Description |
|-----------|------|-------------|
| `contracts.rs` (execution) | **High** | Native contract dispatch (HTLC, Vault, Multisig, Token, LightNode), WASM via `ContractRunner`, commit-on-success semantics, gas metering |
| `Runtime::execute` (runtime) | **High** | Wasmi fuel metering (`gas_limit` default 10M), memory limit (16 pages = 1 MiB), deterministic engine, argument/result buffer copy via `kovanica_alloc`/`kovanica_dealloc` |
| Host ABI (`crates/kovanica-common/src/wasm.rs`) | **High** | Fixed imports: `kovanica_caller`, `kovanica_contract_address`, `kovanica_block_height`, `kovanica_timestamp`, `kovanica_balance_of`, `kovanica_storage_get/set`, `kovanica_transfer`, `kovanica_emit_log`, `kovanica_alloc`, `kovanica_dealloc` |
| Contract crates (`kovanica-htlc`, `kovanica-vault`, `kovanica-multisig`, `kovanica-token`, `kovanica-staking/light.rs`) | **High** | Entry points returning packed `i64` (negative = error code 0..11), all state via `Host` trait |

**WASM threat model:** untrusted bytecode, gas exhaustion, memory exhaustion, host function reentrancy, trap handling, deterministic execution.

### 2.5 Staking & Tokenomics — `kovanica-staking` (CRITICAL)

| Area | Risk | Description |
|------|------|-------------|
| Emission schedule | **Critical** | `block_reward(height)`: 2.5 KUNA × (3/4)^era, era = 8.1M committed leaders; cumulative capped at 81M |
| Genesis validator allocation | **Critical** | 1M KUNA split evenly (dust to first), min stake 50K KUNA locked |
| Treasury vesting | **High** | 8M KUNA over 8 years (1M/year linear), `claim_treasury_vesting(committed_height)` |
| Validator lifecycle | **High** | Bond/unbond (100 000 **committed leader blocks**, ≈13.9 days at 12 s/leader — not 100k DAG rounds and not one epoch), active set 15–21, commission (bps, change cooldown 7200 blocks), offline detection (100 missed leaders), slashing (500 bps = 5%) |
| Delegation | **High** | Delegate/undelegate/claim rewards, pending rewards tracked separately from `StakingState` bincode format |
| Light nodes | **Medium** | Separate escrow (20% of block reward = `LIGHT_REWARD_BPS`), witness submission, 100 slots, min bond 1K KUNA |

**Supply invariants:** `TOTAL_SUPPLY = FOUNDER_PREMINE (0.2M) + GENESIS_VALIDATOR_ALLOCATION (1M) + TREASURY_TOTAL (8M) + MINING_SUBSIDY_BUDGET (81M) = 90.2M KUNA`

**Genesis committee invariant:** a mainnet genesis must declare 15..=20 validators
(deduplicated across `genesis_validators.toml` and `validators.json`). The floor is
`MIN_ACTIVE_VALIDATORS`; the ceiling is the genesis allocation divided by the 50 000 KUNA
minimum stake, so 21 active validators is a post-genesis state, not a genesis one. Enforced
in `init_genesis` before any state is written, and in `--check-config` when a ceremony file
is present.

**Genesis file invariant:** `funded_accounts.toml` pre-funds arbitrary balances and is
refused outright on mainnet (chain 1) — at startup (`init_genesis`, before the
already-initialised early return), in `genesis_config_digest` (so no digest is ever
computed over it), and in `--check-config`. It remains accepted on 2/3/4/1337, where the
balances are test money. Rejection is a hard error rather than a silent skip: skipping
would boot a genesis different from the one the operator configured.

### 2.6 Cryptography — `kovanica-crypto` (CRITICAL)

| Primitive | Risk | Description |
|-----------|------|-------------|
| Ed25519 (dalek v2.1) | **Critical** | `sign`, `verify` (strict: rejects non-canonical S, weak/small-order keys), batch verify (strict per-item) |
| ECVRF (`ecvrf` crate v0.4.3) | **Critical** | `vrf_prove`, `vrf_verify`, `derive_vrf_secret_from_seed`, `vrf_hash_to_u64` for leader election. Construction: ristretto255 group, SHA3-512 hash-to-curve, SHA3-256 challenge (**untruncated, 32 B**) and SHA3-256 output (32 B) — **not** an RFC 9381 ciphersuite. Proof = `Gamma(32) ‖ c(32) ‖ s(32)` = **96 bytes**; block statements framing = `b"KUNA-VRF1"(9) ‖ hash(32) ‖ proof(96)` = **137 bytes**; `SubmitLightWitness` tx body carries the raw 96-byte proof. Random (non-deterministic) nonce ⇒ proofs are malleable, `beta` is deterministic. Pinned `curve25519-dalek` 3.2.0 via `ecvrf` (RUSTSEC-2024-0344, Scalar-subtraction timing variability — already suppressed in `.cargo/audit.toml`). **Licence note:** `ecvrf` 0.4.3 is **GPL-3.0-or-later** while this project ships under Apache-2.0 — please advise on compatibility. Full analysis + file:line map: `docs/archive/VRF-PROOF-LENGTH.md` |
| Vote signature format v1 | **Critical** | Domain `KUNA/vote/v1`, 74-byte encoding: `chain_id (LE) || epoch (LE) || voter (LE) || leader_round (LE) || leader_hash`; ctx built from LOCAL chain_id + committee epoch only |
| Commit seal format | **High** | Domain `KUNA/commit/v1`, covers `LeaderHeader` (state root, blue/non-blue roots, epoch, committee_hash) |
| Keystore v2 | **High** | Argon2id (64 MiB, 3 iter, 4 parallelism), XChaCha20-Poly1305, salt 16B, nonce 24B; v1 migration only |

### 2.7 RPC / JSON-RPC — `kovanica-rpc` (MEDIUM)

| Component | Risk | Description |
|-----------|------|-------------|
| `rpc_middleware.rs` | **Medium** | Rate limiting (token bucket per IP), auth (Bearer tokens), CORS, method classification (READ vs WRITE) |
| `rpc_methods.rs` | **Medium** | `kovanica_sendRawTransaction`, `kovanica_getBlock`, `kovanica_call` (WASM simulation), staking/contract methods |
| `subscriptions.rs` | **Low** | WebSocket event bus: `newBlock`, `newTransaction`, `vote`, `seal`, `health` |
| Request timeout | **Low** | 10s global timeout per call |

### 2.8 Keystore / Key Management — `kovanica-keystore` (HIGH)

- Argon2id parameters fixed (memory-hard, not tunable by user)
- Atomic write with `tempfile`, symlink refusal
- V1 read-only migration path (explicit `replace_file` with validation)
- Seed material never in cleartext on disk; `Zeroizing` for v1 secrets

### 2.9 Node Integration — `kovanica-node` (MEDIUM)

- Genesis/config loading, chain_id pinning to data dir
- Committee build from staking state (active validators only, stake ≥ 50K)
- Seal handling (local validators sign, non-validators store)
- Recovery: committed sub-DAG replay from DAG store, execution idempotency via `execution_committed_subdags` table
- Vote transfer (RFC-009): `VoteSync` requests votes for synced leader rounds, buffers out-of-order responses, bounds outstanding work (64), and retries with a bounded attempt count; the local vote is persisted at cast time

---

## 3. Out of Scope

- Frontend / wallet applications (`packages/`, `apps/`)
- CLI/TUI (`kovanica-cli`) — only the signing logic is in-scope via `kovanica-crypto`/`kovanica-types`
- Fuzzing harnesses (`fuzz/`)
- Deployment / ops tooling (`ops/`)
- Documentation

---

## 4. Highest-Risk Areas (Prioritized for Auditor Attention)

| Rank | Area | Rationale |
|------|------|-----------|
| 0 | **Committed-chain fork via node-local skip** (§2.1.1, PRO-35) | Two honest nodes can commit *different* leader blocks at the *same* height ⇒ divergent state roots, divergent subsidy/epoch schedule. Pre-existing, routinely reachable, blocks PRO-7. |
| 1 | **Consensus engine commit logic** (`engine.rs` `try_commit_and_deliver`, `committer.rs`) | Safety/liveness of the entire chain; fork resolution, late votes, skip persistence |
| 2 | **VRF leader election** (`mysticghost.rs`, `engine.rs` `scheduled_leader_for_round`) | Biasable leader selection → chain takeover; quorum threshold correctness |
| 3 | **GHOSTDAG colouring** (`ghostdag_scoped.rs`) | k=3 correctness, mergeset bounds, previous-tip seeding |
| 4 | **Vote signature verification** (`crypto.rs` `verify_vote_signature`) | Cross-chain/epoch replay, domain separation, strict verification |
| 5 | **Mempool RBF + in-flight timeout** | Fee sniping, transaction censorship, DoS via nonce exhaustion |
| 6 | **WASM gas/memory metering** | Out-of-gas handling, trap cleanup, host function reentrancy |
| 7 | **Staking slashing + delegation accounting** | Double-counting, arithmetic overflow, unbonding race conditions. Evidence-based slashing (RFC-010) and the PRO-19 jail (immediate deactivation, `JAIL_ROUNDS`, explicit-only reactivation, versioned store v2) are implemented, but slashing is gated off behind `SLASHING_ACTIVE_FROM_ROUND = u64::MAX`; it lands live only at the chain 4 reset. Leader reward and liveness are resolved through the epoch's frozen committee snapshot (not the live authority index), with a pre-transaction freeze and forfeit when the resolved leader is no longer active. |
| 8 | **P2P validation + peer scoring** | Eclipse/Sybil, invalid message amplification, scoring manipulation |

---

## 5. Test Coverage Notes

- Unit tests: 1035 passing across workspace, 1 ignored (2026-10-23)
- Integration tests: `sustained_liveness_integration`, `multi_node_integration`, `late_join_integration`
- Property tests: `proptest` in `kovanica-consensus` (wave arithmetic, committer properties)
- Fuzzing: Block, vote, transaction, consensus fuzzers (cargo-fuzz)
- Known flaky: `red_block_transactions_return_to_mempool_after_restart` (gossip timing)

---

## 6. Recommended Audit Approach

1. **Week 1–2:** Consensus (mysticghost, engine, committer, GHOSTDAG) + crypto (VRF, vote sigs)
2. **Week 3:** Mempool + P2P validation/scoring + staking tokenomics
3. **Week 4:** WASM runtime + contract host + RPC surface
4. **Week 5:** Integration review, cross-component invariants, report writing

---

## 7. Contact / Repository

- Repository: `https://github.com/your-org/kovanica` (private pre-audit)
- Branch: `main`
- Contact: [audit-contact@kovanica.example]
- Build: `cargo build --workspace --release`
- Test: `cargo test --workspace`

---

## 8. Version Pinning for Audit

```toml
# Key dependency versions (from Cargo.lock)
ed25519-dalek = "2.1.0"
ecvrf = "0.4.3"
libp2p = "0.57.0"
wasmi = "0.40.0"
redb = "2.1.0"
blake3 = "1.5.1"
argon2 = "0.5"
chacha20poly1305 = "0.10"
bincode = "1.3.3"  # unmaintained — consider migration
```

---

*End of scope document. This document should be shared with the audit firm under NDA.*
