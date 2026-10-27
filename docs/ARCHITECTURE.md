# Kovanica Architecture Overview

## High-level flow

```
Network (P2P)
    │
    ▼
Mempool ──────────────────────────────────┐
    │                                     │
    ▼                                     │
DAG Block Producer (per validator)        │
    │                                     │
    ▼                                     │
Consensus (Mysticeti-style DAG)           │
    │  produces CommittedSubDag           │
    ▼                                     │
Execution Layer ◄─────────────────────────┘
    │  - apply native txs
    │  - execute WASM contracts (Wasmi)
    │  - pay leader block reward
    │  - advance treasury vesting
    ▼
State (accounts, staking, contracts)
    │
    ▼
Storage (redb / pruning / snapshots)
```

## Reward path (detail)

1. `UniversalCommitter` decides a leader → `Linearizer` produces `CommittedSubDag`
2. Node calls `ExecutionContext::execute_committed_subdag(&subdag)`
3. Inside execution:
   - transactions are applied
   - `staking.on_leader_committed(subdag.leader_author)` is called
   - reward amount = `block_reward(committed_leader_height)`
   - balance of the leader's payout address is credited
   - treasury vesting is advanced

## Key crates

| Crate            | Responsibility                                      |
|------------------|-----------------------------------------------------|
| kovanica-types       | Core data structures                                |
| kovanica-crypto      | Signatures, hashing                                 |
| kovanica-dag         | Causal DAG store                                    |
| kovanica-consensus   | Commit rules, linearizer                            |
| kovanica-staking     | Emission, treasury, validator set                   |
| kovanica-runtime     | Wasmi WASM engine                                   |
| kovanica-execution   | State transition + reward distribution              |
| kovanica-node        | Binary that wires everything together               |

## Resource targets

- Full node comfortable on **2–4 GB RAM** VPS
- Aggressive pruning of committed DAG history
- Wasmi chosen for deterministic, low-footprint contract execution

---

## Deployment & Operations

### Docker Compose (Current Milestone)
- `docker-compose.yml` defines `kovanica-quorum-4` — 4-node in-process cluster for integration tests.
- Single-node validation via `ops/docker/` scripts.
- Focus remains on P2P multi-node soak before K8s orchestration.

### K8s / Helm (Deferred — Post-Testnet)
**Status**: deferred (see A13.2)
**Exit criteria**:
- Helm chart skeleton (`helm/` or `deploy/helm/`) with `StatefulSet` + `ConfigMap` for `kovanica-node`
- Persistent volume claim mapped to `KOVANICA_DATA`
- Liveness/readiness probes against `/api/head`

### Soak Testing
**6h / 3GB Memory Soak** (D15.5):
- Script: `ops/soak/soak.sh` (duration 21600s, interval 30s)
- Memory limit: `MEM_LIMIT=3G` via cgroup v2 `memory.max` (best-effort)
- Sampling: `/proc/<pid>/status` VmRSS, alert threshold >3G (3,145,728 KB)
- Expected RSS range (4-node devnet, transfer-only): 400–1200 MB
- Safety: `set -euo pipefail`; does not modify node binary or crate code

**24h Multi-node Soak** (E15.6):
- Deferred; 6h soak covers baseline
- Partition/recovery logic covered by deterministic in-process harness (`crates/kovanica-node/tests/multi_node_integration.rs`)

---

## Development Platform (Phase 22)

| Component | Status | Location |
|-----------|--------|----------|
| TypeScript API client | Implemented | `packages/api-client/src/index.ts` |
| OpenAPI / JSON schema generator | Implemented | `crates/kovanica-rpc/src/openapi.rs` |
| Contract SDK (Rust + TS) | Implemented | `kovanica-htlc`, `kovanica-vault`, `kovanica-multisig`, `kovanica-token` |
| Dev faucet service | Implemented | `crates/kovanica-faucet` |
| Indexer skeleton | Planned | WebSocket push subscriptions (`/ws`) |

---

## Execution / Gas (Phase C — Partial)

### Current State
- Wasmi runtime: `kovanica-runtime` crate present
- `gas_limit` / `gas_used` fields present in `kovanica-execution/src/lib.rs` (lines 107, 387)

### Missing (Before Mainnet)
- ABI spec for contract calls
- Gas pricing per opcode/byte
- Deterministic metering audit trail
- Wasmi config must set `fuel` consistently; verify no `random`/`time` sources

---

## Observability (Phase 21)

### Done
- `kovanica-consensus/src/metrics.rs` — registry and recorders: `block_height`
  (committed leader height), `current_round`, `peer_count`, `mempool_size`,
  `commit_latency` (wall-clock commit work), `rss_proxy`, `mergeset_size`,
  `mysticghost_*` (mergeset size, colouring duration, pruned blocks/waves),
  `rpc_*` (per-method requests, errors, latency)
- `kovanica_*` operational set (PRO-10, additive to the names above):
  `kovanica_committed_leaders_total`, `kovanica_skipped_leaders_total{reason}`
  (`timeout` / `indirect` / `direct_blame`), `kovanica_finality_latency_seconds`
  (node-local: first sighting of the leader block → durable commit),
  `kovanica_last_committed_round`, `kovanica_connected_peers`,
  `kovanica_active_validators`, `kovanica_sync_errors_total{kind}`,
  `kovanica_last_committed_digest_prefix`, `kovanica_rss_bytes`
- `alerts_reference_registered_metrics` is a test, not a convention: it parses
  every `expr:` in `ops/prometheus/alerts.yml` and fails if a rule alerts on a
  series the registry never exports. Five series were dead before this test
  existed.
- `GET /metrics` on the RPC listener, Prometheus text exposition
- `ops/prometheus/alerts.yml` (alert rules) and
  `ops/grafana/kovanica-overview.json` (dashboard)
- `prometheus-client = 0.25` in workspace Cargo.toml

### Notes
- Metric series are process-global; `block_height` must never be fed the local
  round (`current_round` exists for that) — the soak runner treats a
  non-increasing `block_height` as a stall.
- Alert rules YAML: `peer_drop`, `sync_stall`, `commit_lag`, `high_memory`
- `kovanica_last_committed_digest_prefix` is a gauge, not an info metric: a
  `digest` label would create one series per commit (~7 200/day).
- `kovanica_committee_peers_connected` is **not** exposed. The network layer
  identifies peers by libp2p `PeerId` and nothing binds a `PeerId` to a
  validator authority index, so any value would be a guess; a permanently-zero
  gauge is worse than an absent one. Implementing it needs a peer-identity
  exchange in the handshake.
- Structured logging (`tracing`) + optional `trace_id` per round

### Exit Criteria
Scrape `block_height`, `peer_count`, `commit_latency`, `mergeset_size` and
`kovanica_committed_leaders_total`; the dashboard shows a live commit rate and
`kovanica_finality_latency_seconds` has samples.

---

## Security — Threat Model (Phase 20)

> Deterministic, auditable, no `kovanica-protocol` mix.

### Scope
- Consensus: Mysticeti DAG, k=3, wave=3
- Execution: Wasmi, deterministic WASM
- Staking / validator set: 15–21, min 50k KUNA
- P2P: libp2p TCP + Noise + Yamux on :8000, DNS seeds only
- Keystore: client-side only — node never receives seed

### Hard Rules (Layer Classification)
- **Client-only**: keys stay in CLI / wallet; node never sees private seed
- **No raw hex in docs**: keystore paths documented, never literal hex
- **Encrypted keystore**: Argon2id + XChaCha20-Poly1305 (`kovanica-cli`)
- **Rate limit**: RPC write methods (`sendRawTransaction`) require bearer token (testnet open-read)
- **Memory budget**: hard cap `MemoryMax=3G` for 6h soak; RSS monitored

### Threats (Priority-Ranked)

| # | Threat | Mitigation |
|---|--------|------------|
| 1 | Key exposure (client-side leak) | Encrypted keystore + client-only path |
| 2 | Replay / nonce reuse | Strict sequential nonce in mempool + domain-separated hashes (`DOMAIN_TX`, `DOMAIN_BLOCK`) |
| 3 | Consensus fork / equivocation | Default: first-valid digest wins, a second digest is rejected. `use_min_digest_fork` (default off) may swap via `DagStore::replace_block` only while the round is undecided and the old digest has no children. Timeout skip on missing leader. |
| 4 | Double-sign / slash | `StakingState::slash` (fixed % evidence tx) |
| 5 | P2P eclipse / Sybil | DNS-only kovanica-native seeds (TBD; no third-party hosts); no orange-cloud peers |

### Fuzz Targets (Future)
- `StatementBlock` deserialize (`kovanica-dag`)
- `process_block` ingest (`kovanica-consensus`)
- Mempool admission (`kovanica-mempool`)

### Keystore Verification Checklist
- [ ] No literal hex in `README.md`, `AGENTS.md`, docs
- [ ] `kovanica-cli` uses `keystore` subcommand (encrypted)
- [ ] Node env never contains `KOVANICA_SEED` or `PRIVATE_KEY`

### Tokenomics (Locked — Never Edited Without Approval)
- Total: 90.2M KUNA (`9_020_000_000_000_000` atoms)
- Decimals: 9
- Founder premine: 200k KUNA; Treasury: 8M KUNA (linear 8yr)
- Subsidy: 2.5 KUNA / 8.1M blocks; decay ×3/4; reward only on committed leader

---

## OpenCode Agent Setup (Internal)

The `kovanica-opencode-setup/` package (now removed) provided:
- Specialized `kovanica` agent with strict isolation from `kovanica-protocol`
- `kovanica-plan` agent for planning-only workflows
- Permissions: `kovanica` = edit+bash allow, `external_directory: deny`; `kovanica-plan` = edit deny, bash ask
- Workflow: Ti → Grok (architect) → OpenCode (implement) → Grok (review)

Current agent config lives in root `AGENTS.md`, `.opencode/agents/kovanica.md`, `opencode.json`.

---

## Current Edit Notes (2026-10-13)

- `use_mysticghost` default = **true** in both `NodeConfig` and `ConsensusConfig` (an older note here said false; the code has defaulted to true for a while). `MysticGhostConfig::default()` is the separate colourer knob and does default `enabled: false`, which is what the committer overrides when it builds its own config. When enabled, `UniversalCommitter` applies scoped GHOSTDAG colouring. Since 2026-10-22 the `KOVANICA_MYSTICGHOST` override is only accepted on devnet/local chains.
- `init_genesis` extended with `founder_premine.hex` + `validators.json` support (Phase 14/16)
- Storage / staking compile fixes applied; `TASKLIST.md` updated
- Tokenomics locked (RFC-006 / `docs/TOKENOMICS.md`)
- Repo cleanup: removed 17 obsolete/duplicate files and 4 private keys
- All builds pass: `cargo check`, `clippy`, 394 unit tests
## Latest code snapshot (2026-10-13)

- `main`: `98d88cc` (tui + console merged; local edits committed)
- Workspace crates: 19 (`kovanica-*`); ~53k Rust LOC
- TS packages: `packages/api-client`, `packages/console`, `packages/signer`, `packages/web`
- Default P2P port: 8000; RPC: 8545; max peers: 50
- Workspace tests: 503+ passing (partial run stopped during sustained-liveness)
- Quarantined temp dirs cleaned; no `bot/*` remote branches remain
