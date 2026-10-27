# Kovanica (KUNA)

> A clean, from-scratch Rust Layer-1 blockchain implementing Mysticeti-style uncertified DAG consensus, account-based state with staked validators, deterministic Wasmi WebAssembly smart contracts, and a native light-client and decentralized communications stack.

**Status: Pre-Alpha / Active Development.**  
Not audited by an external security firm. Do not use with real value. Not for production.  
All tokenomics parameters and network protocols are binding per `AGENTS.md`.

<a id="adresni-format-kanonski"></a>
### Project & Address Identity
- **Network Name:** **Kovanica**
- **Native Coin Ticker:** **KUNA** (9 decimals: `1 KUNA = 1_000_000_000 atoms`)
- **Codebase / Namespace Prefix:** `kovanica` (`crates/kovanica-*`, `KOVANICA_*`, `@kovanica/*`)
- **Canonical Address Format (PRO-21):** Exactly 64 characters:
  ```text
  kvnc + 57 base32 characters + dag
  ```
  The 57 characters encode the 32-byte Ed25519 public key (256 bits) concatenated with the first 29 bits of its BLAKE3 hash MSB-first (`256 + 29 = 285 bits = 57 base32 chars` using the BIP-173 bech32 lowercase alphabet `qpzry9x8gf2tvdw0s3jn54khce6mua7l`, unpadded).
  - `FromStr for Address` strictly enforces the 64-character base32 form.
  - Legacy hex formats (`kvnc<72hex>dag` and bare/`0x` 64-hex keys) are supported **only** on Devnet (`3`), Testnet v2 (`4`), and Local (`1337`).
  - Mainnet (`1`), Testnet (`2`), and all other chain IDs strictly reject legacy formats (`legacy_address_allowed = false`).
  - **Rule:** Never use "KVNC" as a currency or token ticker (the currency is strictly **KUNA**).

---

## 1. Core Architecture

Kovanica is engineered from scratch in Rust for high throughput and predictable low latency, designed to run comfortably on standard 2–4 GB RAM virtual servers:

1. **Mysticeti-Style Uncertified DAG Consensus:**
   - Wave-based consensus progression with wave length `WAVE_LENGTH = 3` DAG rounds (Leader $\to$ Vote $\to$ Decide).
   - Direct quorum commits ($2f+1$ stake threshold) and recursive indirect causal commit rules without intermediate certificate synchronization.
   - Target consensus round duration: `4,000 ms` (4 s), yielding a committed leader block every `12 s` (`LEADER_INTERVAL_SECS = 12`).
   - Leader election: stake-weighted verifiable random function via the `ecvrf` crate (Ristretto255 + SHA3-512, 96-byte proof; see `docs/archive/VRF-PROOF-LENGTH.md`), falling back to stake-weighted round-robin when VRF keys are unpopulated.
   - **MysticGhost Hybrid Colouring:** Scoped GHOSTDAG ($k=3$) sub-DAG topological sort for transactions; uncoloured (non-blue) blocks are safely recycled back to the mempool without transaction loss.
2. **Account Model & Staking:**
   - Account-based ledger tracking nonces, balances, contract storage, and validator stakes.
   - Active validator set target: **15 to 21 active validators** with a minimum self-stake of **50,000 KUNA**.
   - Deterministic committee epoch rotation every **8 hours** (`EPOCH_ROUNDS = 7,200` DAG rounds = `EPOCH_LEADER_HEIGHTS = 2,400` committed leader heights).
   - Stake unbonding cooldown: **100,000 committed leader blocks** ($\approx 13.9$ days at 12 s/leader).
   - Evidence-based slashing (RFC-010) with fixed 500 bps (5%) penalty and 7,200 committed heights jail.
3. **Execution & WebAssembly Runtime:**
   - Deterministic smart contract sandbox powered by **Wasmi** (v0.40) with instruction-level fuel metering, strict memory paging limits (16 pages = 1 MiB), and isolated host call ABI (`Host` trait).
   - Native built-in contracts with shared execution semantics: **HTLC** (hash time-locked swaps), **Vault** (linear/cliff vesting), **Multisig** ($M$-of-$N$ threshold multi-signature), **Token** (fungible token standard), and **Name Registry** (RFC-008 decentralized comms naming).
4. **P2P Networking & Storage:**
   - Built on `libp2p` with TCP, Noise transport encryption, Yamux multiplexing, Kademlia routing, and Gossipsub message propagation with peer scoring.
   - Embedded storage using **redb** with dedicated tables for blocks, DAG state, transactions, receipts, and consensus decisions, featuring opt-in background history retention/pruning.
5. **Light Client & Decentralized Comms:**
   - Light-client verification (`kovanica-light`, `kovanica-lightnode`) following committed leader headers and committee seals without full DAG execution. Light nodes earn a 20% block reward share across 32 witness slots.
   - UniFFI mobile bindings (`kovanica-light-ffi`) powering native Android and iOS light wallet clients.
   - Cryptographic communications suite (`kovanica-comms-core`, `kovanica-comms-crypto`, `kovanica-comms-relay`) providing E2E sealed messaging (X25519 + XChaCha20-Poly1305) and canonical comms identity.

---

## 2. Tokenomics (Frozen & Normative)

Canonical parameters implemented in `crates/kovanica-staking/src/lib.rs` and documented in [`docs/TOKENOMICS.md`](docs/TOKENOMICS.md):

| Parameter | Value | Description |
|-----------|-------|-------------|
| **Total Supply** | **90,200,000 KUNA** | Hard maximum supply ceiling (`90_200_000 * 10^9` atoms) |
| **Decimals** | **9** | Smallest unit: 1 atom = $10^{-9}$ KUNA |
| **Founder Premine** | **200,000 KUNA** | Allocated at genesis to the founder address |
| **Genesis Validator Allocation** | **1,000,000 KUNA** | Split evenly across 5–20 genesis validators (dust distributed deterministically) |
| **Treasury Allocation** | **8,000,000 KUNA** | Linear vesting over 8 years (1,000,000 KUNA/year) for development and grants |
| **Mining Subsidy Budget** | **81,000,000 KUNA** | Derived subsidy pool: $90.2\text{M} - 0.2\text{M} - 8\text{M} - 1\text{M} = 81\text{M}$ KUNA |
| **Initial Block Reward** | **2.5 KUNA** | Minted exclusively on committed leader blocks ($5 \times 10^9 / 2$ atoms) |
| **Subsidy Era Length** | **8,100,000 blocks** | Committed leader blocks per era |
| **Reward Decay Rate** | **$\times 3/4$** | Emission multiplies by $3/4$ (25% decay) at each era boundary |
| **Minimum Validator Stake** | **50,000 KUNA** | Minimum self-bond required to enter the active validator committee |
| **Active Committee Size** | **15–21** | Active consensus validator range |
| **Unbonding Period** | **100,000 blocks** | Committed leader blocks ($\approx 13.9$ days at 12 s/leader) |
| **Epoch Duration** | **8 hours** | 7,200 DAG rounds = 2,400 committed leader heights (independent of era) |
| **Slashing Penalty** | **500 bps (5%)** | Penalty applied on verifiable equivocation evidence |
| **Light-Node Reward Share** | **20% (2,000 bps)** | Escrowed for light-node witnesses across 32 winning slots per epoch |
| **Target Round Duration** | **4,000 ms (4 s)** | Consensus round duration $\to$ 1 committed leader every 12 seconds |

---

## 3. Repository Layout

The monorepo is organized into 27 workspace crates, 5 TypeScript packages, 6 applications, operational deployment scripts, and specifications:

```text
├── crates/                    # 27 workspace Rust crates
│   ├── kovanica-types         # Core primitives (Block, Transaction, Address, Committee, Proofs)
│   ├── kovanica-crypto        # Ed25519, BLAKE3, and Ristretto255 ECVRF cryptographic primitives
│   ├── kovanica-keystore      # Encrypted keystore v2 (Argon2id + XChaCha20-Poly1305)
│   ├── kovanica-storage       # redb embedded storage engines, state trees, and pruning
│   ├── kovanica-dag           # Causal history DAG, block manager, and mergesets
│   ├── kovanica-consensus     # Mysticeti wave consensus, committer, MysticGhost, leader election
│   ├── kovanica-mempool       # Nonce-tracking fee-priority transaction pool
│   ├── kovanica-network       # libp2p swarm (TCP, Noise, Yamux, Gossipsub, peer scoring)
│   ├── kovanica-runtime       # Wasmi WebAssembly engine and gas metering
│   ├── kovanica-execution     # State transitions, GHOSTDAG execution ordering, rewards
│   ├── kovanica-staking       # Staking state, emission curves, validator lifecycle, slashing
│   ├── kovanica-node          # Full-node daemon binary (kovanica-node) and genesis tooling
│   ├── kovanica-cli           # CLI client (kovanica), benchmark runner, validator generators, TUI
│   ├── kovanica-rpc           # JSON-RPC 2.0 & WebSocket server, metrics, OpenAPI generator
│   ├── kovanica-common        # Shared contract types, Host trait, and WASM bindings
│   ├── kovanica-htlc          # Hash Time-Locked Contract (atomic swaps)
│   ├── kovanica-vault         # Time-lock and linear vesting vault contracts
│   ├── kovanica-multisig      # M-of-N threshold multisig contract
│   ├── kovanica-token         # Standardized fungible token contract
│   ├── kovanica-name-registry # On-chain comms name registry smart contract (RFC-008)
│   ├── kovanica-faucet        # Rate-limited testnet faucet daemon
│   ├── kovanica-light         # Light-client verification engine (headers, seals, proofs)
│   ├── kovanica-lightnode     # Light node daemon binary (kovanica-lightnode)
│   ├── kovanica-light-ffi     # UniFFI language bindings for mobile integration
│   ├── kovanica-comms-core    # Canonical comms identity derivation
│   ├── kovanica-comms-crypto  # 1:1 E2E message encryption (X25519 + XChaCha20-Poly1305)
│   └── kovanica-comms-relay   # Store-and-forward relay server for opaque comms envelopes
├── packages/                  # 5 TypeScript packages
│   ├── api-client             # Minimal typed fetch client for JSON-RPC
│   ├── comms                  # Comms app TypeScript glue (identity & RPC)
│   ├── console                # React 18 + Vite web console for node management
│   ├── signer                 # Browser transaction signer (v1 signature format)
│   └── web                    # React 18 + Vite block explorer application
├── apps/                      # 6 client applications
│   ├── android                # Android light client app (Kotlin + UniFFI)
│   ├── android-comms          # Android decentralized comms app (Kotlin)
│   ├── android-wallet         # Android wallet application (Kotlin)
│   ├── console-desktop        # Desktop node console (Tauri v2 + React)
│   ├── desktop                # Desktop comms client (Tauri v2 + React)
│   └── ios                    # iOS light client app (SwiftUI)
├── docs/                      # Technical specifications, RFCs, ADRs, and guides
│   ├── adr/                   # Architecture Decision Records (0001 Weighted Consensus, 0002 Keystore)
│   ├── design/                # In-depth designs (epoch rotation, multi-proposer DAG)
│   ├── rfcs/                  # Wire protocol RFCs (RFC-009 Vote Sync, RFC-010 Slashing, RFC-011 Skips)
│   └── archive/               # Historical plans, runbooks, and superseded drafts (README indexed)
├── ops/                       # Docker compose, genesis ceremony, benchmark, and monitoring configs
└── scripts/                   # Validation, hook installation, and build helper scripts
```

---

## 4. Quick Start Guide

### Prerequisites
- **Rust Toolchain:** Stable Rust (MSRV 1.90+).
- **C Compiler & CMake:** Required for building cryptographic and storage C dependencies.
- **Node.js (Optional):** Version 18+ for building packages in `packages/` and desktop webviews.

### 4.1 Building and Testing the Workspace

Clone the repository and compile all workspace crates:

```bash
git clone https://github.com/KovanicaDAG/kovanica.git
cd kovanica

# Build the complete Rust workspace
cargo build --workspace

# Run the test suite (excluding long-running stress tests)
cargo test --workspace -- --skip sustained_liveness

# Local quality gate (GitHub Actions workflows removed 2026-10-23; run locally)
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo test --doc
cargo doc --no-deps --all-features
cargo audit
cargo +1.90 build --all-targets
```

---

### 4.2 Running a Local Read-Only / RPC Node

The fastest way to run a local node for development and JSON-RPC access without generating validator signing keys:

```bash
# Copy example configuration
cp config.example.toml config.toml

# Start the node as a non-validating read-only RPC node:
KOVANICA_RUN_VALIDATOR=false cargo run -p kovanica-node -- --config config.toml
```

*(Alternatively, set `run_validator = false` inside `config.toml` and launch `cargo run -p kovanica-node -- --config config.toml`).*

**Verify node health:**
```bash
curl -fsS http://127.0.0.1:8545/health
# Returns: {"status":"ok","peer_count":0,"is_healthy":true,...} (HTTP 200)
```

---

### 4.3 Running a Local Validator Node

To run an active validating node that participates in consensus block proposals:

1. **Generate a validator signing key:**
   ```bash
   # Generate a 32-byte hex seed (mode 0600)
   python -c "import secrets; print(secrets.token_hex(32))" > validator.key
   chmod 600 validator.key
   ```
2. **Configure `config.toml`:**
   ```toml
   run_validator = true
   validator_key = "validator.key"
   data_dir = "./data"
   listen_addr = "0.0.0.0:8000"
   rpc_addr = "127.0.0.1"
   rpc_port = 8545
   ```
3. **Verify configuration without booting:**
   ```bash
   cargo run -p kovanica-node -- --config config.toml --check-config
   ```
4. **Boot the validator node:**
   ```bash
   cargo run -p kovanica-node -- --config config.toml
   ```

---

### 4.4 Interacting via JSON-RPC 2.0

The node exposes HTTP JSON-RPC 2.0 on `POST /rpc`, WebSocket push events on `GET /ws`, health checks on `GET /health`, and Prometheus metrics on `GET /metrics`.

**Query current block height:**
```bash
curl -s -X POST http://127.0.0.1:8545/rpc \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"kovanica_blockNumber","params":[]}'
```
Response:
```json
{"jsonrpc":"2.0","id":1,"result":"0x0"}
```

**Query node sync status:**
```bash
curl -s -X POST http://127.0.0.1:8545/rpc \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":2,"method":"kovanica_syncStatus","params":[]}'
```

**Supported JSON-RPC Methods (27 Core Methods):**
- **Chain & Block:** `kovanica_blockNumber`, `kovanica_getBlockByHash`, `kovanica_getBlockByNumber`, `kovanica_syncStatus`
- **Transactions & Accounts:** `kovanica_sendRawTransaction`, `kovanica_getTransactionReceipt`, `kovanica_getTransactionByHash`, `kovanica_getTransactionHistory`, `kovanica_getPendingTransactions`, `kovanica_estimateFee`, `kovanica_getBalance`, `kovanica_getNonce`, `kovanica_getCode`, `kovanica_getStorageAt`, `kovanica_getLogs`
- **Consensus & Staking:** `kovanica_getValidators`, `kovanica_getStake`, `kovanica_getRewards`, `kovanica_getLeaderSchedule`, `kovanica_getCommittee`, `kovanica_getCommitteeInfo`
- **Light Client & Verification:** `kovanica_getLeaderHeader`, `kovanica_getCommitSeals`, `kovanica_getTxProof`, `kovanica_getAccountProof`, `kovanica_getLightSet`, `kovanica_lightClientCheckpoint`

**WebSocket Subscription Topics (`GET /ws`):**
- `newHeads`: Emitted when a new block is accepted into the DAG.
- `newCommittedLeader`: Emitted when consensus commits a leader sub-DAG.
- `pendingTransactions`: Emitted when a validated transaction enters the mempool.
- `logs`: Emitted for execution receipts of committed sub-DAG transactions.
- `newSealedHeader`: Emitted when an executed leader header is sealed.

---

### 4.5 CLI Client Usage (`kovanica`)

The `kovanica-cli` crate provides the primary command-line wallet and management tool:

```bash
# Key management (creates encrypted keystore.json using Argon2id + XChaCha20-Poly1305)
cargo run -p kovanica-cli --bin kovanica -- keygen --out keystore.json

# Derive canonical PRO-21 address from keystore
cargo run -p kovanica-cli --bin kovanica -- address --key-file keystore.json

# Launch interactive Terminal User Interface (TUI) wallet
cargo run -p kovanica-cli --bin kovanica -- tui --keystore keystore.json

# Query account balance
cargo run -p kovanica-cli --bin kovanica -- balance <address>

# Transfer KUNA (atoms: 1 KUNA = 1_000_000_000 atoms)
cargo run -p kovanica-cli --bin kovanica -- transfer \
  --to <recipient-address> \
  --amount 1000000000 \
  --keystore keystore.json

# Stake as a validator (minimum 50,000 KUNA)
cargo run -p kovanica-cli --bin kovanica -- stake \
  --amount 50000000000000 \
  --keystore keystore.json

# Delegate to an active validator
cargo run -p kovanica-cli --bin kovanica -- delegate \
  --validator <validator-address> \
  --amount 10000000000 \
  --keystore keystore.json
```

---

### 4.6 Multi-Node Devnet via Docker Compose

To run a complete 4-node local testnet (1 seed node + 3 active consensus validators):

```bash
# 1. Build CLI binary for devnet key generation
cargo build --release -p kovanica-cli

# 2. Generate local devnet validator keys and genesis
./ops/docker/validators/generate.sh

# 3. Build Docker container image
docker build -t kovanica-node:local .

# 4. Launch the compose cluster
docker compose up -d

# 5. Check cluster health and logs
docker compose ps
curl -fsS http://127.0.0.1:8545/health
curl -fsS http://127.0.0.1:8546/health
```

---

## 5. Network Configuration & Registry

Default network configuration parameters (`crates/kovanica-node/src/config.rs`):

| Parameter | Environment Variable | Default Value | Description |
|-----------|----------------------|---------------|-------------|
| `data_dir` | `KOVANICA_DATA_DIR` | `./data` | Database storage directory |
| `listen_addr` | `KOVANICA_LISTEN_ADDR` | `0.0.0.0:8000` | P2P listen address (TCP) |
| `rpc_addr` | `KOVANICA_RPC_ADDR` | `127.0.0.1` | JSON-RPC bind host |
| `rpc_port` | `KOVANICA_RPC_PORT` | `8545` | JSON-RPC HTTP/WS port |
| `bootnodes` | `KOVANICA_BOOTNODES` | `[]` (empty) | Comma-separated bootstrap peer multiaddrs |
| `max_peers` | `KOVANICA_MAX_PEERS` | `50` | Maximum active P2P peers |
| `round_duration_ms` | `KOVANICA_ROUND_DURATION_MS` | `4000` | Consensus round target duration in ms |
| `run_validator` | `KOVANICA_RUN_VALIDATOR` | `true` | Participate in block authoring and consensus |
| `rpc_rate_limit_per_min` | `KOVANICA_RPC_RATE_LIMIT_PER_MIN` | `60` | Token-bucket rate limit per client IP |

### Chain ID Registry
- **`1`**: **Mainnet** (`MAINNET`) — strictly enforces PRO-21 canonical base32 addresses; consensus parameters frozen.
- **`2`**: **Testnet (legacy)** (`TESTNET`) — not the public testnet; enforces PRO-21 addresses.
- **`3`**: **Devnet** (`DEVNET`) — lenient address parsing; allows parameter overrides.
- **`4`**: **Public Testnet** (`TESTNET_V2`) — the public testnet; supports PRO-21 and legacy migration.
- **`1337`**: **Local Devnet** (`LOCAL`) — single-node / local cluster testing.

---

## 6. Key Documentation Links

Detailed architectural specifications and operational runbooks:

- **System Architecture:** [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)
- **Tokenomics Specification:** [`docs/TOKENOMICS.md`](docs/TOKENOMICS.md)
- **Contract Execution & ABI:** [`docs/CONTRACTS.md`](docs/CONTRACTS.md) and [`docs/EXAMPLES.md`](docs/EXAMPLES.md)
- **Gas & Metering Schedule:** [`docs/GAS_SCHEDULE.md`](docs/GAS_SCHEDULE.md)
- **Signature & Domain Format:** [`docs/SIGNATURE_FORMAT.md`](docs/SIGNATURE_FORMAT.md)
- **Validator Onboarding Guide:** [`docs/VALIDATOR-ONBOARDING.md`](docs/VALIDATOR-ONBOARDING.md)
- **Governance Specification:** [`docs/GOVERNANCE.md`](docs/GOVERNANCE.md)
- **Audit Scope & Threat Model:** [`docs/AUDIT-SCOPE.md`](docs/AUDIT-SCOPE.md)
- **Documentation Archive Index:** [`docs/archive/README.md`](docs/archive/README.md)
- **JSON-RPC Reference:** [`docs/RPC.md`](docs/RPC.md)
- **Comprehensive 2026 Audit Report:** [`docs/AUDIT_REPORT_2026.md`](docs/AUDIT_REPORT_2026.md)

---

## 7. Status, Security & License

- **Project Status:** Pre-Alpha. Active testnets are running with ongoing stress testing and performance tuning.
- **Quality Gates & CI:** GitHub Actions workflows were decommissioned on 2026-10-23 (Toni). CI moves to the public `KovanicaDAG/kovanica-protocol` repo once the frozen code is there. Until then, quality checks are run locally via the local gate commands (`cargo fmt`, `clippy`, `cargo test`, `cargo test --doc`, `cargo doc`, `cargo audit`, and `cargo +1.90 build`).
- **Security Audit:** Automated security checks (`AUTOMATED_SECURITY_CHECKS.md`) and pre-audit vulnerability catalogues (`AUDIT_REPORT.md`) are maintained. Professional third-party security audits are planned prior to mainnet launch.
- **License:** The Kovanica codebase is distributed under the **Apache License, Version 2.0**.
