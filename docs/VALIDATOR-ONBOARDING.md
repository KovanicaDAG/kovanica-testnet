# Kovanica Testnet Validator Onboarding Guide

This guide walks you through becoming a validator on the **Kovanica testnet** (chain ID: `2`).

**Status:** Active — testnet onboarding guide (chain ID `2`).
**Consensus impact:** none — client-only documentation; no consensus or ledger rule change.

---

## 1. Prerequisites

| Requirement | Specification |
|-------------|---------------|
| **Hardware** | 2–4 GB RAM VPS, 2 vCPU, 50 GB SSD |
| **OS** | Ubuntu 22.04+ / Debian 12+ (systemd) |
| **Network** | Public IPv4, port `8000` (TCP) open for P2P |
| **Software** | Docker 24+ **or** Rust 1.90+ toolchain |
| **Keys** | Ed25519 validator key + VRF key pair (generated below) |

> **Note**: Testnet uses chain ID `2`. Local devnet uses `1337`. Mainnet will use `1`.

---

## 2. Key Generation

### 2.1 Validator Identity Key (Ed25519)

```bash
# Using kovanica-cli (recommended)
cargo install --path crates/kovanica-cli
kovanica-cli key generate --output validator.keystore

# Or manually with openssl
openssl genpkey -algorithm ed25519 -out validator.key
# Convert to KVNC keystore format if needed
```

The keystore file is encrypted with a passphrase. **Store the passphrase securely.**

### 2.2 VRF Key Pair (for leader selection)

```bash
# Using kovanica-cli (VRF key generation included in key generate)
kovanica-cli key generate --output validator.keystore --with-vrf

# The VRF public key will be embedded in the keystore
# You can also extract it:
kovanica-cli key inspect --keystore validator.keystore
```

> **Why VRF?** Kovanica uses stake-weighted VRF leader selection. The implementation is the `ecvrf` 0.4.3 crate (ristretto255 group + SHA3-512 hash-to-curve, 32-byte output, 96-byte proof) — it is **not** an RFC 9381 ciphersuite, despite the older "ECVRF-ED25519-SHA512-Elligator2" label that used to appear here. See `docs/archive/VRF-PROOF-LENGTH.md` for the suite, the byte layout and why the RFC 9381 80-byte proof length does not apply. The VRF public key must be registered at genesis.

---

## 3. Genesis Participation

### 3.1 Submit Your Keys

Before the genesis ceremony, submit to the testnet coordinators:

1. **Validator Ed25519 public key** (from keystore)
2. **VRF public key** (from keystore)
3. **P2P address** (your public IP:8000)
4. **Desired stake amount** (≥ 50,000 KUNA)

### 3.2 Genesis Ceremony

Coordinators will:
1. Collect all validator keys
2. Generate `genesis.json` with staking state
3. Distribute `genesis.json` + `genesis_validators.toml`

You will receive:
- `genesis.json` — genesis block + initial staking state
- `genesis_validators.toml` — validator set with VRF keys

**Use the bundle byte for byte.** The node derives its network tag
(`<chain_id>-<16 hex>`) from the chain id, the treasury address, the binary's
genesis-block digest, and every genesis file in the data directory
(`validators.json`, `founder_premine.hex`, `funded_accounts.toml`,
`genesis_validators.toml`). Every node of the chain needs the same `chain_id`,
the same binary and the same file set. A missing file changes the tag: a node
that lacks one of those files does not match a node that has it. The treasury
comes from `treasury_address` in the config, or from `KOVANICA_TREASURY_ADDRESS`
when that variable is set. If both are unset, the all-zero address goes into
the digest.

This applies to validators, seeds, RPC nodes, the explorer and the faucet
alike. In the data directory, before the first start:

```sh
sha256sum -c SHA256SUMS
kovanica-node network-tag --config kovanica.toml
```

`SHA256SUMS` lists the bundle files. Off mainnet that can include
`funded_accounts.toml`. On mainnet (chain 1) the file is forbidden, so the
checksum list must not name it. `network-tag` prints the tag
without starting a node; it must equal the tag published with the checksums.
The publication place is chosen when the bundle is cut (it is not named in
this repo). A running node returns the same value as `networkTag` on
`kovanica_syncStatus` and logs
`network identity: peers must share this tag … network_tag=…`.
See `docs/TESTNET-RESET.md`. How the ceremony assembles the files is in
`docs/GENESIS-CEREMONY.md`.

---

## 4. Node Configuration

### 4.1 Copy Example Config

```bash
cp config.example.toml kovanica.toml
```

### 4.2 Edit `kovanica.toml` for Validator

```toml
# Network
listen_addr = "0.0.0.0:8000"          # P2P port (must be publicly reachable)
rpc_addr = "127.0.0.1:8545"           # JSON-RPC (bind to localhost only!)
bootnodes = [
    "seed1.kovanica.online:8000",           # testnet seed 1
    "seed2.kovanica.online:8000",              # testnet seed 2
    "seed3.kovanica.online:8000"               # testnet seed 3
]

# Validator
run_validator = true                   # Enable block production
validator_key = "/path/to/validator.keystore"
validator_key_pass = "your-passphrase" # Or use KOVANICA_VALIDATOR_KEY_PASS env var

# Data directory
data_dir = "/var/lib/kovanica"

# Optional: enable faucet (only for seed nodes)
# faucet = false
```

### 4.3 Environment Variables (Alternative to Config File)

```bash
export KOVANICA_LISTEN_ADDR=0.0.0.0:8000
export KOVANICA_RPC_ADDR=127.0.0.1
export KOVANICA_RPC_PORT=8545
export KOVANICA_BOOTNODES="seed1.kovanica.online:8000,seed2.kovanica.online:8000,seed3.kovanica.online:8000"
export KOVANICA_DATA_DIR="/var/lib/kovanica"
export KOVANICA_VALIDATOR_KEY="/path/to/validator.key"
export KOVANICA_RUN_VALIDATOR=true
```

---

## 5. Staking

### 5.1 Minimum Stake

| Parameter | Value |
|-----------|-------|
| **Min stake** | 50,000 KUNA (50,000,000,000,000 atoms) |
| **Active validators** | 15–21 |
| **Epoch** | 7,200 DAG rounds = 2,400 committed leader blocks (~8 h) |
| **Unbonding** | 100 000 committed leader blocks (~13.9 days at 12 s/leader) — **not** 1 epoch |

### 5.2 Stake via CLI

```bash
# Get testnet KUNA from faucet first
curl -X POST https://faucet-testnet.kovanica.online/faucet \
  -H "Content-Type: application/json" \
  -d '{"address": "kvnc<your-address>dag"}'

# Stake
kovanica-cli stake \
  --keystore /path/to/validator.keystore \
  --amount 50000000000000 \
  --chain-id 2 \
  --rpc-url http://127.0.0.1:8545
```

### 5.3 Delegate (Optional)

```bash
# Delegate to another validator
kovanica-cli delegate \
  --keystore /path/to/delegator.keystore \
  --validator <validator-address> \
  --amount 10000000000000 \
  --chain-id 2
```

---

## 6. Running the Node

### Option A: Docker Compose (Recommended)

```yaml
# docker-compose.yml
version: '3.8'
services:
  kovanica:
    image: ghcr.io/kovanica/kovanica-node:latest
    container_name: kovanica-validator
    restart: unless-stopped
    ports:
      - "8000:8000"          # P2P
      - "127.0.0.1:8545:8545" # RPC (localhost only)
    volumes:
      - ./kovanica.toml:/kovanica.toml:ro
      - ./validator.keystore:/validator.keystore:ro
      - kovanica-data:/var/lib/kovanica
    environment:
      - KOVANICA_VALIDATOR_KEY=/validator.keystore
      - KOVANICA_VALIDATOR_KEY_PASS=${VALIDATOR_PASS}
    deploy:
      resources:
        limits:
          memory: 3G
          cpus: '2.0'

volumes:
  kovanica-data:
```

```bash
export VALIDATOR_PASS="your-passphrase"
docker compose up -d
```

### Option B: Systemd Service

```ini
# /etc/systemd/system/kovanica.service
[Unit]
Description=Kovanica Validator Node
After=network.target

[Service]
Type=simple
User=kovanica
WorkingDirectory=/opt/kovanica
ExecStart=/opt/kovanica/kovanica-node --config /opt/kovanica/kovanica.toml
Restart=on-failure
RestartSec=10
LimitNOFILE=65536
Environment=KOVANICA_VALIDATOR_KEY=/opt/kovanica/validator.keystore
Environment=KOVANICA_VALIDATOR_KEY_PASS=your-passphrase

# Resource limits (cgroup v2)
MemoryMax=3G
CPUQuota=200%
IOWeight=100

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now kovanica
```

### Option C: Binary Directly

```bash
# Build from source
cargo build --release -p kovanica-node

# Run
./target/release/kovanica-node --config kovanica.toml
```

---

## 7. Monitoring

### 7.1 Health Check

```bash
curl http://127.0.0.1:8545/health
# {"status":"ok","height":12345,"peers":3,"round":456}
```

### 7.2 Prometheus Metrics

```bash
curl http://127.0.0.1:8545/metrics
# Exposes: block_height, current_round, mempool_size, peer_count,
# commit_latency, rss_proxy, mysticghost_*, rpc_*, plus the kovanica_* set:
#   kovanica_committed_leaders_total, kovanica_skipped_leaders_total{reason},
#   kovanica_finality_latency_seconds (histogram),
#   kovanica_last_committed_round, kovanica_connected_peers,
#   kovanica_active_validators, kovanica_sync_errors_total{kind},
#   kovanica_last_committed_digest_prefix, kovanica_rss_bytes
```

`block_height` is the **committed leader** height; `current_round` is the local
round counter (three rounds pass per committed leader at the default 4 s round /
12 s leader cadence). Use `block_height`, not `current_round`, to judge chain
progress.

The `kovanica_*` series are additive: the unprefixed names above are unchanged
so existing dashboards keep working.

`kovanica_finality_latency_seconds` is **node-local**: it measures from the
moment this node first held the leader block to the durable commit, not from
the proposal (`StatementBlock` has no timestamp).

`kovanica_last_committed_digest_prefix` is the leading 64 bits of the last
committed leader digest as a number. Scrape it from several validators: equal
values mean they committed the same history, different values mean they
diverged. It is a gauge, not an info metric, so it stays at one series per node
instead of one series per committed block.

### 7.3 Grafana Dashboard

Import `ops/grafana/kovanica-overview.json` for:
- Committed height & current round
- Mempool size & transaction throughput
- Peer count & sync status
- Commit latency
- Memory (RSS)

### 7.4 Key Metrics to Watch

Thresholds match `ops/prometheus/alerts.yml`.

| Metric | Healthy Range | Alert If |
|--------|---------------|----------|
| `block_height` | Increasing | No increase for 5 min |
| `peer_count` | ≥ 3 | < 3 for 2 min |
| `mempool_size` | < 1,000 | > 1,000 for 5 min |
| `commit_latency` | < 500 ms | > 5,000 ms for 3 min |
| `rss_proxy` | < 3,000 MB | > 3,000 MB warn / > 3,500 MB critical |
| `kovanica_active_validators` | 15–21 | Outside that range |
| `kovanica_skipped_leaders_total{reason="timeout"}` | Rarely increases | Any increase = a leader block missed its deadline; since PRO-35 the chain **stalls** instead of skipping, so a sustained increase pairs with a frozen `block_height` (liveness incident, not a fork) |
| `kovanica_sync_errors_total{kind}` | Flat | Sustained increase = a peer or range is failing |
| `kovanica_last_committed_digest_prefix` | Same across validators | Any validator differing = divergence |

---

## 8. Testnet Specifics

| Parameter | Value |
|-----------|-------|
| **Chain ID** | `2` |
| **RPC endpoint** | `http://<your-ip>:8545` (local) / `https://rpc-testnet.kovanica.online` (public) |
| **Explorer** | `https://explorer.kovanica.online` |
| **Faucet** | `https://faucet-testnet.kovanica.online` (3 req/hr/IP, 10 KUNA) |
| **Seed nodes** | `seed1.kovanica.online:8000`, `seed2.kovanica.online:8000`, `seed3.kovanica.online:8000` |
| **Genesis file** | Distributed by coordinators |

### 8.1 Get Test KUNA

```bash
# Via CLI
kovanica-cli faucet --address kvnc<your-address>dag --chain-id 2

# Via HTTP
curl -X POST https://faucet-testnet.kovanica.online/faucet \
  -H "Content-Type: application/json" \
  -d '{"address": "kvnc<your-address>dag"}'
```

---

## 9. Troubleshooting

### 9.1 Peers Not Connecting

| Symptom | Cause | Fix |
|---------|-------|-----|
| `peer_count = 0` | Port 8000 blocked | Open TCP 8000 in firewall/security group |
| `peer_count = 1` | Only one seed reachable | Check all 3 seed IPs; verify `bootnodes` config |
| `dial error` | IPv6 mismatch | Ensure `listen_addr = "0.0.0.0:8000"` (not `::`) |

### 9.2 Sync Stuck

| Symptom | Cause | Fix |
|---------|-------|-----|
| Height not increasing | Non-blue blocks, fork | Check logs for `non_blue` / `fork` messages; restart node |
| `round` not advancing | No quorum | Verify ≥ 3 peers; check seed nodes are up |
| `mempool_size` growing | Transactions not committing | Check if you're leader; verify stake ≥ 50K KUNA |

### 9.3 RPC Errors

| Error | Cause | Fix |
|-------|-------|-----|
| `connection refused` | RPC not bound | Check `rpc_addr = "127.0.0.1:8545"` and firewall |
| `chain_id mismatch` | Wrong chain ID | Use `--chain-id 2` for testnet |
| `nonce too low` | Stale local state | Restart node to resync |

### 9.4 Validator Not Producing Blocks

| Check | Command |
|-------|---------|
| Am I in active set? | `curl -s http://127.0.0.1:8545/rpc -d '{"method":"kovanica_getValidators"}'` |
| Is my stake ≥ 50K? | `kovanica-cli balance --address <your-address>` |
| Is VRF key registered? | `kovanica-cli key inspect --keystore validator.keystore` |
| Is node leader this round? | Check `round` in `/health` vs your validator index |

---

## 10. Useful Commands

```bash
# Check node status
curl -s http://127.0.0.1:8545/health | jq .

# Check validator set
curl -s -X POST http://127.0.0.1:8545/rpc \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"kovanica_getValidators","params":[],"id":1}' | jq .

# Check own balance
kovanica-cli balance --address kvnc<your-address>dag --rpc-url http://127.0.0.1:8545

# Check staking info
kovanica-cli staking-info --address kvnc<your-address>dag --rpc-url http://127.0.0.1:8545

# View logs (docker)
docker logs -f kovanica-validator

# View logs (systemd)
journalctl -u kovanica -f
```

---

## 11. Support

- **Testnet Discord**: `#kovanica-testnet-validators`
- **GitHub Issues**: `github.com/kovanica/kovanica/issues`
- **Docs**: `https://docs.kovanica.online`

---

*Last updated: 2026-10-14 for testnet chain ID 2*