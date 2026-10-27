# Testnet seed nodes — kovanica L1

**Network:** public testnet: `chain_id 4` (local dev only: `1337`)
**Deployed:** 2026-10-13 (build c44f672, mempool requeue fix)
**P2P:** TCP 8000, libp2p swarm
**RPC:** 8545 (loopback-only)

## Seed nodes

| # | Hostname | IP | VPS | Validator key | Composer peers |
|---|---|---|---|---|---|
| 1 | seed1.kovanica.online | seed1.kovanica.online | VPS#1 (this machine) | val1.pem | 3 |
| 2 | seed2.kovanica.online | seed2.kovanica.online | VPS#2 | val2.pem | 3 |
| 3 | seed3.kovanica.online | seed3.kovanica.online | VPS#3 | val3.pem | 3 |

**All seed nodes run with `mine=0 faucet=0 operator=0 allow_reset=0`.**

## Verified state (2026-10-13T18:40Z)

```
seed1: peer_count 2, height ~294, exec_subdags=24, healthy
seed2: peer_count 2, height ~290, exec_subdags 13, healthy
seed3: peer_count 2, height ~294, exec_subdags 14, healthy
```

Mesh fully connected (3 nodes, each sees 2 peers), all executing.

## Operations

### Start / stop
```
# VPS#1 (this node)
systemctl start kovanica-node.service  # or nohup /root/Projects/kvnc/run-seed1-wrapper.sh
# below VPS via SSH
systemctl start kovanica-node.service
```

### Health checks
```bash
curl -s http://127.0.0.1:8545/health
curl -s -X POST http://127.0.0.1:8545/rpc \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"kovanica_blockNumber","params":[]}'
```

### DNS
- seed1.kovanica.online → seed1.kovanica.online (A record, grey cloud)
- seed2.kovanica.online → seed2.kovanica.online
- seed3.kovanica.online → seed3.kovanica.online

### Logs
- VPS#1: /root/Projects/kvnc/seed1.log
- VPS#2: /root/Projects/kvnc/seed2.log
- VPS#3: /root/Projects/kvnc/seed3.log

### Binaries
- VPS#1: /usr/local/bin/kovanica-node (built from c44f672)
- VPS#2, VPS#3: /usr/local/bin/kovanica-node (scp'd from VPS#1 build)

### Data dirs (all VPS)
- /root/Projects/kvnc/node-data: contains genesis_validators.toml + v.dat (0600 seed)

## Block