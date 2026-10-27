# Phase 12.4 — TPS + Memory Soak

## Scripts
- `ops/bench/tps.sh` — 4-node local devnet (`docker-compose.yml`), transfer txs only, 60 s. Measures submitted and committed/sec. Target >=100 committed/sec.
- `ops/soak/soak.sh` — 6 h soak with 30 s RSS logging, `MemoryMax=3G` (cgroup or best-effort). Log at `/tmp/soak-*.log`.

## Version markers (no crate version change)
- `ops/VERSION`: phase-12.4, node binary 0.1.0, scripts listed.
- `node/VERSION`: node binary 0.1.0.

## Observed RSS (fill after soak)
- Start: ___ KB
- Peak: ___ KB (must stay <= 3,145,728 KB / 3G)
- End: ___ KB
- Note: GHOSTDAG k=3; 4-node topology; native KUNA only.
