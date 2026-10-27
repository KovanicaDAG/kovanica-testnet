# Soak testing

Two scripts live here:

| Script      | Purpose                                                                 | Used by |
|-------------|-------------------------------------------------------------------------|---------|
| `run-soak.sh` | **The soak runner.** Brings up the compose stack, waits for health + commits, exercises the node for `SOAK_SECS`, samples `/health` + `/metrics`, fails on the first stall or crash, and collects logs on failure. | Local automated & manual soak runner (the `soak.yml` workflow was removed 2026-10-23 (kvnc PR #78); CI moves to KovanicaDAG/kovanica-protocol (PRO-14)) |
| `soak.sh`   | Legacy Phase 12.4 RSS/memory monitor. Assumes a 4-node stack is *already* running (`kovanica-quorum-node1..4`) and only logs memory every 30 s; it never brings the stack up and never gates on a stall. | manual memory runs only |

For local soak testing use `run-soak.sh`. `soak.sh` predates the current compose service names
(see "Known gaps" below) and is kept for the memory-specific 6h runs.

## run-soak.sh

```bash
# CI default: 10 minutes
./ops/soak/run-soak.sh

# explicit duration / interval
./ops/soak/run-soak.sh --duration 30 --interval 5

# soak an already-running stack (no compose up, no teardown)
SOAK_SKIP_UP=1 SOAK_SECS=60 ./ops/soak/run-soak.sh
```

What it does:

1. `docker compose -p kovanica-soak -f docker-compose.yml up -d --build`
   (skipped with `SOAK_SKIP_UP=1`).
2. **Warm-up** — waits up to `WARMUP_TIMEOUT` for every node to be running,
   return `HTTP 200` + `{"status":"ok"}` from `/health`, and advance
   `block_height` on `/metrics`.
3. **Soak loop** — every `INTERVAL` seconds it samples `/health` (status,
   peer count, committed leaders, `last_error`) and `/metrics`
   (`block_height`, `mempool_size`, `rss_proxy`), appends a CSV row to
   `samples.csv`, and sends a best-effort `kovanica_blockNumber` JSON-RPC probe.
4. **Failure** — exits non-zero on the first:
   * container not running (crash),
   * `/health` != `HTTP 200` or `status != "ok"` (the node returns `503` /
     `degraded` once execution or consensus stops, or once commits stall),
   * `block_height` unchanged on any node for more than `STALL_SECS`,
   * `/metrics` unreachable.
   On failure it collects `compose ps`, `docker ps -a`, `compose logs`,
   per-container `docker inspect` and the soak log into `OUT_DIR`, then exits 1.
5. **Success** — prints the peak `block_height` per node and exits 0. Tears the
   stack down with `down -v` unless `SOAK_SKIP_UP=1` or `SOAK_TEARDOWN=0`.

### Configuration

| Env var           | Default                          | Meaning |
|-------------------|----------------------------------|---------|
| `SOAK_SECS`       | `600`                            | Soak duration, seconds |
| `INTERVAL`        | `15`                             | Sample interval, seconds |
| `WARMUP_TIMEOUT`  | `300`                            | Seconds to wait for a healthy, committing stack |
| `STALL_SECS`      | `120`                            | Max seconds a node may go without `block_height` advancing |
| `PROJECT_NAME`    | `kovanica-soak`                  | Compose project name |
| `COMPOSE_FILES`   | `docker-compose.yml`             | Colon-separated compose files |
| `SOAK_RPC_PORTS`  | `8545 8546 8547 8548`            | Host RPC ports for seed..val3 |
| `SOAK_SKIP_UP`    | `0`                              | `1` = don't run `compose up` |
| `SOAK_TEARDOWN`   | `1`                              | `1` = `compose down -v` on success |
| `SOAK_RPC_METHOD` | `kovanica_blockNumber`           | Best-effort JSON-RPC probe method |
| `SOAK_RPC_BURST`  | `1`                              | RPC probes per sample round |
| `OUT_DIR`         | `${TMPDIR:-/tmp}/kovanica-soak`  | Log + artifact directory |

### Why progress is measured from `block_height`

`/health` returns `{"status":"ok", ...}` and only degrades to `503` on builds
that wire the consensus commit-liveness signal. The `block_height` gauge on
`/metrics` is present on every build and advances only when the chain commits,
so the runner gates on it directly rather than trusting `/health` status alone.
The `/health` consensus/execution sub-fields are recorded when present but are
not required.

`SOAK_SECS` is deliberately far below 24h so CI stays fast. The **24h soak is a
manual setting** — a GitHub-hosted job is capped at 6h, so run it on a
long-lived machine:

```bash
SOAK_SECS=86400 ./ops/soak/run-soak.sh
```

## CI / Automated Workflow
> **Note on CI:** Repository-level GitHub Actions workflows were decommissioned on 2026-10-23 (`.github/workflows/soak.yml` was removed in kvnc PR #78; CI moves to KovanicaDAG/kovanica-protocol (PRO-14)); soak testing is executed using the local runner scripts directly or integrated into self-hosted runners.

Until the soak job exists again, run the runner by hand:

```bash
SOAK_SECS=86400 OUT_DIR=soak-artifacts ops/soak/run-soak.sh
```

The runner specifications:

* **Triggers:** Automated nightly schedule or manual invocation with a
  `duration` input (seconds).
* **Concurrency:** A running soak should not be overlapped.
* **Timeout:** Recommended 180 minutes for automated runs (build + warm-up + soak).
* **Artifacts:** The `soak-artifacts/` directory (`OUT_DIR`) contains all logs (`compose ps`, `docker inspect`, `samples.csv`).

## Known gaps / prerequisites

* **A local `docker-compose.soak.yml` override (if present) may be stale.** That
  file is **gitignored** (`.gitignore`) and is *not* part of the repository — it
  is a machine-local scratch override. On a machine that still has one it may
  override a service named `node1`, while the committed `docker-compose.yml`
  defines `seed`/`val1`/`val2`/`val3`; `docker compose -f docker-compose.soak.yml
  config -q` then fails with *"service \"node1\" has neither an image nor a build
  context"*. The runner uses `docker-compose.yml` alone, so a stale local
  override is harmless and can simply be deleted.
* **`soak.sh`** still targets the old `kovanica-quorum-node1..4` container names
  and the old 4-node quorum layout; it is not wired into CI.
* The devnet builds a per-node single-authority committee, so the four nodes do
  not form a real M-of-N quorum (see `ops/docker/README.md`), but each node
  still commits leaders — `block_height` advances, which is what the runner
  relies on.
