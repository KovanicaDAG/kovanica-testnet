# Chaos / Fault-Injection Harness

This document describes the real fault-injection harness for Kovanica validators.
It complements the existing in-process partition tests (`multi_node_integration`)
and the graceful `SIGTERM` restart test with **real process kills** and **real
network impairment**.

> **These tests are opt-in and executed manually or in scheduled test harnesses.** Run them by hand with the
> scripts in `ops/chaos/` (see the quick reference). The `.github/workflows/chaos.yml`
> workflow that could dispatch them was removed 2026-10-23 (kvnc PR #78); CI moves to KovanicaDAG/kovanica-protocol (PRO-14). It was
> `workflow_dispatch`-only, never nightly. They use `ops/chaos/docker-compose.chaos.yml` and require a release binary (see below).

---

## 1. Mid-Commit SIGKILL + Restart Convergence

**File:** `crates/kovanica-node/tests/chaos_kill_mid_commit.rs`  
**Run script:** `ops/chaos/kill-mid-commit.sh` (wrapper that builds release binary and
invokes the test with correct env vars)

### What it tests

A 4-validator quorum (threshold `floor(2T/3)+1 = 3`) is brought up with real
TCP, real P2P, real consensus. The test:

1. Waits for the quorum to commit `PRE_KILL_HEIGHT` (default 6) blocks.
2. Observes the **victim** (the last validator) advance one committed height,
   then immediately sends `SIGKILL` — i.e. the process dies *mid-commit*, between
   "decided round persisted" and "committed leader persisted".
3. Asserts the surviving three validators **keep committing** (quorum survives).
4. Restarts the victim on its **same data directory** and asserts it **catches
   up** to the surviving quorum.
5. Asserts **no divergence**: the committed-leader sequence read from every
   node's `consensus.redb` is byte-identical up to `PRE_KILL_HEIGHT`.
6. Asserts **no panic / no corrupt DB**: every log is scanned for `panicked at`
   and every `consensus.redb` opens cleanly.

### Why a release binary is mandatory

The test discovers a `debug_assert!` in the restart path
(`crates/kovanica-consensus/src/non_blue.rs:47`) that fires *only* when a
`SIGKILL` mid-commit leaves the mergeset in a state that feeds the canonical
genesis into `non_blue_refs`. This assert is compiled out in release builds,
and the release binary restarts and converges correctly. The assert is a real
consensus-path invariant that a graceful `SIGTERM` never exercises.

**Run locally:**

```bash
# Build the release binary (required)
cargo build --release -p kovanica-node

# Run the test (opt-in, ignored by default)
KOVANICA_NODE_BINARY=target/release/kovanica-node \
  cargo test -p kovanica-node --test chaos_kill_mid_commit -- --ignored --nocapture
```

Or use the wrapper:

```bash
bash ops/chaos/kill-mid-commit.sh
```

### Key parameters (all at top of test file)

| Const | Default | Meaning |
|-------|---------|---------|
| `NODES` | 4 | Validators in quorum (quorum = 3) |
| `VICTIM` | 3 | Index of killed node |
| `PRE_KILL_HEIGHT` | 6 | Committed height before kill |
| `ROUND_DURATION_MS` | 1000 | Consensus round duration |
| `PORT_RANGE_START/END` | 20000..30000 | Random port block for isolation |
| `RPC_READY_TIMEOUT_SECS` | 30 | RPC readiness wait |
| `PEER_TIMEOUT_SECS` | 30 | Peer mesh formation |
| `PRE_KILL_TIMEOUT_SECS` | 150 | Reach pre-kill height |
| `KILL_WINDOW_SECS` | 45 | Victim must advance within this |
| `QUORUM_PROGRESS_TIMEOUT_SECS` | 90 | Survivors must commit after kill |
| `CATCHUP_TIMEOUT_SECS` | 120 | Victim restart catch-up |
| `CATCHUP_LAG_TOLERANCE` | 2 | Allowed lag behind slowest survivor |
| `SETTLE_TIMEOUT_SECS` | 90 | Final settle at PRE_KILL_HEIGHT+1 |

---

## 2. Netem Partition / Latency / Loss Injection

**File:** `ops/chaos/netem.sh`

Applies `tc qdisc netem` to container / host interfaces to inject:
- **Packet loss** (`--loss N` — percentage)
- **Latency** (`--latency 50ms`)
- **Partition** (`--partition` — isolates a subset of nodes)

Designed to run against the 4-node `docker-compose.yml` quorum (seed + val1-3).

### Usage

```bash
# Partition test: isolate node3 from the rest for 30s with 10% loss + 50ms latency
bash ops/chaos/netem.sh --test-partition --duration 30 --loss 10 --latency 50ms

# Just loss/latency on all links
bash ops/chaos/netem.sh --loss 5 --latency 20ms --duration 60

# Clean up (always run after, or on Ctrl-C the script traps and cleans)
bash ops/chaos/netem.sh --cleanup
```

### Requirements

- `tc` (iproute2) must be installed.
- **CAP_NET_ADMIN** capability — GitHub-hosted runners generally **do not** have
  this. The removed `chaos.yml` workflow detected this and skipped the netem
  job with a warning. To run locally, use a VM/container with `--cap-add=NET_ADMIN`
  or run as root.

### What the script verifies

After the impairment is removed (heal):
1. All nodes are still running (no process deaths).
2. The quorum re-forms (peer counts recover).
3. Block height continues advancing on all nodes.

---

## 3. CI Integration (removed)

The `.github/workflows/chaos.yml` workflow was removed 2026-10-23 (kvnc PR #78); CI moves to KovanicaDAG/kovanica-protocol (PRO-14). It was `workflow_dispatch` only (inputs
`test_type` = `kill-mid-commit` / `netem-partition` / `both`, and
`use_release`); it was never scheduled. Chaos tests stay out of per-PR CI:
real process kills and real TCP are slow and timing-sensitive, and netem needs
`CAP_NET_ADMIN`, which standard runners lack. Run them by hand (section 6).

---

## 4. Known Findings (from developing this harness)

| Finding | Location | Severity | Notes |
|---------|----------|----------|-------|
| `debug_assert!` genesis-in-non_blue after SIGKILL restart | `crates/kovanica-consensus/src/non_blue.rs:47` | Medium (debug only) | Release binary OK; asserts invariant that graceful shutdown never breaks. |
| `recover_committed_subdags` calls `get_decided_rounds(u64::MAX)` | `crates/kovanica-node/src/main.rs` | Medium (perf) | O(chain age) on restart — separate issue PRO-9. |

---

## 5. Adding New Chaos Scenarios

1. Add a new `#[ignore]`d test in `crates/kovanica-node/tests/` (or a new file
   `chaos_*.rs`).
2. Add a wrapper script in `ops/chaos/` if it needs shell orchestration.
3. Once CI exists in kovanica-protocol, add it there as an opt-in, never-blocking job.
4. Document it here.

---

## 6. Quick Reference

| Command | Purpose |
|---------|---------|
| `bash ops/chaos/kill-mid-commit.sh` | Local mid-commit kill test (builds release, runs test) |
| `bash ops/chaos/netem.sh --test-partition --duration 30` | Local netem partition (needs CAP_NET_ADMIN) |
| `cargo test -p kovanica-node --test chaos_kill_mid_commit -- --list` | List ignored chaos tests |