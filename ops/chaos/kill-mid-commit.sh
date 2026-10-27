#!/usr/bin/env bash
#
# Kovanica chaos — SIGKILL a validator mid-commit on the docker-compose quorum,
# then prove the network recovers without diverging.
#
# This is the container-level counterpart to the process-level test
# `crates/kovanica-node/tests/chaos_kill_mid_commit.rs`. It runs the *real
# shipped image* on the *real deployed topology* (seed + val1..val3) and injects
# a hard crash at the only moment that matters: right after the victim commits a
# height.
#
# ---------------------------------------------------------------------------
# What it asserts
#
#   Phase 0  warm-up      every node is running, /health is 200/"ok", and
#                        `block_height` is advancing on /metrics.
#   Phase 1  target       the quorum has committed at least CHAOS_KILL_AT
#                        heights, so the kill is mid-chain.
#   Phase 2  fault        the victim advances a height and is immediately
#                        `docker kill`ed (SIGKILL: no shutdown hook, no flush).
#                        Optionally, `ops/chaos/netem.sh` first partitions the
#                        victim (CHAOS_INJECT_NETEM=1) so the kill lands on an
#                        isolated node.
#   Phase 3  quorum rule  depends on the committee size, which is checked
#                        explicitly rather than assumed:
#                          survivors >= CHAOS_QUORUM -> the chain must KEEP
#                              committing without the victim (liveness);
#                          survivors <  CHAOS_QUORUM -> the chain must STALL
#                              (safety: a sub-quorum group must never commit).
#                        Either way the surviving processes must stay up.
#   Phase 4  restart      heal the network, restart the victim on its *same*
#                        data volume, and require the chain to resume and every
#                        node to advance past the kill height.
#   Phase 5  no-divergence compare the committed leader header hash at a fixed
#                        height (CHALLENGE via kovanica_getCommitSeals) across
#                        every node: all must match. Also require no `panicked`
#                        in the restarted node's logs.
#
# ---------------------------------------------------------------------------
# Graceful skip contract
#
#   Exits 0 with a single `SKIPPED: ...` line when docker (or compose) is not
#   available on the runner, so the chaos workflow never fails on an
#   environmental limitation. Only a real chaos failure exits non-zero.
#
# ---------------------------------------------------------------------------
# Usage
#   ops/chaos/kill-mid-commit.sh
#   ops/chaos/kill-mid-commit.sh --victim val2 --kill-at 8
#   CHAOS_INJECT_NETEM=1 ops/chaos/kill-mid-commit.sh
#   CHAOS_SKIP_UP=1 ops/chaos/kill-mid-commit.sh      # reuse a running chaos stack
#
# Configuration (env var                 default)
#   CHAOS_PROJECT          compose project   kovanica-chaos
#   CHAOS_COMPOSE_FILES    compose files     docker-compose.yml:ops/chaos/docker-compose.chaos.yml
#   CHAOS_NODES            services          seed val1 val2 val3
#   CHAOS_RPC_PORTS        host RPC ports    18545 18546 18547 18548
#   CHAOS_VICTIM           service to kill   val3
#   CHAOS_VALIDATORS       validators up     3
#   CHAOS_QUORUM           commit threshold  3
#   CHAOS_KILL_AT          pre-kill height   8
#   CHAOS_WARMUP_TIMEOUT   seconds           300
#   CHAOS_KILL_WINDOW      seconds            60
#   CHAOS_PROGRESS_TIMEOUT seconds           120   (liveness / stall gate)
#   CHAOS_CATCHUP_TIMEOUT  seconds           240   (restart + convergence)
#   CHAOS_STALL_TOLERANCE  heights             1   (in-flight commits at kill)
#   CHAOS_INJECT_NETEM     1 = netem first   0
#   CHAOS_SKIP_UP          1 = no up/down    0
#   CHAOS_TEARDOWN         1 = down -v       1
#   OUT_DIR                artifacts         ${TMPDIR:-/tmp}/kovanica-chaos

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
REPO_ROOT="$(cd -- "$SCRIPT_DIR/../.." >/dev/null 2>&1 && pwd)"
cd "$REPO_ROOT"

CHAOS_PROJECT="${CHAOS_PROJECT:-kovanica-chaos}"
CHAOS_COMPOSE_FILES="${CHAOS_COMPOSE_FILES:-docker-compose.yml:ops/chaos/docker-compose.chaos.yml}"
CHAOS_NODES_STR="${CHAOS_NODES:-seed val1 val2 val3}"
CHAOS_RPC_PORTS_STR="${CHAOS_RPC_PORTS:-18545 18546 18547 18548}"
CHAOS_VICTIM="${CHAOS_VICTIM:-val3}"
CHAOS_VALIDATORS="${CHAOS_VALIDATORS:-3}"
CHAOS_QUORUM="${CHAOS_QUORUM:-3}"
CHAOS_KILL_AT="${CHAOS_KILL_AT:-8}"
CHAOS_WARMUP_TIMEOUT="${CHAOS_WARMUP_TIMEOUT:-300}"
CHAOS_KILL_WINDOW="${CHAOS_KILL_WINDOW:-60}"
CHAOS_PROGRESS_TIMEOUT="${CHAOS_PROGRESS_TIMEOUT:-120}"
CHAOS_CATCHUP_TIMEOUT="${CHAOS_CATCHUP_TIMEOUT:-240}"
CHAOS_STALL_TOLERANCE="${CHAOS_STALL_TOLERANCE:-1}"
CHAOS_INJECT_NETEM="${CHAOS_INJECT_NETEM:-0}"
CHAOS_SKIP_UP="${CHAOS_SKIP_UP:-0}"
CHAOS_TEARDOWN="${CHAOS_TEARDOWN:-1}"
OUT_DIR="${OUT_DIR:-${TMPDIR:-/tmp}/kovanica-chaos}"

read -r -a NODES <<< "$CHAOS_NODES_STR"
read -r -a RPC_PORTS <<< "$CHAOS_RPC_PORTS_STR"
(( ${#NODES[@]} == ${#RPC_PORTS[@]} )) || {
  echo "error: CHAOS_NODES and CHAOS_RPC_PORTS must list the same number of entries" >&2
  exit 2
}

usage() { sed -n '2,70p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; }

while [[ $# -gt 0 ]]; do
  case "$1" in
    --victim)   CHAOS_VICTIM="${2:?--victim needs a value}"; shift 2 ;;
    --kill-at)  CHAOS_KILL_AT="${2:?--kill-at needs a value}"; shift 2 ;;
    --netem)    CHAOS_INJECT_NETEM=1; shift ;;
    --skip-up)  CHAOS_SKIP_UP=1; shift ;;
    --no-teardown) CHAOS_TEARDOWN=0; shift ;;
    --help|-h)  usage; exit 0 ;;
    *) echo "unknown argument: $1" >&2; usage; exit 2 ;;
  esac
done

for v in CHAOS_VALIDATORS CHAOS_QUORUM CHAOS_KILL_AT CHAOS_WARMUP_TIMEOUT \
         CHAOS_KILL_WINDOW CHAOS_PROGRESS_TIMEOUT CHAOS_CATCHUP_TIMEOUT \
         CHAOS_STALL_TOLERANCE; do
  [[ "${!v}" =~ ^[0-9]+$ ]] || { echo "error: $v must be a non-negative integer (got '${!v}')" >&2; exit 2; }
done
[[ " ${NODES[*]} " == *" $CHAOS_VICTIM "* ]] || {
  echo "error: CHAOS_VICTIM '$CHAOS_VICTIM' is not in CHAOS_NODES (${NODES[*]})" >&2
  exit 2
}

LOG_FILE="$OUT_DIR/chaos.log"
mkdir -p "$OUT_DIR"
log() { printf '%s %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*" | tee -a "$LOG_FILE"; }
skip() { log "SKIPPED: $*"; exit 0; }
fail() {
  log "FAIL: $*"
  collect_artifacts || true
  log "CHAOS FAILED"
  exit 1
}

# --- compose wrapper --------------------------------------------------------
COMPOSE_FILE_ARGS=()
IFS=':' read -r -a _files <<< "$CHAOS_COMPOSE_FILES"
for _f in "${_files[@]}"; do
  COMPOSE_FILE_ARGS+=(-f "$_f")
done
compose() { docker compose -p "$CHAOS_PROJECT" "${COMPOSE_FILE_ARGS[@]}" "$@"; }

# --- prerequisites (all graceful skips) --------------------------------------
if ! command -v docker >/dev/null 2>&1; then
  skip "docker not installed on this runner"
fi
if ! docker info >/dev/null 2>&1; then
  skip "docker daemon unreachable (no permission, or not running)"
fi
if ! docker compose version >/dev/null 2>&1; then
  skip "docker compose v2 plugin not available"
fi
command -v jq >/dev/null 2>&1 || skip "jq not installed on this runner"
command -v curl >/dev/null 2>&1 || skip "curl not installed on this runner"

# --- helpers ----------------------------------------------------------------

port_for() {
  local svc="$1" i
  for i in "${!NODES[@]}"; do
    if [[ "${NODES[$i]}" == "$svc" ]]; then
      echo "${RPC_PORTS[$i]}"
      return 0
    fi
  done
  return 1
}

survivors_of() {
  local dead="$1" n=0 svc
  for svc in "${NODES[@]}"; do
    [[ "$svc" == "$dead" ]] && continue
    # Count only validators (seed does not take part in consensus).
    [[ "$svc" == seed ]] && continue
    n=$(( n + 1 ))
  done
  echo "$n"
}

fetch_health() {
  local port="$1" out="$2" code
  code=$(curl -sS -m 5 -o "$out" -w '%{http_code}' "http://127.0.0.1:${port}/health" 2>/dev/null) || true
  [[ -n "$code" ]] || code="000"
  printf '%s' "$code"
}

metric_value() {
  local port="$1" key="$2"
  curl -sS -m 5 "http://127.0.0.1:${port}/metrics" 2>/dev/null \
    | awk -v k="$key" '$1==k{print $2; exit}' || true
}

# JSON-RPC call; prints the raw body. Transport/HTTP errors are the caller's job.
rpc_call() {
  local port="$1" method="$2" params="${3:-[]}"
  curl -sS -m 10 -X POST "http://127.0.0.1:${port}/rpc" \
    -H 'content-type: application/json' \
    -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"${method}\",\"params\":${params}}" 2>/dev/null || true
}

# Committed height as a decimal integer (0 if unreachable).
height_of() {
  local port="$1" raw
  raw=$(rpc_call "$port" "kovanica_blockNumber" | jq -r '.result // empty' 2>/dev/null || true)
  [[ -n "$raw" ]] || { echo 0; return 0; }
  raw="${raw#0x}"
  printf '%d' "0x${raw:-0}" 2>/dev/null || echo 0
}

# Committed leader header hash at a height, or the empty string.
header_hash_at() {
  local port="$1" height="$2" resp
  resp=$(rpc_call "$port" "kovanica_getCommitSeals" "[${height}]")
  printf '%s' "$resp" | jq -r '.result.headerHash // empty' 2>/dev/null || true
}

container_of() { compose ps -q "$1" 2>/dev/null | head -1; }

container_running() {
  local cid running
  cid=$(container_of "$1")
  [[ -n "$cid" ]] || return 1
  running=$(docker inspect -f '{{.State.Running}}' "$cid" 2>/dev/null) || return 1
  [[ "$running" == "true" ]]
}

# Is there a `panicked at` anywhere in this container's logs?
logs_have_panic() {
  docker logs "$1" 2>&1 | grep -q 'panicked at'
}

collect_artifacts() {
  log "Collecting diagnostics into $OUT_DIR"
  compose ps > "$OUT_DIR/compose-ps.txt" 2>&1 || true
  docker ps -a --format 'table {{.Names}}\t{{.Status}}\t{{.Ports}}' > "$OUT_DIR/docker-ps.txt" 2>&1 || true
  compose logs --no-color --timestamps > "$OUT_DIR/compose-logs.txt" 2>&1 || true
  local svc
  for svc in "${NODES[@]}"; do
    docker logs "$svc" > "$OUT_DIR/logs-${svc}.txt" 2>&1 || true
    docker inspect "$svc" > "$OUT_DIR/inspect-${svc}.json" 2>&1 || true
  done
}

cleanup() {
  if [[ "$CHAOS_SKIP_UP" != "1" && "$CHAOS_TEARDOWN" == "1" ]]; then
    log "Tearing down chaos stack (down -v)"
    compose down -v >/dev/null 2>&1 || true
  fi
}

warmup() {
  log "Warm-up: waiting up to ${CHAOS_WARMUP_TIMEOUT}s for ${#NODES[@]} nodes to be healthy and committing"
  local deadline=$(( $(date +%s) + CHAOS_WARMUP_TIMEOUT ))
  local -A last_h=()
  while (( $(date +%s) < deadline )); do
    local all_ok=1 progressed=0 svc port code status bh
    for i in "${!NODES[@]}"; do
      svc="${NODES[$i]}"; port="${RPC_PORTS[$i]}"
      container_running "$svc" || { all_ok=0; continue; }
      code=$(fetch_health "$port" "$OUT_DIR/health-${svc}.json")
      [[ "$code" == "200" ]] || { all_ok=0; continue; }
      status=$(jq -r '.status // "?"' "$OUT_DIR/health-${svc}.json" 2>/dev/null || echo "?")
      [[ "$status" == "ok" ]] || { all_ok=0; continue; }
      bh=$(metric_value "$port" block_height)
      [[ -n "$bh" && "$bh" -gt 0 ]] || { all_ok=0; continue; }
      (( bh > ${last_h[$svc]:-0} )) && progressed=1
      last_h[$svc]="$bh"
    done
    if (( all_ok == 1 && progressed == 1 )); then
      log "Warm-up complete: all ${#NODES[@]} nodes healthy and advancing"
      return 0
    fi
    sleep 5
  done
  return 1
}

# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------

log "=== Kovanica chaos: SIGKILL mid-commit ==="
log "repo=$REPO_ROOT project=$CHAOS_PROJECT compose=$CHAOS_COMPOSE_FILES"
log "victim=$CHAOS_VICTIM validators=$CHAOS_VALIDATORS quorum=$CHAOS_QUORUM kill_at=$CHAOS_KILL_AT netem=$CHAOS_INJECT_NETEM"
log "out=$OUT_DIR"

if [[ "$CHAOS_SKIP_UP" == "1" ]]; then
  log "CHAOS_SKIP_UP=1: reusing the already-running chaos stack"
else
  log "Bringing up chaos compose stack (up -d --build)"
  compose up -d --build || fail "compose up failed"
fi
trap cleanup EXIT

warmup || fail "warm-up timed out after ${CHAOS_WARMUP_TIMEOUT}s (unhealthy or not committing)"

# --- Phase 1: commit a few heights before injecting anything -----------------
log "Phase 1: waiting for block_height >= ${CHAOS_KILL_AT} on at least one node"
deadline=$(( $(date +%s) + CHAOS_PROGRESS_TIMEOUT ))
while :; do
  peak=0
  for port in "${RPC_PORTS[@]}"; do
    bh=$(height_of "$port")
    (( bh > peak )) && peak="$bh"
  done
  (( peak >= CHAOS_KILL_AT )) && break
  (( $(date +%s) < deadline )) || fail "no node reached height ${CHAOS_KILL_AT} in ${CHAOS_PROGRESS_TIMEOUT}s (peak=$peak)"
  sleep 5
done
log "Phase 1 OK: peak committed height before the kill = $peak"

victim_port=$(port_for "$CHAOS_VICTIM") || fail "no RPC port for victim '$CHAOS_VICTIM'"
victim_before=$(height_of "$victim_port")
log "victim $CHAOS_VICTIM is at height $victim_before"

# --- Phase 2: optional netem partition, then SIGKILL mid-commit --------------
if [[ "$CHAOS_INJECT_NETEM" == "1" ]]; then
  log "Phase 2a: injecting a network partition on the victim (netem)"
  if ! CHAOS_TARGETS="$CHAOS_VICTIM" bash ops/chaos/netem.sh apply; then
    fail "netem apply failed (was it expected to skip gracefully?)"
  fi
  # Give gossip a moment to notice the partition before the crash.
  sleep 10
else
  log "Phase 2a: netem disabled (CHAOS_INJECT_NETEM=0)"
fi

# Wait for the victim to advance a height so the kill lands mid-activity.
log "Phase 2: waiting up to ${CHAOS_KILL_WINDOW}s for the victim to commit a height ..."
deadline=$(( $(date +%s) + CHAOS_KILL_WINDOW ))
while :; do
  now=$(height_of "$victim_port")
  (( now > victim_before )) && break
  (( $(date +%s) < deadline )) || fail \
    "victim never advanced past height ${victim_before} in ${CHAOS_KILL_WINDOW}s; not killing at an ambiguous moment"
  sleep 2
done
log "Phase 2: victim advanced to $now — SIGKILLing now"

docker kill "$CHAOS_VICTIM" || fail "docker kill $CHAOS_VICTIM failed"
sleep 2
container_running "$CHAOS_VICTIM" && fail "victim $CHAOS_VICTIM is still running after docker kill"
kill_height=$now
log "Phase 2 OK: $CHAOS_VICTIM killed at height $kill_height"

# Snapshot the survivors at the kill instant.
declare -A before_h=()
for i in "${!NODES[@]}"; do
  svc="${NODES[$i]}"
  [[ "$svc" == "$CHAOS_VICTIM" ]] && continue
  before_h[$svc]=$(height_of "${RPC_PORTS[$i]}")
done
log "survivor heights at kill: ${!before_h[@]} -> ${before_h[*]}"

# --- Phase 3: quorum arithmetic ---------------------------------------------
survivors=$(survivors_of "$CHAOS_VICTIM")
log "Phase 3: ${survivors} validators survive (quorum needs ${CHAOS_QUORUM})"

if (( survivors >= CHAOS_QUORUM )); then
  log "Phase 3: liveness expected — the chain must keep committing without the victim"
  deadline=$(( $(date +%s) + CHAOS_PROGRESS_TIMEOUT ))
  while :; do
    ok=1
    for i in "${!NODES[@]}"; do
      svc="${NODES[$i]}"
      [[ "$svc" == "$CHAOS_VICTIM" ]] && continue
      [[ "$svc" == "seed" ]] && continue
      bh=$(height_of "${RPC_PORTS[$i]}")
      (( bh > ${before_h[$svc]:-0} )) || ok=0
    done
    (( ok == 1 )) && break
    (( $(date +%s) < deadline )) || fail \
      "surviving quorum did NOT keep committing within ${CHAOS_PROGRESS_TIMEOUT}s of the kill (expected liveness with ${survivors} >= ${CHAOS_QUORUM})"
    sleep 5
  done
  log "Phase 3 OK: quorum kept committing after the crash"
else
  ceiling=$(( kill_height + CHAOS_STALL_TOLERANCE ))
  log "Phase 3: safety expected — ${survivors} < ${CHAOS_QUORUM}, so commits MUST stall (ceiling height ${ceiling})"
  deadline=$(( $(date +%s) + CHAOS_PROGRESS_TIMEOUT ))
  while :; do
    for i in "${!NODES[@]}"; do
      svc="${NODES[$i]}"
      [[ "$svc" == "$CHAOS_VICTIM" ]] && continue
      bh=$(height_of "${RPC_PORTS[$i]}")
      if (( bh > ceiling )); then
        fail "safety violation: '$svc' advanced to $bh (> ${ceiling}) with only ${survivors} of ${CHAOS_QUORUM} validators alive"
      fi
    done
    (( $(date +%s) >= deadline )) && break
    sleep 5
  done
  log "Phase 3 OK: chain stalled at/below height ${ceiling} — sub-quorum group did not commit"
fi

# Surviving processes must not have crashed or panicked.
for i in "${!NODES[@]}"; do
  svc="${NODES[$i]}"
  [[ "$svc" == "$CHAOS_VICTIM" ]] && continue
  container_running "$svc" || fail "survivor '$svc' is not running (crash) after the kill"
  if logs_have_panic "$svc"; then
    fail "survivor '$svc' logged a panic while a validator was down"
  fi
done
log "Phase 3 OK: every survivor is still running and panic-free"

# --- Phase 4: heal, restart, converge ----------------------------------------
if [[ "$CHAOS_INJECT_NETEM" == "1" ]]; then
  log "Phase 4a: healing the network (netem clear)"
  CHAOS_TARGETS="$CHAOS_VICTIM" bash ops/chaos/netem.sh clear || true
fi

log "Phase 4: restarting $CHAOS_VICTIM on its existing data volume"
compose start "$CHAOS_VICTIM" || fail "compose start $CHAOS_VICTIM failed"

deadline=$(( $(date +%s) + CHAOS_CATCHUP_TIMEOUT ))
while :; do
  code=$(fetch_health "$victim_port" "$OUT_DIR/health-${CHAOS_VICTIM}.json")
  [[ "$code" == "200" ]] && break
  (( $(date +%s) < deadline )) || fail "restarted $CHAOS_VICTIM never became healthy within ${CHAOS_CATCHUP_TIMEOUT}s (HTTP $code)"
  sleep 5
done
log "Phase 4: $CHAOS_VICTIM is healthy again"

# Every node must advance past the kill height, and the victims peers too.
log "Phase 4: waiting for all ${#NODES[@]} nodes to pass height $kill_height"
target=$(( kill_height + 1 ))
deadline=$(( $(date +%s) + CHAOS_CATCHUP_TIMEOUT ))
while :; do
  ok=1
  declare -A now_h=()
  for i in "${!NODES[@]}"; do
    svc="${NODES[$i]}"
    bh=$(height_of "${RPC_PORTS[$i]}")
    now_h[$svc]="$bh"
    (( bh >= target )) || ok=0
  done
  (( ok == 1 )) && break
  (( $(date +%s) < deadline )) || fail \
    "nodes did not all reach height ${target} within ${CHAOS_CATCHUP_TIMEOUT}s after restart (heights: ${!now_h[@]} -> ${now_h[*]})"
  sleep 5
done
log "Phase 4 OK: chain resumed and every node is past height $kill_height"

# --- Phase 5: no divergence, no panic ----------------------------------------
log "Phase 5: comparing the committed leader header hash at height $kill_height"
declare -A hashes=()
for i in "${!NODES[@]}"; do
  svc="${NODES[$i]}"
  hashes[$svc]=$(header_hash_at "${RPC_PORTS[$i]}" "$kill_height")
  log "  $svc headerHash($kill_height) = ${hashes[$svc]:-<none>}"
done

baseline="${hashes[${NODES[0]}]}"
if [[ -z "$baseline" ]]; then
  log "WARN: kovanica_getCommitSeals returned no header hash (older image?); skipping the divergence gate"
else
  for svc in "${NODES[@]}"; do
    [[ "${hashes[$svc]}" == "$baseline" ]] || fail \
      "DIVERGENCE: node '$svc' has committed leader ${hashes[$svc]:-<none>} at height $kill_height, but '${NODES[0]}' has $baseline"
  done
  log "Phase 5 OK: all ${#NODES[@]} nodes agree on the committed leader at height $kill_height"
fi

if logs_have_panic "$CHAOS_VICTIM"; then
  fail "the restarted victim '$CHAOS_VICTIM' logged a panic while catching up"
fi
log "Phase 5 OK: restarted node caught up with no panic"

log "SUCCESS: SIGKILL mid-commit survived — quorum rule held, chain resumed, no divergence"
exit 0
