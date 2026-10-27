#!/usr/bin/env bash
#
# Kovanica soak runner — brings up the docker-compose testnet stack, waits for
# it to be healthy and committing, then exercises it for a configurable
# duration while sampling `/health` and `/metrics`. Exits non-zero on the first
# stall or crash and collects diagnostics on failure.
#
# This runner was wired into .github/workflows/soak.yml until that workflow was
# removed 2026-10-23 (kvnc PR #78); CI moves to KovanicaDAG/kovanica-protocol (PRO-14).
# Run it by hand or on a long-lived host. It is deliberately
# self-contained: it brings the stack up itself (the older ops/soak/soak.sh
# only monitors an already-running quorum and never gates on a stall).
#
# ---------------------------------------------------------------------------
# Usage
#   SOAK_SECS=600 ./ops/soak/run-soak.sh            # 10 min (default)
#   ./ops/soak/run-soak.sh --duration 30 --interval 5
#   SOAK_SKIP_UP=1 SOAK_SECS=60 ./ops/soak/run-soak.sh   # soak an already-running stack
#
# Duration
#   SOAK_SECS is intentionally much lower than 24h by default so a routine run stays fast.
#   * CI / nightly default ........ 600 s   (10 min)
#   * The 24h "long soak" is a MANUAL setting: on a long-lived machine run
#       SOAK_SECS=86400 ./ops/soak/run-soak.sh
#     A GitHub-hosted job is capped at 6h, so 24h cannot run inside the
#     nightly workflow — see ops/soak/README.md.
#
# Configuration (env var                              default)
#   SOAK_SECS           soak duration, seconds         600
#   INTERVAL            sample interval, seconds       15
#   WARMUP_TIMEOUT      seconds to wait for health     300
#   STALL_SECS          max seconds without progress   120
#   PROJECT_NAME        compose project name           kovanica-soak
#   COMPOSE_FILES       colon-separated compose files  docker-compose.yml
#   SOAK_RPC_PORTS      host RPC ports (seed..val3)    8545 8546 8547 8548
#   SOAK_SKIP_UP        1 = don't run `compose up`     0
#   SOAK_TEARDOWN       1 = `compose down -v` at end   1
#   SOAK_RPC_METHOD     best-effort JSON-RPC probe     kovanica_blockNumber
#   SOAK_RPC_BURST      RPC probes per sample round    1
#   OUT_DIR             artifact/output directory      ${TMPDIR:-/tmp}/kovanica-soak
#
# Notes
#   * Progress is measured from the `block_height` gauge on `/metrics`, which is
#     stable across node builds. `/health`'s consensus/execution sub-fields are
#     only present on recent builds, so they are recorded but not required.
#   * The JSON-RPC probe is best-effort: method renames / an older image do not
#     fail the soak (a transport error is logged, a "-32601 method not found" is
#     noted once). The soak gates are `/health` and `block_height` progress.
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
REPO_ROOT="$(cd -- "$SCRIPT_DIR/../.." >/dev/null 2>&1 && pwd)"
cd "$REPO_ROOT"

SOAK_SECS="${SOAK_SECS:-600}"
INTERVAL="${INTERVAL:-15}"
WARMUP_TIMEOUT="${WARMUP_TIMEOUT:-300}"
STALL_SECS="${STALL_SECS:-120}"
PROJECT_NAME="${PROJECT_NAME:-kovanica-soak}"
COMPOSE_FILES="${COMPOSE_FILES:-docker-compose.yml}"
RPC_PORTS_STR="${SOAK_RPC_PORTS:-8545 8546 8547 8548}"
SKIP_UP="${SOAK_SKIP_UP:-0}"
TEARDOWN="${SOAK_TEARDOWN:-1}"
RPC_METHOD="${SOAK_RPC_METHOD:-kovanica_blockNumber}"
RPC_BURST="${SOAK_RPC_BURST:-1}"
OUT_DIR="${OUT_DIR:-${TMPDIR:-/tmp}/kovanica-soak}"

read -r -a PORTS <<< "$RPC_PORTS_STR"
NODES=(seed val1 val2 val3)

usage() {
  sed -n '2,50p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --duration|-d) SOAK_SECS="${2:?--duration needs a value}"; shift 2 ;;
    --interval)    INTERVAL="${2:?--interval needs a value}"; shift 2 ;;
    --timeout)     WARMUP_TIMEOUT="${2:?--timeout needs a value}"; shift 2 ;;
    --stall)       STALL_SECS="${2:?--stall needs a value}"; shift 2 ;;
    --project)     PROJECT_NAME="${2:?--project needs a value}"; shift 2 ;;
    --skip-up)     SKIP_UP=1; shift ;;
    --no-teardown) TEARDOWN=0; shift ;;
    -h|--help)     usage; exit 0 ;;
    *) echo "unknown argument: $1" >&2; usage; exit 2 ;;
  esac
done

for v in SOAK_SECS INTERVAL WARMUP_TIMEOUT STALL_SECS RPC_BURST; do
  [[ "${!v}" =~ ^[0-9]+$ ]] || { echo "error: $v must be a non-negative integer (got '${!v}')" >&2; exit 2; }
done
(( ${#PORTS[@]} == ${#NODES[@]} )) || { echo "error: SOAK_RPC_PORTS must list ${#NODES[@]} ports" >&2; exit 2; }

LOG_FILE="$OUT_DIR/soak.log"
SAMPLES="$OUT_DIR/samples.csv"
RPC_UNSUPPORTED_LOGGED=0

mkdir -p "$OUT_DIR"

log() {
  printf '%s %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*" | tee -a "$LOG_FILE"
}

# --- compose wrapper (supports a colon-separated list of compose files) ------
COMPOSE_FILE_ARGS=()
IFS=':' read -r -a _compose_files <<< "$COMPOSE_FILES"
for _f in "${_compose_files[@]}"; do
  COMPOSE_FILE_ARGS+=(-f "$_f")
done
compose() { docker compose -p "$PROJECT_NAME" "${COMPOSE_FILE_ARGS[@]}" "$@"; }

# --- helpers ----------------------------------------------------------------

# Echo the HTTP status code for /health on a host port (000 on failure).
fetch_health() {
  local port="$1" out="$2" code
  code=$(curl -sS -m 5 -o "$out" -w '%{http_code}' "http://127.0.0.1:${port}/health" 2>/dev/null) || true
  [[ -n "$code" ]] || code="000"
  printf '%s' "$code"
}

# Read a single gauge value from /metrics on a host port.
metric_value() {
  local port="$1" key="$2"
  curl -sS -m 5 "http://127.0.0.1:${port}/metrics" 2>/dev/null | awk -v k="$key" '$1==k{print $2; exit}' || true
}

# Is the container for a compose service running? Falls back to name matching
# when the current project does not own it (SOAK_SKIP_UP against a foreign stack).
container_running() {
  local svc="$1" cid running
  cid=$(compose ps -q "$svc" 2>/dev/null) || true
  if [[ -z "$cid" ]]; then
    cid=$(docker ps --filter "name=${svc}" -q 2>/dev/null | head -1) || true
  fi
  [[ -n "$cid" ]] || return 1
  running=$(docker inspect -f '{{.State.Running}}' "$cid" 2>/dev/null) || true
  [[ "$running" == "true" ]]
}

collect_artifacts() {
  log "Collecting diagnostics into $OUT_DIR"
  compose ps > "$OUT_DIR/compose-ps.txt" 2>&1 || true
  docker ps -a --format 'table {{.Names}}\t{{.Status}}\t{{.Ports}}' > "$OUT_DIR/docker-ps.txt" 2>&1 || true
  compose logs --no-color --timestamps > "$OUT_DIR/compose-logs.txt" 2>&1 || true
  local svc cid
  for svc in "${NODES[@]}"; do
    cid=$(compose ps -q "$svc" 2>/dev/null) || true
    [[ -n "$cid" ]] || cid=$(docker ps --filter "name=${svc}" -q 2>/dev/null | head -1) || true
    [[ -n "$cid" ]] || continue
    docker inspect "$cid" > "$OUT_DIR/inspect-${svc}.json" 2>&1 || true
  done
  ls -l "$OUT_DIR" >> "$LOG_FILE" 2>&1 || true
}

fail() {
  log "FAIL: $*"
  collect_artifacts || true
  log "Soak FAILED"
  exit 1
}

# Wait until every node is running, /health is 200/"ok", and block_height > 0
# with at least one node advancing. Returns non-zero on timeout.
warmup() {
  log "Warm-up: waiting up to ${WARMUP_TIMEOUT}s for all ${#NODES[@]} nodes to be healthy and committing"
  local deadline=$(( $(date +%s) + WARMUP_TIMEOUT ))
  local -a last_h=()
  local -a last_ok=()
  while (( $(date +%s) < deadline )); do
    local all_ok=1 progressed=0 i node port code status bh
    for i in "${!NODES[@]}"; do
      node="${NODES[$i]}"; port="${PORTS[$i]}"
      if ! container_running "$node"; then all_ok=0; continue; fi
      code=$(fetch_health "$port" "$OUT_DIR/health-${node}.json")
      [[ "$code" == "200" ]] || { all_ok=0; continue; }
      status=$(jq -r '.status // "?"' "$OUT_DIR/health-${node}.json" 2>/dev/null || echo "?")
      [[ "$status" == "ok" ]] || { all_ok=0; continue; }
      bh=$(metric_value "$port" block_height)
      if [[ -z "$bh" || "$bh" -le 0 ]]; then all_ok=0; continue; fi
      if (( bh > ${last_h[$i]:-0} )); then progressed=1; fi
      last_h[$i]="$bh"
      last_ok[$i]=1
    done
    if (( all_ok == 1 && progressed == 1 )); then
      log "Warm-up complete: all ${#NODES[@]} nodes healthy and advancing"
      return 0
    fi
    sleep 5
  done
  return 1
}

# One sample round: verify liveness/health/progress and append a CSV row.
sample_once() {
  local now elapsed i node port code status peers commit last_err
  now=$(date +%s); elapsed=$(( now - SOAK_START ))
  for i in "${!NODES[@]}"; do
    node="${NODES[$i]}"; port="${PORTS[$i]}"

    if ! container_running "$node"; then
      fail "container for service '$node' is not running (crash) at elapsed=${elapsed}s"
    fi

    local hfile="$OUT_DIR/health-${node}.json"
    code=$(fetch_health "$port" "$hfile")
    if [[ "$code" != "200" ]]; then
      fail "service '$node' /health returned HTTP $code (degraded/unreachable) at elapsed=${elapsed}s"
    fi
    status=$(jq -r '.status // "?"' "$hfile" 2>/dev/null || echo "?")
    if [[ "$status" != "ok" ]]; then
      fail "service '$node' /health status='$status' (not ok) at elapsed=${elapsed}s"
    fi

    peers=$(jq -r '.peer_count // -1' "$hfile" 2>/dev/null || echo -1)
    commit=$(jq -r '.consensus.committed_leaders // -1' "$hfile" 2>/dev/null || echo -1)
    last_err=$(jq -r '.last_error // ""' "$hfile" 2>/dev/null || echo "")

    local mfile="$OUT_DIR/metrics-${node}.txt"
    curl -sS -m 5 "http://127.0.0.1:${port}/metrics" -o "$mfile" 2>/dev/null || true
    local bh mp rss
    bh=$(awk '$1=="block_height"{print $2; exit}' "$mfile")
    mp=$(awk '$1=="mempool_size"{print $2; exit}' "$mfile")
    rss=$(awk '$1=="rss_proxy"{print $2; exit}' "$mfile")
    if [[ -z "$bh" ]]; then
      fail "service '$node' /metrics unreachable (no block_height) at elapsed=${elapsed}s"
    fi

    if (( bh > ${PREV_H[$node]:-0} )); then
      PREV_H[$node]="$bh"
      LAST_PROG[$node]="$now"
    else
      local since=$(( now - ${LAST_PROG[$node]:-$now} ))
      if (( since > STALL_SECS )); then
        fail "stall: service '$node' block_height stuck at $bh for ${since}s (prev ${PREV_H[$node]:-0}) at elapsed=${elapsed}s"
      fi
    fi

    printf '%s,%s,%s,%s,%s,%s,%s,%s,%s,%s\n' \
      "$now" "$elapsed" "$node" "$code" "$status" "$peers" "$commit" "$bh" "${mp:-}" "${rss:-}" \
      >> "$SAMPLES"
    if [[ -n "$last_err" && "$last_err" != "null" ]]; then
      log "NOTE: service '$node' reports last_error='$last_err'"
    fi
  done
}

# Best-effort JSON-RPC exercise. Never fatal: only transport errors are logged.
exercise_rpc() {
  local resp n found=0
  for (( n=0; n<RPC_BURST; n++ )); do
    if ! resp=$(curl -sS -m 5 -X POST "http://127.0.0.1:${PORTS[0]}/rpc" \
        -H 'content-type: application/json' \
        -d "{\"jsonrpc\":\"2.0\",\"id\":$((n+1)),\"method\":\"${RPC_METHOD}\",\"params\":[]}" 2>/dev/null); then
      log "WARN: JSON-RPC probe transport error (method=${RPC_METHOD})"
      return 0
    fi
    printf '%s' "$resp" | grep -q '"result"' && found=1
  done
  if (( found == 0 && RPC_UNSUPPORTED_LOGGED == 0 )); then
    log "NOTE: JSON-RPC method '${RPC_METHOD}' unavailable on this image (best-effort probe; /health + block_height remain the gates)"
    RPC_UNSUPPORTED_LOGGED=1
  fi
}

# --- main -------------------------------------------------------------------

log "=== Kovanica soak starting ==="
log "repo=$REPO_ROOT project=$PROJECT_NAME compose=$COMPOSE_FILES"
log "duration=${SOAK_SECS}s interval=${INTERVAL}s stall=${STALL_SECS}s warmup=${WARMUP_TIMEOUT}s out=$OUT_DIR"
: > "$SAMPLES"
printf 'epoch,elapsed_s,node,http,status,peers,committed_leaders,block_height,mempool_size,rss_proxy\n' >> "$SAMPLES"

if [[ "$SKIP_UP" == "1" ]]; then
  log "SOAK_SKIP_UP=1: skipping compose up; expecting the stack to be running already"
else
  log "Bringing up compose stack (up -d --build)"
  compose up -d --build || fail "compose up failed"
fi

warmup || fail "warm-up timed out after ${WARMUP_TIMEOUT}s (stack unhealthy or not committing)"

declare -A PREV_H=()
declare -A LAST_PROG=()
for i in "${!NODES[@]}"; do
  node="${NODES[$i]}"
  PREV_H[$node]=$(metric_value "${PORTS[$i]}" block_height)
  PREV_H[$node]="${PREV_H[$node]:-0}"
  LAST_PROG[$node]="$(date +%s)"
done

SOAK_START=$(date +%s)
log "Soak loop for ${SOAK_SECS}s ..."
rounds=0
while :; do
  now=$(date +%s)
  (( now - SOAK_START >= SOAK_SECS )) && break
  sample_once
  exercise_rpc
  rounds=$(( rounds + 1 ))
  sleep "$INTERVAL"
done

SOAK_END=$(date +%s)
log "Soak loop finished: ${rounds} sample rounds over $(( SOAK_END - SOAK_START ))s"
awk -F, 'NR>1 && $8+0>max[$3]{max[$3]=$8+0} END{for(k in max) printf "  peak block_height %-5s = %s\n", k, max[k]}' "$SAMPLES" | tee -a "$LOG_FILE" || true

if [[ "$SKIP_UP" != "1" && "$TEARDOWN" == "1" ]]; then
  log "Tearing down compose stack (down -v)"
  compose down -v || true
fi

log "SUCCESS: soak passed (no stall, no crash)"
exit 0
