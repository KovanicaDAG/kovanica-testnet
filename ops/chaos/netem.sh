#!/usr/bin/env bash
#
# Kovanica chaos — tc/netem link-fault injector for the docker-compose quorum.
#
# Applies `tc qdisc netem` to the *host-side veth* of one or more containers, so
# traffic crossing the docker bridge between the selected nodes and the rest of
# the quorum can be degraded or dropped entirely. It is a pure impairment tool:
# it never starts or stops containers, and it never touches product code.
#
# Everything it does is reversible with `ops/chaos/netem.sh clear`.
#
# ---------------------------------------------------------------------------
# Graceful skip contract (important for CI)
#
#   This script exits 0 and prints a single `SKIPPED: ...` line whenever it
#   cannot do its job for an *environmental* reason, so a runner without
#   iproute2, docker, or NET_ADMIN never fails the job:
#     * `tc` not installed           -> skip
#     * not root / no CAP_NET_ADMIN  -> skip
#     * docker missing or not running -> skip
#     * target containers not running -> skip
#     * kernel rejects the qdisc     -> skip (e.g. netem feature unsupported)
#   It only exits non-zero for a genuine misuse (unknown mode/argument).
#
# ---------------------------------------------------------------------------
# Usage
#   ops/chaos/netem.sh apply                 # impair $CHAOS_TARGETS
#   ops/chaos/netem.sh clear                 # remove every netem we added
#   ops/chaos/netem.sh status                # show the current qdisc per target
#   ops/chaos/netem.sh selftest              # prove tc+NET_ADMIN work on `lo`
#   ops/chaos/netem.sh help
#
# Configuration (env var                default)
#   CHAOS_TARGETS          containers       $CHAOS_VICTIM
#   CHAOS_VICTIM           single node      chaos-val3
#   CHAOS_MODE             fault kind      partition
#                           partition | loss | delay | corrupt | duplicate | reorder
#   CHAOS_LOSS             percent         100 (partition) / 5 (loss)
#   CHAOS_DELAY_MS         ms              0
#   CHAOS_JITTER_MS        ms              0
#   CHAOS_CORRUPT          percent         0
#   CHAOS_DUPLICATE        percent         0
#   CHAOS_REORDER          percent         0
#   CHAOS_DRY_RUN          1 = print only  0
#
# Notes
#   * netem shapes *egress from the host into the container*, i.e. everything
#     arriving at that node. Impairing both sides of a pair is a full partition;
#     impairing one side is one-way damage. `CHAOS_TARGETS` selects the side(s)
#     to impair, so a 3+1 partition is `CHAOS_TARGETS=chaos-val3 CHAOS_MODE=partition`.
#   * The qdisc is attached to the container's veth, so it disappears with the
#     container. Re-running `apply` is idempotent (`tc qdisc replace`).
#   * Do not run this against a production testnet from a shared host: the
#     impairment is host-wide for those containers.

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
REPO_ROOT="$(cd -- "$SCRIPT_DIR/../.." >/dev/null 2>&1 && pwd)"
cd "$REPO_ROOT"

CHAOS_VICTIM="${CHAOS_VICTIM:-chaos-val3}"
CHAOS_TARGETS="${CHAOS_TARGETS:-$CHAOS_VICTIM}"
CHAOS_MODE="${CHAOS_MODE:-partition}"
CHAOS_LOSS="${CHAOS_LOSS:-}"
CHAOS_DELAY_MS="${CHAOS_DELAY_MS:-0}"
CHAOS_JITTER_MS="${CHAOS_JITTER_MS:-0}"
CHAOS_CORRUPT="${CHAOS_CORRUPT:-0}"
CHAOS_DUPLICATE="${CHAOS_DUPLICATE:-0}"
CHAOS_REORDER="${CHAOS_REORDER:-0}"
CHAOS_DRY_RUN="${CHAOS_DRY_RUN:-0}"

if [[ "$CHAOS_MODE" == "partition" && -z "$CHAOS_LOSS" ]]; then
  CHAOS_LOSS="100"
elif [[ -z "$CHAOS_LOSS" ]]; then
  CHAOS_LOSS="5"
fi

log() { printf '%s %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*"; }

# Environmental blocker -> exit 0 so CI never fails on a runner limitation.
skip() { log "SKIPPED: $*"; exit 0; }
# Real misuse -> non-zero.
die()  { log "ERROR: $*"; exit 1; }

have() { command -v "$1" >/dev/null 2>&1; }

usage() { sed -n '2,55p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; }

read -r -a TARGETS <<< "$CHAOS_TARGETS"

# ---------------------------------------------------------------------------
# Preconditions — every failure here is a graceful skip, not a failure
# ---------------------------------------------------------------------------

preflight() {
  have docker || skip "docker not installed on this host"
  have ip     || skip "ip(8) not installed on this host"
  have tc || skip "tc(8)/iproute2 not installed on this host"

  if ! docker info >/dev/null 2>&1; then
    skip "docker daemon unreachable (no permission, or not running)"
  fi

  # NET_ADMIN check: try a trivial `tc qdisc show` first, then the real op.
  if [[ "$(id -u)" != "0" ]]; then
    if ! capsh --has-p=cap_net_admin >/dev/null 2>&1; then
      skip "not root and no CAP_NET_ADMIN: tc cannot change qdiscs here"
    fi
  fi
}

# Resolve the host-side veth for a running container by matching the container
# eth0's peer ifindex (`/sys/class/net/eth0/iflink`) against `ip -o link`.
container_veth() {
  local name="$1" iflink running
  running="$(docker inspect -f '{{.State.Running}}' "$name" 2>/dev/null || true)"
  [[ "$running" == "true" ]] || return 1
  iflink="$(docker exec "$name" cat /sys/class/net/eth0/iflink 2>/dev/null | tr -d '\r\n' || true)"
  [[ "$iflink" =~ ^[0-9]+$ ]] || return 1
  ip -o link | awk -F': ' -v n="$iflink" '$1 == n {print $2}' | cut -d@ -f1
}

# Run `tc`, classifying the failure. Permission/unsupported -> graceful skip.
run_tc() {
  local out
  if out=$("$@" 2>&1); then
    return 0
  fi
  case "$out" in
    *"Operation not permitted"*|*"Permission denied"*)
      skip "tc refused the change (no NET_ADMIN on this runner): $out"
      ;;
    *"Operation not supported"*|*"not supported"*)
      skip "kernel does not support this qdisc/feature here: $out"
      ;;
    *"No such file or directory"*|*"Cannot find device"*)
      skip "network device vanished while applying (container stopped?): $out"
      ;;
    *)
      log "tc command failed: $*"
      log "output: $out"
      exit 1
      ;;
  esac
}

# Build the netem argument list for the configured mode (echoes the args).
netem_args() {
  local -a args=(netem)
  case "$CHAOS_MODE" in
    partition|loss) args+=(loss "${CHAOS_LOSS}%") ;;
    delay)          args+=(delay "${CHAOS_DELAY_MS}ms" "${CHAOS_JITTER_MS}ms" distribution normal) ;;
    corrupt)        args+=(corrupt "${CHAOS_CORRUPT}%") ;;
    duplicate)      args+=(duplicate "${CHAOS_DUPLICATE}%") ;;
    reorder)        args+=(delay "${CHAOS_DELAY_MS}ms" reorder "${CHAOS_REORDER}%" 50%) ;;
    *)              die "unknown CHAOS_MODE '$CHAOS_MODE' (use partition|loss|delay|corrupt|duplicate|reorder)" ;;
  esac
  printf '%s\n' "${args[@]}"
}

# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

cmd_apply() {
  preflight
  local -a netem
  mapfile -t netem < <(netem_args)
  log "CHAOS_MODE=$CHAOS_MODE -> tc qdisc replace ... ${netem[*]}"
  local name veth
  for name in "${TARGETS[@]}"; do
    if ! veth=$(container_veth "$name"); then
      skip "container '$name' is not running (or has no eth0) — nothing to impair"
    fi
    log "  $name -> host veth $veth"
    if [[ "$CHAOS_DRY_RUN" == "1" ]]; then
      log "  DRY-RUN: tc qdisc replace dev $veth root ${netem[*]}"
      continue
    fi
    run_tc tc qdisc replace dev "$veth" root "${netem[@]}"
    log "  applied: $(tc qdisc show dev "$veth" 2>/dev/null | tr '\n' ' ')"
  done
  log "netem applied to: ${TARGETS[*]}"
}

cmd_clear() {
  preflight
  local name veth cleared=0
  for name in "${TARGETS[@]}"; do
    if ! veth=$(container_veth "$name"); then
      log "  $name: not running, nothing to clear"
      continue
    fi
    # `del` may legitimately fail when no root qdisc exists; never fatal.
    if tc qdisc del dev "$veth" root 2>/dev/null; then
      cleared=$(( cleared + 1 ))
      log "  $name ($veth): root qdisc removed"
    fi
  done
  log "netem cleared on $cleared target(s)"
}

cmd_status() {
  preflight
  local name veth
  for name in "${TARGETS[@]}"; do
    if ! veth=$(container_veth "$name"); then
      printf '%-10s  (not running)\n' "$name"
      continue
    fi
    printf '%-10s  veth=%-12s  %s\n' "$name" "$veth" \
      "$(tc qdisc show dev "$veth" 2>/dev/null | head -1)"
  done
}

# Prove the two hard requirements (tc binary + NET_ADMIN) without touching any
# container: attach and remove a netem on loopback. Safe and instantaneous.
cmd_selftest() {
  have tc || skip "tc(8)/iproute2 not installed on this host"
  if ! tc qdisc replace dev lo root netem loss 0% 2>&1; then
    skip "cannot attach a netem qdisc even on loopback (no NET_ADMIN / unsupported)"
  fi
  local out
  out="$(tc qdisc show dev lo 2>/dev/null | head -1 || true)"
  tc qdisc del dev lo root 2>/dev/null || true
  log "selftest OK: attached and removed netem on lo ($out)"
  log "tc + NET_ADMIN are available on this host"
}

case "${1:-status}" in
  apply)   cmd_apply ;;
  clear)   cmd_clear ;;
  status)  cmd_status ;;
  selftest) cmd_selftest ;;
  help|-h|--help) usage ;;
  *) usage; die "unknown command '$1' (apply|clear|status|selftest|help)" ;;
esac
