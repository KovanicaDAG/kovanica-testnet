#!/usr/bin/env bash
# Kovanica Chain 4 Testnet Health & Consensus Monitor
# Usage: ops/monitoring/check-cluster.sh

set -euo pipefail

ENDPOINTS=(
  "seed1:https://seed1.kovanica.online"
  "seed2:https://seed2.kovanica.online"
  "seed3:https://seed3.kovanica.online"
  "rpc-testnet:https://rpc-testnet.kovanica.online"
)

STALL_THRESHOLD=60
MIN_PEERS=3
EXIT_CODE=0

echo "======================================================================"
echo "KOVANICA CHAIN 4 TESTNET CLUSTER HEALTH MONITOR"
echo "Timestamp: $(date -u '+%Y-%m-%d %H:%M:%S UTC')"
echo "======================================================================"

for ENTRY in "${ENDPOINTS[@]}"; do
  NAME="${ENTRY%%:*}"
  URL="${ENTRY#*:}"

  # Query /health
  HEALTH_JSON=$(curl -s -m 5 "${URL}/health" 2>/dev/null || echo '{"error": "curl_failed"}')
  
  PEERS=$(echo "$HEALTH_JSON" | grep -o '"peer_count":[0-9]*' | cut -d: -f2 || echo "0")
  LAST_COMMIT=$(echo "$HEALTH_JSON" | grep -o '"seconds_since_last_commit":[0-9]*' | cut -d: -f2 || echo "999")
  
  # Query RPC blockNumber
  RPC_JSON=$(curl -s -m 5 -X POST "${URL}/rpc" \
    -H "Content-Type: application/json" \
    -d '{"jsonrpc":"2.0","method":"kovanica_blockNumber","params":[],"id":1}' 2>/dev/null || echo '{"error": "curl_failed"}')
  
  BLOCK_HEX=$(echo "$RPC_JSON" | grep -o '"result":"[^"]*"' | cut -d'"' -f4 || echo "0x0")
  BLOCK_NUM=$(printf "%d" "$BLOCK_HEX" 2>/dev/null || echo "0")

  STATUS="[OK]"
  WARNINGS=()

  if [[ -z "$PEERS" ]] || [[ "$PEERS" -lt "$MIN_PEERS" ]]; then
    STATUS="[FAIL]"
    WARNINGS+=("Low peers: ${PEERS:-0} < ${MIN_PEERS}")
    EXIT_CODE=1
  fi

  if [[ -z "$LAST_COMMIT" ]] || [[ "$LAST_COMMIT" -gt "$STALL_THRESHOLD" ]]; then
    STATUS="[FAIL]"
    WARNINGS+=("Consensus stalled: ${LAST_COMMIT:-999}s since last commit (> ${STALL_THRESHOLD}s)")
    EXIT_CODE=1
  fi

  if [[ "$BLOCK_NUM" -eq 0 ]]; then
    STATUS="[FAIL]"
    WARNINGS+=("RPC blockNumber failed or 0")
    EXIT_CODE=1
  fi

  printf "%-6s %-12s | Block: %-6s | Peers: %-3s | Last Commit: %2ss ago\n" "$STATUS" "$NAME" "$BLOCK_NUM" "$PEERS" "$LAST_COMMIT"
  for W in "${WARNINGS[@]-}"; do
    echo "       -> WARNING: $W"
  done
done

echo "======================================================================"
if [[ "$EXIT_CODE" -eq 0 ]]; then
  echo "CLUSTER STATUS: ALL NODES HEALTHY AND CONSENSUS PROGRESSING NORMAL."
else
  echo "CLUSTER STATUS: ISSUES DETECTED. CHECK WARNINGS ABOVE."
fi

exit "$EXIT_CODE"
