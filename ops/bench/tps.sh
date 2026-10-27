#!/usr/bin/env bash
# Kovanica TPS Benchmark — Phase 12.4
# Uses kovanica-bench binary for proper nonce management, funding, and committed counting.
# Target: >= 100 committed transactions/sec on 4-node devnet (2GB RAM target)

set -euo pipefail

# Configuration
DUR=${DUR:-60}                              # benchmark duration (seconds)
RPC_URL=${RPC_URL:-http://127.0.0.1:8545}   # node1 RPC endpoint
CHAIN_ID=${CHAIN_ID:-1337}                  # local chain ID
FUNDER_KEYS=${FUNDER_KEYS:-}                # space-separated funder key files
SENDERS=${SENDERS:-8}                       # number of derived bench senders
TXS_PER_SENDER=${TXS_PER_SENDER:-16}        # transactions per sender (clamped to 64)
CONCURRENCY=${CONCURRENCY:-64}              # max concurrent submissions
FUND_AMOUNT=${FUND_AMOUNT:-10000000000}     # atoms per funding tx (10 KUNA = 1e10 atoms)
TX_AMOUNT=${TX_AMOUNT:-1}                   # transfer amount per tx (atoms)
TX_FEE=${TX_FEE:-1000000}                   # fee per tx (atoms, ~0.001 KUNA for non-zero fee_rate)
WAIT_SECS=${WAIT_SECS:-240}                 # wait for commits (seconds, must exceed commit latency)
QUORUM_WAIT_SECS=${QUORUM_WAIT_SECS:-60}    # wait for quorum formation before bench
BENCH_BIN=${BENCH_BIN:-./target/release/kovanica-bench}

# Derived funder keys from pre-funded accounts (if not provided)
if [ -z "$FUNDER_KEYS" ]; then
    FUNDER_KEYS=("/tmp/opencode/kovanicabench/funded/sender0" "/tmp/opencode/kovanicabench/funded/sender1" "/tmp/opencode/kovanicabench/funded/sender2" "/tmp/opencode/kovanicabench/funded/sender3" "/tmp/opencode/kovanicabench/funded/sender4")
else
    # Convert space-separated string to array
    read -ra FUNDER_KEYS <<< "$FUNDER_KEYS"
fi

set -x

echo "=== Kovanica TPS Benchmark ==="
echo "duration=${DUR}s  rpc=${RPC_URL}  chain=${CHAIN_ID}"
echo "funders=($FUNDER_KEYS)"
echo "senders=${SENDERS}  txs_per_sender=${TXS_PER_SENDER}  concurrency=${CONCURRENCY}"
echo "fund_amount=${FUND_AMOUNT}  tx_amount=${TX_AMOUNT}  tx_fee=${TX_FEE}"
echo "wait=${WAIT_SECS}s  quorum_wait=${QUORUM_WAIT_SECS}s"
echo "bench_binary=${BENCH_BIN}"

# Verify bench binary exists
if [ ! -x "$BENCH_BIN" ]; then
    echo "ERROR: Bench binary not found at $BENCH_BIN"
    echo "Build with: cargo build --release -p kovanica-cli --bin kovanica-bench"
    exit 1
fi

# Wait for quorum formation before starting benchmark
echo "=== Waiting for 4-node quorum to form (${QUORUM_WAIT_SECS}s) ==="
sleep "$QUORUM_WAIT_SECS"

# Verify nodes are healthy and connected
for i in 1 2 3 4; do
    PORT=$((8544 + i))
    echo "Checking node $i on port $PORT..."
    curl -sf "http://127.0.0.1:$PORT/health" || echo "Node $i health check failed"
done

# Run benchmark
OUT_FILE="/tmp/tps-$(date +%s).log"
echo "=== Kovanica TPS Benchmark $(date -Iseconds) ===" | tee "$OUT_FILE"
echo "config: dur=${DUR} rpc=${RPC_URL} chain=${CHAIN_ID} senders=${SENDERS} txs_per_sender=${TXS_PER_SENDER} concurrency=${CONCURRENCY} fund_amount=${FUND_AMOUNT} tx_amount=${TX_AMOUNT} tx_fee=${TX_FEE} wait=${WAIT_SECS} quorum_wait=${QUORUM_WAIT_SECS}" >> "$OUT_FILE"

# Run the bench binary
FUNDER_ARGS=()
for key in "${FUNDER_KEYS[@]}"; do
    FUNDER_ARGS+=(--funder-key-file "$key")
done

"$BENCH_BIN" \
    --rpc-url "$RPC_URL" \
    --chain-id "$CHAIN_ID" \
    "${FUNDER_ARGS[@]}" \
    --senders "$SENDERS" \
    --txs-per-sender "$TXS_PER_SENDER" \
    --fund-amount "$FUND_AMOUNT" \
    --fund-wait-secs "$WAIT_SECS" \
    --concurrency "$CONCURRENCY" \
    --amount "$TX_AMOUNT" \
    --fee "$TX_FEE" \
    --wait-secs "$WAIT_SECS" \
    2>&1 | tee -a "$OUT_FILE"

BENCH_EXIT=${PIPESTATUS[0]}

# Extract TPS from output
BENCH_LINE=$(grep "^BENCH " "$OUT_FILE" | tail -1 || true)
if [ -n "$BENCH_LINE" ]; then
    TPS=$(echo "$BENCH_LINE" | sed 's/.* tps=\([0-9.]*\)$/\1/')
    COMMITTED=$(echo "$BENCH_LINE" | sed 's/.* committed=\([0-9]*\).*/\1/')
    echo ""
    echo "=== RESULT ==="
    echo "Committed transactions: $COMMITTED"
    echo "TPS: $TPS"
    echo "Target (>=100): $([ "$(echo "$TPS >= 100" | bc -l 2>/dev/null || echo 0)" = "1" ] && echo "PASS" || echo "FAIL")"
    echo "Log: $OUT_FILE"
else
    echo "ERROR: No BENCH output line found"
    BENCH_EXIT=1
fi

exit $BENCH_EXIT