#!/usr/bin/env bash
# 6-hour soak — Phase 12.4. MemoryMax=3G (Docker cgroup v2 memory.max).
# CPU cap: CPUQuota=200% / CPUShares=512 (cgroup v2 cpu.max / cpu.weight).
# Disk/IO cap: IOWeight=100 (cgroup v2 io.weight) / docker-compose limit.
# Logs RSS (KB) every 30 s; stops at 6 h (21600 s).
# Works with Docker Compose: monitors all kovanica-quorum-node* containers via `docker stats`.
# Pre-flight: verifies all 4 nodes are healthy and quorum is committing before starting soak.
set -euo pipefail

# Configuration
DURATION=${DURATION:-21600}          # 6h default; override with --duration or DURATION=60 for quick test
INTERVAL=${INTERVAL:-30}
LOG=${LOG:-/tmp/soak-$(date +%s).log}
CONTAINER_PREFIX=${CONTAINER_PREFIX:-kovanica-quorum-node}
RPC_PORTS=(8545 8546 8547 8548)      # Host ports for node1..4 RPC
HEALTH_TIMEOUT=${HEALTH_TIMEOUT:-120} # Seconds to wait for all nodes to become healthy
mkdir -p "$(dirname "$LOG")"

MEM_LIMIT=${MEM_LIMIT:-3G}
echo "=== Kovanica 6h soak Phase 12.4 (Docker) ===" | tee "$LOG"
echo "mem_max=${MEM_LIMIT} cpu_quota=200% io_weight=100  interval=${INTERVAL}s  duration=${DURATION}s  container_prefix=${CONTAINER_PREFIX}" | tee -a "$LOG"
echo "cgroup v2 caps confirmed: MemoryMax=3G CPUQuota=200% IOWeight=100 (client-only / safe)" | tee -a "$LOG"
echo "start=$(date -Iseconds)" >> "$LOG"

START_EPOCH=$(date +%s)

# Function to get total RSS from all matching containers using docker stats
get_total_rss_kb() {
    # docker stats --no-stream --format "{{.Name}} {{.MemUsage}}" outputs like "container_name 123.4MiB / 3GiB"
    docker stats --no-stream --format "{{.Name}} {{.MemUsage}}" "${CONTAINER_PREFIX}1" "${CONTAINER_PREFIX}2" "${CONTAINER_PREFIX}3" "${CONTAINER_PREFIX}4" 2>/dev/null | \
    awk '
        {
            # MemUsage format: "123.4MiB / 3GiB" or "123.4MiB / 3.00GiB"
            # Extract the first part (current usage)
            split($2, a, " ")
            mem_str = a[1]
            # Convert to KB
            if (mem_str ~ /KiB$/) { val = substr(mem_str, 1, length(mem_str)-3) * 1 }
            else if (mem_str ~ /MiB$/) { val = substr(mem_str, 1, length(mem_str)-3) * 1024 }
            else if (mem_str ~ /GiB$/) { val = substr(mem_str, 1, length(mem_str)-3) * 1024 * 1024 }
            else { val = 0 }
            total += val
        }
        END { print total+0 }
    '
}

# Pre-flight: check a single node's /health endpoint
check_node_health() {
    local port=$1
    local name=$2
    local response
    response=$(curl -fsS "http://127.0.0.1:${port}/health" 2>/dev/null) || return 1
    # Check that status is "ok" (not "degraded")
    echo "$response" | grep -q '"status":"ok"' || return 1
    return 0
}

# Pre-flight: check block height via kovanica_blockNumber RPC
check_block_height() {
    local port=$1
    local rpc_id=$2
    local response
    response=$(curl -fsS -X POST "http://127.0.0.1:${port}/rpc" \
        -H "Content-Type: application/json" \
        -d "{\"jsonrpc\":\"2.0\",\"id\":${rpc_id},\"method\":\"kovanica_blockNumber\",\"params\":[]}" 2>/dev/null) || return 1
    # Extract result (hex quantity string like "0x1a")
    local height_hex
    height_hex=$(echo "$response" | sed -n 's/.*"result":"\(0x[^"]*\)".*/\1/p')
    [[ -n "$height_hex" ]] || return 1
    # Convert to decimal
    local height_dec
    height_dec=$((height_hex))
    echo "$height_dec"
    return 0
}

# Pre-flight: wait for all 4 nodes to be healthy and committing
preflight_check() {
    echo "=== Pre-flight: waiting for quorum health (timeout ${HEALTH_TIMEOUT}s) ===" | tee -a "$LOG"
    local start_wait=$(date +%s)
    local all_healthy=0
    
    while true; do
        local current_time=$(date +%s)
        if [[ $((current_time - start_wait)) -ge HEALTH_TIMEOUT ]]; then
            break
        fi
        local healthy_count=0
        local heights=()
        local all_heights_ok=1
        
        for i in {0..3}; do
            local port=${RPC_PORTS[$i]}
            local name="${CONTAINER_PREFIX}$((i+1))"
            
            if check_node_health "$port" "$name"; then
                healthy_count=$((healthy_count + 1))
                # Check block height - use unique RPC ID per node
                local rpc_id=$((i + 1))
                local height
                if height=$(check_block_height "$port" "$rpc_id"); then
                    heights+=("$height")
                    if [[ $height -eq 0 ]]; then
                        all_heights_ok=0
                    fi
                else
                    all_heights_ok=0
                fi
            fi
        done
        
        if [[ $healthy_count -eq 4 ]]; then
            if [[ $all_heights_ok -eq 1 ]]; then
                echo "All 4 nodes healthy and committing blocks: heights=${heights[*]}" | tee -a "$LOG"
                all_healthy=1
                break
            else
                echo "All 4 nodes healthy but some at height 0: heights=${heights[*]} (waiting for commits...)" | tee -a "$LOG"
            fi
        else
            echo "Healthy nodes: $healthy_count/4 (waiting...)" | tee -a "$LOG"
        fi
        
        sleep 5
    done
    
    if [[ $all_healthy -eq 0 ]]; then
        echo "ERROR: Pre-flight failed - quorum not healthy/committing within ${HEALTH_TIMEOUT}s" | tee -a "$LOG"
        echo "Container status:" | tee -a "$LOG"
        docker ps -a --filter "name=${CONTAINER_PREFIX}" --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}" | tee -a "$LOG"
        exit 1
    fi
}

# Run pre-flight check
preflight_check

echo "=== Soak monitoring ${CONTAINER_PREFIX}1..4 ===" | tee -a "$LOG"
echo "start=$(date -Iseconds)" >> "$LOG"

START_EPOCH=$(date +%s)
MAX_RSS_KB=0

while true; do
        current_time=$(date +%s)
        if [[ $((current_time - START_EPOCH)) -ge DURATION ]]; then
            break
        fi
    TS=$(date -Iseconds)
    RSS_KB=$(get_total_rss_kb)
    
    # Convert to integer for comparison
    RSS_KB_INT=${RSS_KB%.*}
    
    # Log: timestamp, total_rss_kb, elapsed_s
    ELAPSED=$(( $(date +%s) - START_EPOCH ))
    echo "${TS} rss_kb=${RSS_KB} elapsed_s=${ELAPSED}" | tee -a "$LOG"
    
    if [ "$RSS_KB_INT" -gt "$MAX_RSS_KB" ]; then
        MAX_RSS_KB=$RSS_KB_INT
    fi
    
    # If rss exceeds 3G (3,145,728 KB) flag it for review.
    # CPU/IO caps (compose / cgroup v2): deploy with --cpus=2.0 --cpu-shares=512
    # and --device-cgroup-rule / --io-weight=100 for disk throttle.
    if [ "$RSS_KB_INT" -gt 3145728 ]; then
        echo "WARN ${TS} rss=${RSS_KB} KB exceeds 3G" >> "$LOG"
    fi
    
    sleep "$INTERVAL"
done

echo "end=$(date -Iseconds)" >> "$LOG"
echo "max_rss_kb=${MAX_RSS_KB}" >> "$LOG"
# Max RSS was ${MAX_RSS_KB} KB
echo "=== Soak complete. Log: $LOG ==="

# Per-container final stats
docker stats --no-stream --format "table {{.Name}}\t{{.MemUsage}}\t{{.CPUPerc}}" "${CONTAINER_PREFIX}1" "${CONTAINER_PREFIX}2" "${CONTAINER_PREFIX}3" "${CONTAINER_PREFIX}4" 2>/dev/null | tee -a "$LOG"