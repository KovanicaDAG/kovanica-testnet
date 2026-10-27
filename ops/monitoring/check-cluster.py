#!/usr/bin/env python3
"""
Kovanica Chain 4 Testnet Health & Consensus Monitor.
Queries all seed endpoints for /health and JSON-RPC consensus status.
Alerts if seconds_since_last_commit exceeds threshold or peer count drops below quorum.
"""

import sys
import json
import urllib.request
import urllib.error
import time

ENDPOINTS = [
    {"name": "seed1", "url": "https://seed1.kovanica.online"},
    {"name": "seed2", "url": "https://seed2.kovanica.online"},
    {"name": "seed3", "url": "https://seed3.kovanica.online"},
    {"name": "rpc-testnet", "url": "https://rpc-testnet.kovanica.online"},
]

STALL_THRESHOLD_SECS = 60
MIN_PEERS = 3

def check_health(base_url, timeout=5):
    health_url = f"{base_url}/health"
    req = urllib.request.Request(health_url, headers={"User-Agent": "Kovanica-Monitor/1.0"})
    start = time.time()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            latency_ms = int((time.time() - start) * 1000)
            data = json.loads(resp.read().decode('utf-8'))
            return {"status": "ok", "latency_ms": latency_ms, "data": data}
    except Exception as e:
        return {"status": "error", "error": str(e)}

def check_rpc(base_url, timeout=5):
    rpc_url = f"{base_url}/rpc"
    payload = json.dumps({
        "jsonrpc": "2.0",
        "method": "kovanica_blockNumber",
        "params": [],
        "id": 1
    }).encode('utf-8')
    req = urllib.request.Request(
        rpc_url,
        data=payload,
        headers={"Content-Type": "application/json", "User-Agent": "Kovanica-Monitor/1.0"}
    )
    start = time.time()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            latency_ms = int((time.time() - start) * 1000)
            res = json.loads(resp.read().decode('utf-8'))
            block_hex = res.get("result", "0x0")
            block_num = int(block_hex, 16)
            return {"status": "ok", "latency_ms": latency_ms, "block_height": block_num}
    except Exception as e:
        return {"status": "error", "error": str(e)}

def main():
    print("=" * 70)
    print("KOVANICA CHAIN 4 TESTNET CLUSTER HEALTH MONITOR")
    print(f"Timestamp: {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}")
    print("=" * 70)

    overall_healthy = True
    results = []

    for ep in ENDPOINTS:
        name = ep["name"]
        url = ep["url"]
        health = check_health(url)
        rpc = check_rpc(url)

        endpoint_ok = True
        warnings = []

        if health["status"] != "ok":
            endpoint_ok = False
            warnings.append(f"Health check failed: {health.get('error')}")
        else:
            hdata = health["data"]
            peer_count = hdata.get("peer_count", 0)
            if peer_count < MIN_PEERS:
                warnings.append(f"Low peers: {peer_count} < {MIN_PEERS}")
                endpoint_ok = False

            consensus = hdata.get("consensus", {})
            stall_secs = consensus.get("seconds_since_last_commit", 999)
            if stall_secs > STALL_THRESHOLD_SECS:
                warnings.append(f"Consensus stalled: {stall_secs}s since last commit (> {STALL_THRESHOLD_SECS}s)")
                endpoint_ok = False

        if rpc["status"] != "ok":
            endpoint_ok = False
            warnings.append(f"RPC blockNumber failed: {rpc.get('error')}")

        status_sym = "[OK]" if endpoint_ok else "[FAIL]"
        if not endpoint_ok:
            overall_healthy = False

        block_height = rpc.get("block_height", "N/A")
        peers = health.get("data", {}).get("peer_count", "N/A")
        last_commit_secs = health.get("data", {}).get("consensus", {}).get("seconds_since_last_commit", "N/A")
        lat = health.get("latency_ms", "N/A")

        print(f"{status_sym:6} {name:<12} | Block: {str(block_height):<6} | Peers: {str(peers):<3} | Last Commit: {str(last_commit_secs):>2}s ago | Latency: {lat}ms")
        for w in warnings:
            print(f"       -> WARNING: {w}")

        results.append({
            "name": name,
            "url": url,
            "healthy": endpoint_ok,
            "block_height": block_height,
            "peer_count": peers,
            "seconds_since_last_commit": last_commit_secs,
            "warnings": warnings,
        })

    print("=" * 70)
    if overall_healthy:
        print("CLUSTER STATUS: ALL NODES HEALTHY AND CONSENSUS PROGRESSING NORMAL.")
        sys.exit(0)
    else:
        print("CLUSTER STATUS: ISSUES DETECTED. CHECK WARNINGS ABOVE.")
        sys.exit(1)

if __name__ == "__main__":
    main()
