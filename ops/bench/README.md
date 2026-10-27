# TPS Bench — Phase 12.4

- Local 4-node (`docker-compose.yml` topology)
- Transfer txs only, 60 s window
- Measure committed/sec via receipt / committed-leader query
- Target >=100/s
- Log: /tmp/tps-<epoch>.log

Run:
```bash
./ops/bench/tps.sh
```
Requires funded `BENCH_KEY` at `/tmp/kovanica-bench.pk` (or export BENCH_KEY_HEX).
No crate version change.
