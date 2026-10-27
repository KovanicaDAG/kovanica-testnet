# Mainnet Freeze Checklist (draft — [DRAFT - needs human review])

Status: Phase 24 (P14) — NOT DONE. Created 2026-10-14 after `nod-1` verification (`a2ec2db`).
Consensus impact: client-only / ledger-safe (freeze is operational, not consensus-rule change).

Pre-freeze gates (all must pass before tag / freeze):

- [ ] Seed nodes 3+ registered (`seed1/2/3.kovanica.online`, grey-cloud TCP 8000). Verify `dig +short seedN.kovanica.online`; `nc -vz seedN.kovanica.online 8000`; `KOVANICA_BOOTNODES` populated at deploy time (do NOT hard-code in `config.rs`; keep defaults empty per safety rule).
- [ ] Genesis ceremony completed: all validator pubkeys collected, `genesis_validators.toml` hash compared across validators, `kovanica-node genesis --force` executed on each validator, `genesis.json` + staking state produced; data-dir (`KOVANICA_DATA`) preserved (never wipe after first genesis write).
- [ ] Genesis hash verified across all 15–20 mainnet genesis validators (`build_committee` output matches).
- [ ] Chain id fixed (`4` for the public testnet / testnet v2; `1` for mainnet when launching; `1337` and `3` are local/dev only). `KOVANICA_CHAIN_ID` set.
- [ ] `KOVANICA_ALLOW_RESET=0`, `KOVANICA_FAUCET=0`, `MINE=0`, `OPERATOR=0` enforced on all public nodes. No open faucet / reset enabled.
- [ ] P2P port 8000; no orange-cloud seed references; `seed.kovanica.online` references removed (already done at `a2ec2db`).
- [ ] `/api/head` matches genesis tip; `bootstrap` shows expected peers.
- [ ] External audit scoped (`docs/AUDIT-SCOPE.md` prepared; `AUDIT_REPORT.md` internal baseline active).
- [ ] Freeze tag committed (`git tag -a mainnet-freeze`); changelog updated; `docs/TESTNET-RESET.md` preserved.
- [ ] Monitoring / alerting live (`ops/prometheus/alerts.yml`, `ops/grafana/kovanica-overview.json`); `NodeHealth` (`/health`) returns 200.
- [ ] Budget cap verified (`circulating_supply()` ≤ 90.2M; `block_reward()` within 81M budget; treasury 8M linearly vested).
- [ ] Light-client stack implemented (`kovanica-light`, `kovanica-lightnode`, `kovanica-light-ffi`).
- [ ] Protocol namespace (`/kovanica/`) verified (`behaviour.rs` line 196); audit gate `audit_62_sync_protocol_is_kovanica` passes.

Rollback / recovery if freeze fails:
- Stop all seed nodes together; do NOT restart single seed alone (will split mesh).
- Preserve `KOVANICA_DATA`; rebuild from `genesis.json`; restart all 3+ seeds with matching `KOVANICA_BOOTNODES`.
- Refer to `docs/TESTNET-RESET.md` for rebuild protocol (all 3 seeds rebuilt from same commit, started together).

References: `TASKLIST.md` #14 / #24; `AGENTS.md` rules (seed policy, reset, faucet); `docs/SEED-DNS-AUDIT.md`; `docs/TESTNET-RESET.md`.
