# External Audit / Seed / DNS — Checklist (f2b05bf corrected)

Based on `docs/SEED-DNS-AUDIT.md` (port 8000 vs 9000 gap) and HARD RULES.

## 1. Seed / DNS audit (must complete before testnet)
- [ ] Register 3+ **kovanica-native** DNS seeds (`seed1/2/3.<kovanica-domain>`); none may reuse another project's names
- [ ] Verify each seed resolves to the origin IP (grey-cloud; no CDN/proxy) for TCP 8000
- [ ] Publish each seed's libp2p PeerId and confirm `/p2p/` in the multiaddr matches
- [ ] Confirm `KOVANICA_BOOTNODES` defaults stay empty in code; seeds only via env/TOML
- [ ] Confirm P2P does not point at explorer/API hostnames

## 2. External audit scope (not completed — recommend before mainnet)
- [ ] Consensus (Mysticeti DAG, wave=3, k=3): verify uncertified commit rule, no certificate dependency
- [ ] Execution (Wasmi): determinism check, gas metering, ABI compatibility
- [ ] Staking (bond/unbond, active set 15–21, min 50 000 KUNA, commission rules)
- [ ] Tokenomics hard cap: 90 200 000 KUNA, subsidy curve ×¾ decay, era 8 100 000, initial reward 2,5 KUNA, genesis validator allocation 1 000 000, maturity 100
- [ ] Crypto: Ed25519 signatures (64-byte / 128 hex), address derivation, key handling client-only
- [ ] P2P: eclipse / Sybil resistance, peer discovery, gossip limits
- [ ] Node / RPC: `KOVANICA_RPC_AUTH=disable` documented for test only; production must enforce auth; no key/seed passed to node

## 3. Live node verification (repeat before release)
- [ ] Run `curl -s http://<kovanica-node>/api/bootstrap | jq` against a **kovanica** node (local or own testnet)
- [ ] Compare `listen` and `peers` fields against docs / env defaults
- [ ] Confirm `MINE=0`, `FAUCET=0`, `OPERATOR=0` on participant nodes
- [ ] Verify `KOVANICA_DATA` preserved after genesis; no reset (`KOVANICA_ALLOW_RESET=0`)

## 4. CLI / wallet audit (related gaps from tasklist)
- [ ] Delegate / claim: verified in `crates/kovanica-staking` and `kovanica-cli`
- [ ] CLI contract calls: verify ABI / gas metering in `docs/GAS_SCHEDULE.md`

Status: audit **not started**; docs complete. Blocked only by external auditor assignment.
