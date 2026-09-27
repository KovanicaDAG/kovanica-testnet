# AGENTS.md

Guidance for AI assistants (and humans) working in the **kovanica-protocol** repository.

> > **Consensus decision (ratified 2026-09-25): Kovanica is PoA-only.**
> > Proof-of-Work is being removed from the protocol. See
> > `protocol/docs/RFC-POA-Migration.md` §0 (canonical). Items marked `[TARGET]`
> > are ratified but not yet implemented; `[CURRENT]` items describe shipped code.
> >
> > **What this means for you as an agent touching `kovanica-dag` / `kovanica-state`:**
> > - `[TARGET]` PoW is **deleted**, not merely off by default. Removal surface:
> >   `Dag::set_proof_of_work` / `set_difficulty` / `proof_of_work_enabled`,
> >   `DagError::InsufficientProofOfWork` / `DifficultyMismatch`, the `pow` module
> >   (`mine`, `mine_from`, `meets_target`, `is_mined`) and the `difficulty` module
> >   (`Retarget`, `TimedWork`, `next_work`), `KOVANICA_POW`, the node mining loop,
> >   the RPC/explorer `kind: "pow"`, FFI `BlockKind::Pow`, and the
> >   `pow`/`pow-vrf` cargo features. Full table with line refs: RFC-POA-Migration §0.1.
> > - `[CURRENT]` All of the above is **still in the tree and still reachable**.
> >   `KOVANICA_POW` is still read (`explorer.rs` ~874, ~981, default `true` when
> >   unset) and `KOVANICA_CONSENSUS=pow` still selects legacy PoW admission.
> >   **Never write a `[TARGET]` claim as though it were shipped** — a previous
> >   revision of RFC-POA §2 claimed PoA "ignored" a block's `work` when the code
> >   did not, and that divergence was a live consensus bug (§6.1(b)). The
> >   `[TARGET]`/`[CURRENT]` split exists to stop that recurring.
> > - **RFC-006 supply math is unaffected.** The emission curve is
> >   **height-indexed** (`subsidy_at`) and issuance is hard-capped in
> >   `apply_block` (`ledger.rs` ~1617: reject if
> >   `cumulative_minted + claimed_native > MAX_SUPPLY`) — neither depends on who
> >   produced a block or how. MAX_SUPPLY **90.2M KVNC**, s₀ **10 KVNC/block**,
> >   era **2,000,000 blocks**, α **3/4**, maturity **100 blocks**, fee split
> >   **75% burned / 25% producer**, GHOSTDAG **k=3**, UTXO, Ed25519,
> >   **1 KVNC = 100_000_000 atoms** — all unchanged. What changes is the
> >   *pace*: fixed `SLOT_DURATION_MS` (default 3000), no retarget, no gap-fill
> >   (an offline authority yields an empty slot). The cap never moves.
> > - **DECIDED 2026-09-25 — hybrid / staked-VRF admission is dropped entirely**
> >   (§0.7.1). `HybridConfig` is PoW **+** staked-VRF, and **both halves go**:
> >   remove `HybridConfig`, `StakedVrf`, `set_hybrid`/`hybrid_enabled`,
> >   `stake_nominal_work`, the `insert_with_vrf` staked-block path, and the
> >   `KOVANICA_HYBRID` env var. The "PoA + staked-VRF secondary tier" option
> >   was considered and **rejected** — do not re-derive it.
> >   **The stake registry retires with it** (`crates/kovanica-state/src/stake.rs`:
> >   referenced only by `ledger.rs`, `lib.rs`, and the `node.rs` unbond path).
> >   ⚠️ **Do not remove `POA_NOMINAL_WORK`** — it is an independent dag-level
> >   constant, not a `HybridConfig` field.
> >   ✅ **RFC-005 vault/CSV and the treasury vaults are UNAFFECTED** —
> >   `crates/kovanica-state/src/vault.rs` has **zero** `stake`/`bond`/`unbond`/
> >   `vrf`/`Freeze` references (verified 2026-09-25). Treasury vault keys are
> >   a separate concern from authority signing keys.
> > - `[OPEN]` **Do not implement these on the strength of §0** — not settled,
> >   and a governance decision rather than an engineering one: **mainnet
> >   authority-set governance** (§0.7.2). The rotation *mechanism* **is**
> >   settled — the set is fixed at genesis and can only ever rotate via an
> >   on-chain M-of-N `AuthorityUpdateTx`; no election, no external randomness,
> >   no off-chain path, no hardcoded schedule. The residuals are the *inputs*:
> >   how the initial mainnet set is chosen, who is eligible, the authority-key
> >   ceremony (distinct from RFC-005 treasury keys), threshold `t`, expansion
> >   toward `n ≤ 16`, and dissolution/recovery if `t` authorities are lost.

> **Status: early implementation.** Three vertical slices exist, build, and are
> tested: the block DAG and GHOSTDAG consensus core (`crates/kovanica-dag`); the
> UTXO ledger/state layer that applies transactions in GHOSTDAG-linearized order
> with ed25519 spend authorisation, per-block state, snapshot persistence, and
> finality-depth pruning / re-orgs (`crates/kovanica-state`); and a runnable node
> binary with a line RPC, a
> mempool, block production, multi-node block gossip, and an in-process
> continuous overlay (`crates/kovanica-node`: `net` one-shot sync + `p2p::Mesh`
> with peer discovery, a delayed relay loop, and tx dissemination).
> **Proof-of-work is real and opt-in `[CURRENT]` / `[TARGET]`-for-removal**:
> blocks carry a `nonce`, and
> `Dag::set_proof_of_work(true)` makes `Dag::insert` require each block's id to
> meet its `work` target (Nakamoto-style `H * work < 2^256`, so `work` = expected
> hashes). Difficulty is both an algorithm (`kovanica-dag::difficulty`) and, now,
> **consensus-enforced**: blocks carry a `timestamp`, and an opt-in policy
> (`Dag::set_difficulty`) requires each block's `work` to equal the target its
> past implies and its timestamp not to precede any parent's; with PoW on too, the
> block must actually be mined to that work. Separately, the
> **node** now enforces a wall-clock future-time bound on block timestamps
> (`Node::receive_block` rejects a block dated more than two hours ahead of the
> local clock) — deliberately node policy, not a pure function of the DAG.
> Keep this file in sync with the code: update it in the same change that adds or
> moves the structure it describes.

---

## 1. What this project is

**kovanica-protocol** is a **DAG-based distributed ledger** — a high-throughput,
parallel-block cryptocurrency/ledger protocol built on a **Directed Acyclic Graph**
(BlockDAG) rather than a single linear chain. The name *kovanica* is
Serbo-Croatian for "coin / mint." Blocks reference **multiple parents**, so many
blocks can be produced in parallel and later merged, which is what enables high
block rates (BPS).

The consensus core follows **GHOSTDAG** (Sompolinsky, Wyborski & Zohar — the
protocol behind Kaspa, a refinement of PHANTOM). Related systems in the design
space, for reference when extending consensus: IOTA Tangle, Hedera Hashgraph,
Fantom Lachesis/Sonic, Avalanche Snow family, Conflux, OHIE, and the DAG-BFT
mempool/ordering line (Narwhal–Tusk, Bullshark, Mysticeti, Sailfish). When
implementing a mechanism from any of these, **name it** in comments so reviewers
can check it against the paper.

## 2. Core domain concepts (shared vocabulary)

Keep these terms precise and consistent across code, comments, and docs:

- **DAG / BlockDAG** — the ledger is a directed acyclic graph; a block references
  **multiple parents/tips**, enabling parallel block creation.
- **Tip** — a block with no children yet; new blocks reference current tips.
- **Past / ancestors** — all blocks reachable by following parent edges.
- **Anticone** — blocks neither ancestor nor descendant of a given block ("parallel").
- **Selected parent** — the parent with the heaviest blue work; forms the chain backbone.
- **Mergeset** — the blocks a new block merges in: `past(B) \ (past(sp) ∪ {sp})`.
- **Blue set / red set** — the well-connected honest cluster (blue) vs. blocks left
  too far to the side (red), decided by the **k-cluster rule**.
- **k parameter** — max tolerated *blue anticone size*: every blue block may have at
  most `k` blue blocks in its anticone. Larger `k` tolerates higher latency/BPS at a
  wider security margin.
- **Blue score / blue work** — size / total work of a block's blue set; drives chain
  selection and ordering.
- **Partial order → total order (linearization)** — consensus deterministically
  linearizes the DAG so every honest node agrees on one sequence.

## 3. Repository layout

```
Cargo.toml                     Workspace manifest (resolver 2); shared deps: blake3, hex, ed25519-dalek
crates/
  kovanica-dag/                The DAG + GHOSTDAG consensus core (first slice)
    src/
      lib.rs                   Crate docs + re-exports + a doctest quick tour
      block.rs                 Block (multi-parent vertex, work + timestamp + nonce) and BlockId (BLAKE3 hash)
      dag.rs                   Dag store: insert/validate, oracle-backed reachability + mergeset, past_size, tips, GhostdagData, preview(), chain_key, set_difficulty/next_work_target [TARGET-for-removal]
      ghostdag.rs              compute_ghostdag(): selected parent, mergeset, k-cluster blue/red colouring
      ordering.rs              linearize() (recursive GHOSTDAG order), selected_tip/selected_chain
      validation.rs            BlockValidator trait + Dag::with_validator: pluggable insert-time validation
      snapshot.rs              Dag::write_snapshot()/read_snapshot(): replay-log persistence; encode_block/decode_block for the incremental log
      difficulty.rs            Retarget::next_work(): difficulty retargeting for block work (algorithm); enforced via Dag::set_difficulty [TARGET-for-removal]
      pow.rs                   meets_target()/mine(): Nakamoto hash-target proof-of-work (H*work < 2^256); enforced via Dag::set_proof_of_work [TARGET-for-removal]
      reachability.rs          Reachability oracle: interval-tree + future-covering sets (the Dag's backing for is_ancestor + mergeset)
      vrf.rs                   ECVRF over Ristretto255 (Ed25519 curve), IRTF CFRG draft; vrf_prove/vrf_verify for leader selection / randomness beacon (Stage 3)
    tests/
      consensus.rs             Integration + adversarial tests (wide fork, determinism, k-cluster invariant, validator hook)
      reachability.rs          Differential: Dag/oracle is_ancestor == naive parent-walk over random adversarial DAGs
      difficulty.rs            Integration + adversarial: enforced work/timestamp (understate/overstate/backdate rejected, target deterministic) [TARGET-for-removal]
      pow.rs                   Integration + adversarial: enforced proof-of-work (unmined rejected, genesis exempt, off-by-default, composes with difficulty) [TARGET-for-removal]
  kovanica-state/              UTXO ledger applied in GHOSTDAG order (second slice)
    src/
      lib.rs                   Crate docs + re-exports + an end-to-end doctest
      keys.rs                  Address, KeyPair, verify() — ed25519 spend authorisation; Address::to_kvnc()/parse() human addresses (`kvnc…dag`, base58; parse accepts hex too)
      tx.rs                    Transaction/TxId/OutPoint/TxInput/TxOutput; canonical encoding; sighash
      utxo.rs                  UtxoSet: the unspent-output state, with balance/total_value
      ledger.rs                apply_block()/apply_dag() (batch) + Ledger (per-block state, stateful insert, snapshot, finality/pruning)
      store.rs                 LedgerStore: incremental append-only on-disk replay log
      validation.rs            TxStructureValidator: context-free structural checks (a BlockValidator)
      multisig.rs               M-of-N multisignature (RFC-001 P2SH): MultisigScript, script hash, threshold signature verification (see docs/RFC-001-Multisig.md)
      script_v2.rs              RFC-003 script v2: bounded stack machine (ED25519_VERIFY/CLTV/CSV/HASH_BLAKE3/EQUAL/AND/OR/THRESHOLD), step budget, ScriptV2::new/execute (see docs/RFC-003-ScriptV2-and-Stealth.md)
      htlc.rs                  RFC-004 HTLC template: 100-byte HtlcScript (preimage_hash/recipient_pk/sender_pk/timeout), parse-time validation, witness-shape helpers (see docs/RFC-004-Htlc.md)
      vault.rs                 RFC-005 time-lock vault template: 40-byte VaultScript (unlock_height/csv/owner_pk), parse-time validation, spend_witness (see docs/RFC-005-Vault.md)
    tests/
      ledger.rs                Integration + adversarial (double-spend across parallel blocks, order-independence)
      validation.rs            Integration: structural rejection at insert vs stateful rejection at apply
      perblock.rs              Integration: per-block state, stateful insert rejection, apply_dag consistency
      persistence.rs           Integration: Ledger snapshot round-trip (state recomputed by replay)
      store.rs                 Integration: append-only log grows; reopen matches snapshot
      finality.rs              Integration: finality-depth pruning, deep-reorg rejection, implicit re-org
      difficulty.rs            Integration: Ledger::set_difficulty enforces work/timestamp end-to-end [TARGET-for-removal]
      multisig_consensus.rs     Adversarial consensus suite for RFC-001 multisig (35 tests: M-of-N spends, malformed scripts, activation gating, mixed P2PK/P2SH, snapshot roundtrip)
      native_token_consensus.rs  Adversarial consensus suite for RFC-002 native tokens (29 tests: single/multi-asset transfers, per-asset conservation, fee-in-native, coinbase minting, activation gating, mixed blocks, parallel-DAG conflicts, checkpoint/snapshot roundtrip)
      stealth_script_v2_consensus.rs  Adversarial consensus suite for RFC-003 stealth + script v2 (25 tests: 12 stealth + 13 script v2 — one-time-key ECDH spends, view tags, CLTV/CSV/hash-lock/threshold scripts, activation gating, parallel-DAG conflicts, checkpoint roundtrip)
      htlc.rs                  Adversarial consensus suite for RFC-004 HTLC (23 tests: redeem/refund paths, timeout boundary, preimage mismatch, activation gating, parallel-DAG double-spend, checkpoint/snapshot roundtrip, CLTV non-final fix)
      vault.rs                 Adversarial consensus suite for RFC-005 vault + real CSV (26 tests: csv final/aged/composed gates, checkpoint v6 roundtrip, vault absolute/relative/both locks, no-lock parse reject, bad script-hash/signature/template, activation gating, parallel-DAG double-spend, snapshot roundtrip, sequence-understatement, creation-height grinding, relay replay)
  kovanica-node/               Runnable node binary, mempool, and block gossip (third slice + multi-node)
    src/
      lib.rs                   Crate docs + re-exports + a doctest of the RPC
      node.rs                  Node: Ledger + Mempool; genesis/send/pool/produce/balance/tips/save/load + gossip; multi-input prepare_transfer/submit_signed (UTXOs accumulated largest-first, one signature attached to every input); vault helpers create_vault/release_vault/balance_of_vault (RFC-005)
      atomic_swap.rs           RFC-004 Tier Nolan atomic swap: SwapParams/SwapSession/SwapError, timeout ordering T_B < T_A, generate_preimage/extract_preimage (see docs/RFC-004-Htlc.md)
      mempool.rs               Mempool: pending txs, deterministic (id) ordering for block assembly
      mempool_v2.rs            Mempool upgrades: orphan pool (missing-input txs held and re-tried), fee-based eviction, capacity limits
      net.rs                   gossip() (in-process) + serve_blocks/pull_blocks (one-shot TCP sync) + framed bidirectional exchange (pull_blocks_timeout/serve_exchange: read peer dump, apply, send own back; old one-way peers still work)
      p2p.rs                   Mesh: peer discovery (hello), delayed relay loop, block+tx flood
      p2p_hardening.rs         P2P hardening: per-peer rate limiting, duplicate suppression, peer scoring/banning
      dht.rs                   Lightweight Kademlia-based DHT for peer routing (256-bit NodeId space, XOR metric, k-buckets)
      dns_seed.rs              DNS multi-seed resolver for peer discovery (injectable DnsResolver: StdDnsResolver + MockDnsResolver)
      relay.rs                 RelaySession: long-lived TCP framing of hello/block/tx
      rpc.rs                   Line RPC: one text command per line in, one line out (execute_line is a pure function of node + command)
      spv.rs                   SPV light client wire sync + proof verification over persistent RelaySession connections
      explorer.rs              self-hosted explorer: JSON API + static UI over Mesh (WebSocket /ws, open faucet, dual-stack P2P listeners, KOVANICA_MINE_SECS interval)
      explorer.html            UI served by `kovanica-node explorer`
      metrics.rs               Prometheus metrics + structured logging (block rate, peer count, histograms)
      fuzz.rs                  Fuzzing infrastructure: Arbitrary impls for core types + libfuzzer/cargo-fuzz targets
      bip39-english.txt        BIP-39 English wordlist (2048 words) for mnemonic seed phrases (data file, not .rs)
      main.rs                  Binary: `serve` (stdin/stdout REPL) and `demo` (scripted scenario)
    tests/
      rpc.rs                   Integration: end-to-end transfers, errors, snapshot round-trip via RPC
      mempool.rs               Integration: pool/produce assembly, conflict partial-inclusion
      network.rs               Integration: multi-node convergence (in-process + conflict + TCP loopback)
      p2p.rs                   Integration: discovery, relay, tx dissemination, mempool eviction
      relay.rs                 Integration: persistent TCP session, block/tx over a live socket
      timestamps.rs            Integration: wall-clock timestamp policy (pinned clock, monotone stamps, far-future reject)
      challenger_1_mining_adversarial.rs   Adversarial/empirical stress on external mining endpoints (9 tests: malformed JSON, invalid parents, corrupted payloads, work/nonce types, timestamp drift, template queries, fuzz burst) [TARGET-for-removal]
      challenger_external_mining.rs        Empirical external-mining JSON endpoint suite (7 tests: full mine loop, invalid nonce, duplicate idempotency, mempool packing, custom payout, mesh propagation, malformed inputs) [TARGET-for-removal]
      challenger_e2e_mining_lifecycle.rs   Challenger 2 e2e external-mining lifecycle + consensus integration harness (1 test: template → PoW → submit → DAG/mempool/coinbase verification) [TARGET-for-removal]
      challenger_consensus_sync.rs         Empirical consensus-invariant suite (10 tests: difficulty retarget clamps, SPV difficulty bounds, wall-clock drift, reorg locator sync, deep-reorg/fork convergence) — the difficulty-retarget cases are [TARGET]-obsolete, the rest survive
      htlc_node.rs             Integration: RFC-004 swap e2e (create/verify/redeem/extract/refund), timeout-ordering enforcement, htlc_* RPC commands
      vault_node.rs            Integration: RFC-005 vault node surface — create/release/balance, absolute + relative + combined gates, owner-signature requirement, vault_* RPC commands
  kovanica-wallet/             Keys: BIP-39 + SLIP-0010 ed25519 derivation, wallet file I/O (client-only; no consensus surface)
    src/
      lib.rs                   Crate docs + re-exports
      slip10.rs                SLIP-0010 ed25519 master/child derivation. `derive_path(&[u8], &[u32])` is the generic hardened path; `derive_ed25519` delegates to it at the FROZEN Kovanica path
      wallet.rs                `Wallet`: generate/restore/load/save, `from_seed` (raw 32-byte) vs `from_mnemonic*` (BIP-39 passphrase support), `load_with_passphrase`, `public_key`
    tests/
      slip10_vectors.rs        Known-answer tests: official SLIP-0010 ed25519 vector 1, the frozen-path index 0/1/2 vectors, render/parse round-trip, generate/restore round-trip
  kovanica-cli/                `kovanica` binary: explorer queries, local wallet, signed transfers, terminal UI (client-only)
    src/
      lib.rs                   Re-exports `Wallet` from kovanica-wallet so `kovanica_cli::Wallet` keeps working
      main.rs                  clap surface + command dispatch
      api.rs                   Thin HTTP client for the explorer JSON API
      tui/                     Terminal UI — `mod.rs` (App/event loop/Screen trait), `theme.rs`, `widgets.rs`, `screens/` (dashboard, explorer, wallet, send, assets, contracts, stealth, nft_rwa, settings)
  kovanica-ffi/                UniFFI bindings for the mobile light node (Slice 3)
```

⚠️ **Key derivation is frozen and has exactly one implementation.** `Wallet`
lives in `kovanica-wallet`, which both `kovanica-node` (genesis keys) and
`kovanica-cli` depend on. The path is `m/44'/3007'/0'/0'/i'`, with **every**
segment hardened (`| 0x80000000`); the official SLIP-0010 index convention (only
the leading `m` unhardened) is deliberately **not** used, because changing it
would move every derived address. `tests/slip10_vectors.rs` pins the vectors, so
the two can never silently diverge again. The standalone `cli/` tree (now
deleted) used a truncating derivation instead, which is why the divergence is
gone. Never add a second BIP-39/SLIP-0010 implementation. Genesis itself never
derives from a mnemonic (founder uses `from_seed(founder_seed)`, treasury uses
`KeyPair::from_u64`), so derivation changes cannot move a balance.

⚠️ **`crossterm` must track the version ratatui 0.29 re-exports** (`0.28.1`).
Declaring a different minor pulls a second `crossterm` into the tree, which
makes `crossterm::event::KeyEvent` and `ratatui::crossterm::event::KeyEvent`
distinct types and silently breaks `Screen::handle_key`'s trait/impl match.

⚠️ **`crates/*/data/` and `desktop-app/data/` are gitignored and hold secrets.**
`Node::data_dir()` defaults to a relative `data/`, so test runs drop the founder
premine key, the operator wallet (possibly a BIP-39 phrase) and validator seeds
into the source tree. Point `KOVANICA_DATA` outside the checkout.

android-light-node/            Jetpack Compose light-node wallet app (slices 9a–9e)
  app/src/main/java/com/kovanica/lightnode/
    data/                      LightNodeRepository (process singleton), WalletRepository, SecureSeedStorage, MultisigRepository
    ui/                        Compose screens, ViewModel, Material3 theme
    work/                      WorkManager periodic sync + local notifications (Slice 9e)
  gradle/libs.versions.toml    AGP / Kotlin / Compose / WorkManager / biometric dependency pins

docs/                          Protocol RFCs + plans: RFC-001-Multisig.md, RFC-002-NativeTokens.md, RFC-003-ScriptV2-and-Stealth.md, RFC-004-Htlc.md, RFC-005-Vault.md, plans/ (mobile-light-node, htlc-atomic-swap, vault-time-lock, …)

VRF is shipped (Stage 3) — see `crates/kovanica-dag/src/vrf.rs` above and the Stage 3 checklist.

### Multisig — RFC-001 (M-of-N witness payloads & P2SH)

Shipped in `kovanica-state`; full spec in `docs/RFC-001-Multisig.md`. Multisig
outputs lock value behind a **threshold redeem script** and spend via a witness
stack, using **Version 0x01 (P2SH)** addresses distinct from the ordinary
Version 0x00 (P2PK) single-key addresses.

- **Redeem script** `[M (1B), N (1B), pk_1 (32B), …, pk_N (32B)]`; `1 <= M <= N`,
  `N <= 16` (`MAX_MULTISIG_KEYS`). Strictly validated at parse (M/N bounds,
  exact length, valid distinct Ed25519 points).
- **Address** = `0x01 || BLAKE3(redeem_script)` (33 versioned bytes; renders as
  `kvnc…dag` like P2PK). `MultisigScript::address()` / `Address::from_script`.
- **Witness layout** on a P2SH input: `witness[0]` = raw redeem script,
  `witness[1..=M]` = exactly `M` valid 64-byte Ed25519 signatures over the
  transaction `sighash` (BLAKE3 of the witness-free encoding). Spend validation
  checks script-hash match, script validity, witness count (`1 + M`), signature
  size, and threshold verification against **distinct** authorized keys
  (duplicates rejected).
- **Activation gating**: P2SH is a consensus upgrade gated on blue score
  (`MULTISIG_ACTIVATION_SCORE = 0` default; `Ledger::set_multisig_activation_score`).
  Pre-activation (`blue_score <= activation_score`) rejects P2SH outputs and
  P2SH/multi-witness spends (`PreActivationMultisig`); post-activation P2PK
  remains valid forever. Enforced identically in the incremental `Ledger` and
  batch `apply_dag`/`apply_block` paths.
- **Tests**: `crates/kovanica-state/tests/multisig_consensus.rs` (35 tests) —
  M-of-N spends (1-of-1 … 16-of-16), invalid M/N, malformed scripts, hash
  mismatches, witness anomalies, crypto integrity, duplicate-signature attacks,
  activation boundary, mixed P2PK/P2SH blocks, parallel-DAG double-spend, and
  snapshot roundtrip.

### Native tokens — RFC-002 (multi-asset outputs)

Shipped in `kovanica-state`; full spec in `docs/RFC-002-NativeTokens.md`.
Native tokens bring Cardano-style **multi-asset** outputs to the UTXO ledger:
an output locks a `value` of a specific `asset_id`, and the ledger conserves
each asset independently. The native KVNC asset is `asset_id = None`
(`AssetId::native()`, all-zero 32 bytes); every other asset carries its
32-byte definition hash.

- **AssetId** = 32-byte BLAKE3 digest of an asset definition; `AssetId::native()`
  is all zeros and `is_native()` distinguishes it. Renders as lowercase hex.
- **TxOutput.asset_id** field (`Option<AssetId>`; `None` = native KVNC) with two
  constructors: `TxOutput::new(value, asset_id, owner)` (explicit asset) and
  `TxOutput::native(value, owner)` (native KVNC). `UtxoSet::balance_of_asset`
  queries per-asset balances; `UtxoSet::balance` is now **native-only** (asset
  outputs are excluded).
- **Encoding change**: the canonical transaction encoding gained a **1-byte
  asset flag** per output (0 = native/None, 1 = present + 32-byte asset id);
  the minimum output size is now **42 bytes** (8 value + 1 flag + 33 owner).
  ⚠️ **FORMAT BUMP** — old wire blobs are **undecodable** by the new reader and
  new blobs by the old reader; the testnet **resets at activation**.
- **Per-asset conservation**: a non-coinbase transaction must conserve each
  asset independently (`inputs[asset] >= outputs[asset]`); minting an asset in
  a regular tx is rejected (`AssetNotConserved`). **Fees are paid in native
  KVNC only** — the native input/output difference is the fee; burning an asset
  (output < input) is allowed.
- **Coinbase may mint any asset** (for initial distribution): the subsidy limit
  applies only to native KVNC outputs, and native-token activation gating does
  **not** apply to coinbase outputs.
- **Activation gating**: native tokens are a consensus upgrade gated on blue
  score (`NATIVE_TOKEN_ACTIVATION_SCORE = 0` default;
  `Ledger::set_native_token_activation_score`). Pre-activation
  (`blue_score <= activation_score`) rejects asset outputs and spends of asset
  inputs (`PreActivationNativeToken`); post-activation native-only outputs
  remain valid forever. Enforced identically in the incremental `Ledger` and
  batch `apply_dag`/`apply_block` paths.
- **Checkpoint v4**: the UTXO checkpoint encoding gained the optional asset_id
  (32 bytes after owner); `read_checkpoint` accepts v3 (stake registry) and v4.
- **Node methods**: `send_asset(from_seed, amount, to_seed, asset_id)`,
  `send_to_asset(from_seed, amount, to, asset_id)`,
  `send_with_asset(kp, amount, to, asset_id)`,
  `build_transfer_with_asset(kp, amount, to, asset_id)`,
  `prepare_transfer_asset(from, amount, to, asset_id)`, and
  `balance_of_asset(owner, asset_id)` — the native-only `send`/`send_to`/
  `send_with`/`prepare_transfer`/`balance` delegate with `asset_id = None`.
- **FFI methods**: `send_asset` / `send_from_asset` / `balance_of_asset`
  (asset id as lowercase hex; `None` = native KVNC), plus `asset_id_hex` on
  `HistoryEntry` and `MultisigSpendOutput`.
- **Tests**: `crates/kovanica-state/tests/native_token_consensus.rs` (29 tests) —
  single/multi-asset transfers, mixed native/asset transfers, unknown/mismatched
  asset ids, per-asset conservation, fee-in-native, coinbase minting, activation
  boundary (pre/post/exact), mixed blocks, parallel-DAG asset conflicts,
  checkpoint/snapshot roundtrip, zero-value outputs, and AssetId/TxOutput
  constructors.

### Stealth addresses & script v2 — RFC-003

Shipped in `kovanica-state`; full spec in `docs/RFC-003-ScriptV2-and-Stealth.md`.
RFC-003 adds two address versions on top of P2PK (`0x00`) and P2SH (`0x01`):
**Version 0x02 (script v2)** locks value behind a small deterministic program;
**Version 0x03 (stealth)** delivers CryptoNote-style one-time output keys via
ECDH. Both are consensus upgrades gated on blue score.

- **Address versions**: `0x02` = `0x02 || BLAKE3(script_bytes)` (33 bytes, same
  shape as P2SH); `0x03` has **two** forms — the **published** 65-byte
  `StealthAddress` (`0x03 || scan_pk || spend_pk`, what senders derive from) and
  the **on-chain owner** `0x03 || BLAKE3(scan_pk || spend_pk)` (33 bytes, what
  the ledger stores). The raw keys are never stored on-chain — the ledger only
  needs the hash to identify the owner and the per-output one-time key `P` to
  verify spends.
- **StealthExt** (`tx.rs`): stealth outputs carry `Option<StealthExt>`
  (`r` = ephemeral point `R = r·G`, `view_tag` = first byte of
  `BLAKE3(r·scan_pk)`, `p` = one-time pubkey `P = H(r·spend_pk)·G`). The
  canonical transaction encoding gained a `stealth_flag` byte + 65-byte
  extension per output; `Transaction` gained `n_lock_time`/`sequence` (u32,
  BIP-65/BIP-112) after the outputs, covered by the sighash.
- **One-time-key ECDH** (Edwards25519, curve25519-dalek): sender
  `StealthAddress::derive_output(r_secret)` produces `(R, view_tag, P)`;
  recipient `derive_one_time_key(spend_sk_seed, R)` recovers the signing key
  and `view_tag_for(scan_sk_seed, R)` recomputes the view tag for SPV
  filtering. A stealth spend is a single 64-byte signature over the sighash
  verified against `P` (`verify_pk`).
- **Script v2** (`script_v2.rs`): a bounded, non-Turing-complete stack machine —
  opcodes `0x01` ED25519_VERIFY, `0x02` CLTV (BIP-65), `0x03` CSV (BIP-112),
  `0x04` HASH_BLAKE3, `0x05` EQUAL, `0x06` AND, `0x07` OR, `0x08` THRESHOLD
  (inline M-of-N). `SCRIPT_V2_MAX_LENGTH = 1024`, `SCRIPT_V2_STEP_BUDGET =
  1000`. `ScriptV2::new` validates at parse time; `ScriptV2::execute(sighash,
  witness, n_lock_time, sequence)` runs with the **witness elements only** as
  the initial stack — the sighash is **not** pre-loaded, it is an environment
  value available to ED25519_VERIFY/THRESHOLD (deliberate divergence from the
  RFC's original §5.3 wording). A script-v2 spend reveals the script in
  `witness[0]` (BLAKE3 must match the owner payload → `ScriptHashMismatch`).
- **Activation gating**: `STEALTH_ACTIVATION_SCORE = 0` /
  `SCRIPT_V2_ACTIVATION_SCORE = 0` (defaults; `Ledger::set_stealth_activation_score`
  / `set_script_v2_activation_score` with getters). Pre-activation
  (`blue_score <= activation_score`) rejects the version's outputs and spends
  (`PreActivationStealth` / `PreActivationScriptV2`); post-activation P2PK/P2SH
  remain valid forever. Enforced identically in the incremental `Ledger` and
  batch `apply_dag`/`apply_block` paths.
- **Checkpoint v5**: the UTXO checkpoint encoding gained the stealth flag +
  65-byte `StealthExt` per output (`CHECKPOINT_VERSION = 5`); `read_checkpoint`
  accepts v3 (stake registry), v4 (asset_id), and v5.
- **Node methods**: `send_to_script_v2(kp, amount, script)`,
  `send_to_stealth(kp, amount, &StealthAddress)`, `balance_of_script(script)`,
  `balance_of_stealth(&StealthAddress)`. ⚠️ The node derives `r_secret`
  deterministically (`BLAKE3(kp.seed() || amount_le || counter_le)` with a
  node-local `AtomicU64` counter) — production should use a random `r` for
  unlinkability.
- **FFI methods**: `send_to_script_v2(signing_secret_hex, amount, script_hex)`,
  `send_to_stealth(signing_secret_hex, amount, stealth_address_hex)`,
  `balance_of_script(script_hex)`, `balance_of_stealth(stealth_address_hex)`.
- **Tests**: `crates/kovanica-state/tests/stealth_script_v2_consensus.rs`
  (25 tests: 12 stealth — coinbase mint, derived-key spend, wrong-key/witness/
  size/tampered-R rejection, view-tag match, activation boundary, parallel-DAG
  double-spend, checkpoint roundtrip; 13 script v2 — single-sig, CLTV/CSV
  pass+reject, hash-lock, AND/OR, threshold 2-of-3 + not-met, hash mismatch,
  invalid script, activation boundary), plus
  `crates/kovanica-node/tests/stealth_script_v2_node.rs` (4 tests) and
  `crates/kovanica-ffi/tests/ffi.rs` (`send_to_script_v2_and_stealth_over_ffi`).

### HTLC / atomic swap — RFC-004

Shipped in `kovanica-state` + `kovanica-node`; full spec in
`docs/RFC-004-Htlc.md`. RFC-004 adds **Version 0x04 (HTLC)** — a dedicated,
structurally-validated 100-byte template (not a script v2 extension) that locks
value behind a preimage hash + timeout, plus a Tier Nolan atomic-swap
orchestration layer. Consensus upgrade gated on blue score.

- **Template** (`htlc.rs`): `HtlcScript` = `preimage_hash (32B) ||
  recipient_pk (32B) || sender_pk (32B) || timeout u32 LE` (100 bytes, no
  version byte inside — the address version is the discriminator). Parse-time
  validation rejects wrong length, invalid Ed25519 points, and duplicate
  recipient/sender keys. `Address::VERSION_HTLC = 0x04`; address =
  `0x04 || BLAKE3(template)` (33 bytes, `kvnc…dag` rendering unchanged);
  `VERSION_MAX` bumps 0x03 → 0x04.
- **Two spend paths** (ledger branch on `is_htlc()`, discriminated by witness
  length — deterministic, no script interpreter): **redeem** (3 elements:
  template, preimage, recipient sig) has no time constraint (BIP-199);
  **refund** (2 elements: template, sender sig) requires `height >= timeout`
  (`HtlcTimeoutNotReached`). Wrong preimage → `HtlcPreimageMismatch`.
- **Activation gating**: `HTLC_ACTIVATION_SCORE = 0` (default;
  `Ledger::set_htlc_activation_score` with getter). Pre-activation
  (`blue_score <= activation_score`) rejects HTLC outputs and spends
  (`PreActivationHtlc`); coinbase outputs exempt. Enforced identically in the
  incremental `Ledger` and batch `apply_dag`/`apply_block` paths.
- **Companion CLTV fix** (BIP-65/BIP-113, separable commit): `apply_regular`
  now rejects any tx with `n_lock_time > block height` (`NonFinalTransaction`)
  — script v2's CLTV becomes real (`block_height >= n_lock_time >= v`). CSV
  (BIP-112) deferred to 5.2 (needs per-UTXO creation-height tracking).
- **Atomic swap** (`atomic_swap.rs`, pure library): `SwapParams`/`SwapSession`/
  `SwapError`; `SwapSession::new` enforces the safety invariant `timeout_b <
  timeout_a` (`TimeoutOrdering`) and distinct parties (`SameParty`);
  `verify_against` is Bob's on-chain check of HTLC-A before funding HTLC-B;
  `generate_preimage`/`preimage_hash`/`extract_preimage` (trustless
  preimage-revelation path).
- **Node methods**: `create_htlc(kp, amount, asset_id, recipient_pk,
  preimage_hash, timeout)` → `HtlcInfo`, `redeem_htlc(kp, outpoint, script,
  preimage, to)`, `refund_htlc(kp, outpoint, script, to)`,
  `balance_of_htlc(script)`, `scan_for_htlc_redeem(script, from_height)`.
- **RPC commands**: `htlc_create`, `htlc_redeem`, `htlc_refund`, `htlc_balance`.
- **FFI methods**: `create_htlc`, `redeem_htlc`, `refund_htlc`,
  `balance_of_htlc`, `htlc_script_hex`, `htlc_preimage_hash_hex`.
- **Tests**: `crates/kovanica-state/tests/htlc.rs` (23 tests — redeem/refund
  paths, timeout boundary, preimage mismatch, activation boundary,
  parallel-DAG double-spend, checkpoint/snapshot roundtrip, CLTV non-final
  fix), `crates/kovanica-node/tests/htlc_node.rs` (4 tests — swap e2e,
  refund path, timeout-ordering enforcement, RPC), plus 2 ffi.rs cases.
- **Format bump: none** — HTLC is an address version in the existing 33-byte
  `owner` field; tx encoding, checkpoint (v5), snapshot, and `kvnc…dag`
  rendering are unchanged. **No testnet reset.**

### Vault / CSV — RFC-005

Shipped in `kovanica-state` + `kovanica-node`; full spec in
`docs/RFC-005-Vault.md`. RFC-005 does two things in one consensus change: makes
**CSV (relative locktime) real** (the half of RFC-004 §5.2 that was deferred)
and layers a dedicated **Version 0x05 (Vault)** template on top. Consensus
upgrade gated on blue score (`VAULT_ACTIVATION_SCORE = 0` default).

- **Per-UTXO creation height** (`utxo.rs`): every unspent output now carries
  `creation_height` — the linearized block height at which it entered the set.
  `UtxoSet` entries are v6 (each gains an 8-byte creation height after the
  output payload); old checkpoints decode with `creation_height = 0`
  (immediate-unlock default — safe because CSV only delays, never
  fast-forwards). **Checkpoint format bumps to v6** (`CHECKPOINT_VERSION`);
  snapshot and wire tx encoding are unchanged.
- **Real CSV ledger rule** (`ledger.rs`, NOT gated behind activation — it is a
  transaction-finality rule like RFC-004's CLTV fix, active from genesis): an
  input with `sequence != 0` is a relative block lock measured per input from
  that input's UTXO creation height. A tx is rejected
  (`NonFinalRelativeSequence`) unless `sequence == 0`, `sequence == u32::MAX`,
  or the BIP-68 disable-flag bit (`0x80000000`) is set (final), or
  `block_height >= creation_height + sequence` (overflow pinned to `u64::MAX`).
- **Vault template** (`vault.rs`): `VaultScript` = `unlock_height u32 LE ||
  csv u32 LE || owner_pk (32B)` (40 bytes, no version byte inside). Parse
  rejects wrong length, an invalid Ed25519 owner point, and **both locks zero**
  (`NoLock` — a lockless vault would be a P2PK output). `Address::VERSION_VAULT
  = 0x05`; address = `0x05 || BLAKE3(template)`. Spend witness:
  `[template, owner_sig over the tx sighash]`.
- **Both locks required** (ledger branch on `is_vault()`): a vault spend is
  accepted only when `block_height >= unlock_height` **and**
  `block_height >= creation_height + csv`; each lock is optional (0 = off) but
  at least one must be set. Failures surface as `VaultAbsoluteNotReached` /
  `VaultRelativeNotReached` (with the required/actual heights in the error).
- **Activation gating**: `VAULT_ACTIVATION_SCORE = 0` default;
  `Ledger::set_vault_activation_score(score)` with getter. Pre-activation
  (`blue_score <= activation_score`) rejects `0x05` **outputs** and P2SH-less
  vault spends (`PreActivationVault`) — note this gates the vault branch only,
  not the finality/CSV ledger rule. Coinbase outputs are exempt. Enforced
  identically in the incremental `Ledger` and batch `apply_dag`/`apply_block`
  paths.
- **Chain-height discipline** (consensus parity): the CSV/vault clocks use the
  **selected-parent chain height**, not blue score (`blue_score` counts merged
  blue blocks and exceeds chain height for mergeset blocks). The incremental
  `Ledger` tracks chain heights per block; the batch `apply_dag` path computes
  the same heights via `GhostdagData.selected_parent` + `Dag::linearize()`
  (ancestors precede descendants), so CSV creation heights agree across paths
  (regression-guarded by `csv_grind_creation`).
- **Node methods**: `create_vault(kp, amount, unlock_height, csv, owner_pk)`
  → `VaultInfo` (template, address, funding tx id, outpoint),
  `release_vault(kp, outpoint, script, to)` (owner signature; pays fee out of
  the vault value), `balance_of_vault(script)`.
- **RPC commands**: `vault_create <from-seed> <amount> <unlock-height> <csv>
  <owner-pk-hex>`, `vault_release <from-seed> <outpoint-tx-hex>
  <outpoint-index> <script-hex> <to-addr>`, `vault_balance <script-hex>`.
- **FFI**: not yet surfaced (the RFC-004 HTLC FFI slice is the model; deferred
  to a follow-up).
- **Tests**: `crates/kovanica-state/tests/vault.rs` (26 tests — csv
  final/aged/composed gates, checkpoint v6 roundtrip, vault
  absolute/relative/both locks, no-lock parse reject, bad
  script-hash/signature/tampered template, activation boundary, parallel-DAG
  double-spend, snapshot roundtrip, sequence-understatement, creation-height
  grinding, relay replay), `crates/kovanica-node/tests/vault_node.rs` (5 tests
  — absolute/relative/combined gates, owner-signature requirement, RPC).
- **Format bump: checkpoint v6 only** — tx encoding, snapshot, and `kvnc…dag`
  rendering unchanged. **No testnet reset.**

### Tokenomics — RFC-006 (emission, cap, maturity, fee burn)

Shipped in `kovanica-state`; full spec in `docs/RFC-006-EmissionCurve.md`.
**Live on `kovanica-testnet`** since 2026-09-20. RFC-006 defines the money
supply: a smooth geometric emission curve, a hard 90.2M cap, 100-block coinbase
maturity, and a 75% fee burn. It is the only RFC that is **not** blue-score
gated — see "Activation" below, which is the reason it needed a genesis reset
rather than a fork.

- **Constants** (`ledger.rs`): `ATOM = 100_000_000` (1 KVNC = 1e8 atoms),
  `RFC006_GENESIS_SUBSIDY = 10 * ATOM`, `RFC006_ERA_LENGTH = 2_000_000`,
  `MAX_SUPPLY = 90_200_000 * ATOM`, `RFC006_PREMINE = 200_000 * ATOM`,
  `RFC006_TREASURY_TOTAL = 10_000_000 * ATOM` (10 × 1M tranches),
  `COINBASE_MATURITY = 100`, `FEE_PRODUCER_NUM/DEN = 1/4`.
- **Emission** (`HalvingSchedule::subsidy_at`): `era = height / 2_000_000`,
  `s(0) = 10 KVNC`, `s(e) = floor(s(e-1) * 3/4)`, **0 for era ≥ 256**. The type
  name `HalvingSchedule` is retained for API stability — the decay is
  **geometric (α = 3/4), not a binary halving**. Do not infer halving semantics
  from the name. (`DEFAULT_HALVING_ERA` is an alias; prefer
  `HalvingSchedule::rfc006()`.)
- **The 80M curve total is asymptotic, not exact.** Summing `s(e) · E` with
  integer flooring at each step realizes **79 999 997.6 KVNC**, so the honest
  emission ceiling is `0.2M + 10M + 79 999 997.6` = **90 199 997.8 KVNC**,
  ~2.2 KVNC *under* `MAX_SUPPLY`. The cap is a backstop against over-claiming
  coinbases, never a curve truncation. Docs quoting a flat "80M curve" are
  quoting the asymptotic limit.
- **Activation — the odd one out.** `TOKENOMICS_ACTIVATION_SCORE = 0` is a
  **documented marker only**: the curve, cap, maturity, and fee split are
  **unconditional hard rules active from genesis**. There is no pre-activation
  schedule (the ledger holds a single emission schedule), so per the code comment
  **do not branch on it**. Structurally opposite to RFC-001…005, which are all
  blue-score gated and therefore backward-compatible; RFC-006 cannot be, which
  is why activating it reset the chain and wiped pre-RFC-006 balances.
- **Cap enforcement** is per-view, in `apply_block`: a coinbase whose native
  outputs would push cumulative minted past the cap is rejected as
  `LedgerError::SupplyCapExceeded { claimed, native_minted, max_supply }`. Two
  parallel blocks that each bring cumulative minted to exactly `MAX_SUPPLY` are
  **both** valid in their own view; the conflict resolves only in the merger's
  view. Landing exactly on the cap is accepted; one atom past is rejected.
  Genesis may mint premine + treasury up to the cap; the curve applies from
  height 1.
- **Maturity** is measured on the **selected-parent chain height**, not blue
  score (blue score counts merged blue blocks and exceeds chain height for
  mergeset blocks) — so the incremental `Ledger` and the batch `apply_dag` path
  agree (`mergeset_coinbase_creation_height_matches_apply_dag`). Genesis is
  exempt. Pruning must retain UTXO creation heights for ≥ `COINBASE_MATURITY`
  blocks.
- **Fees**: floor `max(1, subsidy / 500_000)` atoms/byte — **2000 atoms/byte at
  genesis**, 1500 at height 2 000 000, never below 1. Decays with the subsidy.
  Paid in **native KVNC only** (RFC-002 non-native assets cannot pay fees).
  Producer takes `fees / 4`, the remaining 75% is burned. Because
  `fees - fees/4` is **not additive**, cumulative burn is tracked as an explicit
  per-block sum (`Ledger::fees_burned`, carried in each block's view) rather than
  recomputed as `total - total/4`, which drifts from the true sum.
- **Treasury**: 10 × 1M RFC-005 vault tranches; tranche *k* (1..=10) unlocks at
  `k * BLOCKS_PER_YEAR` (`31_536_000`, one tranche/year at 1 block/s), enforced
  by the RFC-005 absolute lock. ⚠️ Owner keys are **testnet placeholders**
  (`KeyPair::from_u64(TREASURY_SEED_BASE + k)` — publicly derivable by design).
  Production **must** pass a real secret `treasury_seed` via key ceremony.
- **Supply metrics** (`Ledger::supply()` → `SupplyMetrics`): `total`/
  `native_minted` (cumulative), `circulating` (tip UTXO native total —
  **approximate**, not a maturity-aware spendable balance; clients must filter
  immature coinbases themselves, which the tx builder already does), `burned`,
  `max_supply`. Exposed on `GET /api/bootstrap`.
- **Format bump: none** — no new persisted field; RFC-006 rides existing ones.
  Breaking at the **economic** layer only: a pre-RFC-006 and an RFC-006 chain
  both parse but disagree on subsidy/maturity/fees, so pre-2026-09-20 testnet
  data is disposable.
- **Tests**: `crates/kovanica-state/tests/tokenomics.rs` (18 tests — geometric
  decay per era, closed-form total, monotone + terminates after 256 eras, cap
  rejection, exact-cap-accepted/over-cap-rejected, near-cap parallel blocks
  rejected order-independently, maturity incl. genesis exemption and mergeset
  rejection in the merger view, fee burn 3/4, parallel fee conflicts at merge,
  batch-path cap enforcement, pruning-heights survival, snapshot/checkpoint
  supply continuity, mergeset creation height).
- **Obsolete numbers** (pre-RFC-006, still quoted in older docs and in git
  history): 200 KVNC/block subsidy, 50 KVNC founder premine, binary halving
  every 1000 blocks, `0.0001 KVNC` min fee. `node/TESTNET.md` used to carry a
  stale copy of these; it is now a pointer to `TESTNET.md`, which is the single
  canonical testnet parameter table. See `TESTNET-RFC006.md` and
  `docs/RFC-006-EmissionCurve.md` for current truth.

### Web app — Grok preview bridge (dev-only)

`web/src/lib/preview-host-bridge.ts`, `web/src/lib/preview-embedder-origin.ts`, and
`web/src/components/preview-host-bridge.tsx` (mounted in `web/src/routes/__root.tsx`)
implement a dev-only `postMessage` bridge for the Grok preview chrome. It activates only
when the app is framed by an allowlisted Grok embedder origin (`grok.com`/
`grok-sandbox.com`); top-level runs (local dev, deployed sites) noop. It lets the preview
chrome drive navigation and query registered routes. Not part of the production web surface.

### Deliberate first-slice simplifications (do not mistake for the final design)

- **Reachability** is answered by the interval-tree + future-covering-set oracle
  (`reachability::Reachability`): the selected-parent tree carries DFS interval
  labels and each block a future-covering set for the non-tree edges. This **is**
  the `Dag`'s backing — the per-block `past` sets are gone; each block keeps only
  its `past_size` (the ancestor *count*, all the topological sort key needs), and
  the mergeset is recomputed by a `sp`-bounded backward walk over parent edges
  (`Dag::mergeset_ordered`). The oracle is maintained **incrementally**:
  `Dag::insert` calls `Reachability::add_block` to fold in just the one new block
  — the **Kaspa reachability** scheme (interval allocation with **reindexing** of
  the minimal enclosing subtree, plus incremental future-covering-set insertion
  over the block's mergeset) — never rebuilding from scratch. Because the DAG is
  append-only and each block's selected parent is fixed at insert, the new block
  is always a fresh tree **leaf**, so existing tree edges never move. The
  from-scratch `Reachability::build` is kept to seed genesis and as an independent
  test oracle. Correctness is guarded by a differential test against an
  independent naive parent-walk, an "incremental oracle == freshly-built oracle
  after every insert" test, reindex-stressing scenarios (long chains, wide fans,
  deep+wide mixes), and the whole consensus/ledger suite (unchanged by the
  cutover). Interval **reindexing amortisation** is now tuned: a `CHILD_RESERVE`
  cap on each allocated child interval keeps a wide fan reindex-free (previously
  `O(width^2)` reindex work) — an interval-numbering-only change guarded by the
  correctness-parity + reindex-metric tests. Still open: the DAG-level
  (`past`-set) pruning the oracle unlocks. See `dag.rs` and `reachability.rs`
  module docs.
- **In-memory working state**, with **replay-log persistence**: `Dag`/`Ledger`
  `write_snapshot`/`read_snapshot` serialise only `k`, the subsidy, and the blocks
  in topological order; loading replays inserts so all derived state (the
  reachability oracle, colouring, per-block UTXO state) is recomputed, never
  trusted from disk. There
  is no incremental on-disk store or mmap yet — a snapshot is written/read whole.
- **Linearization** is the recursive GHOSTDAG order:
  `order(B) = order(selected_parent(B)) ++ mergeset_order(B) ++ [B]`, unrolled over
  the selected chain and closed with the selected tip's anticone (the virtual
  block's mergeset). The selected chain is a subsequence and each merged block
  sits directly before its merger. Mergeset order within a block is a deterministic
  topological sort by `(past_size, id)` — a valid GHOSTDAG-spirit order, not Kaspa's
  exact blue-work mergeset tiebreak. See `ordering.rs` module docs.
- **State (`kovanica-state`)** applies transactions in GHOSTDAG order. Two views:
  `apply_dag` folds a finished DAG from scratch; `Ledger` maintains each block's
  view state incrementally from its selected parent (per-block state stored in
  full — an O(n²) memory trade-off; the DAG's own `past` sets have since been
  replaced by the reachability oracle, but the per-block UTXO state has not). A
  halving schedule ([`HalvingSchedule`]) controls per-block subsidy; coinbase
  maturity is only "not spendable in the same block"; TX size/weight limits are
  enforced via [`MAX_TX_SIZE`], [`MAX_BLOCK_PAYLOAD_SIZE`], [`MAX_TXS_PER_BLOCK`].
  `Ledger::with_finality` prunes the per-block state of final blocks (more than
  `finality_depth` blue score below the tip) and rejects blocks built on final
  history; re-orgs above the finality point are implicit (`ledger_state` follows
  the selected tip, no revert). Pruning is of the per-block *state* only — the
  DAG stays append-only (DAG/`past`-set pruning waits on the reachability oracle).
  See `ledger.rs` module docs.
- **Insert-time validation** now has both layers. `Dag::with_validator` +
  `TxStructureValidator` reject malformed/structurally-invalid blocks; `Ledger`
  additionally runs the **stateful** rules (input existence, signatures, value
  conservation, coinbase amount) against a block's view state before it enters the
  DAG (via `Dag::preview`), so a block invalid in its own view is rejected at
  insert. Two *parallel* blocks that spend the same output are each valid in their
  own view and both admitted; their conflict resolves only in a merger's view.
- **Proof-of-work** `[CURRENT]` / `[TARGET]`-for-removal — is now real, and
  opt-in. `Block` carries a `nonce` (in the
  canonical id encoding); `pow::meets_target(id, work)` is the
  Nakamoto/Bitcoin-style hash-target rule — the id read as a big-endian 256-bit
  integer `H` must satisfy `H * work < 2^256`, so `work` is the *expected number
  of hashes* to find the block (a fraction `1/work` pass) and heavier blocks are
  genuinely harder, making blue work measure real spent hash power. The 256×128
  check is dependency-free limb arithmetic. `Dag::set_proof_of_work(true)` opts a
  DAG into **enforcement**: `Dag::insert` then rejects any non-genesis block whose
  id does not meet its target (`DagError::InsufficientProofOfWork`); genesis is
  exempt. `pow::mine` searches the nonce; `Ledger::set_proof_of_work` threads the
  switch through the state layer and the node mines produced blocks when it is on.
  **Off by default**, so a DAG that does not opt in accepts any nonce, exactly as
  before. PoW and difficulty are independent, composable switches (with both on,
  difficulty pins `work` and PoW requires the block to be mined to it).
  **`[TARGET]`** all of this — the whole bullet, plus the `pow` and `difficulty`
  modules, `Dag::set_proof_of_work`/`set_difficulty`/`proof_of_work_enabled`,
  `InsufficientProofOfWork`/`DifficultyMismatch`, `KOVANICA_POW`, the node mining
  loop and the RPC `kind: "pow"` — is **removed** under RFC-POA-Migration §0.1.
  Do not extend it, and do not port it to a new crate. Note the PoA path does
  **not** need it: under PoA `work` is pinned to the nominal `POA_NOMINAL_WORK = 1`
  at admission, so blue work is a plain block count (RFC-POA §6.1(b)).
- **Difficulty** `[CURRENT]` / `[TARGET]`-for-removal — now has both the
  algorithm and consensus enforcement. `Block`
  carries a `timestamp_ms` (in the canonical id encoding); `work` is caller-set
  *unless* difficulty is enabled.
  `difficulty::Retarget::next_work` is the retargeting *algorithm*;
  `Dag::set_difficulty(retarget)` opts a DAG into **enforcement**, after which
  `Dag::insert` requires every non-genesis block's `work` to equal
  `Dag::next_work_target(parents)` (the retarget over the last `window + 1` blocks
  of the selected-parent chain — a pure function of the DAG) and its timestamp not
  to precede any parent's. Genesis is exempt. `Ledger::set_difficulty` threads the
  same switch through the state layer, and the node mines produced blocks to
  `next_work_target` when it is set. Enforcement is **opt-in**, so a DAG built
  without it accepts any `work`, exactly as before. The wall-clock "not too far
  in the future" bound on timestamps is *not* here — that is node policy, not a
  pure function of the DAG. It lives in `kovanica-node` (`Node::receive_block`
  rejects a block whose `timestamp_ms` exceeds the node's clock by more than
  `MAX_FUTURE_DRIFT_MS` = 2h); the node's clock is injectable (`Node::set_now_ms`)
  so production timestamps and the bound are deterministic in tests, and produced
  blocks now stamp wall-clock now clamped monotone above their parents.
  **`[TARGET]`** the `difficulty` module, `Dag::set_difficulty`/`clear_difficulty`
  and `DifficultyMismatch` are **removed** (RFC-POA-Migration §0.1). PoA has
  nothing to retarget: a fixed `SLOT_DURATION_MS` (default 3000) and no gap-fill,
  so there is no "difficulty window" to tune. Two consequences for ops: the
  `difficulty` tuning knob in the soak/tuning review is moot, and the
  "difficulty retarget window" non-trigger in `TESTNET-RESET-POLICY.md` is
  `[TARGET]`-historic. There is **no** `KOVANICA_DIFFICULTY` env var today and
  none is planned — difficulty was always node-local policy, never operator-set.

## 4. Build, test & run

Rust workspace (edition 2021, `rust-version` 1.75). From the repo root:

- **Build:** `cargo build`
- **Test (all: unit + integration + doctests):** `cargo test`
- **Single test:** `cargo test <name>` (e.g. `cargo test adversarial_wide_fork`)
- **Lint:** `cargo clippy --all-targets` (keep it warning-clean)
- **Format:** `cargo fmt` (CI-style check: `cargo fmt --check`)
- **Run the node:** `cargo run -p kovanica-node -- demo` (scripted end-to-end
  scenario) or `cargo run -p kovanica-node` (a `serve` REPL reading commands from
  stdin; try `help`).

`unsafe` code is **forbidden** crate-wide (`#![forbid(unsafe_code)]` via
`[lints.rust]`). `kovanica-dag`/`kovanica-state` are libraries; `kovanica-node`
is a library plus a binary (`serve`/`demo`).

## 5. Engineering conventions

- **Consensus correctness is paramount.** Any change to selected-parent choice,
  mergeset, k-cluster colouring, blue score/work, or linearization can break safety
  (double-spend) or liveness. Such changes require: a written rationale naming the
  protocol semantics being followed, and **deterministic + adversarial tests**
  (Byzantine/equivocating parents, wide forks beyond `k`, tie-breaks, partitions).
- **Determinism.** Consensus output must be a pure function of the DAG — identical on
  every node. Never let HashMap iteration order, wall-clock time, or unstable sorts
  affect a consensus result. (The colouring iterates a HashMap but its *outcome* is
  order-independent; preserve that property.)
- **Tie-breaks** fall back to `BlockId` byte order — keep it that way for determinism.
- **Tests:** prefer property/invariant and adversarial tests for graph/consensus code.
  The k-cluster invariant (`blue_anticone_size <= k` for every blue block) is a good
  general assertion — see `tests/consensus.rs`.
- **Style:** match surrounding code; document *why*. Keep consensus-affecting changes
  in focused commits.

## 6. Git workflow

- **Never commit to the default branch directly.** Develop on a feature branch and
  open a **draft PR**.
- **Branch naming:** short, kebab-case, scoped — `consensus/…`, `dag/…`, `ledger/…`,
  or `claude/<topic>` for assistant-driven work.
- **Commits:** clear, imperative subject lines describing *why*. Run `cargo fmt`,
  `cargo clippy --all-targets`, and `cargo test` before pushing.
- **Push:** `git push -u origin <branch-name>`; open a PR if none exists for the branch.

## 7. For AI assistants — working notes

- This file is the **source of truth for conventions**; when reality and this file
  disagree, fix one or the other in the same PR — don't silently diverge.
- **Do not invent** APIs, module paths, or commands. If a section here is TODO, say so
  rather than fabricating specifics.
- When reasoning about consensus, cite the concrete reference system (GHOSTDAG,
  Bullshark, Avalanche, …) so the design stays auditable.
- Before claiming tests/builds pass, actually run them and report real output.

---

## Roadmap

Work is organised in **stages**. Stage 0 is shipped history (kept for
context); Stages 1–3 are the live plan, in order. Each stage should end
testable and deployable on its own — do not start a stage while the
previous one has open items without a written reason.

### Stage 0 — Shipped: single-chain → BlockDAG testnet

Everything below is deployed on `kovanica-testnet` (seed:
`seed.kovanica.online:9000`, explorer: `explorer.kovanica.online`).
CI gates every push (`fmt --check`, `clippy -D warnings`,
`cargo test`) before deploy is allowed to run.

- [x] Transactions + a UTXO state layer; apply state in linearized order (`kovanica-state`).
- [x] Signatures (ed25519) for spend authorisation.
- [x] Block-level validation at insert time: context-free structural validation
      (`BlockValidator` hook + `TxStructureValidator`) and stateful (UTXO-aware)
      validation (`Ledger` + `Dag::preview`).
- [x] Recursive GHOSTDAG linearization (`order(B) = order(sp) ++ mergeset ++ [B]`),
      the ordering per-block UTXO state composes along.
- [x] Per-block UTXO state built incrementally from each block's selected parent
      (`Ledger`), matching `apply_dag`; enables stateful validation at insert.
- [x] Finality-depth pruning + re-orgs (`Ledger::with_finality`): prune the
      per-block state of final blocks, reject blocks built on final history, and
      follow the selected tip (implicit re-org, no revert).
- [x] Persistence: replay-log snapshots of the DAG and ledger
      (`Dag`/`Ledger` `write_snapshot`/`read_snapshot`) — state recomputed on load.
- [x] Reachability oracle (`reachability::Reachability`): interval-tree +
      future-covering sets, now the `Dag`'s backing for ancestor queries and
      mergeset computation. The per-block `past` sets are dropped (each block keeps
      only `past_size`); mergeset is a selected-parent-bounded backward walk.
- [x] Incremental reachability maintenance (Kaspa reachability / interval
      **reindexing**): `Dag::insert` folds in just the one new block via
      `Reachability::add_block` (tree-interval allocation, subtree reindexing on
      capacity exhaustion, future-covering-set insertion over the mergeset)
      instead of rebuilding the oracle from scratch each insert. Behaviour-
      preserving — guarded by an "incremental == freshly-built after every insert"
      differential test plus reindex-stressing scenarios. Still open: the DAG-level
      `past`-set / interval-reindex pruning this unlocks.
- [x] Incremental / streaming on-disk store (`LedgerStore`): append-only replay
      log; loading recomputes state. Whole-file snapshots remain for portable
      backups.
- [x] Runnable node binary + a line RPC over the ledger (`kovanica-node`:
      `serve`/`demo`, snapshot-backed).
- [x] Mempool + block production (`pool`/`produce`), and multi-node block
      dissemination — in-process `gossip` and a one-shot TCP pull sync — with
      nodes converging on the same DAG (conflicts resolved identically).
- [x] Continuous in-process p2p gossip (`p2p::Mesh`): peer discovery via hello
      advertisements, a delayed relay loop, tx (not just block) dissemination,
      and mempool eviction of txs whose inputs are gone from the selected-tip
      UTXO view.
- [x] Long-lived TCP relay (`relay::RelaySession`): the same hello/block/tx
      envelopes as the in-process mesh, framed on a persistent socket. WebSocket
      sessions implemented in `explorer.rs` (`/ws` endpoint).
- [x] Difficulty adjustment for `work`: the retargeting algorithm
      (`difficulty::Retarget::next_work`) plus **consensus enforcement**. `Block`
      now carries a `timestamp_ms`; `Dag::set_difficulty` opts a DAG into
      validating each block's `work` against `Dag::next_work_target` (the retarget
      over the selected-parent chain — a pure function of the DAG) and its
      timestamp against its parents'. Threaded through `Ledger::set_difficulty` and
      the node's miner.
      **`[TARGET]`-for-removal** — PoA has nothing to retarget (fixed
      `SLOT_DURATION_MS`, no gap-fill). Keep the record; do not build on it
      (RFC-POA-Migration §0.1).
- [x] Wall-clock future-time bound on block timestamps (**node policy**, not
      pure-DAG): `Node::receive_block` rejects a block whose `timestamp_ms` is more
      than `MAX_FUTURE_DRIFT_MS` (2h) ahead of the node's clock. The clock is
      injectable (`Node::set_now_ms`) for deterministic tests; produced blocks
      stamp wall-clock now clamped monotone above their parents
      (`crates/kovanica-node/tests/timestamps.rs`).
- [x] Real proof-of-work (`kovanica-dag::pow`): `Block` carries a `nonce`, and
      `pow::meets_target` is the Nakamoto hash-target rule (`H * work < 2^256`,
      dependency-free 256×128 limb arithmetic), so `work` = expected hashes and
      blue work measures spent hash power. `Dag::set_proof_of_work(true)` opts a
      DAG into enforcement (`Dag::insert` → `InsufficientProofOfWork`; genesis
      exempt); `pow::mine` searches the nonce; threaded through
      `Ledger::set_proof_of_work` and the node's miner. Opt-in and composable with
      difficulty (`crates/kovanica-dag/tests/pow.rs`).
      **`[TARGET]`-for-removal** — this item is the history of a subsystem that
      is being deleted. Keep the record; do not build on it (RFC-POA-Migration §0.1).
- [x] Halving schedule (`HalvingSchedule` in `ledger.rs`, `Node::issuance_at()` in `node.rs`)
- [x] TX size limits (`MAX_TX_SIZE`, `MAX_BLOCK_PAYLOAD_SIZE`, `MAX_TXS_PER_BLOCK` in `validation.rs`)
- [x] WebSocket explorer (`/ws` endpoint in `explorer.rs`, `WsMsg` types)
- [x] Live frontend WS client/hooks (`web/src/lib/api/client.ts`: `wsClient`, `useWsMessage`, `useWsState`, `useWsBlocks`, `useWsTxs`)
- [x] CORS proxy for live explorer (`/proxy` path on explorer.kovanica.online)
- [x] Human addresses (`Address::to_kvnc`/`parse`, `kvnc…dag` base58 wrap over the
      32 key bytes; parse also accepts 64-hex) — reconciled from the testnet
      deployment snapshot so the canonical repo and deployed nodes share one
      address rendering (`crates/kovanica-state/src/keys.rs`).
- [x] Framed bidirectional TCP sync: `pull_blocks_timeout` reads a framed dump,
      applies it, and writes its own pre-apply snapshot back; `serve_exchange`
      mirrors that on the seed side (old one-way peers still work — reply
      write failures are ignored). Replaces EOF-delimited one-shot pulls on
      the explorer P2P loop, which now binds dual-stack listeners
      (`0.0.0.0:P` + `[::]:P`) and exchanges instead of only serving.
- [x] Multi-input transfers in `Node::prepare_transfer` (UTXOs accumulated
      largest-first until they cover amount + fee; one signature attached to
      every input) — no more spurious `InsufficientFunds` when the balance is
      spread across many coinbases.
- [x] ~~TAP micro-faucet on the explorer~~ — **removed 2026-08-24**: `/api/tap`,
      the `data/taps.txt` rate-limit store, and `KOVANICA_TAP` are gone; the open
      faucet (`POST /api/faucet`, 1 KVNC from operator funds) remains, plus
      `KOVANICA_MINE_SECS` for the public mine interval. Explorer addresses
      accept `kvnc…dag` or hex everywhere.
- [x] CI gate + dual-stack P2P: every push runs `fmt --check`,
      `clippy -D warnings`, `cargo test` before deploy may start (deploy job
      additionally armed via a `DEPLOY_ENABLED` repo variable); the seed's
      `[::]:P` listener binds with `IPV6_V6ONLY` so v4 and v6 coexist.

### Stage 1 — Operations hardening

Goal: make the running testnet trustworthy to operate day-to-day. No
consensus changes.

- [x] Arm auto-deploy: `VPS_HOST` / `VPS_USERNAME` / `VPS_PRIVATE_KEY`
      secrets + `DEPLOY_ENABLED=true`; verified end-to-end (merge → tests →
      SSH build on the VPS → pm2 restart; deploy exports cargo/pm2 PATH for
      the non-interactive shell).
- [x] Seed ops runbook: `OPERATIONS.md` — backup/restore of `data/`,
      restart drill, post-deploy checks (`api/head`, both listeners,
      peer exchange), log locations, network-marker semantics.
- [x] Web proxy question resolved: kovanica-web reaches the explorer
      **server-side** (`src/lib/api/upstream.server.ts`), so there is no
      cross-origin problem to solve; the cors-proxy worker and the
      `/proxy` path are dropped (kept only as an unused local folder).
      Local kovanica-web/kovanica-node clones are stale snapshots of the
      GitHub repos — GitHub is authoritative for those two.
- [x] Show `kvnc…dag` addresses in the web wallet UI — shipped upstream
      (kovanica-web `bcef5f0`: wallet displays kvnc, send accepts hex or
      kvnc).

### Stage 2 — Scale & persistence

Goal: survive growth. Sync that does not re-download the world; memory
and disk that do not grow forever.

- [x] Headers-first sync: peers exchange tips/headers first, then fetch
      block bodies by hash on demand — replaces whole-dump exchange as the
      default catch-up path.
- [x] DAG-level pruning behind the reachability oracle (the item its
      incremental maintenance unlocked): bounded ancestor state, append-only
      DAG with prunable payloads.
      - `Block.payload` is now `Option<Vec<u8>>`; `None` means pruned
      - `Dag::set_payload_pruning_depth(depth)` evicts payloads of blocks
        more than `depth` blue score below the selected tip
      - `Dag::prune_old_payloads()` called automatically on insert
      - Reachability queries (`is_ancestor`, mergeset, GHOSTDAG colouring,
        linearization) work correctly on pruned blocks — the oracle never
        inspects payloads
      - Snapshots encode pruned blocks with empty payload; load reconstructs
        `payload = None`
      - `Ledger::with_payload_pruning()` and `Ledger::with_finality_and_payload_pruning()`
        thread the depth through the state layer
      - `Node::genesis_with_finality()` and `Node::set_payload_pruning_depth()`
        expose it at the node layer
      - `Node::receive_block` rejects blocks whose selected parent has a
        pruned payload (mirrors finality check but uses payload pruning depth)
- [x] Finality checkpointing: persist the UTXO set at finality depth so a
      restart replays only post-checkpoint blocks instead of all history.
      - `Ledger::write_checkpoint()` / `read_checkpoint()` serialise the UTXO
        set at the finality boundary plus the tip segment (non-final blocks).
      - `LedgerStore::create_checkpoint()` / `open_checkpoint()` for file I/O.
      - `Node::save_checkpoint()` / `load_checkpoint()` and RPC commands
        `checkpoint` / `load_checkpoint` for node-level operations.
      - Checkpoint format v2 stores checkpoint block height for correct subsidy
        calculation on restore. The checkpoint block is included in the tip
        segment and reconstructed with its original ID via `Block::new_pruned`.
      - Restored ledger applies checkpoint UTXO set directly and replays only
        the tip segment, avoiding full history replay.
- [x] Reachability interval-reindex amortisation tuning (open from Stage 0):
      cap each freshly-allocated child interval at `CHILD_RESERVE` so a wide fan
      no longer exhausts its parent's interval every ~log2(width) children —
      turning the old `O(width^2)` reindex work for a broad fan into zero
      reindexes below the ~8M-child threshold (chains/deep-wide unchanged).
      Interval-numbering-only, so every reachability answer is identical;
      `Dag::reachability_reindex_metrics()` exposes the reindex counters the
      amortisation tests assert on.

### Stage 3 — Protocol evolution

Goal: consensus-level features. Each item needs a written rationale
naming the reference protocol (GHOSTDAG paper, Kaspa, PHANTOM §…) plus
deterministic + adversarial tests per the conventions above.

- [x] VRF for leader selection / a randomness beacon (the standing TODO).
  - `kovanica-dag::vrf`: ECVRF over Ristretto255 (Ed25519 curve), IRTF CFRG draft
  - `vrf_prove`/`vrf_verify`: deterministic VRF with Schnorr-style proof `(Γ, c, s)`
  - Block fields: `vrf_public_key`, `vrf_proof`, `vrf_output` (Option for backward compat)
  - `Dag::set_vrf(threshold)`: consensus-enforced leader eligibility
  - VRF input = `H(tip1 || tip2 || ...)` from parent tips
  - Eligibility: `VRF_output.as_u64() < threshold`; `u64::MAX` = all eligible (randomness beacon)
  - Composes with PoW + difficulty (independent opt-in switches) —
    `[TARGET]`-obsolete: **both** halves are removed. The PoW/difficulty half
    dies with PoW (§0.1); the VRF half died with hybrid (§0.7.1)
  - Snapshot format v5 includes VRF fields
  - Tests: eligibility, invalid proof, wrong key, missing fields, composes with PoW, beacon
- [x] P2P hardening: per-peer rate limits on framed reads, duplicate-block
      suppression metrics, peer scoring/banning.
  - `kovanica-node::p2p_hardening`: configurable hardening parameters
  - Rate limiting: max bytes/messages per peer per time window
  - Duplicate suppression: track known blocks/txs per peer, penalize resends
  - Peer scoring: reward valid blocks/txs (+1), penalize duplicates (-5/-2), heavy penalty for invalid (-20/-10)
  - Auto-ban when score <= threshold (default -50); manual ban/unban API
  - Integration: rate limits checked on `Mesh::enqueue`, duplicates checked on `Mesh::deliver`
  - Stats: `Mesh::peer_stats` / `all_peer_stats` for monitoring
  - Tests: rate limit enforcement, duplicate penalties, ban prevents relay, stats
- [x] Mempool upgrades: orphan handling, fee-based eviction, capacity limits.
- [x] Stake registry for hybrid PoW + VRF-staked validation (slice 1: ledger layer).
  - `[TARGET]` **Retiring.** This registry existed to feed VRF-staked admission,
    and hybrid is now **removed entirely** (RFC-POA-Migration §0.7.1, decided
    2026-09-25), so the registry retires with it. `stake.rs` is referenced only
    by `ledger.rs`, `lib.rs` and the `node.rs` unbond path — there is no
    remaining consumer. Delete with the rest of the hybrid surface; do not
    retain it "in case it is useful later".
  - ⚠️ **This is NOT RFC-005.** Vault/CSV and the 10 × 1M KVNC treasury
    tranches do **not** touch the stake registry — `vault.rs` has zero stake
    references. Do not "clean up" vault code alongside this.
  - `kovanica-state::stake`: bond/unbond via tag conventions on ordinary
    transactions — no new tx types. Bond tag = `KVB1 || vrf_pk(32)`, unbond tag
    = `KVU1`. A bond must pay one output back to its own input owner; that
    output becomes **frozen** in the per-block `StakeState` (registry overlay;
    the UTXO itself is unchanged). Unbond spends frozen outpoints only, after
    `UNBOND_MATURITY` (100 blocks of blue height), releasing value.
  - Enforcement lives in `apply_block_with_stake` (atomic across UTXO set and
    registry; regular spends of frozen outpoints are rejected with
    `LedgerError::Stake`). `Ledger` keeps a per-block `StakeState` mirroring its
    per-block `UtxoSet`; checkpoint format bumped to v3 (length-prefixed stake
    blob after the UTXO set).
  - Eligibility math for the future VRF-staked block production:
    `StakeState::eligibility_threshold(stake, total, num, den)` /
    `is_eligible(output, …)` — Algorand/Praos-style sortition comparing
    `VrfOutput::as_u64()` against `(stake << 64)/total × rate`.
  - NOT yet wired: epoch randomness beacon (VRF input is still parent tips —
    grinding-resistant beacon is follow-up), FFI/mobile bindings.
  - Tests: freeze/unfreeze accounting, maturity gate, frozen-input rejection,
    per-block stake across heights, threshold/sortition distribution,
    encode/decode roundtrip.
- [x] Hybrid PoW + VRF-staked block admission (slice 2: enforcement layer).
  - `[TARGET]` **REMOVED ENTIRELY — decided 2026-09-25**, not "partly obsolete"
    (RFC-POA-Migration **§0.7.1**, Option A). Both halves go: the PoW half with
    §0.1, the staked-VRF half with this decision. Remove `HybridConfig`,
    `StakedVrf`, `Ledger::set_hybrid` / `hybrid_enabled`, the `set_poa`/
    `hybrid` mutual exclusion, `stake_nominal_work`, the `insert_with_vrf`
    staked-block path, and the `KOVANICA_HYBRID` env var. The "PoA +
    staked-VRF secondary tier" option was considered and **rejected** — do not
    build a second tier on top of PoA.
  - ⚠️ Keep `POA_NOMINAL_WORK` (`dag.rs`) — it is **not** a `HybridConfig` field,
    and removing the wrong constant reintroduces the §6.1(b) work-inflation
    exploit.
  - Historical rationale (why it existed): kept PoW as the chain-selection work
    source while letting a bonded validator win slots by stake-weighted
    sortition — the phone-friendly production path. Both halves of that premise
    are gone.
  - All admission lives in `Ledger` (`crates/kovanica-state/src/ledger.rs`);
    the DAG core's own PoW/difficulty/VRF switches are CLEARED by
    `Ledger::set_hybrid(HybridConfig)` to avoid double standards.
  - Two paths per block: **PoW** (no VRF fields) requires
    `pow::meets_target(id, work)` AND — when `HybridConfig::retarget` is set —
    `work == Dag::work_target_with(parents, retarget)` (new dag helper;
    `next_work_target` delegates to it). **Staked** (`StakedVrf{vrf_pk,proof,
    output}`) requires a verifying proof over `Dag::vrf_input(parents)`,
    `output < StakeState::eligibility_threshold(...)` against the SELECTED
    PARENT's pre-state registry (a bond in the same block cannot vote for its
    own producer), `timestamp_ms >= max(parent ts)`, and at most ONE staked
    block per `(vrf_pk, selected_parent)` (`staked_seen` map, pruned with
    finality) — the sibling-spam/grinding guards.
  - Staked blocks pin `work == HybridConfig::stake_nominal_work` (default 1):
    cheaply-inflatable blue weight stays out of chain selection no matter how
    a winner grinds parent combinations.
  - Insert API split: `insert()` (legacy PoW template), `insert_with_vrf()`
    (forces nominal work), `insert_prepared_block(block, txs)` /
    `insert_raw_block(block)` — identity-preserving paths for wire receive and
    snapshot/checkpoint replay. Snapshot restore of hybrid-era chains needs
    `Ledger::read_snapshot_with_hybrid(bytes, cfg)` (checkpoint:
    `read_checkpoint_with_hybrid`); plain readers keep legacy strip-VRF
    behaviour for old snapshots. Wire format: `BlockRecord` gained
    `Option<StakedVrf>`, encoded as a flag byte after nonce (0 none / 1 =
    pk32+proof96+output32) in net.rs encode/decode (min record 49 bytes).
  - Node layer: `set_validator_seed([u8;32])`, `enable_hybrid(cfg)`,
    `validator_public_key()`, `total_stake()`, `stake_of()`; `produce_block`
    and `produce_empty` try the staked draw first and fall back to PoW when
    uneligible; `receive_block` builds the received block once with VRF fields
    and inserts via `insert_prepared_block`. RPC read-only command:
    `staking [vrf-pk-hex]`.
  - Tests: `crates/kovanica-state/tests/hybrid.rs` (12: admission matrix,
    pins, sibling guard, timestamp rule, bad proofs, hybrid snapshot/
    checkpoint roundtrips) and `crates/kovanica-node/tests/hybrid_node.rs`
    (3: produce→gossip→readmit convergence incl. wire VRF bytes, PoW fallback,
    RPC reporting).
- [x] Native tokens (Slice 4A / RFC-002): Cardano-style multi-asset outputs.
  - `AssetId` (32-byte definition hash; `AssetId::native()` = all zeros) and
    `TxOutput.asset_id` (`Option<AssetId>`; `None` = native KVNC) with
    `TxOutput::new(value, asset_id, owner)` / `TxOutput::native(value, owner)`.
  - Per-asset conservation (each asset conserved independently; fees paid in
    native KVNC only; asset burning allowed); coinbase may mint any asset for
    initial distribution.
  - Activation gate on blue score (`NATIVE_TOKEN_ACTIVATION_SCORE`,
    `Ledger::set_native_token_activation_score`, `PreActivationNativeToken`);
    checkpoint format bumped to v4 (optional asset_id in UTXO encoding).
  - Node surface: `send_asset`/`send_to_asset`/`send_with_asset`/
    `build_transfer_with_asset`/`prepare_transfer_asset`/`balance_of_asset`;
    FFI surface: `send_asset`/`send_from_asset`/`balance_of_asset` plus
    `asset_id_hex` on `HistoryEntry` and `MultisigSpendOutput`.
  - 29-test adversarial suite (`native_token_consensus.rs`): transfers,
    conservation, fee-in-native, coinbase minting, activation boundary, mixed
    blocks, parallel-DAG conflicts, checkpoint/snapshot roundtrip.
  - ⚠️ **FORMAT BUMP**: the 1-byte asset flag makes old wire blobs undecodable
    and new blobs undecodable by old readers — the testnet **resets at
    activation**.
- **Slice 3 — `kovanica-ffi` (UniFFI bindings for mobile light nodes)**:
  - New workspace crate wrapping `Node` behind one exported object,
    `LightNode` (`Mutex<Node>` inside; poison-tolerant lock). Full surface:
    genesis config (`LightConfig`), validator/miner seed setup, hybrid
    enablement, `bond_stake` (auto-splits an oversized coin via two mined
    blocks, then bonds), production (`produce_block` / `produce_empty_block`
    — staked draw first, PoW fallback), transfers, byte-blob sync
    (`export_blocks` → wire format, `receive_blocks(blob)` → count of records
    processed), queries (balances as decimal strings, block ids as hex),
    snapshot save/load. u128 values cross the FFI as hi/lo pairs
    (`U128Parts{high,low}`) or decimal strings.
  - Binding generation: build the cdylib then
    `cargo run -p kovanica-ffi --bin uniffi-bindgen -- generate --library
    target/release/libkovanica_ffi.so --language kotlin|swift --out-dir
    crates/kovanica-ffi/bindings/{kotlin,swift}` (uniffi 0.32). Generated
    Kotlin/Swift are committed under `bindings/`.
  - Supporting API additions: `Ledger::hybrid_config()` getter,
    `Node::hybrid_config()`, `Node::load_with_hybrid(path, cfg)` — FFI
    `load_snapshot` restores hybrid-era chains with their policy so staked
    ids survive replay; `BlockValidator` now requires `Send` (a DAG may cross
    threads) and its closure impl gained the same bound.
  - Tests: `crates/kovanica-ffi/tests/ffi.rs` (9: lifecycle, seed validation,
    bond split/freeze + staked win, rebond skipping frozen outputs, PoW
    fallback work semantics, two-node blob sync convergence, garbage-blob
    rejection, hybrid-aware snapshot roundtrip that keeps producing).
  - Semantics surfaced by the tests (do not re-litigate): bonding internally
    mines founder coinbase, so a miner-founder can keep bonding after its
    unfrozen supply is exhausted; in un-retargeted hybrid mode PoW-fallback
    blocks carry the legacy fixed work target (1), not nominal stake work;
    `receive_blocks` counts records processed — known blocks re-validate as
    no-ops (ledger insert is idempotent), so idempotent re-sync is measured
    by `block_count`, not by the return value.
- **Slice 4 — custody & unbond (FFI + node)**:
  - Spending keys: `Node::send_with(kp, amount, to)` signs with an explicit
    keypair (`send`/`send_to` delegate); FFI `send_from(secret_hex, amount,
    to_address)` — secrets cross the bridge per call and are never stored.
    Validator identity needed no change: `set_validator_seed` already takes
    client-generated 32-byte secrets.
  - Unbond: ledger rules pre-existed (`KVU1` whole-tag txs only, inputs must
    all be matured frozen outpoints, `height >= bond_height +
    UNBOND_MATURITY(100)` with height = selected-parent height + 1). New:
    `Ledger::tip_blue_score`, `Node::{chain_height, pending_unbond_height,
    unbond_with}` (FIFO over matured owned coins, fee-0 value-conserving,
    change unfrozen), `NodeError::{InsufficientStake, UnbondOwnerMismatch}`;
    FFI `unbond(from_seed, amount)` / `pending_unbond_height()` /
    `chain_height()`. Retarget-enabled hybrid e2e via peer-rejection symmetry.
  - Tests: `crates/kovanica-node/tests/unbond_node.rs` (lifecycle, FIFO
    partial maturity, foreign-signer guard) and 3 new ffi.rs cases
    (`send_from`, FFI unbond immaturity, retarget pin+sync).
  - Lesson: a release's own block advances the chain, so maturity windows are
    measured from the post-release tip — bonds close together in height can
    both mature by the time the second release applies (the gate is
    `>=`, equality included).
- **Slice 5 — SPV / filters over FFI**:
  - Node helpers: `block_filter(id, k)` (distinct payload output addresses →
    Golomb-Rice `BlockFilter`) and `merkle_proof(id, tx_id)`; header chain was
    already covered by `export_spv_headers()`.
  - FFI: versioned light-sync blob (`KVLS`v1: fixed-160-byte headers + filters)
    via `export_light_sync`/`receive_light_sync` (verified through real
    `SpvClient`, require_pow=false), local watch queries
    `synced_filter_matches`/`synced_height`, standalone `block_filter` +
    `filter_matches`, and inclusion proofs `prove_tx`/`verify_tx_proof`
    (root must match the synced header; unknown block errors). Serialization
    is hand-rolled BE in the FFI layer — protocol structs stay wire-free.
  - Lesson: single-payload-tx blocks prove as bare leaves — empty merkle path,
    84-byte proof blob. Tamper tests must hit the root region; path/index
    bytes don't exist there.
- **Slice 6 — mobile packaging & CI drift guard**:
  - `crates/kovanica-ffi/build-android.sh` (cargo-ndk, `--platform 24`,
    arm64-v8a + x86_64 → `android/src/main/jniLibs/`) and
    `build-apple.sh` (iOS/macOS staticlibs → one
    `target/kovanica.xcframework` with the uniffi header + modulemap per
    slice). The apple path required `"staticlib"` in the FFI crate-type list
    (App Store forbids shipping our own dylibs on iOS); cdylib stays for
    Android/JNA and the drift-guard build.
  - `crates/kovanica-ffi/android/`: minimal Gradle library module (namespace
    `uniffi.kovanica`, minSdk 24) compiling the committed `bindings/kotlin`
    tree via `sourceSets`; sole runtime dep `net.java.dev.jna:jna:5.14.0@aar`;
    consumer R8 rules included.
  - Drift guard: `.github/workflows/bindings.yml` regenerates kotlin+swift
    into a temp dir on every PR touching `crates/kovanica-ffi/**` and fails
    on any difference (`diff -r -x README.md` — the hand-written READMEs sit
    beside generated output and must not trip it), plus shellcheck of both
    scripts. Verified byte-identical at landing.
  - Mirror decision resolved as recommended: `kovanica-ffi` now rides
    `sync-public-node.yml`; kovanica-cli stays excluded.
- **Slice 7 — wallet UX layer (node + FFI)**:
  - `Node::history_of(owner, max_blocks)` (`crates/kovanica-node/src/node.rs`):
    reconstructs an address's history by scanning `dag.linearize()` in canonical
    order while tracking outpoints owned by `owner`; spending a seen outpoint is
    a `Sent` event, each owned output a `Received` event (a send's change back to
    the sender appears as its own `Received`). `max_blocks` bounds the scan
    window from the tip (`0` = all). Exports `WalletEvent`/`WalletDirection`.
  - FFI (`crates/kovanica-ffi/src/light_node.rs`): `history_of(address,
    max_blocks) -> Vec<HistoryEntry>` passthrough (hex ids, decimal-string
    amounts), plus the batched watch helper `filter_matches_any(blob,
    [addresses])` that decodes the Golomb-Rice filter once for multi-address
    watch wallets; an empty list never matches and malformed blobs error cleanly.
  - Fee-floor knob deferred per plan — soak hasn't shown congestion.
  - Tests: `crates/kovanica-node/tests/wallet_history.rs` (canonical order,
    spend-after-receive debit, window bound) and two ffi.rs cases
    (`history_over_ffi_matches_utxo_semantics`,
    `filter_matches_any_batches_watch_addresses`).
- **Slice 8 — docs & release**:
  - Plan file marked landed (`docs/plans/mobile-light-node.md`); slice-4/5
    surprises promoted into §8 hard-won lessons.
  - Root `README.md` rewritten for the protocol repo with a
    "Run a light node from Kotlin/Swift" section — copy-paste snippets
    mirroring the ffi.rs two-node blob-sync convergence test, plus the SPV
    light-sync surface and packaging pointers.
  - Workspace version bumped to **0.2.0** (Stage 3 close-out: VRF leader
    eligibility, hybrid PoW+staked admission, stake registry, P2P hardening,
    mempool v2, metrics/observability, DHT+DNS discovery, mobile FFI slices
    1–8).
- **Slice 9 — Android LightNode app (plan + genesis gate)**:
  - Plan: `docs/plans/android-light-node-app.md` (slices 9a–9f). Owner-locked
    decisions: full `/api/blocks` pull in v0.1 (SPV node endpoint later);
    extend `POST /api/mine/submit` for staked blocks; project-dir AAR link;
    debug-signed v0.1 APKs. No Android SDK on this host — APK builds must run
    in GitHub Actions (mirrors `build-web`).
  - **9a genesis gate landed**: `crates/kovanica-ffi/tests/live_sync_spike.rs`
    + `tests/fixtures/live-alpha-blocks.bin` (captured `GET /api/blocks` from
    seed1). Proof a phone `LightNode` boots to the live genesis and imports the
    live chain: default `LightConfig` diverges; live params are `LightConfig {
    k:3, subsidy:10*ATOM, founder_amount:200_000*ATOM, founder_seed:1, pruning
    MAX }` (ATOM=100_000_000, explorer `genesis_node()`), which reproduces the
    network genesis byte-for-byte; then `receive_blocks` converges to the live
    tip. v0.1 pins these params as app constants (`/api/bootstrap` doesn't
    expose subsidy/premine/seed); add them to the endpoint before mainnet.
  - **9b wallet UX landed**: Onboarding (create/import mnemonic), home, send,
    receive, history and settings screens in Compose/Material3. Secure seed
    storage via Android Keystore `AES/GCM/NoPadding`; the mnemonic only exists
    in memory during derivation/signing. Address derivation matches the Rust
    `KeyPair::from_seed(seed).address()` path (`0x00 || ed25519_pk`, base58
    wrapped as `kvnc…dag`).
  - **9c light sync landed**: `LightNodeRepository` owns the in-process
    `uniffi.kovanica.LightNode` and persists the KVLS v1 light-sync blob to
    `filesDir/light_sync.bin`. Startup calls `receiveLightSync` on the saved
    blob; `sync(nodeUrl, walletAddress)` fetches `/api/light_sync?from=<tip>`,
    merges it, writes the merged blob back, then checks Golomb-Rice filters
    with `syncedFilterMatches` and pulls only matching full blocks via
    `/api/blocks?from=<id>`. Wallet address, balance and history are exposed
    through the FFI surface.
  - **9d staking uplink landed**: `WalletRepository` wraps seed-derived
    transfers (`sendFrom`), bonding (`bondStake`), unbonding (`unbond`), and
    validator enablement (`setValidatorSeed` + `enableHybrid`). `produceBlock`
    now calls `produceBlock`/`produceEmptyBlock`, exports the produced block
    with the new `export_block` FFI method, and submits the wire-format blob
    to `POST /api/mine/submit` (octet-stream path) so phone-produced staked
    blocks land on the explorer. `NodeClient` implements the HTTP surface
    (light sync, full blocks, history, UTXOs, faucet, block submit).
  - New Android data layer files:
    `android-light-node/app/src/main/java/com/kovanica/lightnode/data/NodeUrl.kt`,
    `NodeClient.kt`, `LightNodeRepository.kt`, `WalletRepository.kt`,
    `Format.kt`; `WalletViewModel.kt` wires them to the designer's UI state.
    Kotlin UniFFI bindings regenerated to include `export_block`.

## 8. Hard-won Lessons & Invariants (Do Not Break)
- **SPV Block Filters**: When encoding 64-bit addresses into the Golomb-Rice filter, you *must* map them into a bounded interval (`N * 2^k`) first. Never attempt to push the raw 64-bit difference as unary 1s, or it will deadlock the encoder.
- **Finality Checkpointing**: When writing a checkpoint block's payload to the disk (e.g., in `Ledger::write_checkpoint`), you must strictly explicitly prune it via `Block::new_pruned_with_vrf` so the bytes exactly match the reconstructed block from `read_checkpoint`.
- **Identity-preserving block replay**: never rebuild a received/decoded block with a fresh `Block::new` template — once VRF fields exist, re-encoding silently changes the id and every child referencing the original parent fails with MissingParent. Use `insert_prepared_block` / `insert_raw_block`, and replay hybrid-era snapshots/checkpoints only through the `_with_hybrid` readers (plain readers deliberately strip VRF for legacy data).
- **DHT handshake contacts**: `Mesh::connect` must register both endpoints as mutual DHT routing-table contacts — a verified handshake exchanges NodeId + address, and established contacts claiming bucket slots first is what gives eclipse resistance its footing (Tier 5 `test_adversarial_eclipse_resistance` asserts this). Do not decouple P2P connect from DHT contact registration.
- **Metrics crate version**: `kovanica-node`'s `metrics` dependency must stay on the same minor version that `metrics-exporter-prometheus` depends on; otherwise emissions land in a noop recorder of the other version's global slot and `/metrics` renders nothing.
- **Unbond maturity gate**: a release's own block advances the chain, so maturity windows are measured from the post-release tip — bonds close together in height can both mature by the time the second release applies. The gate is `>=`, equality included.
- **Single-tx merkle proofs**: single-payload-tx blocks prove as bare leaves — empty merkle path, 84-byte proof blob. Tamper tests must hit the root region; path/index bytes don't exist there.

---

## Roadmap

- [x] Mempool policy upgrades: orphan-tx handling, fee-based eviction order.
  - `kovanica-node::mempool_v2`: enhanced mempool with orphan pool and fee-based eviction
  - Orphan pool: txs with missing inputs held separately, auto-promoted when block adds inputs
  - Fee-based eviction: lowest fee-rate txs evicted first when capacity exceeded
  - Capacity limits: configurable max tx count (default 100k) and max bytes (default 100MB)
  - Minimum fee rate enforcement (default 1 atom/byte)
  - Orphan auto-expiry after configurable block age (default 100 blocks)
  - Backward-compatible `Mempool` wrapper for existing code
  - Tests: orphan promotion, fee ordering, capacity eviction, min fee rate

### Beyond

Formerly-parked ideas that have since shipped (see Post-Stage 3 below):
**light clients / SPV-style proofs** over the linearized chain (header chain,
Merkle proofs, Golomb-Rice block filters, `SpvClient`) and **multi-seed
discovery** (DNS seeds + DHT Kademlia) — the latter shipped with its remaining
deployment wiring tracked in `TODO.md`. Still parked: anything the testnet
teaches us it needs.

### Post-Stage 3 — Production hardening (suggested order)

1. ~~**Light clients / SPV proofs** — verify payments without full sync:~~ ✅
   - Header chain (linearized selected chain only)
   - Merkle proof of transaction inclusion in block payload
   - Compact block filters (Golomb-Rice) for address-watching
   - `SpvClient` state machine: checkpoint → header chain → Merkle proofs
   - Wire protocol: `getheaders`/`getblocks` with proof verification (next)

2. ~~**Multi-seed discovery** — decentralize bootstrap:~~ ✅ code shipped;
   deployment wiring tracked in TODO.md
   - DNS seed records (A/AAAA for bootstrap nodes)
   - DHT (Kademlia) for peer discovery
   - Fallback to hardcoded seeds only

   Shipped: `dns_seed.rs` (injectable `DnsResolver`, dedup + fallback),
   `dht.rs` Kademlia (XOR metric, k-buckets) with relay tags 0x20–0x23,
   Mesh integration, and `tests/dht_discovery.rs` Tiers 1–5 green.
   The live DNS-seed hostnames are `seed` (primary, Hostinger VPS) and `seed2`
   (Hostinger KVM2 VPS `srv1991525`; `seed3`/AWS is retired but still
   resolves); `deploy-seed.sh` defaults new seeds to
   `KOVANICA_PEERS=seed.kovanica.online:9000,seed2.kovanica.online:9000`.
   Remaining wiring: the node binary's default `KOVANICA_PEERS` still names only
   `seed.kovanica.online:9000`; new-install defaults now use seed+seed2
   (installer updated 2026-09-20).

4. ~~**Mobile light-node slices 4–8**:~~ ✅ landed 2026-08-25 (workspace v0.2.0)
   - Full plan with per-slice implementation notes: `docs/plans/mobile-light-node.md`
   - Slice 4 custody & unbond FFI (`send_from`, `unbond`, FIFO maturity) ·
     Slice 5 SPV/filter FFI (`KVLS`v1 light-sync blobs, merkle proofs,
     Golomb-Rice filters) · Slice 6 Android/iOS packaging + bindings
     drift-guard CI · Slice 7 wallet UX (`history_of`, batched watch filters) ·
     Slice 8 docs & release (README light-node guide, hard-won lessons).

3. ~~**Observability & reliability** — production readiness:~~ ✅
   - `kovanica-node::metrics`: real Prometheus recording (metrics 0.22, unified
     with the exporter's recorder) for block rate, peer count, mempool size,
     reorg depth, sync latency, DHT, validation and storage metrics
   - Structured JSON logging via tracing; spans for block/peer/sync/DHT/RPC ops
   - Scrape endpoints: explorer `/metrics` renders the live recorder payload;
     standalone listener (default `0.0.0.0:9090`) serves the same series
   - `alerting_rules.yml`: Prometheus alerts (peer count < 2, block-rate drop,
     reorg depth, mempool/DHT churn) + recording rules
   - `fuzz.rs`: cargo-fuzz targets for block/tx/payload encoding roundtrips,
     block validation against a real DAG, and snapshot write/read roundtrip
     (plus deterministic proptest coverage under `cargo test`)
   - Note: `metrics` must stay on the same minor version as
     `metrics-exporter-prometheus`'s dependency, or emissions go to a noop
     recorder in the other crate version's global slot

4. **Testnet soak & parameter tuning** — run for weeks: **◀ ACTIVE NEXT**
   - ⚠️ `[TARGET]` **This soak must be re-planned before it counts.** It is
     written for a PoW testnet; under PoA-only (§0) a soak is a *multi-authority*
     soak, and the existing testnet chain must be reset first (mandatory, §0.6).
   - 24/7 testnet with multiple independent seed operators
     (seed = Hostinger VPS, unit `kovanica-explorer`; **seed2 = Hostinger KVM2
     VPS `76.13.250.65`** (`srv1991525`) — live since 2026-08-24, mining on,
     genesis verified, DNS `seed2.kovanica.online`; `seed3.kovanica.online`
     (AWS) retired) — `[CURRENT]`-state description of the *pre-reset* PoW
     testnet; those hosts will need re-genesis under PoA.
   - Measure: orphan rate, propagation latency, fork rate, disk growth
     (both seeds expose `/metrics`; `alerting_rules.yml` ready to arm)
   - Tune: `k`, finality depth, payload pruning depth, difficulty window
     — `[TARGET]` the **difficulty window** is obsolete (removed with PoW);
     PoA tuning knobs are the authority set, `KOVANICA_SLOT_DURATION`, and the
     authority-set threshold.

5. ~~**Wallet & explorer polish** — end-user UX:~~ ✅
   - Hardware wallet (Ledger via WebHID, Trezor via WebUSB) in the node explorer
   - BIP39/BIP44 derivation, transaction history
   - Fee estimation from mempool p90 (`POST /api/fee_estimate`, Rust + web preview)
   - Explorer: real-time DAG viz with zoom/pan + WebSocket updates, analytics panel

---

## Upgrade phases

Cross-repo execution plan from `Obsidian-Vault/Poslovno/KovanicaDAG/UPGRADE-PHASES.md`.

| Phase | Status | PR |
|---|---|---|
| 1 — Foundation & consensus infra | ✅ completed | dormant mainnet profile, staked uplink, light_sync, rate limits, dead `mempool.rs` removed, cargo-audit CI (D2) |
| 2 — Consensus evolution | ✅ completed | B1 epoch randomness beacon (#49) · B2 DAG-level past-set pruning (#36, #51) · B3 UTXO undo log (#50); node/explorer integration landed |
| 3 — Performance & scalability | ✅ completed | merged `c85013a` (#37) |
| 4 — Mobile light-node | ✅ completed | merged `84b6516` (#38); Oracle follow-ups (seed/address mismatch, UI-state cleanup, NodeUrl/lastSyncedBlockId wiring, importWallet dedupe) fixed and merged |
| 5 — Wallet & security | ✅ completed | multisig node layer + FFI bindings: `8a3bec6` (#41) |
| 6 — Operations & reliability | ✅ completed | operations automation: `840e8f1` (#40) |
| 7 — P2 polish | ✅ completed | see breakdown below |
| 8 — Stealth + script v2 (RFC-003) | ✅ completed | `consensus/stealth-script-v2-rfc-003` |
| 9 — HTLC / atomic swap (RFC-004) | ✅ completed | `consensus/htlc-atomic-swap-rfc-004` |

### Phase 7 breakdown

| Item | Status | PR |
|---|---|---|
| Android background sync + Keystore hardening | ✅ completed | merged `f8d261f` (#39) |
| Soak snapshot docs (genesis hash, rate recovery, no retune) | ✅ completed | merged `cee3e98` (#45) |
| Fuzz/property tests + Criterion benchmarks + P2P ban persistence | ✅ completed | merged `9407d24` (#43) |
| Explorer detail views + API docs | ✅ completed | merged `16ff775` (#44) |
| Fee market & RBF | ✅ completed | merged `49dfce0` (#46) |
| Web wallet custody + multisig UI | ✅ closed as superseded | UI merged via `0830c39` (#48); #47 closed |

> **Follow-up note:** All Phase 7 PRs merged to `main`. Android unit tests for `Format.kt`, KVLS header parsing, and address derivation remain pending — no SDK/device available to run them locally.
