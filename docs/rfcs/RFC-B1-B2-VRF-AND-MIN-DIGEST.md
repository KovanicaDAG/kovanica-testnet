# RFC-012 — VRF Leader Election (B1) and Min-Digest Fork Resolution (B2)

- **Status:** Draft / Gated (TASKLIST item 15)
- **Crate Scope:** `kovanica-crypto`, `kovanica-consensus`, `kovanica-dag`
- **Primary References:**
  - VRF implementation: [`crates/kovanica-crypto/src/lib.rs`](file:///crates/kovanica-crypto/src/lib.rs)
  - Consensus VRF election: [`crates/kovanica-consensus/src/engine.rs`](file:///crates/kovanica-consensus/src/engine.rs)
  - Min-digest replacement: [`crates/kovanica-dag/src/dag_store.rs`](file:///crates/kovanica-dag/src/dag_store.rs)
  - Related RFCs:
    - [`RFC-002-MYSTICETI-DAG-CONSENSUS-AND-LEADER-LOGIC.md`](file:///docs/rfcs/RFC-002-MYSTICETI-DAG-CONSENSUS-AND-LEADER-LOGIC.md)
    - [`RFC-003-STAKING-EPOCHS-AND-VALIDATOR-LIFECYCLE.md`](file:///docs/rfcs/RFC-003-STAKING-EPOCHS-AND-VALIDATOR-LIFECYCLE.md)

---

## Sažetak (Executive Summary)

RFC-012 (izvorno B1/B2) specificira dvije opcionalne konsenzusne nadogradnje:
1. **B1: Izbor lidera putem Verifiable Random Function (VRF):** Validatori prilažu 96-bajtni ECVRF dokaz (ristretto255 + SHA3 iz `ecvrf` crate-a), a komitet deterministički bira lidera s najmanjim ulogom ponderiranim VRF izlazom, zamjenjujući deterministički round-robin.
2. **B2: Rješavanje račvanja najmanjim hešom (Min-Digest Fork Resolution):** U slučaju da validator proizvede dva bloka za isti liderski krug prije odluke komiteta, `replace_block` u `DagStore` atomski mijenja pohranjeni blok leksikografski manjim hešom unutar jedne transakcije upisa.

Obje funkcionalnosti su zaštićene konfiguracijskim prekidačima (`use_vrf_leader = false`, `use_min_digest_fork = false`) i ostaju neaktivne do koordiniranog mrežnog resetiranja.

---

> **Update 2026-10-21 (TASKLIST item 15).** The VRF implementation is the
> `ecvrf` 0.4.3 crate (ristretto255 + SHA3) — **not** an RFC 9381 ciphersuite.
> The proof is **96 bytes** (`Gamma(32) ‖ c(32) ‖ s(32)`), carried in
> `StatementBlock::statements` behind the `b"KUNA-VRF1"` magic (137 bytes total; `KVNC-VRF1` before the chain-4 reset)
> and covered by `compute_digest_statements`. The RFC 9381 80-byte proof length
> does **not** apply. Suite, byte layout and the full file:line map:
> `docs/archive/VRF-PROOF-LENGTH.md`.
>
> This note supersedes the "Not activated" wording below for the *statements
> framing* only: the digest-covered `b"KUNA-VRF1"` VRF blob does exist in the
> tree today. The VRF **leader-election** activation items (1-4 below) are
> unchanged — `use_vrf_leader` still defaults to false.

## B1 — stake-weighted VRF leader election

### Already in tree

- `kovanica-crypto` implements the VRF (`vrf_prove` / `vrf_verify`) on top of the
  `ecvrf` 0.4.3 crate — ristretto255 + SHA3, **not** an RFC 9381 ciphersuite
  (proof layout and the 96 B vs 80 B question: `docs/archive/VRF-PROOF-LENGTH.md`).
- `Authority` / `AuthorityInfo` already carry an optional `vrf_public_key`.
- `Committee::leader_with_vrf` selects the lowest stake-weighted VRF hash when
  every authority in the map has an output, and otherwise falls back to
  round-robin.

### Not activated

`StatementBlock` has no VRF proof field. `compute_digest` does not cover one.
Adding a required field, or treating an optional field as consensus-critical
without a coordinated upgrade, splits the network.

Until a block carries a verifiable VRF output:

- `ConsensusEngine::scheduled_leader_for_round` stays round-robin
  (`CommitteeInfo::leader`), unless an explicit `leader_schedule` override is set.
- `ConsensusConfig::use_vrf_leader` exists and **defaults to false**.
- When the flag is true, `scheduled_leader_for_round` ignores the
  round-robin prefetch (`leader_schedule` for rounds 0..1000) and calls
  `CommitteeInfo::leader_with_vrf` with `record_verified_vrf_output` entries
  for that round. An empty map is round-robin. The node must not record a
  hash it has not verified. Live blocks still carry no proof, so the
  default-off flag does not change the scheduled leader.

### Activation requirements (not in this change)

1. Optional, digest-covered VRF proof on leader blocks, versioned so old
   blocks still hash the same way, **or** a hard-fork height after which the
   field is required.
2. Every authority publishes a VRF public key in the committee.
3. Peers verify the proof against
   `domain || chain_id || epoch || round || author` before the output may
   enter `leader_with_vrf`.
4. Missing or invalid proofs must not silently fall back to a different
   leader than honest peers. Fallback is only legal when **no** authority
   has a VRF key (pre-upgrade committees).

## B2 — min-digest fork resolution

### Live default

For a scheduled leader slot, the first block that validates is canonical.
A later block from the same author and round with a different digest is
rejected as equivocation. Tests lock this
(`fork_first_valid_digest_wins_deterministic`).

The committer's `update_leader` already prefers the lexicographically smaller
digest in its in-memory leader map. That map is not the DAG. Preferring a
hash the store does not contain would commit a block that was never accepted.

### Gated path

`ConsensusConfig::use_min_digest_fork` defaults to **false**.

When it is true, `process_block` may replace the stored leader block only if
`DagStoreTrait::replace_block` succeeds. Replacement must:

- remove the previous digest from the store and from parent/child indexes
- refuse if either digest is already a parent of another stored block
- refuse if the round is already decided

`DagStore::replace_block` implements that swap in one write transaction and
refuses a decided round, a missing existing digest, an already-stored
incoming digest, or an existing digest that already has children. The node
adapter calls it. Other `DagStoreTrait` impls keep the default refusal.

If replacement is unsupported or refused, the new digest is rejected. The
engine must not update leader state to a digest the DAG does not hold.

Transaction re-execution is out of scope. Replacement is a pre-commit store
swap only. A decided round is final.

## What this change does not do

- It does not alter `StatementBlock` or `compute_digest`.
- It does not change default leader selection.
- It does not change default equivocation handling.
- It does not re-execute transactions on a fork.
