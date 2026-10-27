# RFC-008 — Name registry contract (`kovanica-name-registry`)

Normative M1 specification of the on-chain comms name registry: a first-come, owner-updatable mapping from a short name to an owner address, a wallet public key, and a set of relay endpoints.

**Status:** Draft (M1 implementation target; not shipped)

**Consensus impact:** ledger-safe — new contract state only; no consensus-rule change, no `kovanica-execution` protocol-table change

**Owner:** docs-writer lane · **Consumers:** `crates/kovanica-name-registry`, `packages/comms/src/registry.ts`

This document specifies `crates/kovanica-name-registry` and is subordinate to the frozen M1 contracts in
[`docs/COMMS-M1-INTERFACES.md`](COMMS-M1-INTERFACES.md) §6 and §8. Where this document and that one
differ, **the interface doc wins**. Where [`docs/COMMS-APP-PLAN.md`](COMMS-APP-PLAN.md) and the
interface doc differ, the interface doc wins. This is the control-plane half of
[`docs/COMMS-THREAT-MODEL.md`](COMMS-THREAT-MODEL.md); the registry is public-by-design, and that
threat model is the source of truth for what its visibility does and does not leak.

---

## 1. Purpose and layer classification

The registry answers exactly one question: *given a name, what is the wallet public key and which
relay endpoints should a peer publish envelopes to?* It carries no message content, no contact graph,
and no presence data.

| Property | Value |
|---|---|
| Contract crate | `crates/kovanica-name-registry` |
| Layer | **ledger-safe** — new contract state, no consensus-rule change |
| Model | first-come, owner-updatable (D4 of [`COMMS-M1-INTERFACES.md`](COMMS-M1-INTERFACES.md)) |
| State | one entry per registered name, keyed by name |
| Global name list | **none** (deliberate; see §7) |
| Fee | none in M1 (see §9) |
| Consensus coupling | none — deployed and called through the existing `deploy` / `call` transaction path |

Nothing in this contract is consensus-critical. It is a WASM contract executed by the existing
Wasmi call path and has no bearing on DAG consensus, staking, rewards, supply, or the fee schedule.
This mirrors the classification of the name registry in [`docs/COMMS-APP-PLAN.md`](COMMS-APP-PLAN.md) §3.

---

## 2. Entry model

`resolve` returns a `NameEntry`. Its bincode 1.x layout (fixed, so Rust and TypeScript agree):

```rust
pub struct NameEntry {
    pub owner: Address,             // [u8; 32] — account that may update/transfer
    pub pubkey: [u8; 32],           // raw Ed25519 public key (wallet key), NOT a comms_id
    pub relay_endpoints: Vec<String>, // 0..=8 entries, each <= 256 bytes, http(s):// only
}
```

- `pubkey` is the raw 32-byte Ed25519 wallet public key. The `comms_id` is derived client-side as
  `BLAKE3(b"kvnc/comms/id" ‖ pubkey)` ([`crates/kovanica-comms-core`](../crates/kovanica-comms-core/src/lib.rs));
  the registry stores the key, not the derived id.
- `relay_endpoints` is stored in the caller-supplied order; consumers MUST NOT rely on ordering.
- The entry carries no expiry field (see §9).
- The entry carries no reverse index (see §9).

---

## 3. Storage layout

| Item | Value |
|---|---|
| Raw key | `b"kvnc/v1/name/" ‖ utf8(normalised_name)` |
| Value | `bincode(NameEntry)` |
| Global/list key | none — no counter, index, or singleton state cell |

Storage-key convention mirrors the other contract crates ([`docs/CONTRACTS.md`](CONTRACTS.md) §5):
contracts pass **raw, variable-length** keys; the host derives the redb table key as
`table_key = blake3(raw_key)` and namespaces it by the contract address (the tuple
`(contract_addr, table_key)`). Two registry instances at different addresses therefore cannot
collide, and keys are per-name (`b"kvnc/v1/name/" ‖ name_bytes`).

There is **no** `b"kvnc/v1/state"` singleton: the registry is not a singleton-per-address contract
like `kovanica-token`. Each name is an independent record.

---

## 4. Entry points

The four entry points below are exercised through the normal `call` transaction path; the wasm
export name equals the method name. ABI, argument/result encoding, and error packing mirror
[`crates/kovanica-token`](../crates/kovanica-token/src/lib.rs) ([`docs/CONTRACTS.md`](CONTRACTS.md) §6).

| Entry point | bincode args | Ok result | Errors |
|---|---|---|---|
| `register` | `(String name, [u8;32] pubkey, Vec<String> relay_endpoints)` | `()` | `InvalidInput`, `AlreadyExists` |
| `resolve` | `(String name,)` | `NameEntry` | `InvalidInput`, `NotFound` |
| `update_endpoints` | `(String name, Vec<String> relay_endpoints)` | `()` | `InvalidInput`, `NotFound`, `Unauthorized` |
| `transfer` | `(String name, [u8;32] new_owner)` | `()` | `InvalidInput`, `NotFound`, `Unauthorized` |

### 4.1 `register(name, pubkey, relay_endpoints)`

- Normalise then validate `name` (§5) and `relay_endpoints` (§6); otherwise `InvalidInput`.
- If an entry for the normalised name already exists — **by any owner, including the caller** — return
  `AlreadyExists`. `register` never overwrites.
- Otherwise write `NameEntry { owner: host.caller(), pubkey, relay_endpoints }` under the normalised
  key and return `()`.
- `pubkey` is any 32 bytes; the contract does not verify that the caller owns `pubkey`.

### 4.2 `resolve(name)`

- Normalise then validate `name`; otherwise `InvalidInput`.
- Return the stored `NameEntry`, or `NotFound` if the name is unregistered.
- Read-only: `resolve` performs no state write and emits no event.

### 4.3 `update_endpoints(name, relay_endpoints)`

- Normalise then validate `name` and `relay_endpoints`; otherwise `InvalidInput`.
- Load the entry; missing → `NotFound`.
- If `host.caller() != entry.owner` → `Unauthorized`.
- Otherwise replace `relay_endpoints` (owner and pubkey unchanged) and return `()`.

### 4.4 `transfer(name, new_owner)`

- Normalise then validate `name`; otherwise `InvalidInput`.
- Load the entry; missing → `NotFound`.
- If `host.caller() != entry.owner` → `Unauthorized`.
- Otherwise set `owner = new_owner` and return `()`. `new_owner` is a fixed 32-byte value; the
  contract applies no further validation (see §9).
- `transfer` is retained in M1 deliberately: it is cheap now and avoids a later ABI addition
  ([`COMMS-M1-INTERFACES.md`](COMMS-M1-INTERFACES.md) §6).

### 4.5 Events

M1 defines **no** contract events for the registry. `resolve` reads state directly and needs no
indexer. If events are added later they MUST be registered as constants in
`kovanica_common::events` ([`docs/CONTRACTS.md`](CONTRACTS.md) §9) and pinned by that module's typo guard.

---

## 5. Name grammar

Normative, applied in this order (normalise-then-validate):

1. **Normalise:** ASCII-lowercase the UTF-8 input. No Unicode case folding, no NFC/NFKC, no other
   transform — the operation must be identical in Rust and TypeScript and must not depend on locale.
2. **Validate** the normalised name; reject with `InvalidInput` unless all hold:
   - length is `3..=32` bytes (every accepted character is ASCII, so bytes == characters);
   - every character is in `[a-z0-9-]`;
   - does not start with `-`;
   - does not end with `-`;
   - contains no consecutive `--`.

The key stored (§3) is the **normalised** name, so `"Alice"` and `"alice"` are the same record, and
the second `register` returns `AlreadyExists`.

---

## 6. Endpoint limits

- At most **8** entries; more → `InvalidInput`.
- Each entry at most **256** bytes (UTF-8 byte length); longer → `InvalidInput`.
- Each entry's scheme MUST be `http://` or `https://` (scheme compared ASCII-case-insensitively);
  any other scheme or a string without a recognised scheme prefix → `InvalidInput`.
- An empty list (`≤ 8` with zero entries) is permitted; `register`/`update_endpoints` may publish a
  name with no endpoints.
- The endpoint string is stored **verbatim** (no normalisation); trailing slashes, ports, and paths
  are passed through untouched.
- No other URL validation is performed in M1: host, port, path, and reachability are not checked.

---

## 7. No global name list (enumeration resistance)

The registry deliberately stores **only** per-name records. There is no singleton list, counter, or
iteration entry point, and `resolve` requires the exact normalised name.

Consequences (normative):

- An observer of contract state cannot enumerate registered names; the state is not a registry
  listing. This is the on-chain-discovery mitigation for **R11** in
  [`docs/COMMS-APP-PLAN.md`](COMMS-APP-PLAN.md) §6.
- Enumeration resistance is **not** confidentiality. Names are guessable strings, so anyone can probe
  `resolve("alice")` and learn whether the name is taken and, if so, its `pubkey` and endpoints.
  Registration is intentionally public so peers can look each other up.
- The registry MUST NOT be extended into a contact-graph oracle. No entry point may return a name
  given a pubkey/address (no reverse index — see §9).

---

## 8. Deploy and call notes

- **Build:** `cargo build -p kovanica-name-registry --target wasm32-unknown-unknown --release`
  (see [`docs/CONTRACTS.md`](CONTRACTS.md) §7). Crate type is `["cdylib", "rlib"]`, matching
  `kovanica-token`.
- **Deploy:** through the ordinary `deploy` transaction; the contract is addressable like any other
  WASM contract.
- **Call:** through the ordinary `call` transaction with `method` equal to the entry-point name
  (`register` / `resolve` / `update_endpoints` / `transfer`) and bincode 1.x args (§4).
- **No `kovanica-execution` registration.** `ENTRY_POINTS` / `is_entry_point`
  (`crates/kovanica-execution/src/contracts.rs`) gate only the **native** dispatcher and are not extended
  for this contract. The WASM call path (`TransactionKind::Call` → `execute_call` →
  `execute_wasm_call(entry: method)`) validates only that the export exists in the module. The name
  registry therefore ships with **zero** consensus-path edits
  ([`COMMS-M1-INTERFACES.md`](COMMS-M1-INTERFACES.md) §8).
- **Return packing:** success is `((out_ptr as u32 as i64) << 32) | (out_len as u32 as i64)`; a
  `()` result packs as `0`. Errors pack as `-1 - code()` (always within `-12..=-1`), decoded by
  `kovanica-runtime` to `RuntimeError::Contract(code)`. `kovanica_alloc` / `kovanica_dealloc` are exported
  alongside the four entry points.

---

## 9. Error semantics

Errors reuse `kovanica_common::ContractError` ([`docs/CONTRACTS.md`](CONTRACTS.md) §1); only four
variants are produced. The wasm return value is `-1 - code()`.

| Error | `code()` | packed return | Returned when |
|---|---:|---:|---|
| `Unauthorized` | 0 | `-1` | `update_endpoints` / `transfer` called by a non-owner |
| `InvalidInput` | 2 | `-3` | name fails §5; endpoints fail §6; args are not decodable bincode |
| `AlreadyExists` | 3 | `-4` | `register` on a name already present (any owner, including the caller) |
| `NotFound` | 4 | `-5` | `resolve` / `update_endpoints` / `transfer` on an unregistered name |

Ordering rules (normative):

- Validation precedes lookup. A malformed name or endpoint list yields `InvalidInput` even when the
  name is unregistered (never `NotFound`).
- Ownership precedes mutation. `update_endpoints` / `transfer` on an existing name by a non-owner
  yield `Unauthorized`, not `AlreadyExists`.
- On any error the host commits nothing: no storage write, no balance delta, no event
  ([`docs/CONTRACTS.md`](CONTRACTS.md) §5).

---

## 10. Non-goals (M1)

- **No fee.** Registration, update, and transfer are free in M1 (D4). Consequence: name squatting is
  free and there is no economic reason to release a name. Fee/squatting policy is deferred; see
  [`docs/COMMS-THREAT-MODEL.md`](COMMS-THREAT-MODEL.md) §9.
- **No expiry / reclaim.** Entries never expire and cannot be reclaimed by anyone but the owner.
- **No reverse resolution.** `pubkey`/`address` → name is not supported, by design (§7).
- **No hierarchy.** No sub-names, namespaces, or per-owner prefixes.
- **No reserved-name authority.** All free names are first-come; there is no privileged registrar.
- **No endpoint semantics.** The contract stores endpoint strings; it does not verify reachability,
  TLS validity, or that the endpoint speaks the relay protocol.
- **No `new_owner` validation** beyond the fixed 32-byte type (e.g. the all-zero address is accepted).
- **No KVP number.** This document does not claim a `KVP-###`; `KVP-101`..`KVP-105` are held by
  multisig / multi-asset / stealth / HTLC / vault ([`docs/CONTRACTS.md`](CONTRACTS.md)).

---

## 11. Verification hooks (M1 evidence)

Owned by the contract lane ([`COMMS-M1-INTERFACES.md`](COMMS-M1-INTERFACES.md) §7); this section only
names what the spec requires to be demonstrated.

- `MemHost` unit tests over `register` / `resolve` / `update_endpoints` / `transfer`, asserting each
  error in §9, the normalise-then-validate order of §5, and the endpoint limits of §6.
- The first-come rule: a second `register` for the same normalised name — by any caller — returns
  `AlreadyExists`, and the stored entry is unchanged.
- `update_endpoints` / `transfer` by a non-owner return `Unauthorized` and leave state unchanged.
- A cross-path agreement test in the style of `wasmi_e2e_kovanica_token_wasm`, confirming the WASM
  exports and native calls agree byte-for-byte over the same storage.

---

## 12. Cross-references

- [`docs/COMMS-M1-INTERFACES.md`](COMMS-M1-INTERFACES.md) §6 — registry semantics (normative parent); §8 — ABI and the "no `kovanica-execution` change" finding.
- [`docs/COMMS-APP-PLAN.md`](COMMS-APP-PLAN.md) §3 — layer classification; §M1 — milestone; §6 — R11 (discovery enumeration), R1 (spam).
- [`docs/COMMS-THREAT-MODEL.md`](COMMS-THREAT-MODEL.md) — what registry visibility leaks, and squatting.
- [`docs/CONTRACTS.md`](CONTRACTS.md) §1 (`ContractError`), §5 (storage/`ContractHost`), §6 (wasm ABI), §7 (building a contract wasm), §9 (event topics).
- [`crates/kovanica-token`](../crates/kovanica-token/src/lib.rs) — ABI reference; `packages/comms/src/registry.ts` — TypeScript binding.
