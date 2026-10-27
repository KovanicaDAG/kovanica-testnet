# COMMS-M2-INTERFACES.md — Frozen M2 Spec (Payments & Anti-Spam)

**Status:** Frozen. No consensus changes. Ledger-safe/client-only.

This document freezes the M2 anti-spam/prepaid design per the oracle decision (ora-1), covering PoW bound to envelope `id`, prepaid credit via HTLC-to-relay proof, wrapper submission to preserve M1 `v=1` envelope wire compatibility, env config, store changes, server validation, TS helpers, and test plan.

---

## 1. Anti-spam model (minimal M2)

M2 enforces spam resistance via a minimal combination:
- **Stateless PoW (primary gate for unauthenticated sends):** Hashcash-style PoW bound to the envelope `id` (BLAKE3 over `nonce || envelope_id_bytes`). Cheap to verify, no identity/keys, prevents work reuse across envelopes.
- **Prepaid credit (paid path):** In-memory per-`comms_id(to)` credit ledger (atoms of native KUNA) funded by presenting a valid HTLC payment proof on submission. 
- **Per-IP rate limiting:** Defense-in-depth only (no per-IP limiting exists today; not primary). 
- **Stake-to-send:** Deferred to M5.

Free tier between mutual contacts is **client-only** (UX). Relay enforces paid/PoW policy globally; `KOVANICA_RELAY_ALLOW_UNPAID` provides a rollout flag.

---

## 2. Envelope identity binding (PoW)

Envelope `id` is defined in M1 (§3.4):  
`id = BLAKE3(b"kvnc/comms/env-id/v1" || signing_bytes)`, where `signing_bytes` excludes `v,id,sig`.

PoW is bound to this `id`. The submission carries an optional `pow` object:
```json
{
  "nonce": "hex",  // arbitrary bytes used as nonce
  "bits": 20       // required leading zero bits (must be >= policy)
}
```
Verification: let `h = BLAKE3(concat(nonce_bytes, id_bytes))`; count leading zero bits in `h`. Accept only if `bits >= required` and `(id, nonce)` not seen within replay window.

Difficulty is fixed for MVP (default 20 bits), configurable via env.

---

## 3. HTLC funding (prepaid credit) — no node dependency

For MVP, sender HTLCs KUNA to the **relay’s address** (i-style). The sender presents a payment proof on envelope submission:
```json
{
  "htlc_id": "hex32",
  "preimage": "base64",  // or hex; JSON uses strings
  "amount_atoms": 1000,
  "expiry": 1234567890000,
  "sender_addr": "hex32?",        // optional
  "claimer_addr": "hex32"          // must equal relay claimer
}
```

HTLC id is deterministic per `crates/kovanica-htlc`:
```
id = BLAKE3(b"htlc/id" || sender(32) || claimer(32) || amount_le(16) || hash_lock(32) || expiry_le(8))
```
Relay verifies:
- `hash_lock = BLAKE3(preimage)` (32 bytes)
- Recompute `id` from provided params and compare to `htlc_id`
- `claimer_addr == KOVANICA_RELAY_CLAIMER_ADDR`
- `expiry > now + margin` (future) and not expired beyond a small window
- `amount_atoms >= KOVANICA_RELAY_MIN_FEE_ATOMS`
- Not replayed

On success, relay credits `comms_id(to)` by `amount_atoms` (or applies per-message unit) with TTL. No chain polling/RPC dependency. Relay remains content-blind and key-less.

---

## 4. Submission wrapper (backward compatible)

To preserve M1 `v=1` envelope wire compatibility, new fields are not added inside the signed envelope. The relay accepts either:
(a) A bare envelope JSON (legacy M1): `{"v":1,...,"sig":"..."}`  
(b) An augmented wrapper:
```json
{
  "envelope": { /* EnvelopeJson v=1 (signed) */ },
  "pow": { "nonce":"hex", "bits":20 },
  "payment": { /* PaymentProof */ }
}
```

The wrapper is not part of the signed envelope. Validation order: deserialize wrapper or envelope; if wrapper, validate envelope shape + `compute_id`, then validate `pow` and/or `payment`, then admission (PoW OR prepaid credit), then insert into store. Back-compat: if no wrapper and `KOVANICA_RELAY_ALLOW_UNPAID=true`, legacy behavior applies (subject to quota). M2 exit requires `ALLOW_UNPAID=false`.

---

## 5. Env config

Flat env vars (no new config struct):
```env
KOVANICA_RELAY_BIND=127.0.0.1:8787
KOVANICA_RELAY_POW_BITS=20                # u8, min leading zero bits
KOVANICA_RELAY_MIN_FEE_ATOMS=1000          # u64
KOVANICA_RELAY_CLAIMER_ADDR=hex32          # relay KUNA address (HTLC claimer)
KOVANICA_RELAY_CREDIT_TTL_MS=86400000      # 24h
KOVANICA_RELAY_MAX_CREDIT_PER_ID=10000000  # cap per comms_id(to)
KOVANICA_RELAY_ALLOW_UNPAID=true           # dev default; prod false for M2 exit
KOVANICA_RELAY_POW_TTL_MS=600000           # 10m replay window (id,nonce)
```

---

## 6. Relay store changes (`crates/kovanica-comms-relay/src/store.rs`)

Add minimal in-memory state:
```rust
#[derive(Clone, Debug)]
struct Credit {
  amount: u64,
  expires_at: u64, // ms
}
struct Inner {
  by_id: HashMap<String, Stored>,
  queues: HashMap<String, Vec<String>>, // to -> list of envelope ids
  credits: HashMap<String, Credit>,     // comms_id(to) -> credit
  // pow_seen managed in server/LRU (or store)
}
```
New methods:
- `credit_add(to: &str, atoms: u64, now: u64) -> u64` (adds, applies cap, sets/extends expiry)
- `credit_deduct(to: &str, atoms: u64, now: u64) -> bool` (succeeds if sufficient unexpired; may drop expired)
- `credit_sweep(now: u64) -> usize` (removes expired credits)

On `insert`, admission check runs before quota: require PoW OR sufficient prepaid credit (deduct 1 message unit or min fee as policy). Use existing `StoreError::RateLimited` → HTTP 429 on rejection.

---

## 7. Relay server changes (`crates/kovanica-comms-relay/src/server.rs`, `lib.rs`)

**Types (lib.rs):**
```rust
#[derive(serde::Deserialize, serde::Serialize, Debug, Clone)]
pub struct PowProof {
  pub nonce: String, // hex
  pub bits: u8,
}
#[derive(serde::Deserialize, serde::Serialize, Debug, Clone)]
pub struct PaymentProof {
  pub htlc_id: String,
  pub preimage: String, // base64 (or hex) — use base64 for JSON consistency with envelope
  pub amount_atoms: u64,
  pub expiry: u64,
  pub sender_addr: Option<String>,
  pub claimer_addr: String,
}
#[derive(serde::Deserialize, serde::Serialize, Debug, Clone)]
pub struct SubmissionWrapper {
  pub envelope: EnvelopeJson,
  pub pow: Option<PowProof>,
  pub payment: Option<PaymentProof>,
}
```

**hashcash verify (lib.rs):** `fn pow_verify(id_hex: &str, nonce_hex: &str, bits: u8) -> bool` using BLAKE3 over `nonce_bytes || id_bytes` and leading-zero-bit count.

**post_envelope:** accept `Bytes` and try to deserialize as `SubmissionWrapper` first; if that fails, try `EnvelopeJson` (bare). For wrapper: parse envelope, validate shape + `compute_id`, validate `pow` and/or `payment` (against env), enforce admission (PoW OR prepaid credit), then call `store.insert`. Preserve M1 error codes/slugs (`rate_limited` on spam rejection).

**POW replay:** track `(id, nonce)` in a small LRU with TTL (`KOVANICA_RELAY_POW_TTL_MS`).

Back-compat is absolute: M1 clients posting bare envelopes continue to work when `ALLOW_UNPAID=true`.

---

## 8. TS helpers (`packages/comms/src`)

**`packages/comms/src/pow.ts` (new):**
- `powCompute(idHex: string, bits: number, maxAttempts?: number): { nonce: string; bits: number }` — compute nonce such that BLAKE3(`nonceBytes || idBytes`) has >= `bits` leading zero bits.
- `powVerify(idHex: string, nonce: string, bits: number): boolean`

**`packages/comms/src/payments.ts` (extend):**
- HTLC proof construction helpers for the relay-funded (HTLC-to-relay) path: build params needed to create HTLC and construct `PaymentProof` (including `htlc_id` recomputation per the deterministic formula). Also helpers to create HTLC via `@kovanica/signer` + raw tx (Call) for the on-chain leg (uses signer Call encoding).
- Keep existing `payments.ts` API minimal and align with plan deliverables.

**Relay client (`packages/comms/src/relay.ts`):** extend to optionally send wrapper when `pow` or `payment` provided (non-breaking; existing API unchanged).

**Index (`packages/comms/src/index.ts`):** export new modules (`pow`, `payments`) as they land.

---

## 9. Wire/encoding notes (no changes to signed envelope)

- Envelope JSON field order is as in M1 (Rust struct order) but JSON is unordered semantically; signing bytes exclude `v,id,sig` and use the byte sequence defined in M1. No change.
- Wrapper is separate JSON body at `POST /v1/envelope`. `v=1` wire remains unchanged.
- Signer Call encoding (variant index 6) is already implemented in `@kovanica/signer` (completed). No further signer changes required.

---

## 10. Test plan (mapping to exit criteria)

**Exit criteria:**
1. **Unpaid flood rejected:** With `KOVANICA_RELAY_ALLOW_UNPAID=false`, send many envelopes without wrapper/proof/PoW → all rejected with HTTP 429 (`rate_limited`); quota not exhausted.
2. **Paid message accepted:** Fund HTLC to relay, submit envelope with valid `payment` proof + preimage, expect 201/200 and envelope stored; `GET /v1/inbox/{to}` returns it.
3. **HTLC settlement + refund tests:** Client-side tests using `kovanica-htlc` API (create/claim/refund), duplicate/expiry/wrong-preimage cases. These are covered by existing HTLC tests; extend `packages/comms` tests to exercise the payment flow.

**Edge cases:** expired HTLC in proof, wrong preimage, idempotent re-POST (duplicate returns same result, no double-credit), credit exhaustion (429), PoW replay rejected, insufficient PoW bits, TTL expiry (credits/sweep + pow_seen), back-compat bare envelope with `ALLOW_UNPAID=true`.

**New tests:** Relay unit tests (PoW verify, credit add/deduct/sweep, wrapper parsing, admission policy, idempotency). Comms TS tests (`powCompute/verify`, payment proof construction). Integration test for paid path.

---

## 11. File-level changes (authoritative)

**Relay (Rust):**
- `crates/kovanica-comms-relay/src/lib.rs` — add `PowProof`, `PaymentProof`, `SubmissionWrapper`, `pow_verify(id_hex, nonce_hex, bits)`; wire types + serde; env defaults helpers.
- `crates/kovanica-comms-relay/src/store.rs` — add `Credit` struct, `credits: HashMap<String,Credit>`, `credit_add/deduct/sweep`; extend `Inner` + sweep logic to cover credits.
- `crates/kovanica-comms-relay/src/server.rs` — accept wrapper or bare envelope; deserialize wrapper first; validate PoW/payment; enforce admission before insert; PoW replay LRU; respect `KOVANICA_RELAY_ALLOW_UNPAID`.
- `crates/kovanica-comms-relay/Cargo.toml` — no new deps (use existing `blake3`).

**Comms TS:**
- `packages/comms/src/pow.ts` (new) — hashcash PoW compute/verify over envelope id (BLAKE3).
- `packages/comms/src/payments.ts` (extend) — HTLC proof construction + helpers for HTLC creation/claim/refund via signer (Call). 
- `packages/comms/src/relay.ts` — support sending wrapper when pow/payment present (non-breaking).
- `packages/comms/src/index.ts` — export pow/payments.

**Docs:**
- `docs/COMMS-THREAT-MODEL.md` — §5 R1: state PoW (envelope.id bound) + prepaid credit as present mitigations; correct “no per-IP rate limiting exists today; defense-in-depth only”; §8 R10: mutual-contact free tier is client-only; add T-POW/T-PAY entries; note minimal in-memory credit state (no PII).
- `docs/COMMS-APP-PLAN.md` — M2 deliverables updated (PoW module + relay payment proof); §8.6 refined to “client-enforced free tier… relay enforces paid/PoW policy”; R1 mitigations updated.
- `docs/COMMS-M2-INTERFACES.md` — this document (frozen).

No consensus changes. M1 `v=1` wire remains unchanged. All changes are ledger-safe or client-only.
