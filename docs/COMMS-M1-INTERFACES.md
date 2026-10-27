# COMMS M1 — Frozen interfaces

Status: **frozen for M1 implementation** (client-only + ledger-safe only; no consensus changes).
Owner: orchestrator. Consumers: `crates/kovanica-comms-crypto`, `crates/kovanica-comms-relay`,
`crates/kovanica-name-registry`, `packages/comms`, `apps/desktop`.

This document is the single source of truth for the byte-level and JSON-level contracts
shared by the Rust core and the TypeScript client. **Change it only in lockstep with every
consumer** — it is the M1 equivalent of the M0 KAT pin.

## 0. Locked decisions (M1)

| # | Decision |
|---|---|
| D1 | E2E crypto is **pluggable**: minimal 1:1 scheme now, OpenMLS (RFC 9420) later for groups (M4). Amends §8.2 to "MLS for groups". |
| D2 | Relay transport = **HTTP/JSON via axum** (POST envelope / GET inbox / POST ack). |
| D3 | Envelope wire format = **versioned JSON + base64** fields (single canonical form in Rust and TS). |
| D4 | `kovanica-name-registry` = **first-come, owner-updatable**; no fee in M1. |

## 1. Encoding primitives (all consumers MUST match)

- **Base64**: standard alphabet (`A–Z a–z 0–9 + /`) **with** `=` padding, no line breaks. Rust: `base64::engine::general_purpose::STANDARD`. TS: `btoa`/`atob` equivalents over bytes.
- **Hex**: lowercase, no `0x` prefix.
- **Integers in signing bytes**: `u64` **little-endian** (house convention, matches `kovanica_common`).
- **Domain prefixes**: ASCII, concatenated with raw bytes, no NUL terminator, no length prefix.
- **Hash**: BLAKE3-256 (`kovanica_common::hash` / `@noble/hashes/blake3`).
- **Signature**: Ed25519, 64 bytes (128 hex).
- **comms_id**: 32 bytes, `BLAKE3(b"kvnc/comms/id" ‖ pubkey)`, rendered as 64 lowercase hex (M0, unchanged).

## 2. E2E crypto v1 (D1)

Algorithm id string: **`x25519-xchacha20poly1305-v1`** (goes in the envelope `alg` field).

### 2.1 Key model
Wallet keys are **Ed25519**. The scheme derives a static X25519 public key from the
recipient's Ed25519 public key via the standard Edwards→Montgomery map
(Rust `ed25519_dalek::VerifyingKey::to_montgomery()`; TS `edwardsToMontgomeryPub` from
`@noble/curves/ed25519`). The wallet's Ed25519 key is **never** used directly as an X25519 key.

### 2.2 Seal (sender → recipient), ephemeral-static ECDH
```text
1. eph        = X25519 keypair (fresh per envelope)            -> epk = eph.public (32 bytes)
2. rcp_x25519 = ed25519_pub_to_x25519(recipient_ed25519_pub)   (32 bytes)
3. shared     = X25519(eph.secret, rcp_x25519)                 (32 bytes)
4. key        = BLAKE3( b"kvnc/comms/e2e/v1" ‖ shared )        // house convention, 32 bytes
                (Rust: kovanica_common::hash; TS: blake3() over the concatenated bytes — §2.5)
5. nonce      = 24 random bytes
6. ct         = XChaCha20-Poly1305(key, nonce, aad, plaintext)
   aad        = "kvnc/comms/e2e/v1" ‖ to_comms_id(32) ‖ from_comms_id(32)
7. wire       = { alg, epk, nonce, ct }   // see §3.2
```
### 2.3 Open (recipient)
```text
shared = X25519(recipient_x25519_secret, epk)
key    = BLAKE3( b"kvnc/comms/e2e/v1" ‖ shared )
plain  = XChaCha20-Poly1305-open(key, nonce, aad, ct)   // aad recomputed identically
```
### 2.4 Authentication & limitations (documented, not hidden)
- **Sender authenticity** comes from the **envelope Ed25519 signature** (§3.3), not from the AEAD.
- v1 has **no forward secrecy / no post-compromise security** (recipient static key compromise
  decrypts past messages). This is an accepted M1 limitation; MLS (M4) supplies FS + PCS + groups.
- The relay never sees plaintext or any key; it sees only `to`, `from`, sizes and times (R10 risk).

### 2.5 Trait boundary (so MLS drops in without leaking MLS concepts)
```rust
/// Per-peer sealing. Implementations own their own state (MLS needs epochs/groups).
pub trait E2eCipher {
    fn alg(&self) -> &'static str;
    fn seal(&mut self, recipient: &PublicKey, plaintext: &[u8], aad: &[u8]) -> Result<Sealed, CryptoError>;
    fn open(&mut self, sealed: &Sealed, aad: &[u8]) -> Result<Vec<u8>, CryptoError>;
}

/// Optional out-of-band handshake. v1 minimal scheme: `None` (no setup needed).
/// MLS: returns/consumes a Welcome/KeyPackage blob.
pub trait KeyExchange {
    fn initiate(&mut self, peer: &PublicKey) -> Result<Option<Vec<u8>>, CryptoError>;
    fn accept(&mut self, blob: &[u8]) -> Result<(), CryptoError>;
}

pub struct Sealed { pub alg: String, pub epk: [u8; 32], pub nonce: [u8; 24], pub ct: Vec<u8> }
```
No MLS types (`GroupId`, `Epoch`, `Welcome`, provider traits) may appear in these signatures.

**Cross-language KDF note:** the KDF is the house convention — plain BLAKE3-256 over
`b"kvnc/comms/e2e/v1" ‖ shared` (`kovanica_common::hash` in Rust, `blake3()` in TS). This avoids
BLAKE3's `derive_key` mode (whose `@noble/hashes` equivalence is unverified) and keeps Rust/TS
parity trivial. Pin it with a shared KAT vector (§5).

### 2.6 Concrete v1 API (frozen — every lane codes against exactly this)
```rust
// kovanica-comms-crypto public surface
pub type PublicKey  = [u8; 32];   // raw Ed25519 public key bytes
pub type SecretSeed = [u8; 32];   // raw Ed25519 secret seed

pub const ALG_V1: &str = "x25519-xchacha20poly1305-v1";

pub struct Sealed { pub alg: String, pub epk: [u8; 32], pub nonce: [u8; 24], pub ct: Vec<u8> }

#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("invalid key length")] InvalidKey,
    #[error("payload too large")] TooLarge,
    #[error("aead failure")]            Aead,
}

pub trait E2eCipher { /* §2.5, verbatim */ }
pub trait KeyExchange { /* §2.5, verbatim */ }

pub struct X25519Cipher { /* private */ }
impl X25519Cipher {
    /// `static_secret` = edwards_to_montgomery of the wallet seed; fresh ephemeral + nonce per `seal`.
    pub fn from_seed(ed25519_seed: &SecretSeed) -> Self;
    /// KAT/tests only: pinned ephemeral secret and nonce.
    pub fn deterministic_from_seed(
        ed25519_seed: &SecretSeed,
        ephemeral_secret: [u8; 32],
        nonce: [u8; 24],
    ) -> Self;
}
impl E2eCipher for X25519Cipher { /* per §2.2 / §2.3 */ }
impl KeyExchange for X25519Cipher { /* v1 no-op: initiate → Ok(None), accept → Ok(()) */ }

pub fn kdf_v1(shared: &[u8; 32]) -> [u8; 32];                            // BLAKE3(b"kvnc/comms/e2e/v1" ‖ shared)
pub fn e2e_aad(to_comms_id: &[u8; 32], from_comms_id: &[u8; 32]) -> Vec<u8>;
pub fn ed25519_pub_to_x25519(pubkey: &PublicKey) -> [u8; 32];            // VerifyingKey::to_montgomery()
pub fn ed25519_seed_to_x25519_secret(seed: &SecretSeed) -> [u8; 32];
pub fn x25519_shared(secret: &[u8; 32], public: &[u8; 32]) -> [u8; 32];  // low-level x25519()
```
`aad` is computed by the caller (messaging layer) via `e2e_aad` and passed into `seal`/`open`.

## 3. Envelope wire format v1 (D3)

### 3.1 JSON schema (object, keys as below)
```jsonc
{
  "v": 1,                                    // version, integer, always 1
  "id": "<64 lowercase hex>",                // envelope id, §3.4
  "to": "<64 hex comms_id>",                 // recipient; relay routes on this
  "from": "<64 hex comms_id>",               // sender
  "sentAt": 1730000000000,                   // u64 ms, client clock (untrusted)
  "expiresAt": 1731209600000,                // u64 ms, relay drops after this
  "alg": "x25519-xchacha20poly1305-v1",
  "epk": "<base64 32 bytes>",
  "nonce": "<base64 24 bytes>",
  "ct": "<base64 ciphertext>",
  "sig": "<base64 64 bytes>"                 // Ed25519 over §3.3 bytes
}
```
Unknown extra keys MUST be ignored (forward compatibility). Missing/extra-typed required keys =
reject.

### 3.2 Plaintext payload (inside `ct`, JSON UTF-8, then zero-padded)
```jsonc
{ "kind": "text" | "ack" | "receipt", "body": "<string>", "ts": 1730000000000 }
```
- Compact JSON (no whitespace between tokens) — `serde_json::to_vec` / `JSON.stringify` output.
- `plaintext = utf8(json) ‖ 0x00 × zeros`, where
  `zeros = (smallest bucket ≥ len(utf8(json)) + 1) − len(utf8(json))`.
- Buckets: **256, 1024, 4096, 16384** bytes. Payload larger than 16384 → reject (`InvalidInput`).
- Receiver: trim trailing `0x00` bytes (unambiguous — compact JSON always ends with `}`), then
  JSON-parse.
- Unknown `kind` MUST be ignored gracefully (not an error).
- (M1 simplification: **no `pad` field**; trailing-zero trimming is the padding contract.)

### 3.3 Signing bytes (exact layout — no JSON canonicalization)
```text
b"kvnc/comms/env/v1"
  ‖ to_comms_id_bytes(32)
  ‖ from_comms_id_bytes(32)
  ‖ sentAt(u64 LE, 8)
  ‖ expiresAt(u64 LE, 8)
  ‖ alg_utf8 (variable, no length prefix, terminated by the fixed-width field that follows)
  ‖ 0x00
  ‖ epk(32)
  ‖ nonce(24)
  ‖ ct (variable, to end)
```
`sig = Ed25519(sender_ed25519_secret, signing_bytes)`.

### 3.4 Envelope id
```text
id_bytes = BLAKE3( b"kvnc/comms/env-id/v1" ‖ signing_bytes )
id       = lowercase hex(id_bytes)   // 64 chars
```
Idempotent: re-POSTing the same envelope yields the same `id`; relay dedups by `id`.

### 3.5 Size limits
- Max envelope JSON: **64 KiB**. Larger → relay `413`.
- `ct` max: 48 KiB (buckets cap plaintext at 16 KiB).

## 4. Relay HTTP API v1 (D2)

Base path `/v1`. All bodies `application/json`. All responses `application/json`.
Errors: `{"error":{"code":"<slug>","message":"..."}}` with slugs `bad_request`, `too_large`,
`not_found`, `rate_limited`, `internal`.

| Method | Path | Body | Success | Errors |
|---|---|---|---|---|
| POST | `/v1/envelope` | envelope (§3.1) | `201 {"ok":true,"id":"<hex>"}` (also `201`/`200` when already present) | `400` bad_request (schema/sig/size), `413` too_large, `429` rate_limited |
| GET | `/v1/inbox/{comms_id}?limit=50&since=<ms>` | — | `200 {"envelopes":[<env>,…]}` (undelivered only, oldest first, ≤`limit` (max 200)) | `400` bad_request (bad id), `404` not_found (unknown recipient → empty list is `200` with `[]`) |
| POST | `/v1/ack` | `{"to":"<comms_id>","ids":["<hex>",…]}` | `200 {"ok":true,"deleted":<n>}` | `400`, `404` |
| GET | `/v1/health` | — | `200 {"ok":true,"version":"<semver>","envelopes":<n>}` | — |

Semantics:
- **Blind relay**: server MUST NOT require or inspect plaintext; it validates shape, `id`
  consistency, optional signature, size and TTL only.
- **GET does not delete.** Deletion happens only via `/v1/ack` (at-least-once delivery; client
  dedups by `id`).
- **Expiry**: default TTL 14 days, hard max 30 days; a background sweep drops expired envelopes.
  `expiresAt` is clamped to `now + max_ttl` on ingest.
- **Quota**: ≤ 1000 stored envelopes per recipient; overflow → `429 rate_limited` (M1 policy).
- **Auth**: none in M1 (self-hosted, D3 of the plan). Rate limiting is per-IP. Bonded/paid relays = M5.
- **CORS**: permissive in M1 dev profile only; documented, not for public deployment.

## 5. Cross-language verification (M1 exit evidence)

Two shared KAT vectors, asserted in Rust **and** TS:
1. **Envelope KAT**: fixed sender/recipient keys, fixed ephemeral secret, fixed nonce, fixed
   plaintext → expected `id` hex and expected `sig` hex (Ed25519 is deterministic).
2. **KDF KAT**: fixed `shared` secret → expected 32-byte key from
   `BLAKE3(b"kvnc/comms/e2e/v1" ‖ shared)`.

**Pinned KAT inputs (Rust and TS MUST both use exactly these):**
```text
sender_ed25519_seed     = 32 × 0x01     (Ed25519 secret seed)
recipient_ed25519_seed  = 32 × 0x02     (Ed25519 secret seed)
ephemeral_x25519_secret = 32 × 0x03     (raw X25519 secret)
nonce                   = 24 × 0x04
shared                  = 32 × 0x05     (KDF KAT input only)
sentAt                  = 1730000000000
expiresAt               = 1731209600000 (sentAt + 14 d)
to_comms_id             = BLAKE3(b"kvnc/comms/id" ‖ <recipient Ed25519 public key>)
from_comms_id           = BLAKE3(b"kvnc/comms/id" ‖ <sender Ed25519 public key>)
payload json (58 bytes) = {"kind":"text","body":"hello kovanica","ts":1730000000000}
plaintext               = json ‖ 198 × 0x00      (bucket 256)
```
Each language asserts the resulting **`id` (64 hex)** and **`sig` (base64)** in its tests and
reports both values; the orchestrator cross-checks them (`§5` evidence).

Plus a **round-trip integration test** (M1 exit criterion):
- two in-process clients + one relay instance (lib, not a spawned binary);
- A seals → POSTs → B GETs → B opens (offline recipient receives on reconnect: B is absent from
  GET until it polls, then receives the buffered envelope);
- assert the wire never contains plaintext, and that `ack` removes it.

## 6. Name registry contract v1 (D4) — semantics

Crate `crates/kovanica-name-registry` (WASM). ABI/export style mirrors `crates/kovanica-token` /
`crates/kovanica-htlc` (entry points, `kovanica_common::Host`, storage keys, error packing).

Entry points (semantics; exact signatures follow the `kovanica-token` ABI convention):
- `register(name, pubkey, relay_endpoints)` — first-come; `AlreadyExists` if the name is taken
  (by anyone, including the caller); `owner = host.caller()`.
- `resolve(name)` → entry (owner, pubkey, relay_endpoints) or `NotFound`.
- `update_endpoints(name, relay_endpoints)` — `Unauthorized` unless `host.caller() == owner`.
- `transfer(name, new_owner)` — `Unauthorized` unless owner (kept in M1: cheap, avoids a later
  ABI addition).

Rules:
- Name: `3..=32` chars, `[a-z0-9-]` only, no leading/trailing `-`, no consecutive `--`;
  stored lowercase; normalise-then-validate, reject otherwise (`InvalidInput`).
- `relay_endpoints`: `≤ 8` entries, each `≤ 256` bytes, `http(s)://` scheme only.
- Storage keys: `b"kvnc/v1/name/" ‖ utf8(lowercase_name)` → bincode(entry).
  **No global name list** (avoids on-chain enumeration, R11).
- Errors: reuse `kovanica_common::ContractError` (`Unauthorized` 0, `InvalidInput` 2,
  `AlreadyExists` 3, `NotFound` 4), packed as `-1 - code()`.
- Layer: **ledger-safe** (new state, no consensus-rule change).

TS binding: `packages/comms/src/registry.ts` builds `register`/`resolve`/`update_endpoints`/
`transfer` calls as contract-call payloads (args bincode-compatible) for `@kovanica/api-client`.

## 7. Lane map & write ownership (disjoint paths)

| Lane | Owner | Paths (exclusive) | Deliverable |
|---|---|---|---|
| orchestrator | me | root `Cargo.toml`, `crates/kovanica-cli/**` (if needed), integration + final verification + commits | wiring, verification, commit |
| crypto | fixer lane | `crates/kovanica-comms-crypto/**` | `E2eCipher`/`KeyExchange` + v1 impl + KAT tests |
| relay | fixer lane | `crates/kovanica-comms-relay/**` | `Envelope` (encoding/signing/id), in-memory store, axum server bin, reqwest client, tests |
| contract | fixer lane | `crates/kovanica-name-registry/**` | WASM contract + `MemHost` tests |
| ts | fixer lane | `packages/comms/src/{envelope,relay,messaging,registry}.ts` + `packages/comms/src/*.test.ts` (new files only) | TS mirror of §2–§4 + registry binding + tests |
| docs | docs-writer lane | `docs/RFC-008-NAME-REGISTRY.md`, `docs/COMMS-THREAT-MODEL.md` | spec + threat model (R1,R4,R6,R10) |

Shared-file rule: only the orchestrator edits root `Cargo.toml` (adding the three new members).

## 8. Open items — RESOLVED (M1)

- **Contract ABI / add-a-contract recipe (exp-1, verified):** contract crates use
  `crate-type = ["cdylib","rlib"]`, `kovanica_common::Host`, and a
  `#[cfg(target_arch = "wasm32")] mod wasm` export block (`kovanica_alloc`/`kovanica_dealloc` + one
  `#[no_mangle] pub extern "C" fn <entry>(ptr: i32, len: i32) -> i64` per entry point;
  `i64` = `((ptr as u32 as i64) << 32) | (len as u32 as i64)`, `()` → `0`, error → `-1 - code()`,
  always `-12..=-1`). Mirror `crates/kovanica-token` and its `wasmi_e2e_kovanica_token_wasm` test
  (isolated `CARGO_TARGET_DIR=target/contract-wasm-e2e`, `memory_limit_pages: 256`).
- **No `kovanica-execution` change needed (decisive):** `ENTRY_POINTS`/`is_entry_point`
  (`crates/kovanica-execution/src/contracts.rs:145-167`; exactly 16 names, pinned by
  `dispatch_covers_all_16_entry_points`) gate **only the native dispatcher**. The WASM call path
  (`TransactionKind::Call` → `execute_call` at `src/lib.rs:856` → `execute_wasm_call(entry: method)`)
  performs **no** entry-name validation — it only requires the export to exist in the module. So the
  name registry is deployed/called through the existing `deploy`/`call` transaction path with
  **zero** consensus-path edits. Contract lane = full callable contract, no protocol-table change.
- **E2E stack (lib-1, verified 2026-10-14):** do **not** adopt OpenMLS for M1 (0.9.1, MSRV 1.91,
  ~21 direct deps, mandatory persisted group state); MLS stays M4. Minimal 1:1 stack =
  `x25519-dalek` (use the low-level `x25519(k, u)` fn with raw `[u8;32]` keys — no dalek features
  needed), `chacha20poly1305` (`XChaCha20Poly1305`/`XNonce`), workspace `ed25519-dalek 2.1`,
  workspace `rand 0.8`, `zeroize`. KDF = house BLAKE3 (above).
- **Edwards→Montgomery helpers confirmed:** Rust `ed25519_dalek::VerifyingKey::to_montgomery()`
  (plus the private-key counterpart); TS `edwardsToMontgomeryPub` / `edwardsToMontgomeryPriv` from
  `@noble/curves/ed25519`.

## 9. Integration decisions (M1) — normative overrides

Where this section conflicts with an earlier section or with `COMMS-APP-PLAN.md`, **§9 wins**.

### 9.1 Name-registry WASM export names + encodings (pin for TS)
Exported entry points (mirroring the `kovanica-token` prefix convention):

| logical entry | WASM export | args (bincode tuple) |
|---|---|---|
| `register` | `name_register` | `(name: String, pubkey: [u8;32], relay_endpoints: Vec<String>)` |
| `resolve` | `name_resolve` | `(name: String)` → returns `bincode(NameEntry)` |
| `update_endpoints` | `name_update_endpoints` | `(name: String, relay_endpoints: Vec<String>)` |
| `transfer` | `name_transfer` | `(name: String, new_owner: [u8;32])` |

`NameEntry` bincode field order = `owner: [u8;32]`, `pubkey: [u8;32]`, `relay_endpoints: Vec<String>`.
The TypeScript binding (`packages/comms/src/registry.ts`) and any client `method` string MUST use the
export names above exactly (`name_register`, …).

### 9.2 Registry semantics clarifications
- `resolve` on a **malformed** name (fails normalise/validate) → `InvalidInput` (2). Only a
  well-formed-but-unknown name → `NotFound` (4).
- Endpoint validation is **scheme-only**: `http://` / `https://` prefix, `str::len` ≤ 256 bytes,
  ≤ 8 entries. Empty list is allowed. No further URL well-formedness is enforced.
- Name length is measured in **bytes** on the ASCII-normalised name.
- The contract emits **no events** in M1 (no registry topic exists in `kovanica-common/src/events.rs`;
  adding one is out of scope for M1).

### 9.3 Relay API clarifications
- `sig` is **required** on `POST /v1/envelope` (§4's "optional signature" wording is superseded).
- `GET /v1/inbox/{comms_id}` returns `404 not_found` **only** when `{comms_id}` is malformed
  (not 64 lowercase hex). A well-formed but unknown recipient → `200 {"envelopes":[]}`.

### 9.4 Accepted M1 risk — unauthenticated `POST /v1/ack` (threat "T-ACK")
Anyone who knows a recipient `comms_id` can delete that recipient's pending envelopes. Accepted for
M1 (self-hosted, operator-trusted relay); recorded in `docs/COMMS-THREAT-MODEL.md`. Authentication
(AUTH/registration or bonded relays) is deferred to M5.

### 9.5 R10 wording override
The M1 relay is content-blind but **NOT identity-blind**: it routes on `to` (and carries `from`), so
the operator can observe the social graph and timing. `COMMS-APP-PLAN.md` §6 R10's "relay blind to
identities" wording is superseded by this note.

### 9.6 KVP number
The name registry is **not** assigned a `KVP-###` in M1 (KVP-101…105 are taken). Revisit when the
registry is proposed for standardisation.

### 9.7 Relay implementation notes (normative; from the relay lane)
1. **`expiresAt` is never rewritten.** It is inside the signing bytes and the id, so mutating the
   stored envelope would break the recipient's signature/id check. §4's "clamped on ingest" refers to
   the relay's *internal* drop deadline only, never the wire field.
2. **Malformed `{comms_id}` path param → `400 bad_request`** (this overrides §9.3's `404`). A
   well-formed but unknown recipient → `GET 200 {"envelopes":[]}` and
   `POST /v1/ack 200 {"ok":true,"deleted":0}`. The `not_found` slug exists in the error enum but is
   unused in M1.
3. **"oldest first" = relay arrival (insertion) order**, because `sentAt` is untrusted. The optional
   `since` filter compares against `sentAt` (ms).
4. **Padding boundary:** the smallest bucket with `bucket > len(json)` (so ≥1 zero byte always). A
   compact JSON of exactly 256/1024/4096/16384 bytes therefore goes to the *next* bucket, and the
   largest accepted JSON payload is 16383 bytes.
5. **The relay cannot verify `sig`.** The envelope carries `from` (a comms_id hash), not the sender's
   Ed25519 public key, so the relay validates shape/id/alg/size/TTL only. Recipients verify with
   `Envelope::verify(sender_pubkey)`. `sig` is still *required* in the JSON (§9.3).
6. **`v` is a JSON number, modeled as `u8`;** any value other than `1` is rejected at ingest (`400`).
7. **An envelope already expired at POST time is accepted (`201`)**; it is then excluded by the inbox
   query and the sweep.
