# COMMS-THREAT-MODEL — Kovanica comms app (M1 scope)

Structured threat model for the M1 1:1 E2E text MVP: assets, adversaries, attack surface, per-risk mitigation, and residual risk — plus what M1 explicitly does **not** protect.

**Status:** Draft (M1 scope; not shipped)

**Consensus impact:** none — analysis document. Everything it covers is **client-only** or **ledger-safe**; no consensus rules are touched.

Scope is **M1 only** (1:1 E2E text over a store-and-forward relay + the on-chain name registry).
Where [`docs/COMMS-APP-PLAN.md`](COMMS-APP-PLAN.md) and
[`docs/COMMS-M1-INTERFACES.md`](COMMS-M1-INTERFACES.md) differ, **the interface doc wins**; this
document follows the interface doc. Risk IDs (R1, R4, R6, R10, R11) are the plan's register
([`docs/COMMS-APP-PLAN.md`](COMMS-APP-PLAN.md) §6). The registry contract itself is specified in
[`docs/RFC-008-NAME-REGISTRY.md`](RFC-008-NAME-REGISTRY.md).

---

## 1. Method

Assets → adversaries → attack surface → per-risk analysis (state, mitigation, residual) → explicit
out-of-scope list → deferred-mitigation schedule. Statements are normative where they constrain M1
behaviour, and descriptive where they record an accepted limitation. Every limitation stated here is
present in the M1 interfaces; none is hidden or softened.

---

## 2. Assets

| ID | Asset | Where it lives | M1 exposure |
|---|---|---|---|
| A1 | Message plaintext | client only; inside envelope `ct` | E2E-encrypted; never on-chain, never plaintext at the relay |
| A2 | Wallet Ed25519 secret seed | device keystore only | never leaves the device; node/relay never receives it |
| A3 | E2E static X25519 key | derived from the wallet key, on device | compromise decrypts past messages (no FS — §6) |
| A4 | Social graph (who talks to whom) | inferred at the relay from `to`/`from` | **not protected in M1** (§8) |
| A5 | Message metadata (time, size, frequency) | relay + wire | coarse length buckets only; timing exposed (§8) |
| A6 | Name registry entries | on-chain contract state | public by design; integrity + ownership matter |
| A7 | Delivery availability | self-hosted relay (phase 1) | single operator; no bonding/HA in M1 |
| A8 | Prepaid balance / funds | on-chain, via `kovanica-htlc` | **not in M1** — payments are M2 |

---

## 3. Adversaries

| ID | Adversary | Capability | Primary targets |
|---|---|---|---|
| ADV-1 | Opportunistic spammer / Sybil | unlimited free Ed25519 keypairs, many source IPs | A7, A5, recipient inbox quota |
| ADV-2 | Network observer | passive on-path; sees TLS-less relay HTTP in dev profile as deployed | A4, A5, A1 (ciphertext only) |
| ADV-3 | Relay operator (honest-but-curious or malicious) | sees every envelope's `to`/`from`/size/time; can drop or delete | A4, A5, A7 |
| ADV-4 | Malicious sender / peer | crafts arbitrary envelopes; re-POSTs, floods, spoofs | A1 (spoofing via sig), A6, A7 |
| ADV-5 | Device attacker | malware, or a stolen unlocked device | A2, A3, A1 |
| ADV-6 | On-chain observer | reads all contract state and calls | A6, and any contact graph wrongly put on-chain |
| ADV-7 | Name squatter / front-runner | registers free names first-come | A6 |
| — | Global passive adversary with full traffic correlation; compromised OS/keyboard; state-level endpoint compromise | — | **out of scope** (§10) |

---

## 4. Attack surface

| Surface | Defined in | Exposed to | Reveals |
|---|---|---|---|
| Envelope wire (`POST /v1/envelope`) | interfaces §3, §4 | ADV-2, ADV-3, ADV-4 | `to`, `from`, `alg`, `epk`, `nonce`, `ct` length, `sentAt`/`expiresAt`, `sig` |
| Inbox (`GET /v1/inbox/{comms_id}`) | interfaces §4 | anyone who knows a `comms_id` | ciphertext list + sizes/times of undelivered envelopes |
| Ack (`POST /v1/ack`) | interfaces §4 | **anyone** (no auth in M1) | can delete a recipient's pending envelopes if `comms_id` is known |
| Relay health (`GET /v1/health`) | interfaces §4 | anyone | relay version, stored-envelope count |
| On-chain registry | RFC-008 | ADV-6, ADV-7 | name → owner, pubkey, endpoints; existence of guessed names |
| Contract `deploy`/`call` path | RFC-008 §8 | any account | the registry has no global list, so no enumeration (§8) |
| Client keystore | ADR 0002 / plan §M0 | ADV-5 | protected at rest; not against a compromised host |

---

## 5. R1 — Sybil / spam

**M1 state.** The relay is **content-blind**: it validates envelope shape, `id` consistency, size, and
TTL, and routes purely on `to`; it never inspects plaintext (interfaces §3, §4). It cannot tell a
wanted message from spam. Sender identity is `comms_id = BLAKE3(b"kvnc/comms/id" ‖ pubkey)`
(interfaces §1), which is derived from an Ed25519 **public** key. Fresh keypairs are free, so any
pubkey-based allow/deny list or reputation keyed on `from` is defeated by generating a new wallet key
per message ("random wrapper keys"). **Pubkey-based anti-spam is therefore not achievable at the relay
in M1.**

**M2 state (implemented in M2).** Anti-spam uses a minimal combination ([`docs/COMMS-M2-INTERFACES.md`](COMMS-M2-INTERFACES.md)):
- **Stateless PoW (primary gate for unauthenticated sends):** Hashcash-style PoW bound to the envelope
  `id` (BLAKE3 over `nonce || envelope_id_bytes`). The `id` is
  `BLAKE3(b"kvnc/comms/env-id/v1" || signing_bytes)` (M1 §3.4), so work is bound to that envelope and
  cannot be reused across envelopes. Configuration: `KOVANICA_RELAY_POW_BITS` (default 20), with
  `KOVANICA_RELAY_POW_TTL_MS` replay window for `(id, nonce)`.
- **Prepaid credit (paid path):** Minimal in-memory per-`comms_id(to)` credit ledger funded by a
  valid HTLC payment proof submitted via the envelope wrapper (no chain polling/RPC dependency in
  M2). Credits are stored as `{ amount: u64, expires_at: u64 }` in memory only — **no PII** is
  persisted with credits. Policies: `KOVANICA_RELAY_MIN_FEE_ATOMS`, `KOVANICA_RELAY_CREDIT_TTL_MS`,
  `KOVANICA_RELAY_MAX_CREDIT_PER_ID`.

**Mitigation present in M2 (minimal).**

- **No per-IP rate limiting exists today;** defense-in-depth only (not primary). The primary
  enforcement is PoW or prepaid credit.
- Per-recipient quota: ≤ 1000 stored envelopes; overflow → `429 rate_limited` (interfaces §4).
- TTL clamp: `expiresAt` clamped to `now + max_ttl` (14 d default, 30 d hard max); a background sweep
  drops expired envelopes (interfaces §4).
- Client-side dedup by envelope `id` (interfaces §3.4) — correctness, not a spam defence.
- Admission gate: require **PoW OR prepaid credit**; rejection → HTTP `429 rate_limited`
  (`StoreError::RateLimited`) with wrapper submission preserving M1 `v=1` wire compatibility.
- Rollout: `KOVANICA_RELAY_ALLOW_UNPAID` (dev true by default; prod must be false for M2 exit).

**Residual risk: HIGH.** Stateless PoW raises cost for unauthenticated bulk sends, and prepaid
credit binds delivery to payment, but work must be done per envelope (id-bound). With cheap compute
and many IPs, well-funded attackers may still generate PoW at scale; prepaid credit is effective
against mass free spam but requires the HTLC-to-relay path. See also §9 (unauthenticated ack, PoW
replay/insufficient bits).

**Deferred.** Stake-to-send and bonded/reputed relay operators with streaming payment → **M5**.

---

## 6. R4 — E2E crypto complexity

**M1 state (v1 scheme).** Algorithm id `x25519-xchacha20poly1305-v1` (interfaces §2). Per envelope:
a fresh X25519 ephemeral keypair, ephemeral-static ECDH against the recipient's static X25519 key
derived from their Ed25519 wallet key via Edwards→Montgomery, a BLAKE3 house KDF over
`b"kvnc/comms/e2e/v1" ‖ shared`, and XChaCha20-Poly1305 with a fresh 24-byte nonce and an AAD bound to
the recipient and sender `comms_id`s (interfaces §2.2–§2.4). The whole scheme sits behind the
`E2eCipher` / `KeyExchange` trait boundary so a future scheme drops in without leaking its concepts
(interfaces §2.5). **MLS (RFC 9420) is deferred to M4**; OpenMLS is explicitly not adopted for M1
(interfaces §8).

**Threats.**

- **Spoofing.** Sender authenticity comes from the **envelope Ed25519 signature**, not the AEAD
  (interfaces §2.4, §3.3). A bug in signature verification or in the exact signing-bytes layout is a
  spoofing vulnerability. Mitigation: the signing bytes are a fixed, length-delimited layout
  (interfaces §3.3) with a pinned KAT.
- **Cross-language divergence.** Rust and TypeScript must produce byte-identical `id`, `sig`, and KDF
  output. Mitigation: two shared KAT vectors asserted in both languages — envelope KAT and KDF KAT
  with pinned inputs (interfaces §5).
- **Nonce/key reuse.** A fresh ephemeral secret and nonce per envelope are required. The test-only
  `deterministic_from_seed` must never be used in production paths (interfaces §2.6).
- **Hand-rolled protocol.** v1 is not a battle-tested ratchet. This is accepted for M1.

**Explicit limitations (not mitigable in M1).** v1 has **no forward secrecy and no
post-compromise security**: compromise of the recipient's static X25519 key decrypts every message
ever sent to it (interfaces §2.4).

**Residual risk: MEDIUM.** Correctness rests on the KATs, the pinned interfaces, and code review;
there is **no external cryptographic audit** in M1. Any such audit is deferred (see plan §6, R4 owner
lane `security-audit`).

**Deferred.** MLS for 1:1 + groups (FS + PCS + group keys) → **M4**; the trait boundary is the M1
investment that makes that swap cheap.

---

## 7. R6 — Mobile key handling

**M1 state.** M1 ships desktop + a headless CLI harness only; mobile is **M6**
([`docs/COMMS-APP-PLAN.md`](COMMS-APP-PLAN.md) §M6). This section states the constraint mobile must
satisfy so it is not designed away later.

**Threats (when mobile lands).**

- **On-device key handling.** Seeds stay on-device in the native OS keystore; the seed is never
  exported and never sent to the node or relay.
- **UI-thread blocking / leaks.** Argon2id at 64 MiB must run **off the UI thread** (plan §M6); a
  UI-thread call can ANR a phone and encourage unsafe shortcuts.
- **At-rest protection.** Keystore v2 uses Argon2id (64 MiB, `t=3`, `p=4`) + XChaCha20-Poly1305 with
  bound metadata ([ADR 0002](adr/0002-cli-wallet-keystore-v2.md) §2).
- **Device attacker (ADV-5).** Malware or a stolen unlocked device exposes live secrets; weak
  passphrases are guessable offline against a copied keystore (ADR 0002 §5).

**Mitigation present (design-level).** `kovanica-light-ffi` (UniFFI) surface; Argon2id off the UI
thread; `zeroize` on secret buffers (best-effort); no seed export; secret import/export rejected in
`--json` mode (ADR 0002 §4).

**Residual risk: HIGH against a compromised device.** Encryption at rest does **not** protect against
a compromised host, malware, passphrase capture, or an unlocked session; it does not make weak
passphrases safe (ADR 0002 §5). This is inherent, not an M1 defect.

**Deferred.** Full mobile packaging, off-thread key ops, and push delivery → **M6**.

---

## 8. R10 — Metadata privacy

**Stated plainly: the relay is content-blind but NOT recipient-blind.** Routing works by the
recipient `comms_id` in the envelope `to` field (interfaces §3.1), so the relay operator sees, for
every envelope: `to`, `from`, `alg`, the ciphertext size, and `sentAt` / `expiresAt`. Over time this
**reveals the social graph and its timing** to the relay operator (ADV-3), independent of E2E
encryption. The interface doc states the same: "the relay never sees plaintext or any key; it sees
only `to`, `from`, sizes and times (R10 risk)" (interfaces §2.4).

> **Divergence, decided by the interface doc:** the plan's R10 mitigation text says "relay blind to
> identities" ([`docs/COMMS-APP-PLAN.md`](COMMS-APP-PLAN.md) §6). **M1 does not achieve that.** The
> frozen interfaces route on `to` (`from` is also carried), so the relay is *not* identity-blind in
> M1. Identity-blinding (sealed sender) is deferred; see §11.

**Other M1 metadata facts (all from the interface doc).**

- **Length leaks only to a power-of-two bucket:** plaintext is UTF-8 JSON zero-padded to the smallest
  bucket ≥ `len+1`, with buckets **256, 1024, 4096, 16384** bytes (interfaces §3.2). Exact length is
  hidden; the **bucket boundary still leaks coarse size**, and an over-16384 payload is rejected.
- **Timing is exposed.** `sentAt` is client-supplied and untrusted, but the relay's own receipt time
  and the request pattern reveal real timing to the operator.
- **Scheme fingerprint.** The `alg` field on the wire identifies the crypto version (interfaces §3.1).
- **On-chain visibility.** The registry publishes name → owner/pubkey/endpoints by design
  ([RFC-008](RFC-008-NAME-REGISTRY.md) §7). Because there is **no global name list**, names cannot be
  enumerated from state — but any guessed name can be resolved. The contact graph MUST NOT be
  published on-chain (R11).
- **No forward secrecy / no post-compromise security**, restated from §6: a later key compromise
  decrypts past messages.

**Mitigation present in M1/M2.** E2E encryption of content; bucket padding of length; no plaintext
contact graph on-chain; opaque envelopes. **Mutual-contact free tier is client-only** (UX); the relay
does not maintain a mutual-contact list or any PII for that tier. Free delivery is not enforced by the
relay — the relay enforces paid/PoW policy globally (see §5 and [`COMMS-M2-INTERFACES.md`](COMMS-M2-INTERFACES.md) §1).

**Residual risk: HIGH.** The relay learns who talks to whom and when. This is the dominant M1 privacy
limitation.

**Deferred.** Sealed sender / recipient-hiding routing, cover traffic, mix-style relays, and metadata
resistant transports are **not in M1**; relay-side identity blinding and incentives land at **M5**
(plan §M5, R10 owner lane `security-audit`).

---

## 9. Additional M1 findings

| ID | Finding | Basis | Impact | M1 response |
|---|---|---|---|---|
| T-ACK | **Unauthenticated deletion.** `POST /v1/ack` takes any `to` + `ids` with no auth, so anyone who knows a recipient `comms_id` can delete that recipient's pending envelopes. | interfaces §4 (Auth: none; ack semantics) | Denial of delivery / message drop (ADV-4) | Accepted in M1 (self-hosted relay); no crypto exposure — envelopes are E2E encrypted | 
| T-SQUAT | **Free name squatting.** Registration is first-come with no fee (D4), so names can be taken at no cost. | interfaces §6; RFC-008 §10 | Namespace squatting; no release incentive (ADV-7) | Accepted in M1; fee/policy deferred |
| T-AVAIL | **Single-operator availability.** Phase 1 relays are self-hosted; there is no bonding or failover. | plan §8.3 | Relay outage or operator malice stops delivery (ADV-3) | Accepted in M1; decentralized bonded relays → M5 |
| T-CORS | **Permissive CORS in the dev profile** is documented as dev-only and not for public deployment. | interfaces §4 | Browser-based abuse if misdeployed | Operational: do not deploy the dev profile publicly |
| T-POW | **PoW cost/collisions.** Stateless PoW is bound to envelope `id` (BLAKE3 over `nonce || id_bytes`); replay of `(id,nonce)` is rejected within the TTL window, and insufficient bits are rejected. | [COMMS-M2-INTERFACES.md](COMMS-M2-INTERFACES.md) §2,§7 | Cheap compute may still allow bulk generation at scale | M2: fixed difficulty by policy, replay window, and admission gate (PoW OR prepaid credit); monitor/raise difficulty if needed |
| T-PAY | **HTLC payment proof abuse.** Proof must match deterministic `htlc_id` (BLAKE3 of params), `hash_lock == BLAKE3(preimage)`, claimer equals relay, expiry valid, not replayed. Credits are in-memory per `comms_id(to)` with TTL/cap and **no PII** stored. | [COMMS-M2-INTERFACES.md](COMMS-M2-INTERFACES.md) §3,§6 | Replay of old proofs, wrong preimage, idempotent re-POST | M2: idempotency, replay prevention, expiry checks, credit sweep; no chain polling/RPC dependency |

`GET /v1/inbox/{comms_id}` also has no auth, but `comms_id` is a 256-bit value; guessing it is
infeasible, and reading it yields only ciphertext. The practical exposure is T-ACK (deletion), not
confidentiality.

---

## 10. Explicitly out of scope / not protected in M1

- **Recipient anonymity / sealed sender.** The relay sees `to` and `from` (§8).
- **Forward secrecy / post-compromise security.** v1 lacks both (§6); a static-key compromise
  decrypts history.
- **Global passive traffic correlation.** An adversary correlating relay and access-network traffic
  by IP/timing is out of scope beyond the TLS-less dev profile.
- **Device compromise.** Malware, a stolen unlocked device, keylogging, or a hostile local
  environment (§7; ADR 0002 §5).
- **Real-time media.** No voice/video, SRTP, or TURN in M1 (M3/M4), so none of their threats apply
  yet and none are mitigated.
- **Group messaging / MLS.** Deferred to M4 (interfaces §0 D1).
- **Economic spam deterrence.** No fee, no stake, no PoW in M1 (§5; M2).
- **Relay incentives / bonding / reputation.** M5.
- **Mobile key custody and push.** M6.
- **eSIM / top-up.** M7.
- **Endpoint honesty.** The registry does not verify that a published relay endpoint is reachable,
  correct, or honest ([RFC-008](RFC-008-NAME-REGISTRY.md) §6, §10).
- **Name-squatting and fee policy** (§9).
- **Availability under targeted DoS** beyond per-IP rate limiting and the 1000-envelope quota (§5, §9).

---

## 11. Deferred mitigations, by milestone

| Risk / finding | M1 state | Deferred mitigation | Milestone |
|---|---|---|---|
| R1 Sybil / spam | per-IP limit + recipient quota only | min per-msg fee / stake-to-send; PoW fallback | M2 |
| R1 / T-SQUAT economics | no cost to send or register | relay bonding, reputation, streaming HTLC pay | M5 |
| R4 crypto complexity | v1 ephemeral-static, `E2eCipher` boundary | MLS (RFC 9420) for 1:1 + groups; external audit | M4 |
| R6 mobile keys | desktop/CLI only | mobile FFI, Argon2id off UI thread, push | M6 |
| R10 metadata | content E2E + bucket padding | sealed sender / identity blinding, cover traffic | M5 |
| R3 NAT / relay cost (adjacent) | n/a in M1 | paid TURN, ICE fallback | M3 |
| T-AVAIL relay availability | single self-hosted relay | bonded third-party relays | M5 |

---

## 12. Cross-references

- [`docs/COMMS-M1-INTERFACES.md`](COMMS-M1-INTERFACES.md) §2 (E2E v1), §3 (envelope/padding/signing), §4 (relay API, auth, quota), §5 (KATs) — normative parent for every factual claim above.
- [`docs/COMMS-APP-PLAN.md`](COMMS-APP-PLAN.md) §3 (layers), §6 (R1, R4, R6, R10, R11), §M1–M7 (milestones).
- [`docs/RFC-008-NAME-REGISTRY.md`](RFC-008-NAME-REGISTRY.md) — registry spec; on-chain visibility and squatting.
- [`docs/adr/0002-cli-wallet-keystore-v2.md`](adr/0002-cli-wallet-keystore-v2.md) — at-rest key protection and its stated limits.
- [`docs/AUDIT-CHECKLIST.md`](AUDIT-CHECKLIST.md) — external-audit scope (not started; recommend before mainnet).
