/**
 * E2E messaging v1 — X25519 + XChaCha20-Poly1305.
 *
 * Byte-for-byte mirror of `crates/kovanica-comms-crypto` (see
 * `docs/COMMS-M1-INTERFACES.md` §2). The scheme is ephemeral-static ECDH:
 * the sender uses a fresh ephemeral X25519 key per envelope against the
 * recipient's static X25519 key (derived from their Ed25519 public key).
 * The recipient opens with its static X25519 secret (derived from the
 * wallet Ed25519 seed) and the envelope's `epk`.
 *
 * Key derivation is the house convention — plain BLAKE3-256 over
 * `utf8("kvnc/comms/e2e/v1") || shared` — *not* BLAKE3 `derive_key` mode.
 * That keeps Rust/TS parity trivial (§2.5 cross-language KDF note).
 *
 * Sender authenticity is carried by the envelope Ed25519 signature
 * (`envelope.ts`), never by the AEAD (§2.4).
 */

// Side-effect: install the SHA-512 hook on this package's `@noble/ed25519`
// before any synchronous Ed25519 call site runs (module init order matters).
import "./ed25519.js";

import { xchacha20poly1305 } from "@noble/ciphers/chacha";
import { edwardsToMontgomeryPriv, edwardsToMontgomeryPub, x25519 } from "@noble/curves/ed25519";
import { blake3 } from "@noble/hashes/blake3";
import { concatBytes } from "@noble/hashes/utils";

import { bytesToHex, hexToBytes } from "@kovanica/signer";

/** Concatenate byte chunks (re-exported so peer modules share one helper). */
export function concat(parts: Uint8Array[]): Uint8Array {
  return concatBytes(...parts);
}

/** Little-endian `u64` encoding (house convention, §1). */
export function u64le(value: number | bigint): Uint8Array {
  const asBig = typeof value === "bigint" ? value : BigInt(value);
  if (asBig < 0n || asBig > 0xffff_ffff_ffff_ffffn) {
    throw new E2eCryptoError("InvalidKey", "value does not fit in a u64");
  }
  const out = new Uint8Array(8);
  new DataView(out.buffer).setBigUint64(0, asBig, true);
  return out;
}

/** Algorithm id string placed in the envelope `alg` field (§2). */
export const ALG_V1 = "x25519-xchacha20poly1305-v1";

/** Domain prefix for the KDF and the AEAD associated data (§1/§2). */
export const E2E_DOMAIN = "kvnc/comms/e2e/v1";

const E2E_DOMAIN_BYTES = new TextEncoder().encode(E2E_DOMAIN);

/** Raw key / nonce / AEAD-tag widths, in bytes. */
export const X25519_KEY_LEN = 32;
export const NONCE_LEN = 24;
export const AEAD_TAG_LEN = 16;

/** Plaintext padding buckets (§3.2). */
export const PAYLOAD_BUCKETS = [256, 1024, 4096, 16384] as const;

/** Largest permitted padded plaintext (§3.2 / §3.5). */
export const MAX_PAYLOAD_BYTES = 16384;

/** Payload `kind` values understood by v1. Unknown kinds must be ignored. */
export type PayloadKind =
  | "text"
  | "ack"
  | "receipt"
  | "webrtc-signal"
  | "group-invite"
  | "group-join-ack"
  | "group-leave"
  | "group-commit"
  | "group-member-update"
  | "webrtc-group-signal"
  | "webrtc-group-control"
  | (string & {});

/** Envelope payload kind (alias for compatibility with M3 naming). */
export type EnvelopePayloadKind = PayloadKind;

/** Compact-JSON plaintext payload carried inside `ct` (§3.2). */
export interface Payload {
  kind: string;
  body: string;
  ts: number;
}

/** Sealed ciphertext triple produced by {@link X25519Cipher.seal} (§2.5/§2.6). */
export interface Sealed {
  alg: string;
  /** 32-byte ephemeral X25519 public key. */
  epk: Uint8Array;
  /** 24-byte XChaCha20-Poly1305 nonce. */
  nonce: Uint8Array;
  /** Ciphertext with the Poly1305 tag appended. */
  ct: Uint8Array;
}

/** Error codes mirroring the Rust `CryptoError` enum (§2.6). */
export type E2eCryptoErrorCode = "InvalidKey" | "TooLarge" | "Aead";

/** Failure in the E2E layer. */
export class E2eCryptoError extends Error {
  constructor(
    public readonly code: E2eCryptoErrorCode,
    message: string,
  ) {
    super(message);
    this.name = "E2eCryptoError";
  }
}

function requireLength(bytes: Uint8Array, length: number, what: string): void {
  if (!(bytes instanceof Uint8Array) || bytes.length !== length) {
    throw new E2eCryptoError("InvalidKey", `${what} must be ${length} bytes`);
  }
}

function randomBytes(length: number): Uint8Array {
  const out = new Uint8Array(length);
  crypto.getRandomValues(out);
  return out;
}

/**
 * KDF v1: `BLAKE3( utf8("kvnc/comms/e2e/v1") || shared )` → 32 bytes.
 *
 * Plain BLAKE3-256 (`@noble/hashes/blake3.blake3`), *not* `derive_key` mode.
 */
export function kdfV1(shared: Uint8Array): Uint8Array {
  requireLength(shared, X25519_KEY_LEN, "shared secret");
  return blake3(concat([E2E_DOMAIN_BYTES, shared]));
}

/** AEAD associated data (§2.2 step 6): `domain || to_comms_id(32) || from_comms_id(32)`. */
export function e2eAad(toCommsId: Uint8Array, fromCommsId: Uint8Array): Uint8Array {
  requireLength(toCommsId, 32, "to_comms_id");
  requireLength(fromCommsId, 32, "from_comms_id");
  return concat([E2E_DOMAIN_BYTES, toCommsId, fromCommsId]);
}

/** Edwards → Montgomery map of an Ed25519 public key (§2.1). */
export function ed25519PubToX25519(publicKey: Uint8Array): Uint8Array {
  requireLength(publicKey, X25519_KEY_LEN, "ed25519 public key");
  return edwardsToMontgomeryPub(publicKey);
}

/** Edwards → Montgomery map of an Ed25519 secret seed into an X25519 secret (§2.1/§2.6). */
export function ed25519SeedToX25519Secret(seed: Uint8Array): Uint8Array {
  requireLength(seed, X25519_KEY_LEN, "ed25519 seed");
  return edwardsToMontgomeryPriv(seed);
}

/** Low-level `x25519(secret, public)` (§2.6). */
export function x25519Shared(secret: Uint8Array, publicKey: Uint8Array): Uint8Array {
  requireLength(secret, X25519_KEY_LEN, "x25519 secret");
  requireLength(publicKey, X25519_KEY_LEN, "x25519 public key");
  return x25519.getSharedSecret(secret, publicKey);
}

// ---------------------------------------------------------------------------
// §3.2 — payload padding (trailing-zero buckets)
// ---------------------------------------------------------------------------

/**
 * Pad compact JSON to the smallest bucket ≥ `len + 1` using trailing `0x00`.
 *
 * @throws {E2eCryptoError} `TooLarge` when the payload exceeds 16384 bytes.
 */
export function padPayload(jsonBytes: Uint8Array): Uint8Array {
  const needed = jsonBytes.length + 1;
  let bucket = 0;
  for (const candidate of PAYLOAD_BUCKETS) {
    if (needed <= candidate) {
      bucket = candidate;
      break;
    }
  }
  if (bucket === 0) {
    throw new E2eCryptoError("TooLarge", `payload ${needed} bytes exceeds ${MAX_PAYLOAD_BYTES}`);
  }
  const out = new Uint8Array(bucket);
  out.set(jsonBytes, 0);
  return out;
}

/** Trim trailing `0x00` bytes from a padded plaintext (§3.2). */
export function unpadPayload(padded: Uint8Array): Uint8Array {
  let end = padded.length;
  while (end > 0 && padded[end - 1] === 0) end -= 1;
  return padded.slice(0, end);
}

/** Compact JSON of a payload object, key order `kind, body, ts` (§3.2). */
export function payloadJson(payload: Payload): string {
  return JSON.stringify({ kind: payload.kind, body: payload.body, ts: payload.ts });
}

/** Encode a payload to padded plaintext bytes (compact JSON + trailing zeros). */
export function encodePayload(payload: Payload): Uint8Array {
  if (typeof payload.kind !== "string" || typeof payload.body !== "string") {
    throw new E2eCryptoError("TooLarge", "payload kind/body must be strings");
  }
  if (!Number.isSafeInteger(payload.ts) || payload.ts < 0) {
    throw new E2eCryptoError("TooLarge", "payload ts must be a non-negative integer");
  }
  return padPayload(new TextEncoder().encode(payloadJson(payload)));
}

/**
 * Decode padded plaintext back into a payload: trim trailing zeros, then
 * JSON-parse. Unknown `kind` values are returned as-is (not an error, §3.2).
 *
 * @throws {E2eCryptoError} `Aead` on malformed JSON or a non-object payload.
 */
export function decodePayload(plaintext: Uint8Array): Payload {
  const trimmed = unpadPayload(plaintext);
  let parsed: unknown;
  try {
    parsed = JSON.parse(new TextDecoder().decode(trimmed));
  } catch {
    throw new E2eCryptoError("Aead", "payload is not valid JSON");
  }
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new E2eCryptoError("Aead", "payload must be a JSON object");
  }
  const record = parsed as Record<string, unknown>;
  if (typeof record.kind !== "string" || typeof record.body !== "string") {
    throw new E2eCryptoError("Aead", "payload kind/body must be strings");
  }
  if (typeof record.ts !== "number") {
    throw new E2eCryptoError("Aead", "payload ts must be a number");
  }
  return { kind: record.kind, body: record.body, ts: record.ts };
}

// ---------------------------------------------------------------------------
// §2.2/§2.3 — seal / open
// ---------------------------------------------------------------------------

function aeadSeal(key: Uint8Array, nonce: Uint8Array, aad: Uint8Array, plaintext: Uint8Array): Uint8Array {
  return xchacha20poly1305(key, nonce, aad).encrypt(plaintext);
}

function aeadOpen(key: Uint8Array, nonce: Uint8Array, aad: Uint8Array, ct: Uint8Array): Uint8Array {
  try {
    return xchacha20poly1305(key, nonce, aad).decrypt(ct);
  } catch {
    throw new E2eCryptoError("Aead", "aead open failed");
  }
}

/**
 * Seal `plaintext` to a recipient Ed25519 public key.
 *
 * `ephemeralSecret` / `nonce` are test-only overrides (deterministic KATs).
 * Production callers pass `undefined` for a fresh ephemeral + nonce per seal.
 */
export function sealTo(
  recipientEd25519Pub: Uint8Array,
  plaintext: Uint8Array,
  aad: Uint8Array,
  ephemeralSecret?: Uint8Array,
  nonce?: Uint8Array,
): Sealed {
  const ephSecret = ephemeralSecret ? ephemeralSecret.slice() : randomBytes(X25519_KEY_LEN);
  requireLength(ephSecret, X25519_KEY_LEN, "ephemeral secret");
  const epk = x25519.getPublicKey(ephSecret);
  const recipientX25519 = ed25519PubToX25519(recipientEd25519Pub);
  const shared = x25519Shared(ephSecret, recipientX25519);
  const key = kdfV1(shared);
  const usedNonce = nonce ? nonce.slice() : randomBytes(NONCE_LEN);
  requireLength(usedNonce, NONCE_LEN, "nonce");
  const ct = aeadSeal(key, usedNonce, aad, plaintext);
  return { alg: ALG_V1, epk, nonce: usedNonce, ct };
}

/** Open a sealed payload with the recipient's Ed25519 seed. */
export function openWith(
  recipientEd25519Seed: Uint8Array,
  sealed: Sealed,
  aad: Uint8Array,
): Uint8Array {
  if (sealed.alg !== ALG_V1) {
    throw new E2eCryptoError("InvalidKey", `unsupported alg: ${sealed.alg}`);
  }
  requireLength(sealed.epk, X25519_KEY_LEN, "epk");
  requireLength(sealed.nonce, NONCE_LEN, "nonce");
  const staticSecret = ed25519SeedToX25519Secret(recipientEd25519Seed);
  const shared = x25519Shared(staticSecret, sealed.epk);
  const key = kdfV1(shared);
  return aeadOpen(key, sealed.nonce, aad, sealed.ct);
}

/**
 * Stateful cipher mirroring the Rust `X25519Cipher` surface (§2.6).
 *
 * Holds the wallet's static X25519 secret (for `open`); `seal` uses a fresh
 * ephemeral per call. `deterministicFromSeed` pins the ephemeral + nonce for
 * shared KAT vectors.
 */
export class X25519Cipher {
  private readonly staticSecret: Uint8Array;
  private readonly pinnedEphemeral: Uint8Array | null;
  private readonly pinnedNonce: Uint8Array | null;

  private constructor(
    staticSecret: Uint8Array,
    pinnedEphemeral: Uint8Array | null,
    pinnedNonce: Uint8Array | null,
  ) {
    this.staticSecret = staticSecret;
    this.pinnedEphemeral = pinnedEphemeral;
    this.pinnedNonce = pinnedNonce;
  }

  /** Build from the wallet Ed25519 seed. A fresh ephemeral + nonce per `seal`. */
  static fromSeed(ed25519Seed: Uint8Array): X25519Cipher {
    return new X25519Cipher(ed25519SeedToX25519Secret(ed25519Seed), null, null);
  }

  /** KAT/tests only: pin the ephemeral secret and nonce. */
  static deterministicFromSeed(
    ed25519Seed: Uint8Array,
    ephemeralSecret: Uint8Array,
    nonce: Uint8Array,
  ): X25519Cipher {
    requireLength(ephemeralSecret, X25519_KEY_LEN, "ephemeral secret");
    requireLength(nonce, NONCE_LEN, "nonce");
    return new X25519Cipher(
      ed25519SeedToX25519Secret(ed25519Seed),
      ephemeralSecret.slice(),
      nonce.slice(),
    );
  }

  alg(): string {
    return ALG_V1;
  }

  /** The wallet's static X25519 public key (derived from the seed). */
  staticPublicKey(): Uint8Array {
    return x25519.getPublicKey(this.staticSecret);
  }

  seal(recipientEd25519Pub: Uint8Array, plaintext: Uint8Array, aad: Uint8Array): Sealed {
    return sealTo(
      recipientEd25519Pub,
      plaintext,
      aad,
      this.pinnedEphemeral ?? undefined,
      this.pinnedNonce ?? undefined,
    );
  }

  open(sealed: Sealed, aad: Uint8Array): Uint8Array {
    if (sealed.alg !== ALG_V1) {
      throw new E2eCryptoError("InvalidKey", `unsupported alg: ${sealed.alg}`);
    }
    requireLength(sealed.epk, X25519_KEY_LEN, "epk");
    requireLength(sealed.nonce, NONCE_LEN, "nonce");
    const shared = x25519Shared(this.staticSecret, sealed.epk);
    const key = kdfV1(shared);
    return aeadOpen(key, sealed.nonce, aad, sealed.ct);
  }

  /** v1 has no handshake (§2.5): `initiate` → `null`, `accept` → no-op. */
  initiate(_peerEd25519Pub: Uint8Array): null {
    return null;
  }

  accept(_blob: Uint8Array): void {
    // v1 minimal scheme: nothing to consume.
  }
}

/** Lowercase-hex helper re-export so callers can render ids consistently. */
export function sealedEpkHex(sealed: Sealed): string {
  return bytesToHex(sealed.epk);
}

/** Decode a 32-byte comms id hex string (64 lowercase hex) into bytes. */
export function commsIdToBytes(hex: string): Uint8Array {
  if (!/^[0-9a-f]{64}$/.test(hex)) {
    throw new E2eCryptoError("InvalidKey", "comms_id must be 64 lowercase hex characters");
  }
  return hexToBytes(hex);
}
