/**
 * Envelope wire format v1 — JSON + base64 (§3 of
 * `docs/COMMS-M1-INTERFACES.md`).
 *
 * Byte-for-byte mirror of the Rust `kovanica-comms-relay` `Envelope` type:
 * - signing bytes use a fixed, non-JSON layout (§3.3);
 * - the id is `BLAKE3(b"kvnc/comms/env-id/v1" || signing_bytes)` (§3.4);
 * - base64 is the STANDARD alphabet (`A–Z a–z 0–9 + /`) with `=` padding and
 *   no line breaks (§1);
 * - hex ids are lowercase, no `0x`;
 * - `sentAt` / `expiresAt` are `u64` ms, little-endian inside signing bytes.
 */

// Side-effect: install the SHA-512 hook on this package's `@noble/ed25519`.
import "./ed25519.js";

import * as ed from "@noble/ed25519";
import { blake3 } from "@noble/hashes/blake3";

import { bytesToHex, hexToBytes } from "@kovanica/signer";

import { ALG_V1, concat, u64le, type Sealed } from "./messaging.js";

/** Wire version, always 1 (§3.1). */
export const ENVELOPE_VERSION = 1 as const;

/** Signing-byte domain prefix (§3.3). */
export const ENV_SIGN_DOMAIN = "kvnc/comms/env/v1";

/** Envelope-id domain prefix (§3.4). */
export const ENV_ID_DOMAIN = "kvnc/comms/env-id/v1";

const ENV_SIGN_DOMAIN_BYTES = new TextEncoder().encode(ENV_SIGN_DOMAIN);
const ENV_ID_DOMAIN_BYTES = new TextEncoder().encode(ENV_ID_DOMAIN);

const EPK_LEN = 32;
const NONCE_LEN = 24;
const SIG_LEN = 64;
const CT_MIN_LEN = 16;

const HEX64 = /^[0-9a-f]{64}$/;

/** Envelope fields that participate in signing / id computation. */
export interface EnvelopeFields {
  /** Recipient comms_id, 64 lowercase hex. */
  to: string;
  /** Sender comms_id, 64 lowercase hex. */
  from: string;
  /** Client clock ms, `u64` (untrusted). */
  sentAt: number;
  /** Relay TTL ms, `u64`. */
  expiresAt: number;
  /** Algorithm id, e.g. {@link ALG_V1}. */
  alg: string;
  /** 32-byte ephemeral X25519 public key. */
  epk: Uint8Array;
  /** 24-byte XChaCha20-Poly1305 nonce. */
  nonce: Uint8Array;
  /** Ciphertext with Poly1305 tag. */
  ct: Uint8Array;
}

/** A signed, self-describing envelope. */
export interface Envelope extends EnvelopeFields {
  v: typeof ENVELOPE_VERSION;
  /** 64 lowercase hex, §3.4. */
  id: string;
  /** 64-byte Ed25519 signature over {@link envelopeSigningBytes}. */
  sig: Uint8Array;
}

/** JSON form of an envelope (base64 / hex strings on the wire). */
export interface EnvelopeJson {
  v: number;
  id: string;
  to: string;
  from: string;
  sentAt: number;
  expiresAt: number;
  alg: string;
  epk: string;
  nonce: string;
  ct: string;
  sig: string;
}

/** Failure decoding or validating an envelope. */
export class EnvelopeError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "EnvelopeError";
  }
}

// ---------------------------------------------------------------------------
// §1 — base64 (standard alphabet, `=` padding, no line breaks)
// ---------------------------------------------------------------------------

/** Encode bytes to standard base64 with `=` padding (no line breaks). */
export function bytesToBase64(bytes: Uint8Array): string {
  let binary = "";
  for (let i = 0; i < bytes.length; i += 1) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

/** Decode standard base64 (with `=` padding) back into bytes. */
export function base64ToBytes(value: string): Uint8Array {
  if (typeof value !== "string" || !/^[A-Za-z0-9+/]*={0,2}$/.test(value)) {
    throw new EnvelopeError("invalid base64");
  }
  let binary: string;
  try {
    binary = atob(value);
  } catch {
    throw new EnvelopeError("invalid base64");
  }
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) {
    out[i] = binary.charCodeAt(i);
  }
  return out;
}

function commsIdBytes(hex: string, what: string): Uint8Array {
  if (typeof hex !== "string" || !HEX64.test(hex)) {
    throw new EnvelopeError(`${what} must be 64 lowercase hex characters`);
  }
  return hexToBytes(hex);
}

function u64Number(value: number, what: string): bigint {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0) {
    throw new EnvelopeError(`${what} must be a non-negative safe integer`);
  }
  return BigInt(value);
}

// ---------------------------------------------------------------------------
// §3.3 — signing bytes
// ---------------------------------------------------------------------------

/**
 * Exact signing-byte layout (§3.3):
 *
 * ```text
 * utf8("kvnc/comms/env/v1")
 *   || to_comms_id(32) || from_comms_id(32)
 *   || sentAt(u64 LE, 8) || expiresAt(u64 LE, 8)
 *   || utf8(alg) || 0x00
 *   || epk(32) || nonce(24) || ct(...)
 * ```
 */
export function envelopeSigningBytes(fields: EnvelopeFields): Uint8Array {
  if (typeof fields.alg !== "string") {
    throw new EnvelopeError("alg must be a string");
  }
  if (!(fields.epk instanceof Uint8Array) || fields.epk.length !== EPK_LEN) {
    throw new EnvelopeError(`epk must be ${EPK_LEN} bytes`);
  }
  if (!(fields.nonce instanceof Uint8Array) || fields.nonce.length !== NONCE_LEN) {
    throw new EnvelopeError(`nonce must be ${NONCE_LEN} bytes`);
  }
  if (!(fields.ct instanceof Uint8Array) || fields.ct.length < CT_MIN_LEN) {
    throw new EnvelopeError(`ct must be at least ${CT_MIN_LEN} bytes`);
  }
  return concat([
    ENV_SIGN_DOMAIN_BYTES,
    commsIdBytes(fields.to, "to"),
    commsIdBytes(fields.from, "from"),
    u64le(u64Number(fields.sentAt, "sentAt")),
    u64le(u64Number(fields.expiresAt, "expiresAt")),
    new TextEncoder().encode(fields.alg),
    Uint8Array.of(0),
    fields.epk,
    fields.nonce,
    fields.ct,
  ]);
}

// ---------------------------------------------------------------------------
// §3.4 — envelope id
// ---------------------------------------------------------------------------

/** `BLAKE3(b"kvnc/comms/env-id/v1" || signing_bytes)` → 32 bytes. */
export function computeEnvelopeIdBytes(signingBytes: Uint8Array): Uint8Array {
  return blake3(concat([ENV_ID_DOMAIN_BYTES, signingBytes]));
}

/** Envelope id as 64 lowercase hex. */
export function computeEnvelopeId(signingBytes: Uint8Array): string {
  return bytesToHex(computeEnvelopeIdBytes(signingBytes));
}

// ---------------------------------------------------------------------------
// Sign / verify
// ---------------------------------------------------------------------------

/** Sign envelope fields with the sender's Ed25519 seed; fills `id` + `sig`. */
export function signEnvelope(fields: EnvelopeFields, ed25519Seed: Uint8Array): Envelope {
  if (!(ed25519Seed instanceof Uint8Array) || ed25519Seed.length !== 32) {
    throw new EnvelopeError("ed25519 seed must be 32 bytes");
  }
  const signingBytes = envelopeSigningBytes(fields);
  const sig = ed.sign(signingBytes, ed25519Seed);
  const id = computeEnvelopeId(signingBytes);
  return { v: ENVELOPE_VERSION, ...fields, id, sig };
}

/** Verify an envelope's Ed25519 signature against the sender's public key. */
export function verifyEnvelope(envelope: Envelope, senderEd25519Pub: Uint8Array): boolean {
  if (!(senderEd25519Pub instanceof Uint8Array) || senderEd25519Pub.length !== 32) {
    return false;
  }
  if (!(envelope.sig instanceof Uint8Array) || envelope.sig.length !== SIG_LEN) {
    return false;
  }
  let signingBytes: Uint8Array;
  try {
    signingBytes = envelopeSigningBytes(envelope);
  } catch {
    return false;
  }
  try {
    return ed.verify(envelope.sig, signingBytes, senderEd25519Pub);
  } catch {
    return false;
  }
}

// ---------------------------------------------------------------------------
// JSON (de)serialization
// ---------------------------------------------------------------------------

/** Serialize an envelope to its wire JSON (base64 / hex string fields). */
export function envelopeToJSON(envelope: Envelope): EnvelopeJson {
  return {
    v: envelope.v,
    id: envelope.id,
    to: envelope.to,
    from: envelope.from,
    sentAt: envelope.sentAt,
    expiresAt: envelope.expiresAt,
    alg: envelope.alg,
    epk: bytesToBase64(envelope.epk),
    nonce: bytesToBase64(envelope.nonce),
    ct: bytesToBase64(envelope.ct),
    sig: bytesToBase64(envelope.sig),
  };
}

function requireString(record: Record<string, unknown>, key: string): string {
  const value = record[key];
  if (typeof value !== "string") {
    throw new EnvelopeError(`missing or invalid ${key}`);
  }
  return value;
}

function requireU64(record: Record<string, unknown>, key: string): number {
  const value = record[key];
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0) {
    throw new EnvelopeError(`missing or invalid ${key}`);
  }
  return value;
}

/**
 * Parse an envelope from wire JSON.
 *
 * Missing or wrongly-typed required keys are rejected; unknown extra keys are
 * ignored (forward compatibility, §3.1).
 */
export function envelopeFromJSON(value: unknown): Envelope {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new EnvelopeError("envelope must be a JSON object");
  }
  const record = value as Record<string, unknown>;

  const v = record.v;
  if (v !== ENVELOPE_VERSION) {
    throw new EnvelopeError(`unsupported envelope version: ${String(v)}`);
  }
  const to = requireString(record, "to");
  const from = requireString(record, "from");
  if (!HEX64.test(to)) throw new EnvelopeError("to must be 64 lowercase hex characters");
  if (!HEX64.test(from)) throw new EnvelopeError("from must be 64 lowercase hex characters");

  const id = requireString(record, "id");
  if (!HEX64.test(id)) throw new EnvelopeError("id must be 64 lowercase hex characters");

  const sentAt = requireU64(record, "sentAt");
  const expiresAt = requireU64(record, "expiresAt");
  const alg = requireString(record, "alg");

  const epk = base64ToBytes(requireString(record, "epk"));
  if (epk.length !== EPK_LEN) throw new EnvelopeError(`epk must be ${EPK_LEN} bytes`);

  const nonce = base64ToBytes(requireString(record, "nonce"));
  if (nonce.length !== NONCE_LEN) throw new EnvelopeError(`nonce must be ${NONCE_LEN} bytes`);

  const ct = base64ToBytes(requireString(record, "ct"));
  if (ct.length < CT_MIN_LEN) throw new EnvelopeError(`ct must be at least ${CT_MIN_LEN} bytes`);

  const sig = base64ToBytes(requireString(record, "sig"));
  if (sig.length !== SIG_LEN) throw new EnvelopeError(`sig must be ${SIG_LEN} bytes`);

  return { v: ENVELOPE_VERSION, id, to, from, sentAt, expiresAt, alg, epk, nonce, ct, sig };
}

/**
 * Convenience: build an envelope from a {@link Sealed} triple plus routing
 * metadata, then sign it.
 */
export function buildSignedEnvelope(
  params: {
    to: string;
    from: string;
    sentAt: number;
    expiresAt: number;
    sealed: Sealed;
  },
  senderEd25519Seed: Uint8Array,
): Envelope {
  return signEnvelope(
    {
      to: params.to,
      from: params.from,
      sentAt: params.sentAt,
      expiresAt: params.expiresAt,
      alg: params.sealed.alg || ALG_V1,
      epk: params.sealed.epk,
      nonce: params.sealed.nonce,
      ct: params.sealed.ct,
    },
    senderEd25519Seed,
  );
}
