import { blake3 } from "@noble/hashes/blake3";

import { bytesToHex, hexToBytes } from "./bytes.js";

const PREFIX = "kvnc";
const SUFFIX = "dag";
/** bech32 data alphabet (BIP-173), lower case only. */
const ALPHABET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
/** Checksum bits: the first 29 bits of BLAKE3(publicKey). */
const CHECKSUM_BITS = 29;
/** (256 + 29) / 5 = 57 base32 characters, no padding. */
const BODY_CHARS = 57;
/** `kvnc` + 57 + `dag`. */
export const ADDRESS_LENGTH = PREFIX.length + BODY_CHARS + SUFFIX.length;
/** Chains that still accept the legacy hex forms: devnet, chain 4, local. */
const LEGACY_HEX_CHAIN_IDS = new Set([3, 4, 1337]);

function checksum29(publicKey: Uint8Array): bigint {
  const d = blake3(publicKey);
  const word = (BigInt(d[0]) << 24n) | (BigInt(d[1]) << 16n) | (BigInt(d[2]) << 8n) | BigInt(d[3]);
  return word >> BigInt(32 - CHECKSUM_BITS);
}

function keyToBigInt(publicKey: Uint8Array): bigint {
  return BigInt(`0x${bytesToHex(publicKey)}`);
}

/**
 * Canonical address (PRO-21): `kvnc` + 57 base32 characters (bech32 alphabet) + `dag`,
 * 64 characters. The 285 bits, most significant first, are the 32-byte public key
 * followed by the first 29 bits of unkeyed BLAKE3 over it. Same as
 * `Address::encode` in kovanica-types.
 */
export function encodeAddress(publicKey: Uint8Array): string {
  if (publicKey.length !== 32) {
    throw new Error("address payload must be 32 bytes");
  }
  let n = (keyToBigInt(publicKey) << BigInt(CHECKSUM_BITS)) | checksum29(publicKey);
  const chars: string[] = new Array(BODY_CHARS);
  for (let i = BODY_CHARS - 1; i >= 0; i -= 1) {
    chars[i] = ALPHABET[Number(n & 31n)];
    n >>= 5n;
  }
  return `${PREFIX}${chars.join("")}${SUFFIX}`;
}

/** Decode the canonical 64-character address and verify its checksum. */
export function decodeAddress(value: string): Uint8Array {
  const trimmed = value.trim();
  if (!trimmed.startsWith(PREFIX) || !trimmed.endsWith(SUFFIX)) {
    throw new Error("address must start with kvnc and end with dag");
  }
  if (trimmed.length !== ADDRESS_LENGTH) {
    throw new Error(`address must be ${ADDRESS_LENGTH} characters`);
  }
  let n = 0n;
  for (const c of trimmed.slice(PREFIX.length, -SUFFIX.length)) {
    const v = ALPHABET.indexOf(c);
    if (v < 0) {
      throw new Error("address contains a character outside the base32 alphabet");
    }
    n = (n << 5n) | BigInt(v);
  }
  const check = n & ((1n << BigInt(CHECKSUM_BITS)) - 1n);
  const key = n >> BigInt(CHECKSUM_BITS);
  const payload = hexToBytes(key.toString(16).padStart(64, "0"));
  if (check !== checksum29(payload)) {
    throw new Error("address checksum mismatch");
  }
  return payload;
}

/** Legacy `kvnc` + hex(key || 4-byte BLAKE3 checksum) + `dag` (chains 3, 4, 1337). */
export function encodeLegacyAddress(publicKey: Uint8Array): string {
  if (publicKey.length !== 32) {
    throw new Error("address payload must be 32 bytes");
  }
  const body = new Uint8Array(36);
  body.set(publicKey, 0);
  body.set(blake3(publicKey).slice(0, 4), 32);
  return `${PREFIX}${bytesToHex(body)}${SUFFIX}`;
}

function decodeLegacy(trimmed: string): Uint8Array {
  if (trimmed.startsWith(PREFIX) || trimmed.endsWith(SUFFIX)) {
    if (!trimmed.startsWith(PREFIX) || !trimmed.endsWith(SUFFIX)) {
      throw new Error("address must start with kvnc and end with dag");
    }
    const text = trimmed.slice(PREFIX.length, -SUFFIX.length);
    // Match Rust: the legacy body is hex digits only. `kvnc0x…dag` is not hex,
    // and a lowercase `0x` prefix is not stripped inside `kvnc…dag`.
    if (!/^[0-9a-fA-F]+$/.test(text)) {
      throw new Error("invalid hex");
    }
    const body = hexToBytes(text);
    if (body.length !== 36) {
      throw new Error("address payload must be 32 bytes plus a 4-byte checksum");
    }
    const payload = body.slice(0, 32);
    if (!equalBytes(body.slice(32), blake3(payload).slice(0, 4))) {
      throw new Error("address checksum mismatch");
    }
    return payload;
  }
  const raw = hexToBytes(trimmed);
  if (raw.length !== 32) {
    throw new Error("address must be 32 bytes");
  }
  return raw;
}

/**
 * Parse an address. The canonical form is accepted everywhere, including when
 * `chainId` is omitted. The legacy hex forms (`kvnc<hex>dag`, bare or lowercase
 * `0x` hex) are accepted only when `chainId` is 3, 4, or 1337. Omitting
 * `chainId` refuses legacy hex. `0X` and `kvnc0x…dag` are refused on every
 * chain, matching Rust. The base32 body is strictly lowercase. Legacy hex
 * digits accept `A-F`; `kvnc`, `dag`, and `0x` do not.
 */
export function parseAddress(value: string, chainId?: number): Uint8Array {
  const trimmed = value.trim();
  if (trimmed.length === ADDRESS_LENGTH && trimmed.startsWith(PREFIX) && trimmed.endsWith(SUFFIX)) {
    return decodeAddress(trimmed);
  }
  const legacy = decodeLegacy(trimmed);
  if (chainId === undefined) {
    throw new Error("legacy hex addresses are not accepted when chain id is omitted");
  }
  if (!LEGACY_HEX_CHAIN_IDS.has(chainId)) {
    throw new Error(`legacy hex addresses are not accepted on chain ${chainId}`);
  }
  return legacy;
}

function equalBytes(left: Uint8Array, right: Uint8Array): boolean {
  if (left.length !== right.length) return false;
  let diff = 0;
  for (let i = 0; i < left.length; i += 1) {
    diff |= left[i] ^ right[i];
  }
  return diff === 0;
}
