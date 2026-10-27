/**
 * Name-registry contract binding (v1) — `docs/COMMS-M1-INTERFACES.md` §6.
 *
 * Builds `name_register` / `name_resolve` / `name_update_endpoints` /
 * `name_transfer` contract calls as bincode-1.3-compatible argument bytes for
 * `@kovanica/api-client` / `kovanica-node`. The Rust contract
 * (`crates/kovanica-name-registry`) decodes exactly these tuples (spec §9.1 — the
 * WASM export names are normative and MUST be used verbatim):
 *
 * | WASM export             | args tuple                          |
 * |-------------------------|-------------------------------------|
 * | `name_register`         | `(String, [u8;32], Vec<String>)`    |
 * | `name_resolve`          | `(String)`                          |
 * | `name_update_endpoints` | `(String, Vec<String>)`             |
 * | `name_transfer`         | `(String, [u8;32])`                 |
 *
 * Bincode 1.3 default config = fixed-int, little-endian (same as the house
 * `kovanica_common` convention): a `String`/`Vec` is an 8-byte LE length prefix
 * followed by the payload; a fixed `[u8; 32]` is 32 raw bytes.
 *
 * `name_resolve` returns `bincode(NameEntry { owner: [u8;32], pubkey: [u8;32],
 * relay_endpoints: Vec<String> })` in that field order; decode it with
 * {@link decodeRegistryEntry}. Contract errors are packed as `-1 - code()`
 * (see {@link REGISTRY_ERROR_CODES}).
 */

import { concat, u64le } from "./messaging.js";

/** Registry entry points — the pinned WASM export names (spec §9.1). */
export const REGISTRY_METHODS = [
  "name_register",
  "name_resolve",
  "name_update_endpoints",
  "name_transfer",
] as const;

export type RegistryMethod = (typeof REGISTRY_METHODS)[number];

/**
 * `kovanica_common::ContractError` codes packed by the contract as `-1 - code()`
 * (spec §6/§9.2). `Unauthorized`/`AlreadyExists` are owner/first-come guards;
 * a malformed name on `name_resolve` is `InvalidInput`, a well-formed unknown
 * name is `NotFound`.
 */
export const REGISTRY_ERROR_CODES = {
  Unauthorized: 0,
  InvalidInput: 2,
  AlreadyExists: 3,
  NotFound: 4,
} as const;

export type RegistryErrorName = keyof typeof REGISTRY_ERROR_CODES;

/** Decode the error code from a contract return value packed as `-1 - code()`. */
export function contractErrorName(returnValue: number | bigint): RegistryErrorName | null {
  const value = typeof returnValue === "bigint" ? returnValue : BigInt(returnValue);
  if (value >= 0n) return null;
  const code = -1n - value;
  for (const [name, codeValue] of Object.entries(REGISTRY_ERROR_CODES)) {
    if (BigInt(codeValue) === code) return name as RegistryErrorName;
  }
  return null;
}

/** Name length bounds (§6). */
export const MIN_NAME_LENGTH = 3;
export const MAX_NAME_LENGTH = 32;

/** Relay endpoint bounds (§6). */
export const MAX_RELAY_ENDPOINTS = 8;
export const MAX_RELAY_ENDPOINT_BYTES = 256;

const NAME_PATTERN = /^[a-z0-9-]+$/;

/** Validation error codes mirroring `kovanica_common::ContractError`. */
export type RegistryErrorCode = "InvalidInput";

/** Thrown when a name or endpoint set fails §6 validation. */
export class RegistryValidationError extends Error {
  constructor(
    message: string,
    public readonly code: RegistryErrorCode = "InvalidInput",
  ) {
    super(message);
    this.name = "RegistryValidationError";
  }
}

/** Normalise a name: §6 stores names lowercase. */
export function normalizeName(name: string): string {
  if (typeof name !== "string") {
    throw new RegistryValidationError("name must be a string");
  }
  return name.toLowerCase();
}

/** Validate an already-normalised name against §6 rules (§9.2: bytes). */
export function validateName(name: string): void {
  if (typeof name !== "string") {
    throw new RegistryValidationError("name must be a string");
  }
  const byteLength = new TextEncoder().encode(name).length;
  if (byteLength < MIN_NAME_LENGTH || byteLength > MAX_NAME_LENGTH) {
    throw new RegistryValidationError(
      `name must be ${MIN_NAME_LENGTH}..=${MAX_NAME_LENGTH} bytes`,
    );
  }
  if (!NAME_PATTERN.test(name)) {
    throw new RegistryValidationError("name may only contain [a-z0-9-]");
  }
  if (name.startsWith("-") || name.endsWith("-")) {
    throw new RegistryValidationError("name must not start or end with '-'");
  }
  if (name.includes("--")) {
    throw new RegistryValidationError("name must not contain consecutive '-'");
  }
}

/** Normalise then validate a name; returns the stored (lowercase) form. */
export function normalizeAndValidateName(name: string): string {
  const normalized = normalizeName(name);
  validateName(normalized);
  return normalized;
}

/** Validate a relay endpoint list against §6 (≤8 entries, ≤256 bytes, http(s)). */
export function validateRelayEndpoints(endpoints: readonly string[]): void {
  if (!Array.isArray(endpoints)) {
    throw new RegistryValidationError("relay_endpoints must be an array");
  }
  if (endpoints.length > MAX_RELAY_ENDPOINTS) {
    throw new RegistryValidationError(
      `at most ${MAX_RELAY_ENDPOINTS} relay endpoints are allowed`,
    );
  }
  for (const endpoint of endpoints) {
    if (typeof endpoint !== "string") {
      throw new RegistryValidationError("each relay endpoint must be a string");
    }
    const byteLength = new TextEncoder().encode(endpoint).length;
    if (byteLength > MAX_RELAY_ENDPOINT_BYTES) {
      throw new RegistryValidationError(
        `each relay endpoint must be at most ${MAX_RELAY_ENDPOINT_BYTES} bytes`,
      );
    }
    if (!/^https?:\/\//.test(endpoint)) {
      throw new RegistryValidationError("relay endpoints must use the http(s):// scheme");
    }
  }
}

/** Validate and return a copy of the endpoint list. */
export function normalizeRelayEndpoints(endpoints: readonly string[]): string[] {
  validateRelayEndpoints(endpoints);
  return [...endpoints];
}

// ---------------------------------------------------------------------------
// Bincode 1.3 encoders
// ---------------------------------------------------------------------------

/** bincode `String`: u64 LE byte length + UTF-8 bytes. */
export function encodeBincodeString(value: string): Uint8Array {
  const bytes = new TextEncoder().encode(value);
  return concat([u64le(BigInt(bytes.length)), bytes]);
}

/** bincode `Vec<String>`: u64 LE element count + each encoded string. */
export function encodeBincodeStringVec(values: readonly string[]): Uint8Array {
  return concat([u64le(BigInt(values.length)), ...values.map(encodeBincodeString)]);
}

/** bincode `[u8; 32]`: exactly 32 raw bytes, no length prefix. */
export function encodeBincodeFixed32(value: Uint8Array): Uint8Array {
  if (!(value instanceof Uint8Array) || value.length !== 32) {
    throw new RegistryValidationError("expected a 32-byte value");
  }
  return value.slice();
}

function nameArg(name: string): Uint8Array {
  return encodeBincodeString(normalizeAndValidateName(name));
}

/** Args for `register(name, pubkey, relay_endpoints)`. */
export function encodeRegisterArgs(
  name: string,
  pubkey: Uint8Array,
  relayEndpoints: readonly string[],
): Uint8Array {
  validateRelayEndpoints(relayEndpoints);
  return concat([
    nameArg(name),
    encodeBincodeFixed32(pubkey),
    encodeBincodeStringVec(relayEndpoints),
  ]);
}

/** Args for `resolve(name)`. */
export function encodeResolveArgs(name: string): Uint8Array {
  return nameArg(name);
}

/** Args for `update_endpoints(name, relay_endpoints)`. */
export function encodeUpdateEndpointsArgs(
  name: string,
  relayEndpoints: readonly string[],
): Uint8Array {
  validateRelayEndpoints(relayEndpoints);
  return concat([nameArg(name), encodeBincodeStringVec(relayEndpoints)]);
}

/** Args for `transfer(name, new_owner)`. */
export function encodeTransferArgs(name: string, newOwner: Uint8Array): Uint8Array {
  return concat([nameArg(name), encodeBincodeFixed32(newOwner)]);
}

// ---------------------------------------------------------------------------
// Contract-call payloads (method + args) for @kovanica/api-client
// ---------------------------------------------------------------------------

/** A ready-to-sign contract call: the entry point and its bincode args. */
export interface RegistryCall {
  method: RegistryMethod;
  args: Uint8Array;
}

/** Build `name_register(name, pubkey, relay_endpoints)`. */
export function buildRegisterCall(
  name: string,
  pubkey: Uint8Array,
  relayEndpoints: readonly string[],
): RegistryCall {
  return { method: "name_register", args: encodeRegisterArgs(name, pubkey, relayEndpoints) };
}

/** Build `name_resolve(name)`. */
export function buildResolveCall(name: string): RegistryCall {
  return { method: "name_resolve", args: encodeResolveArgs(name) };
}

/** Build `name_update_endpoints(name, relay_endpoints)`. */
export function buildUpdateEndpointsCall(
  name: string,
  relayEndpoints: readonly string[],
): RegistryCall {
  return { method: "name_update_endpoints", args: encodeUpdateEndpointsArgs(name, relayEndpoints) };
}

/** Build `name_transfer(name, new_owner)`. */
export function buildTransferCall(name: string, newOwner: Uint8Array): RegistryCall {
  return { method: "name_transfer", args: encodeTransferArgs(name, newOwner) };
}

/** Decoded registry entry returned by `name_resolve`. */
export interface RegistryEntry {
  owner: Uint8Array;
  pubkey: Uint8Array;
  relayEndpoints: string[];
}

/**
 * Decode the bincode `NameEntry` returned by `name_resolve` (§9.1):
 * `owner: [u8;32]`, `pubkey: [u8;32]`, `relay_endpoints: Vec<String>`.
 */
export function decodeRegistryEntry(bytes: Uint8Array): RegistryEntry {
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  let offset = 0;
  const readFixed32 = (): Uint8Array => {
    if (offset + 32 > bytes.length) throw new RegistryValidationError("truncated registry entry");
    const out = bytes.slice(offset, offset + 32);
    offset += 32;
    return out;
  };
  const readString = (): string => {
    if (offset + 8 > bytes.length) throw new RegistryValidationError("truncated registry entry");
    const length = Number(view.getBigUint64(offset, true));
    offset += 8;
    if (offset + length > bytes.length) throw new RegistryValidationError("truncated registry entry");
    const text = new TextDecoder().decode(bytes.subarray(offset, offset + length));
    offset += length;
    return text;
  };

  const owner = readFixed32();
  const pubkey = readFixed32();
  if (offset + 8 > bytes.length) throw new RegistryValidationError("truncated registry entry");
  const count = Number(view.getBigUint64(offset, true));
  offset += 8;
  const relayEndpoints: string[] = [];
  for (let i = 0; i < count; i += 1) {
    relayEndpoints.push(readString());
  }
  return { owner, pubkey, relayEndpoints };
}
