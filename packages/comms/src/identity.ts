import { blake3 } from "@noble/hashes/blake3";

import { bytesToHex } from "@kovanica/signer";

/**
 * Domain-separation prefix for the comms identity.
 *
 * The canonical id is:
 *
 * ```text
 * commsId = BLAKE3( utf8("kvnc/comms/id") || <32-byte Ed25519 public key> )
 * ```
 *
 * The Rust side (`kovanica-comms-core`) must use the exact same byte string. Do not
 * change it without updating the Rust crate in lockstep.
 */
export const COMMS_ID_DOMAIN = "kvnc/comms/id";

const DOMAIN_BYTES = new TextEncoder().encode(COMMS_ID_DOMAIN);

const PUBLIC_KEY_LENGTH = 32;

/**
 * Derive the raw 32-byte comms id from a 32-byte Ed25519 public key.
 *
 * @throws if `publicKey` is not exactly 32 bytes.
 */
export function deriveCommsIdBytes(publicKey: Uint8Array): Uint8Array {
  if (publicKey.length !== PUBLIC_KEY_LENGTH) {
    throw new Error("public key must be 32 bytes");
  }
  const input = new Uint8Array(DOMAIN_BYTES.length + PUBLIC_KEY_LENGTH);
  input.set(DOMAIN_BYTES, 0);
  input.set(publicKey, DOMAIN_BYTES.length);
  return blake3(input);
}

/**
 * Derive the comms id as lowercase hex (64 characters).
 *
 * @throws if `publicKey` is not exactly 32 bytes.
 */
export function deriveCommsId(publicKey: Uint8Array): string {
  return bytesToHex(deriveCommsIdBytes(publicKey));
}
