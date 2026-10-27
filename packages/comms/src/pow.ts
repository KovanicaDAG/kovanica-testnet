import { blake3 } from "@noble/hashes/blake3";

const DEFAULT_MAX_ATTEMPTS = 10_000_000;

function hexToBytes(hex: string): Uint8Array {
  if (typeof hex !== "string") {
    throw new Error("hex must be a string");
  }
  const lower = hex.toLowerCase();
  if (lower.length % 2 === 1 || !/^[0-9a-f]+$/.test(lower)) {
    throw new Error("hex string must have even length of hex chars");
  }
  const out = new Uint8Array(lower.length / 2);
  for (let i = 0; i < lower.length; i += 2) {
    out[i / 2] = parseInt(lower.slice(i, i + 2), 16);
  }
  return out;
}

function bytesToHex(bytes: Uint8Array): string {
  const parts: string[] = [];
  for (let i = 0; i < bytes.length; i += 1) {
    parts.push(bytes[i].toString(16).padStart(2, "0"));
  }
  return parts.join("");
}

function leadingZeroBits(hash: Uint8Array): number {
  let bits = 0;
  for (let i = 0; i < hash.length; i += 1) {
    const b = hash[i];
    if (b === 0) {
      bits += 8;
      continue;
    }
    bits += Math.clz32(b) - 24;
    break;
  }
  return bits;
}

export interface PowProof {
  /** Hex-encoded nonce bytes. */
  nonce: string;
  /** Number of leading zero bits required/achieved. */
  bits: number;
}

/**
 * Compute PoW nonce such that BLAKE3(nonceBytes || idBytes) has >= `bits`
 * leading zero bits (hashcash-style, bound to envelope `id`).
 */
export function powCompute(
  idHex: string,
  bits: number,
  maxAttempts = DEFAULT_MAX_ATTEMPTS,
): PowProof {
  if (!Number.isInteger(bits) || bits < 0) {
    throw new Error("bits must be a non-negative integer");
  }
  if (maxAttempts <= 0) {
    throw new Error("maxAttempts must be > 0");
  }
  const idBytes = hexToBytes(idHex);
  // Use 8-byte counter nonce for deterministic search (sufficient for typical bits)
  const nonceBytes = new Uint8Array(8);
  for (let i = 0; i < maxAttempts; i += 1) {
    // Increment nonce (little-endian not required; just bytes)
    let j = 0;
    while (j < nonceBytes.length && nonceBytes[j] === 255) {
      nonceBytes[j] = 0;
      j += 1;
    }
    if (j < nonceBytes.length) {
      nonceBytes[j] += 1;
    } else {
      // Wrap around; expand by appending if extremely high attempts (rare)
      const expanded = new Uint8Array(nonceBytes.length + 1);
      expanded.set(nonceBytes);
      expanded[nonceBytes.length] = 1;
      // replace
      (nonceBytes as any).length = expanded.length;
      for (let k = 0; k < expanded.length; k++) (nonceBytes as any)[k] = expanded[k];
    }
    // compute hash = blake3(nonce || id)
    const input = new Uint8Array(nonceBytes.length + idBytes.length);
    input.set(nonceBytes);
    input.set(idBytes, nonceBytes.length);
    const hash = blake3(input);
    if (leadingZeroBits(hash) >= bits) {
      return { nonce: bytesToHex(nonceBytes), bits };
    }
  }
  throw new Error(`failed to find PoW solution for ${bits} bits within ${maxAttempts} attempts`);
}

/** Verify PoW bound to envelope id. */
export function powVerify(idHex: string, nonce: string, bits: number): boolean {
  if (!Number.isInteger(bits) || bits < 0) {
    return false;
  }
  try {
    const idBytes = hexToBytes(idHex);
    const nonceBytes = hexToBytes(nonce);
    const input = new Uint8Array(nonceBytes.length + idBytes.length);
    input.set(nonceBytes);
    input.set(idBytes, nonceBytes.length);
    const hash = blake3(input);
    return leadingZeroBits(hash) >= bits;
  } catch {
    return false;
  }
}
