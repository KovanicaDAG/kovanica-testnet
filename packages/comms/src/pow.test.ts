import { describe, expect, it } from "vitest";
import { blake3 } from "@noble/hashes/blake3";
import { powCompute, powVerify } from "./pow.js";

function hexToBytes(hex: string): Uint8Array {
  const lower = hex.toLowerCase();
  const out = new Uint8Array(lower.length / 2);
  for (let i = 0; i < lower.length; i += 2) {
    out[i / 2] = parseInt(lower.slice(i, i + 2), 16);
  }
  return out;
}

describe("pow", () => {
  it("verifies computed nonce", () => {
    const idHex = "a".repeat(64);
    const sol = powCompute(idHex, 0);
    expect(powVerify(idHex, sol.nonce, sol.bits)).toBe(true);
  });

  it("computes solution meeting bits threshold", () => {
    const idHex = "1234567890abcdef".repeat(4);
    const sol = powCompute(idHex, 4, 200000);
    const nonceBytes = hexToBytes(sol.nonce);
    const idBytes = hexToBytes(idHex);
    const input = new Uint8Array(nonceBytes.length + idBytes.length);
    input.set(nonceBytes);
    input.set(idBytes, nonceBytes.length);
    const hash = blake3(input);
    // count leading zero bits
    let bits = 0;
    for (let i = 0; i < hash.length; i++) {
      const b = hash[i];
      if (b === 0) { bits += 8; continue; }
      bits += Math.clz32(b) - 24;
      break;
    }
    expect(bits >= sol.bits).toBe(true);
    expect(sol.bits >= 4).toBe(true);
  });

  it("rejects invalid", () => {
    expect(powVerify("ab", "01", 1)).toBe(false);
    expect(powVerify("00", "zz", 1)).toBe(false);
    expect(powVerify("00", "01", -1)).toBe(false);
  });
});
