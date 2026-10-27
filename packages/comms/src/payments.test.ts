import { describe, expect, it } from "vitest";
import { blake3 } from "@noble/hashes/blake3";
import {
  buildPaymentProof,
  computeHtlcHashLock,
  computeHtlcId,
} from "./payments.js";

function bytesToHex(bytes: Uint8Array): string {
  return [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
}

describe("payments", () => {
  it("computes HTLC id per deterministic formula", () => {
    const sender = new Uint8Array(32).fill(1);
    const claimer = new Uint8Array(32).fill(2);
    const amount = 1000n;
    const preimage = new TextEncoder().encode("secret");
    const hashLock = computeHtlcHashLock(preimage);
    const expiry = 1234567890000n;
    const id = computeHtlcId({ sender, claimer, amountAtoms: amount, hashLock, expiryMs: expiry });
    expect(id).toHaveLength(32);
    // Recompute
    const domain = new TextEncoder().encode("htlc/id");
    const input = new Uint8Array(domain.length + 32 + 32 + 8 + 32 + 8);
    let off = 0;
    input.set(domain, off); off += domain.length;
    input.set(sender, off); off += 32;
    input.set(claimer, off); off += 32;
    const u64 = (n: bigint) => {
      const b = new Uint8Array(8);
      for (let i = 0; i < 8; i++) b[i] = Number((n >> BigInt(i * 8)) & 0xffn);
      return b;
    };
    input.set(u64(amount), off); off += 8;
    input.set(hashLock, off); off += 32;
    input.set(u64(expiry), off); off += 8;
    expect(bytesToHex(id)).toBe(bytesToHex(blake3(input)));
  });

  it("builds payment proof", () => {
    const sender = new Uint8Array(32).fill(5);
    const claimer = new Uint8Array(32).fill(7);
    const preimage = new Uint8Array([10, 11, 12]);
    const proof = buildPaymentProof(preimage, {
      sender,
      claimer,
      amountAtoms: 5000n,
      hashLock: computeHtlcHashLock(preimage),
      expiryMs: 2000000n,
    });
    expect(proof.amountAtoms).toBe(5000n);
    expect(proof.claimerAddr).toHaveLength(64);
    expect(proof.htlcId).toHaveLength(64);
    expect(proof.preimage).toBeTruthy();
  });
});
