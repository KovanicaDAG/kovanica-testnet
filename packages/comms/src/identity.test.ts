import { blake3 } from "@noble/hashes/blake3";
import { describe, expect, it } from "vitest";

import { bytesToHex } from "@kovanica/signer";

import { COMMS_ID_DOMAIN, deriveCommsId, deriveCommsIdBytes } from "./identity.js";

const KEY_A = Uint8Array.from({ length: 32 }, (_, i) => i);
const KEY_B = Uint8Array.from({ length: 32 }, (_, i) => 255 - i);

describe("comms identity", () => {
  it("uses the documented domain-separation string", () => {
    expect(COMMS_ID_DOMAIN).toBe("kvnc/comms/id");
  });

  it("is deterministic for a given public key", () => {
    expect(deriveCommsId(KEY_A)).toBe(deriveCommsId(KEY_A));
    expect(deriveCommsIdBytes(KEY_A)).toEqual(deriveCommsIdBytes(KEY_A));
  });

  it("is 32 bytes and 64 lowercase hex characters", () => {
    expect(deriveCommsIdBytes(KEY_A)).toHaveLength(32);

    const hex = deriveCommsId(KEY_A);
    expect(hex).toHaveLength(64);
    expect(hex).toMatch(/^[0-9a-f]{64}$/);
    expect(hex).toBe(bytesToHex(deriveCommsIdBytes(KEY_A)));
  });

  it("separates different public keys", () => {
    expect(deriveCommsId(KEY_A)).not.toBe(deriveCommsId(KEY_B));
  });

  it("domain-separates from a bare BLAKE3 hash of the key", () => {
    expect(deriveCommsId(KEY_A)).not.toBe(bytesToHex(blake3(KEY_A)));
  });

  it("rejects a public key that is not 32 bytes", () => {
    expect(() => deriveCommsId(new Uint8Array(31))).toThrow();
    expect(() => deriveCommsId(new Uint8Array(33))).toThrow();
  });

  it("matches the Rust cross-language known-answer vector", () => {
    // KAT shared with crates/kovanica-comms-core/src/lib.rs (key = 32 x 0x01).
    expect(deriveCommsId(new Uint8Array(32).fill(1))).toBe(
      "6076cc6f05dbd8ad851ba6aa6b7e85c8dce112186e16d3e267663641d9fa9339",
    );
  });
});
