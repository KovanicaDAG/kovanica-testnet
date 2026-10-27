import { describe, expect, it } from "vitest";

import {
  MAX_RELAY_ENDPOINTS,
  REGISTRY_ERROR_CODES,
  REGISTRY_METHODS,
  RegistryValidationError,
  buildRegisterCall,
  buildResolveCall,
  buildTransferCall,
  buildUpdateEndpointsCall,
  contractErrorName,
  decodeRegistryEntry,
  encodeBincodeFixed32,
  encodeBincodeString,
  encodeBincodeStringVec,
  encodeRegisterArgs,
  encodeResolveArgs,
  encodeTransferArgs,
  encodeUpdateEndpointsArgs,
  normalizeAndValidateName,
  normalizeName,
  normalizeRelayEndpoints,
  validateName,
  validateRelayEndpoints,
} from "./registry.js";

const PUBKEY = Uint8Array.from({ length: 32 }, (_, i) => i);
const OWNER = Uint8Array.from({ length: 32 }, (_, i) => 255 - i);

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  return a.length === b.length && a.every((byte, i) => byte === b[i]);
}

describe("registry — name rules (§6)", () => {
  it("normalises to lowercase", () => {
    expect(normalizeName("Alice-01")).toBe("alice-01");
    expect(normalizeAndValidateName("Bob")).toBe("bob");
  });

  it("accepts valid names", () => {
    for (const name of ["abc", "a-b-c", "kovanica-relay-01", "x".repeat(32), "123"]) {
      expect(() => validateName(name)).not.toThrow();
    }
  });

  it("rejects invalid names", () => {
    const bad = [
      "ab", // too short
      "x".repeat(33), // too long
      "Alice", // uppercase (must be normalised first)
      "a_b", // illegal char
      "a b", // space
      "-abc", // leading dash
      "abc-", // trailing dash
      "a--b", // consecutive dashes
      "a.b",
    ];
    for (const name of bad) {
      expect(() => validateName(name)).toThrow(RegistryValidationError);
    }
  });
});

describe("registry — relay endpoint rules (§6)", () => {
  it("accepts http(s) endpoints up to the cap", () => {
    expect(() =>
      validateRelayEndpoints(["https://relay.example", "http://127.0.0.1:8080"]),
    ).not.toThrow();
    expect(normalizeRelayEndpoints(["https://a.example"])).toEqual(["https://a.example"]);
  });

  it("rejects too many endpoints, oversized, or non-http schemes", () => {
    const tooMany = Array.from({ length: MAX_RELAY_ENDPOINTS + 1 }, () => "https://a.example");
    expect(() => validateRelayEndpoints(tooMany)).toThrow(RegistryValidationError);

    const oversized = `https://a.example/${"x".repeat(300)}`;
    expect(() => validateRelayEndpoints([oversized])).toThrow(RegistryValidationError);

    expect(() => validateRelayEndpoints(["ftp://a.example"])).toThrow(RegistryValidationError);
    expect(() => validateRelayEndpoints(["relay.example"])).toThrow(RegistryValidationError);
  });
});

describe("registry — bincode encoders", () => {
  it("encodes a String as u64 LE length + UTF-8 bytes", () => {
    expect(encodeBincodeString("abc")).toEqual(
      Uint8Array.of(3, 0, 0, 0, 0, 0, 0, 0, 0x61, 0x62, 0x63),
    );
  });

  it("encodes a Vec<String> as u64 LE count + elements", () => {
    const encoded = encodeBincodeStringVec(["a", "b"]);
    expect(encoded).toHaveLength(8 + 9 + 9);
    expect(new DataView(encoded.buffer).getBigUint64(0, true)).toBe(2n);
    expect(new DataView(encoded.buffer).getBigUint64(8, true)).toBe(1n); // len of "a"
    expect(encoded[16]).toBe(0x61);
  });

  it("encodes a fixed [u8;32] verbatim and rejects other lengths", () => {
    expect(encodeBincodeFixed32(PUBKEY)).toEqual(PUBKEY);
    expect(() => encodeBincodeFixed32(new Uint8Array(31))).toThrow(RegistryValidationError);
  });
});

describe("registry — contract-call arg tuples (§6)", () => {
  const endpoints = ["https://relay.example"];

  it("builds register(name, pubkey, endpoints)", () => {
    const args = encodeRegisterArgs("alice", PUBKEY, endpoints);
    // (String, [u8;32], Vec<String>)
    expect(args.subarray(0, 13)).toEqual(encodeBincodeString("alice"));
    expect(args.subarray(13, 45)).toEqual(PUBKEY);
    expect(args.subarray(45)).toEqual(encodeBincodeStringVec(endpoints));
  });

  it("normalises the name before encoding", () => {
    expect(encodeRegisterArgs("Alice", PUBKEY, endpoints)).toEqual(
      encodeRegisterArgs("alice", PUBKEY, endpoints),
    );
  });

  it("builds resolve(name)", () => {
    expect(encodeResolveArgs("alice")).toEqual(encodeBincodeString("alice"));
  });

  it("builds update_endpoints(name, endpoints)", () => {
    const args = encodeUpdateEndpointsArgs("alice", endpoints);
    expect(args.subarray(0, 13)).toEqual(encodeBincodeString("alice"));
    expect(args.subarray(13)).toEqual(encodeBincodeStringVec(endpoints));
  });

  it("builds transfer(name, new_owner)", () => {
    const args = encodeTransferArgs("alice", OWNER);
    expect(args.subarray(0, 13)).toEqual(encodeBincodeString("alice"));
    expect(args.subarray(13)).toEqual(OWNER);
  });

  it("wraps each arg tuple in a method + args payload", () => {
    expect(buildRegisterCall("alice", PUBKEY, endpoints)).toEqual({
      method: "name_register",
      args: encodeRegisterArgs("alice", PUBKEY, endpoints),
    });
    expect(buildResolveCall("alice")).toEqual({
      method: "name_resolve",
      args: encodeResolveArgs("alice"),
    });
    expect(buildUpdateEndpointsCall("alice", endpoints)).toEqual({
      method: "name_update_endpoints",
      args: encodeUpdateEndpointsArgs("alice", endpoints),
    });
    expect(buildTransferCall("alice", OWNER)).toEqual({
      method: "name_transfer",
      args: encodeTransferArgs("alice", OWNER),
    });
  });

  it("uses the pinned WASM export names verbatim (spec §9.1)", () => {
    expect(REGISTRY_METHODS).toEqual([
      "name_register",
      "name_resolve",
      "name_update_endpoints",
      "name_transfer",
    ]);
  });
});

describe("registry — contract error codes (§6/§9.2)", () => {
  it("pins the ContractError codes", () => {
    expect(REGISTRY_ERROR_CODES).toEqual({
      Unauthorized: 0,
      InvalidInput: 2,
      AlreadyExists: 3,
      NotFound: 4,
    });
  });

  it("decodes a packed -1 - code() return value", () => {
    expect(contractErrorName(-1)).toBe("Unauthorized");
    expect(contractErrorName(-3)).toBe("InvalidInput");
    expect(contractErrorName(-4)).toBe("AlreadyExists");
    expect(contractErrorName(-5)).toBe("NotFound");
    expect(contractErrorName(0)).toBeNull();
    expect(contractErrorName(42)).toBeNull();
  });
});

describe("registry — resolve result decoding", () => {
  it("round-trips a bincode entry", () => {
    const endpoints = ["https://relay.example", "https://backup.example"];
    const encoded = new Uint8Array([
      ...OWNER,
      ...PUBKEY,
      ...encodeBincodeStringVec(endpoints),
    ]);
    const entry = decodeRegistryEntry(encoded);
    expect(bytesEqual(entry.owner, OWNER)).toBe(true);
    expect(bytesEqual(entry.pubkey, PUBKEY)).toBe(true);
    expect(entry.relayEndpoints).toEqual(endpoints);
  });

  it("rejects a truncated entry", () => {
    expect(() => decodeRegistryEntry(new Uint8Array(10))).toThrow(RegistryValidationError);
  });
});
