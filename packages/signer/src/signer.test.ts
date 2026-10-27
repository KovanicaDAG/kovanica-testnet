import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import {
  ADDRESS_LENGTH,
  decodeAddress,
  encodeAddress,
  encodeLegacyAddress,
  parseAddress,
} from "./address.js";
import { formatKuna, parseKuna } from "./amount.js";
import { bytesToHex, hexToBytes } from "./bytes.js";
import "./ed25519.js";
import { keyFromMnemonic, seedToMnemonic } from "./keys.js";
import { encodeRawTransaction, rawTransactionSize, signTransaction, signingHash } from "./tx.js";
import type { TxKind, UnsignedTx } from "./tx.js";

const here = dirname(fileURLToPath(import.meta.url));
const fixture = JSON.parse(
  readFileSync(join(here, "../fixtures/wire.json"), "utf8"),
) as {
  chainId: number;
  seedHex: string;
  publicKeyHex: string;
  senderAddress: string;
  senderAddressLegacy: string;
  recipientAddress: string;
  recipientAddressLegacy: string;
  mnemonic: string;
  transactions: Array<{
    name: string;
    nonce: number;
    fee: number;
    signingHash: string;
    signature: string;
    rawHex: string;
  }>;
};

const seed = hexToBytes(fixture.seedHex);
const sender = hexToBytes(fixture.publicKeyHex);
const recipient = hexToBytes("22".repeat(32));

function unsigned(name: string): UnsignedTx {
  const row = fixture.transactions.find((entry) => entry.name === name);
  if (!row) throw new Error(name);
  const kind = kindFor(name);
  return {
    sender,
    nonce: BigInt(row.nonce),
    fee: BigInt(row.fee),
    kind,
  };
}

function kindFor(name: string): TxKind {
  switch (name) {
    case "transfer":
      return { type: "transfer", to: recipient, amount: 1_000_000n };
    case "stake":
      return { type: "stake", amount: 77n };
    case "unstake":
      return { type: "unstake", amount: 78n };
    case "delegate":
      return { type: "delegate", validator: recipient, amount: 79n };
    case "claimNone":
      return { type: "claimRewards", validator: null };
    case "claimSome":
      return { type: "claimRewards", validator: recipient };
    case "call-value-zero":
      return {
        type: "call",
        contract: hexToBytes("33".repeat(32)),
        value: 0n,
        method: "transfer",
        args: hexToBytes("010203"),
        gasLimit: 100_000n,
      };
    case "call-value-500":
      return {
        type: "call",
        contract: hexToBytes("33".repeat(32)),
        value: 500n,
        method: "transfer",
        args: hexToBytes("010203"),
        gasLimit: 100_000n,
      };
    default:
      throw new Error(name);
  }
}

describe("signature format v1", () => {
  it("reproduces the spec transfer, call, and valued-call vectors", async () => {
    const transfer = unsigned("transfer");
    expect(bytesToHex(signingHash(transfer, 2))).toBe(
      "4acde0e0a120d6c03eaa197c082238fefadaf36f4f40bc1364ae8b3faa067798",
    );
    const signed = await signTransaction(transfer, 2, seed);
    expect(bytesToHex(signed.signature)).toBe(
      "2413f8c3a1508e2b1b2809c5cc9cc74982118d47e8a8e9afaab2d2719349724265b8f80d67359b579001b9c4845723edb9530372a79da9f4093d2f7228820d0e",
    );

    const call = {
      sender,
      nonce: 6n,
      fee: 10n,
      kind: {
        type: "call" as const,
        contract: hexToBytes("33".repeat(32)),
        value: 0n,
        method: "transfer",
        args: hexToBytes("010203"),
        gasLimit: 100_000n,
      },
    };
    expect(bytesToHex(signingHash(call, 2))).toBe(
      "439e1830573896f46dc642cedb37605c1e478880f417f0cfae5126eaca48026a",
    );
    expect(bytesToHex((await signTransaction(call, 2, seed)).signature)).toBe(
      "0ff9438c1ea9e8a70e3b491d873c712e8e7d0339b637b00def16d42eea4eed3301454ef10f61b958bf37c95351a89f01270fe194ab8fa046b45373ee54e47f07",
    );

    const valued = {
      ...call,
      kind: { ...call.kind, value: 500n },
    };
    expect(bytesToHex(signingHash(valued, 2))).toBe(
      "9b76e7fc940641c6e11226b537841ace9ceb000a3943f6b3923b3cf2c6f4f794",
    );
    expect(bytesToHex((await signTransaction(valued, 2, seed)).signature)).toBe(
      "ce4e4d5dcc49159d2b6f72faa3210fe4db5b040e93eadbe315a159afe61f32ff66fc0abf9591c902500a1ce4e02d3816dbae80b8f1721725f03ed52b119f6608",
    );
  });

  it("matches the node bincode for every console transaction kind", async () => {
    for (const row of fixture.transactions) {
      const signed = await signTransaction(unsigned(row.name), fixture.chainId, seed);
      expect(bytesToHex(signed.hash), row.name).toBe(row.signingHash);
      expect(bytesToHex(signed.signature), row.name).toBe(row.signature);
      expect(encodeRawTransaction(signed), row.name).toBe(row.rawHex);
    }
  });
});

describe("addresses and amounts", () => {
  it("uses the checksum form the node prints", () => {
    expect(encodeAddress(sender)).toBe(fixture.senderAddress);
    expect(encodeAddress(recipient)).toBe(fixture.recipientAddress);
    expect(bytesToHex(decodeAddress(fixture.senderAddress))).toBe(fixture.publicKeyHex);
    expect(fixture.senderAddress.length).toBe(ADDRESS_LENGTH);
    expect(ADDRESS_LENGTH).toBe(64);
    const body = fixture.senderAddress.slice(0, -3);
    const flipped = body.slice(0, -1) + (body.endsWith("q") ? "p" : "q");
    expect(() => decodeAddress(`${flipped}dag`)).toThrow(/checksum/);
    expect(() => decodeAddress(`${body.slice(0, -1)}bdag`)).toThrow(/alphabet/);
    expect(() => decodeAddress(`${body.slice(0, -1)}dag`)).toThrow(/64 characters/);
    expect(() => decodeAddress(`kvnx${fixture.senderAddress.slice(4)}`)).toThrow(/start with kvnc/);
  });

  it("accepts legacy hex on dev chains and chain 4, and refuses it elsewhere (PRO-21)", () => {
    expect(encodeLegacyAddress(sender)).toBe(fixture.senderAddressLegacy);
    expect(encodeLegacyAddress(recipient)).toBe(fixture.recipientAddressLegacy);
    for (const legacy of [fixture.senderAddressLegacy, fixture.publicKeyHex, `0x${fixture.publicKeyHex}`]) {
      for (const chain of [3, 4, 1337]) {
        expect(bytesToHex(parseAddress(legacy, chain))).toBe(fixture.publicKeyHex);
      }
      expect(() => parseAddress(legacy)).toThrow(/chain id is omitted/);
      expect(() => parseAddress(legacy, 1)).toThrow(/not accepted on chain 1/);
      expect(() => parseAddress(legacy, 2)).toThrow(/not accepted on chain 2/);
      expect(() => parseAddress(legacy, 99)).toThrow(/not accepted on chain 99/);
    }
    for (const chain of [1, 2, 3, 4, 1337]) {
      expect(bytesToHex(parseAddress(fixture.senderAddress, chain))).toBe(fixture.publicKeyHex);
    }
  });

  it("treats legacy hex digits as case-insensitive and base32 as lowercase (PRO-21)", () => {
    const upperHex = fixture.publicKeyHex.toUpperCase();
    expect(bytesToHex(parseAddress(upperHex, 4))).toBe(fixture.publicKeyHex);
    expect(bytesToHex(parseAddress(`0x${upperHex}`, 1337))).toBe(fixture.publicKeyHex);
    const legacy = fixture.senderAddressLegacy;
    const upperLegacy = `kvnc${legacy.slice(4, -3).toUpperCase()}dag`;
    expect(bytesToHex(parseAddress(upperLegacy, 3))).toBe(fixture.publicKeyHex);
    expect(() => parseAddress(upperLegacy, 1)).toThrow(/not accepted/);
    const letter = [...fixture.senderAddress].findIndex(
      (c, i) => i > 3 && i < 61 && c >= "a" && c <= "z",
    );
    expect(letter).toBeGreaterThan(3);
    const upperBody =
      fixture.senderAddress.slice(0, letter) +
      fixture.senderAddress[letter].toUpperCase() +
      fixture.senderAddress.slice(letter + 1);
    expect(() => parseAddress(upperBody, 4)).toThrow(/alphabet/);
  });

  it("refuses an omitted chain id, 0X, and kvnc0x (PRO-21)", () => {
    expect(bytesToHex(parseAddress(fixture.senderAddress))).toBe(fixture.publicKeyHex);
    expect(bytesToHex(hexToBytes(`0x${fixture.publicKeyHex}`))).toBe(fixture.publicKeyHex);
    expect(() => hexToBytes(`0X${fixture.publicKeyHex}`)).toThrow(/invalid hex/);
    expect(() => parseAddress(`0X${fixture.publicKeyHex}`, 4)).toThrow(/invalid hex/);
    const body = fixture.senderAddressLegacy.slice(4, -3);
    expect(() => parseAddress(`kvnc0x${body}dag`, 4)).toThrow(/invalid hex/);
    expect(() => parseAddress(`kvnc0x${body}dag`, 1)).toThrow(/invalid hex/);
  });

  it("parses KUNA with 9 decimal places", () => {
    expect(parseKuna("1.5")).toBe(1_500_000_000n);
    expect(parseKuna("0")).toBe(0n);
    expect(parseKuna("50000")).toBe(50_000_000_000_000n);
    expect(formatKuna(1_500_000_000n)).toBe("1.5");
    expect(formatKuna(50_000_000_000_000n)).toBe("50000");
    expect(() => parseKuna("1.1234567891")).toThrow(/9 decimal/);
    expect(() => parseKuna("-1")).toThrow(/amount/);
    expect(() => parseKuna("1e2")).toThrow(/amount/);
  });

  it("round-trips the spec seed through the 24-word phrase", async () => {
    expect(seedToMnemonic(seed)).toBe(fixture.mnemonic);
    const key = await keyFromMnemonic(fixture.mnemonic);
    expect(bytesToHex(key.publicKey)).toBe(fixture.publicKeyHex);
    expect(key.address).toBe(fixture.senderAddress);
    await expect(keyFromMnemonic("abandon ".repeat(12).trim())).rejects.toThrow(/24/);
  });

  it("encodes call with exact wire bytes matching fixture", async () => {
    const call = {
      sender,
      nonce: 6n,
      fee: 10n,
      kind: {
        type: "call" as const,
        contract: hexToBytes("33".repeat(32)),
        value: 0n,
        method: "transfer",
        args: hexToBytes("010203"),
        gasLimit: 100_000n,
      },
    };
    const signed = await signTransaction(call, 2, seed);
    const encoded = encodeRawTransaction(signed);
    expect(encoded).toBe(fixture.transactions.find((r) => r.name === "call-value-zero")?.rawHex);
  });

  it("rawTransactionSize equals encoded length / 2 for call", async () => {
    const tx = {
      sender,
      nonce: 1n,
      fee: 123n,
      kind: {
        type: "call" as const,
        contract: hexToBytes("44".repeat(32)),
        value: 5n,
        method: "fn",
        args: new Uint8Array([9, 8, 7, 6, 5]),
        gasLimit: 1_000_000n,
      },
    };
    const signed = await signTransaction(tx, 2, seed);
    const hex = encodeRawTransaction(signed);
    const size = rawTransactionSize(tx);
    expect(size).toBe(hex.length / 2);
    expect(size).toBeGreaterThan(0);
  });

  it("rejects call with empty method and invalid contract/value/gas", () => {
    const base = {
      sender,
      nonce: 1n,
      fee: 1n,
      kind: {
        type: "call" as const,
        contract: hexToBytes("44".repeat(32)),
        value: 0n,
        method: "x",
        args: new Uint8Array(),
        gasLimit: 100n,
      },
    };
    expect(() => rawTransactionSize({ ...base, kind: { ...base.kind, method: "" } as any })).toThrow(/method/);
    expect(() => rawTransactionSize({ ...base, kind: { ...base.kind, contract: new Uint8Array(31) } as any })).toThrow(/contract/);
    expect(() => rawTransactionSize({ ...base, kind: { ...base.kind, contract: new Uint8Array(33) } as any })).toThrow(/contract/);
  });
});
