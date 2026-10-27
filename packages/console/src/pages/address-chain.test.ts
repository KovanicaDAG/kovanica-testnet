import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { bytesToHex } from "@kovanica/signer";
import { describe, expect, it } from "vitest";

import { buildKind } from "./Stake";
import { transferRecipient } from "./Transfer";

const fixture = JSON.parse(
  readFileSync(
    join(dirname(fileURLToPath(import.meta.url)), "../../../signer/fixtures/wire.json"),
    "utf8",
  ),
) as {
  recipientAddress: string;
  recipientAddressLegacy: string;
  senderAddress: string;
  senderAddressLegacy: string;
};

const recipientKey = "22".repeat(32);

describe("console addresses follow the chain", () => {
  it("accepts the wire.json canonical recipient on every chain", () => {
    for (const chainId of [1, 2, 3, 4, 1337, 0, 42]) {
      expect(bytesToHex(transferRecipient(fixture.recipientAddress, chainId))).toBe(recipientKey);
    }
  });

  it("accepts the wire.json legacy recipient only on chains 3, 4, and 1337", () => {
    for (const chainId of [3, 4, 1337]) {
      expect(bytesToHex(transferRecipient(fixture.recipientAddressLegacy, chainId))).toBe(
        recipientKey,
      );
    }
    for (const chainId of [1, 2, 0, 42]) {
      expect(() => transferRecipient(fixture.recipientAddressLegacy, chainId)).toThrow(
        /legacy hex addresses are not accepted/,
      );
    }
  });

  it("builds stake kinds with the same chain policy", () => {
    expect(buildKind("stake", "1", "not-an-address", 2)).toEqual({
      type: "stake",
      amount: 1_000_000_000n,
    });
    expect(buildKind("claim", "", "", 2)).toEqual({ type: "claimRewards", validator: null });

    const delegated = buildKind("delegate", "1", fixture.recipientAddress, 2);
    expect(delegated).toEqual({
      type: "delegate",
      validator: expect.any(Uint8Array),
      amount: 1_000_000_000n,
    });
    if (delegated.type === "delegate") {
      expect(bytesToHex(delegated.validator)).toBe(recipientKey);
    }

    expect(() => buildKind("delegate", "1", fixture.recipientAddressLegacy, 2)).toThrow(
      /legacy hex addresses are not accepted/,
    );
    const legacyDelegate = buildKind("delegate", "1", fixture.recipientAddressLegacy, 4);
    if (legacyDelegate.type === "delegate") {
      expect(bytesToHex(legacyDelegate.validator)).toBe(recipientKey);
    }

    expect(() => buildKind("claim", "", fixture.senderAddressLegacy, 1)).toThrow(
      /legacy hex addresses are not accepted/,
    );
    const claimed = buildKind("claim", "", fixture.senderAddress, 1);
    expect(claimed.type).toBe("claimRewards");
    if (claimed.type === "claimRewards" && claimed.validator) {
      expect(bytesToHex(claimed.validator)).toBe(
        "ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c",
      );
    }
  });
});
