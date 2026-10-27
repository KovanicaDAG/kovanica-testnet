import { describe, expect, it } from "vitest";

import {
  MAINNET,
  TESTNET,
  networksFor,
  rejectionMessage,
  resolveNetwork,
} from "./network";

describe("network selection", () => {
  const networks = networksFor(true);

  it("ships testnet as the only sendable network in production", () => {
    expect(networks.map((network) => network.id)).toEqual(["testnet", "mainnet"]);
    expect(networks.find((network) => network.id === "local")).toBeUndefined();
    expect(TESTNET.enabled).toBe(true);
    expect(TESTNET.chainId).toBe(4);
    expect(MAINNET.enabled).toBe(false);
    expect(MAINNET.chainId).toBe(1);
    expect(MAINNET.faucetUrl).toBeNull();
    expect(TESTNET.rpcUrl).toBe("https://rpc-testnet.kovanica.online/rpc");
  });

  it("ignores mainnet from the query string and from storage", () => {
    expect(resolveNetwork("mainnet", "mainnet", networks).id).toBe("testnet");
    expect(resolveNetwork("mainnet", "mainnet", networks).chainId).toBe(4);
    expect(rejectionMessage("mainnet", networks)).toMatch(/not open yet/i);
    expect(rejectionMessage("testnet", networks)).toBeNull();
  });

  it("keeps a stored testnet choice", () => {
    expect(resolveNetwork(null, "testnet", networks).id).toBe("testnet");
  });
});
