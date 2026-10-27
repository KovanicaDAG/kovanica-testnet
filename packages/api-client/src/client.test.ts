import { afterEach, describe, expect, it, vi } from "vitest";

import { KovanicaRpcClient, subscriptionHead } from "./index.js";

afterEach(() => {
  vi.unstubAllGlobals();
});

function jsonResponse(result: unknown, status = 200): Response {
  return new Response(JSON.stringify({ jsonrpc: "2.0", id: 1, result }), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

describe("KovanicaRpcClient", () => {
  it("parses quantities and posts to /rpc", async () => {
    const bodies: unknown[] = [];
    vi.stubGlobal(
      "fetch",
      vi.fn(async (_url: string, init: RequestInit) => {
        bodies.push(JSON.parse(String(init.body)));
        return jsonResponse("0x2a");
      }),
    );
    const client = new KovanicaRpcClient("http://127.0.0.1:8545/rpc");
    await expect(client.getNonce("kvnctestdag")).resolves.toBe(42n);
    await expect(client.getStake("kvnctestdag")).resolves.toBe(42n);
    await expect(client.estimateFee()).resolves.toBe(42n);
    expect(bodies[0]).toMatchObject({ method: "kovanica_getNonce", params: ["kvnctestdag"] });
  });

  it("returns null when a receipt is not in a block yet", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => jsonResponse(null)),
    );
    const client = new KovanicaRpcClient("http://127.0.0.1:8545");
    await expect(client.getTransactionReceipt("abc")).resolves.toBeNull();
  });

  it("reads peer count from /health beside the rpc path", async () => {
    const urls: string[] = [];
    vi.stubGlobal(
      "fetch",
      vi.fn(async (url: string) => {
        urls.push(url);
        return new Response(JSON.stringify({ status: "ok", peer_count: 4 }), { status: 200 });
      }),
    );
    const client = new KovanicaRpcClient("https://rpc-testnet.kovanica.online/rpc");
    await expect(client.health()).resolves.toEqual({ status: "ok", peerCount: 4 });
    expect(urls[0]).toBe("https://rpc-testnet.kovanica.online/health");
  });

  it("surfaces an RPC error message", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () =>
        new Response(JSON.stringify({ jsonrpc: "2.0", id: 1, error: { message: "nope" } }), {
          status: 200,
        }),
      ),
    );
    const client = new KovanicaRpcClient("http://127.0.0.1:8545/rpc");
    await expect(client.blockNumber()).rejects.toThrow("nope");
  });
});

describe("subscriptionHead", () => {
  it("returns the head payload and ignores other frames", () => {
    expect(
      subscriptionHead({
        jsonrpc: "2.0",
        method: "kovanica_subscription",
        params: { subscription: "0x1", result: { round: "0x3" } },
      }),
    ).toEqual({ round: "0x3" });
    expect(subscriptionHead({ jsonrpc: "2.0", id: 1, result: "0x1" })).toBeNull();
  });
});
