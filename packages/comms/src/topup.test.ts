import { getPublicKey } from "@noble/ed25519";
import { bytesToHex } from "@kovanica/signer";
import { describe, expect, it } from "vitest";

import { bytesToBase64, computeHtlcHashLock } from "./payments.js";
import {
  TopupClient,
  TopupClientError,
  validateQuote,
  verifyHashLock,
  type TopupQuote,
} from "./topup.js";
import { HttpTopupProvider, signWebhook } from "./topup/provider.js";
import { MockTopupProvider } from "./topup/mock.js";

const SEED = new Uint8Array(32).fill(9);
const PUB = await getPublicKey(SEED);
const SIGNER = { publicKey: bytesToHex(PUB), seed: bytesToHex(SEED) };
const CLAIMER = "ab".repeat(32);
const NOW = 1_000_000;

function fakeClock(): { now: () => number; set: (t: number) => void } {
  let t = NOW;
  return { now: () => t, set: (v) => (t = v) };
}

function fakeRpc(): {
  raw: string[];
  getNonce(address: string): Promise<bigint>;
  sendRawTransaction(rawHex: string): Promise<string>;
} {
  const raw: string[] = [];
  return {
    raw,
    getNonce: async () => 1n,
    sendRawTransaction: async (rawHex: string) => {
      raw.push(rawHex);
      return `tx-${raw.length}`;
    },
  };
}

function jsonResponse(body: unknown, status = 200, headers: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json", ...headers },
  });
}

function quoteWire(over: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    quoteId: "q1",
    providerId: "p1",
    sku: "s",
    currency: "KUNA",
    amountAtoms: "5000000000",
    claimerAddr: CLAIMER,
    htlcExpiryMs: "4600000",
    quoteExpiresAt: 1_600_000,
    issuedAt: NOW,
    ...over,
  };
}

function clientWith(
  provider: MockTopupProvider,
  rpc = fakeRpc(),
  opts: Partial<ConstructorParameters<typeof TopupClient>[0]> = {},
): { client: TopupClient; rpc: ReturnType<typeof fakeRpc> } {
  const clock = fakeClock();
  const client = new TopupClient({
    provider,
    rpc,
    signerKey: SIGNER,
    chainId: 1,
    clock: clock.now,
    feeAtoms: 1000n,
    ...opts,
  });
  return { client, rpc };
}

describe("topup — happy path", () => {
  it("quote → purchase (HTLC funded) → provisioned → fulfill → settled", async () => {
    const mock = new MockTopupProvider({ now: fakeClock().now, claimerAddr: CLAIMER });
    const { client, rpc } = clientWith(mock);

    const order = await client.purchase("esim-1gb");
    expect(order.status).toBe("provisioned");
    expect(order.activationCode).toBe("ACTIVATION-CODE");
    expect(rpc.raw).toHaveLength(1);

    const settled = await client.fulfill(order.orderId);
    expect(settled.status).toBe("settled");
    expect((await client.status(order.orderId)).status).toBe("settled");
  });
});

describe("topup — idempotency", () => {
  it("repeat purchase reuses the order and never double-funds", async () => {
    const mock = new MockTopupProvider({ now: fakeClock().now, claimerAddr: CLAIMER });
    const { client, rpc } = clientWith(mock);

    const a = await client.purchase("sku");
    const b = await client.purchase("sku");
    expect(b.orderId).toBe(a.orderId);
    expect(rpc.raw).toHaveLength(1);

    const proof = {
      htlcId: a.htlcId ?? "0".repeat(64),
      txId: a.fundingTxId ?? "tx",
      senderAddr: a.senderAddr ?? "0".repeat(64),
      hashLock: "0".repeat(64),
    };
    const o1 = await mock.notifyFunded(a.orderId, proof);
    const o2 = await mock.notifyFunded(a.orderId, proof);
    expect(o2.orderId).toBe(a.orderId);
    expect(o2.htlcId).toBe(o1.htlcId);
    expect(rpc.raw).toHaveLength(1);
  });
});

describe("topup — retry / backoff (HTTP provider)", () => {
  it("retries 5xx with backoff, then succeeds", async () => {
    let calls = 0;
    const sleeps: number[] = [];
    const provider = new HttpTopupProvider({
      baseUrl: "https://topup.example",
      providerId: "p1",
      fetchImpl: async () => {
        calls += 1;
        return calls === 1
          ? jsonResponse({ error: { code: "provider_unavailable", message: "x" } }, 503)
          : jsonResponse(quoteWire());
      },
      sleep: async (ms) => void sleeps.push(ms),
      retry: { retries: 2, baseDelayMs: 10, maxDelayMs: 100 },
    });
    const quote = await provider.quote({ sku: "s" });
    expect(calls).toBe(2);
    expect(sleeps).toEqual([10]);
    expect(quote.amountAtoms).toBe(5_000_000_000n);
  });

  it("does not retry a 400", async () => {
    let calls = 0;
    const provider = new HttpTopupProvider({
      baseUrl: "https://topup.example",
      providerId: "p1",
      fetchImpl: async () => {
        calls += 1;
        return jsonResponse({ error: { code: "bad_request", message: "nope" } }, 400);
      },
      sleep: async () => {},
      retry: { retries: 3 },
    });
    await expect(provider.quote({ sku: "s" })).rejects.toMatchObject({
      status: 400,
      code: "bad_request",
      message: "nope",
    });
    expect(calls).toBe(1);
  });

  it("honors Retry-After on 429", async () => {
    let calls = 0;
    const sleeps: number[] = [];
    const provider = new HttpTopupProvider({
      baseUrl: "https://topup.example",
      providerId: "p1",
      fetchImpl: async () => {
        calls += 1;
        return calls === 1
          ? jsonResponse({ error: { code: "rate_limited", message: "slow" } }, 429, {
              "retry-after": "1",
            })
          : jsonResponse(quoteWire());
      },
      sleep: async (ms) => void sleeps.push(ms),
      retry: { retries: 2 },
    });
    await provider.quote({ sku: "s" });
    expect(sleeps).toEqual([1000]);
  });
});

describe("topup — timeout", () => {
  it("aborts deterministically on timeout", async () => {
    const provider = new HttpTopupProvider({
      baseUrl: "https://topup.example",
      providerId: "p1",
      retry: { retries: 0 },
      fetchImpl: (_url, init) =>
        new Promise<Response>((_resolve, reject) => {
          init?.signal?.addEventListener("abort", () => {
            const err = new Error("aborted");
            err.name = "AbortError";
            reject(err);
          });
        }),
    });
    const err = await provider.quote({ sku: "s" }, { timeoutMs: 5 }).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(TopupClientError);
    expect(String((err as Error).message)).toMatch(/timed out/i);
  });
});

describe("topup — race after funding", () => {
  it("marks the order refundable and does not re-fund on provider timeout", async () => {
    const mock = new MockTopupProvider({ now: fakeClock().now, claimerAddr: CLAIMER });
    mock.failNext("notifyFunded", { kind: "timeout" });
    const { client, rpc } = clientWith(mock);

    const order = await client.purchase("esim");
    expect(order.status).toBe("refundable");
    expect(order.fundingTxId).toBeTruthy();
    expect(rpc.raw).toHaveLength(1);

    const again = await client.purchase("esim");
    expect(again.status).toBe("refundable");
    expect(rpc.raw).toHaveLength(1);
  });
});

describe("topup — webhook", () => {
  it("accepts a valid HMAC, rejects bad/unsigned, tolerates replay", () => {
    const secret = "s3cret";
    const provider = new HttpTopupProvider({
      baseUrl: "https://topup.example",
      providerId: "p1",
      webhookSecret: () => secret,
    });
    const body = JSON.stringify({ orderId: "o1", status: "provisioned", ts: 5 });
    const headers = { "x-kovanica-signature": signWebhook(secret, body) };

    expect(provider.verifyWebhook(headers, body)).toEqual({
      orderId: "o1",
      status: "provisioned",
      ts: 5,
    });
    expect(provider.verifyWebhook({ "x-kovanica-signature": "sha256=00" }, body)).toBeNull();
    expect(provider.verifyWebhook({}, body)).toBeNull();
    // Replay is idempotent (stateless verification).
    expect(provider.verifyWebhook(headers, body)).toEqual({
      orderId: "o1",
      status: "provisioned",
      ts: 5,
    });
  });
});

describe("topup — quote rejections", () => {
  const policy = { maxAtoms: 10_000n, minExpiryMarginMs: 120_000 };
  const base: TopupQuote = {
    quoteId: "q",
    providerId: "p",
    sku: "s",
    currency: "KUNA",
    amountAtoms: 1000n,
    claimerAddr: CLAIMER,
    htlcExpiryMs: BigInt(NOW + 3_600_000),
    quoteExpiresAt: NOW + 600_000,
    issuedAt: NOW,
  };

  it("rejects malformed quotes", () => {
    expect(() => validateQuote({ ...base, currency: "USD" as unknown as "KUNA" }, NOW, policy)).toThrow(/currency/);
    expect(() => validateQuote({ ...base, amountAtoms: 0n }, NOW, policy)).toThrow(/positive/);
    expect(() => validateQuote({ ...base, amountAtoms: 20_000n }, NOW, policy)).toThrow(/limit/);
    expect(() => validateQuote({ ...base, quoteExpiresAt: NOW - 1 }, NOW, policy)).toThrow(/expired/);
    expect(() => validateQuote({ ...base, htlcExpiryMs: BigInt(NOW) }, NOW, policy)).toThrow(/too short/);
    expect(() => validateQuote({ ...base, claimerAddr: "xyz" }, NOW, policy)).toThrow(/malformed/);
  });

  it("rejects a hash lock that does not match the client preimage", () => {
    const preimage = new Uint8Array(32).fill(7);
    expect(() => verifyHashLock(preimage, "00".repeat(32))).toThrow(/hash lock/);
    expect(() => verifyHashLock(preimage, bytesToHex(computeHtlcHashLock(preimage)))).not.toThrow();
  });

  it("rejects an oversized quote at the client boundary before funding", async () => {
    const mock = new MockTopupProvider({ now: fakeClock().now, claimerAddr: CLAIMER });
    const { client, rpc } = clientWith(mock, fakeRpc(), { policy: { maxAtoms: 1n } });
    await expect(client.purchase("esim")).rejects.toMatchObject({ code: "bad_request" });
    expect(rpc.raw).toHaveLength(0);
  });
});

describe("topup — redaction", () => {
  it("never leaks the preimage or activation code in thrown messages", async () => {
    const preimage = new Uint8Array(32).fill(7);
    const secretB64 = bytesToBase64(preimage);
    const secretHex = bytesToHex(preimage);
    const err = (() => {
      try {
        verifyHashLock(preimage, "00".repeat(32));
      } catch (e) {
        return e as Error;
      }
      return null;
    })();
    expect(err).toBeInstanceOf(TopupClientError);
    expect(err?.message).not.toContain(secretB64);
    expect(err?.message).not.toContain(secretHex);

    const mock = new MockTopupProvider({ now: fakeClock().now, claimerAddr: CLAIMER });
    const { client } = clientWith(mock);
    const order = await client.purchase("esim");
    expect(Object.keys(order)).not.toContain("preimage");
    expect(order.activationCode).toBeTruthy();
  });
});
