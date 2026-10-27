import { getPublicKey } from "@noble/ed25519";
import { describe, expect, it } from "vitest";

import {
  type Envelope,
  envelopeToJSON,
  signEnvelope,
} from "./envelope.js";
import { deriveCommsId } from "./identity.js";
import { ALG_V1, e2eAad, encodePayload, sealTo } from "./messaging.js";
import {
  DEFAULT_INBOX_LIMIT,
  MAX_INBOX_LIMIT,
  RelayClient,
  RelayClientError,
} from "./relay.js";

const SENDER_KEY = new Uint8Array(32).fill(1);
const RECIPIENT_KEY = new Uint8Array(32).fill(2);
const SENDER_PUB = getPublicKey(SENDER_KEY);
const RECIPIENT_PUB = getPublicKey(RECIPIENT_KEY);
const TO_COMMS_ID = deriveCommsId(RECIPIENT_PUB);
const FROM_COMMS_ID = deriveCommsId(SENDER_PUB);

interface Call {
  url: string;
  init: RequestInit;
}

function fakeFetch(handler: (call: Call) => Response): {
  fn: typeof fetch;
  calls: Call[];
} {
  const calls: Call[] = [];
  const fn = (input: string, init?: RequestInit): Promise<Response> => {
    const call: Call = { url: input, init: init ?? {} };
    calls.push(call);
    return Promise.resolve(handler(call));
  };
  return { fn: fn as unknown as typeof fetch, calls };
}

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
}

function sampleEnvelope(): Envelope {
  const plaintext = encodePayload({ kind: "text", body: "hi", ts: 42 });
  const aad = e2eAad(hexToBytes(TO_COMMS_ID), hexToBytes(FROM_COMMS_ID));
  const sealed = sealTo(RECIPIENT_PUB, plaintext, aad);
  return signEnvelope(
    {
      to: TO_COMMS_ID,
      from: FROM_COMMS_ID,
      sentAt: 42,
      expiresAt: 99,
      alg: ALG_V1,
      epk: sealed.epk,
      nonce: sealed.nonce,
      ct: sealed.ct,
    },
    SENDER_KEY,
  );
}

function hexToBytes(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i += 1) {
    out[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

describe("relay — POST /v1/envelope (§4)", () => {
  it("posts the wire JSON and returns the id", async () => {
    const envelope = sampleEnvelope();
    const { fn, calls } = fakeFetch(() => jsonResponse({ ok: true, id: envelope.id }, 201));
    const client = new RelayClient("https://relay.example", fn);

    const result = await client.postEnvelope(envelope);
    expect(result).toEqual({ ok: true, id: envelope.id, status: 201 });
    expect(calls).toHaveLength(1);
    expect(calls[0].url).toBe("https://relay.example/v1/envelope");
    expect(calls[0].init.method).toBe("POST");
    expect(JSON.parse(String(calls[0].init.body))).toEqual(envelopeToJSON(envelope));
  });

  it("also accepts a pre-serialized envelope JSON", async () => {
    const envelope = sampleEnvelope();
    const json = envelopeToJSON(envelope);
    const { fn } = fakeFetch(() => jsonResponse({ ok: true, id: envelope.id }, 200));
    const client = new RelayClient("https://relay.example/", fn);
    const result = await client.postEnvelope(json);
    expect(result.status).toBe(200);
    expect(result.id).toBe(envelope.id);
  });
});

describe("relay — GET /v1/inbox (§4)", () => {
  it("parses undelivered envelopes and sends limit/since", async () => {
    const envelope = sampleEnvelope();
    const { fn, calls } = fakeFetch(() => jsonResponse({ envelopes: [envelopeToJSON(envelope)] }));
    const client = new RelayClient("https://relay.example", fn);

    const inbox = await client.getInbox(TO_COMMS_ID, { limit: 25, since: 10 });
    expect(inbox).toHaveLength(1);
    expect(inbox[0]).toEqual(envelope);
    expect(calls[0].url).toBe(`${"https://relay.example"}/v1/inbox/${TO_COMMS_ID}?limit=25&since=10`);
    expect(calls[0].init.method).toBe("GET");
  });

  it("clamps limit to [1, 200] and defaults to 50", async () => {
    const high = fakeFetch(() => jsonResponse({ envelopes: [] }));
    await new RelayClient("https://relay.example", high.fn).getInbox(TO_COMMS_ID, { limit: 9999 });
    expect(high.calls[0].url).toContain(`limit=${MAX_INBOX_LIMIT}`);

    const low = fakeFetch(() => jsonResponse({ envelopes: [] }));
    await new RelayClient("https://relay.example", low.fn).getInbox(TO_COMMS_ID, { limit: 0 });
    expect(low.calls[0].url).toContain("limit=1");

    const dflt = fakeFetch(() => jsonResponse({ envelopes: [] }));
    await new RelayClient("https://relay.example", dflt.fn).getInbox(TO_COMMS_ID);
    expect(dflt.calls[0].url).toContain(`limit=${DEFAULT_INBOX_LIMIT}`);
  });

  it("returns 200 [] for a well-formed but unknown recipient", async () => {
    const { fn } = fakeFetch(() => jsonResponse({ envelopes: [] }));
    const inbox = await new RelayClient("https://relay.example", fn).getInbox(TO_COMMS_ID);
    expect(inbox).toEqual([]);
  });

  it("propagates 404 (unused in M1, §9.7.2) as an error", async () => {
    const { fn } = fakeFetch(() =>
      jsonResponse({ error: { code: "not_found", message: "nope" } }, 404),
    );
    await expect(
      new RelayClient("https://relay.example", fn).getInbox(TO_COMMS_ID),
    ).rejects.toBeInstanceOf(RelayClientError);
  });

  it("validates the comms id before calling fetch", async () => {
    const { fn, calls } = fakeFetch(() => jsonResponse({ envelopes: [] }));
    const client = new RelayClient("https://relay.example", fn);
    await expect(client.getInbox("not-a-comms-id")).rejects.toBeInstanceOf(RelayClientError);
    expect(calls).toHaveLength(0);
  });
});

describe("relay — POST /v1/ack (§4)", () => {
  it("posts to/ids and returns the deletion count", async () => {
    const { fn, calls } = fakeFetch(() => jsonResponse({ ok: true, deleted: 2 }));
    const client = new RelayClient("https://relay.example", fn);
    const result = await client.ack(TO_COMMS_ID, ["aa", "bb"]);
    expect(result).toEqual({ ok: true, deleted: 2 });
    expect(calls[0].url).toBe("https://relay.example/v1/ack");
    expect(JSON.parse(String(calls[0].init.body))).toEqual({ to: TO_COMMS_ID, ids: ["aa", "bb"] });
  });
});

describe("relay — GET /v1/health (§4)", () => {
  it("returns the health body", async () => {
    const { fn, calls } = fakeFetch(() =>
      jsonResponse({ ok: true, version: "1.2.3", envelopes: 7 }),
    );
    const health = await new RelayClient("https://relay.example", fn).health();
    expect(health).toEqual({ ok: true, version: "1.2.3", envelopes: 7 });
    expect(calls[0].url).toBe("https://relay.example/v1/health");
  });
});

describe("relay — error handling (§4)", () => {
  it("maps relay error slugs to RelayClientError", async () => {
    const { fn } = fakeFetch(() =>
      jsonResponse({ error: { code: "rate_limited", message: "slow down" } }, 429),
    );
    const client = new RelayClient("https://relay.example", fn);
    await expect(client.health()).rejects.toMatchObject({
      name: "RelayClientError",
      status: 429,
      code: "rate_limited",
      message: "slow down",
    });
  });

  it("falls back to internal for an unknown slug or non-JSON body", async () => {
    const unknown = fakeFetch(() =>
      jsonResponse({ error: { code: "teapot", message: "?" } }, 400),
    );
    await expect(new RelayClient("https://relay.example", unknown.fn).health()).rejects.toMatchObject(
      { status: 400, code: "internal" },
    );

    const nonJson = fakeFetch(() => new Response("<html>oops</html>", { status: 500 }));
    await expect(new RelayClient("https://relay.example", nonJson.fn).health()).rejects.toMatchObject(
      { status: 500, code: "internal" },
    );
  });

  it("rejects an empty base URL", () => {
    expect(() => new RelayClient("")).toThrow();
  });
});
