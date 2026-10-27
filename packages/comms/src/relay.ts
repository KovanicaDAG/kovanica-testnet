/**
 * Relay HTTP client (v1) — `docs/COMMS-M1-INTERFACES.md` §4.
 *
 * Base path `/v1`, JSON in / JSON out. This client only speaks the blind
 * relay contract: it never inspects or needs plaintext. Errors are
 * `{"error":{"code":"<slug>","message":"..."}}` with slugs `bad_request`,
 * `too_large`, `not_found`, `rate_limited`, `internal`.
 *
 * The transport is injectable so tests can stub `fetch` (no live server).
 */

import {
  type Envelope,
  type EnvelopeJson,
  envelopeFromJSON,
  envelopeToJSON,
} from "./envelope.js";

/** PoW proof for wrapper submission. */
export interface PowProof {
  nonce: string;
  bits: number;
}

/** Payment proof for wrapper submission. */
export interface PaymentProof {
  htlcId: string;
  preimage: string;
  amountAtoms: bigint | number;
  expiry: bigint | number;
  senderAddr?: string;
  claimerAddr: string;
}

export interface SubmissionWrapper {
  envelope: EnvelopeJson;
  pow?: PowProof;
  payment?: PaymentProof;
}

/** Error slugs returned by the relay (§4). */
export type RelayErrorCode = "bad_request" | "too_large" | "not_found" | "rate_limited" | "internal";

const RELAY_ERROR_CODES: readonly string[] = [
  "bad_request",
  "too_large",
  "not_found",
  "rate_limited",
  "internal",
];

/** Thrown for any non-2xx relay response. */
export class RelayClientError extends Error {
  constructor(
    public readonly status: number,
    public readonly code: string,
    message: string,
  ) {
    super(message);
    this.name = "RelayClientError";
  }
}

/** `GET /v1/health` body. */
export interface RelayHealth {
  ok: boolean;
  version: string;
  envelopes: number;
}

/** `POST /v1/envelope` success body. */
export interface PostEnvelopeResult {
  ok: boolean;
  id: string;
  status: number;
}

/** `POST /v1/ack` success body. */
export interface AckResult {
  ok: boolean;
  deleted: number;
}

/** Options for {@link RelayClient.getInbox}. */
export interface InboxOptions {
  /** Max envelopes, clamped to `[1, 200]`. Default 50. */
  limit?: number;
  /** Only envelopes with `sentAt >= since` (ms). */
  since?: number;
}

/** Default inbox page size (§4). */
export const DEFAULT_INBOX_LIMIT = 50;

/** Hard maximum inbox page size (§4). */
export const MAX_INBOX_LIMIT = 200;

const HEX64 = /^[0-9a-f]{64}$/;

type FetchLike = (input: string, init?: RequestInit) => Promise<Response>;

interface RelayErrorBody {
  error?: { code?: unknown; message?: unknown };
}

function clampLimit(limit: number | undefined): number {
  if (limit === undefined) return DEFAULT_INBOX_LIMIT;
  if (!Number.isFinite(limit)) return DEFAULT_INBOX_LIMIT;
  const truncated = Math.trunc(limit);
  if (truncated < 1) return 1;
  if (truncated > MAX_INBOX_LIMIT) return MAX_INBOX_LIMIT;
  return truncated;
}

/** JSON fetch client for one relay base URL (e.g. `https://relay.example`). */
export class RelayClient {
  private readonly baseUrl: string;
  private readonly fetchImpl: FetchLike;

  /**
   * @param baseUrl Relay origin; a trailing slash is tolerated.
   * @param fetchImpl Transport override (defaults to global `fetch`).
   */
  constructor(baseUrl: string, fetchImpl?: FetchLike) {
    if (typeof baseUrl !== "string" || baseUrl.length === 0) {
      throw new Error("relay base URL is required");
    }
    this.baseUrl = baseUrl.replace(/\/+$/, "");
    this.fetchImpl = fetchImpl ?? ((input, init) => fetch(input, init));
  }

  private url(path: string): string {
    return `${this.baseUrl}/v1${path}`;
  }

  private async send(
    method: string,
    path: string,
    body?: unknown,
  ): Promise<{ status: number; json: unknown }> {
    const init: RequestInit = { method, headers: { Accept: "application/json" } };
    if (body !== undefined) {
      init.headers = { ...(init.headers as Record<string, string>), "Content-Type": "application/json" };
      init.body = JSON.stringify(body);
    }
    const res = await this.fetchImpl(this.url(path), init);
    let json: unknown = null;
    const text = await res.text();
    if (text.length > 0) {
      try {
        json = JSON.parse(text);
      } catch {
        json = null;
      }
    }
    if (!res.ok) {
      const errorBody = (json ?? {}) as RelayErrorBody;
      const rawCode = errorBody.error?.code;
      const code = typeof rawCode === "string" && RELAY_ERROR_CODES.includes(rawCode)
        ? rawCode
        : "internal";
      const rawMessage = errorBody.error?.message;
      const message = typeof rawMessage === "string" ? rawMessage : `relay HTTP ${res.status}`;
      throw new RelayClientError(res.status, code, message);
    }
    return { status: res.status, json };
  }

  /**
   * `POST /v1/envelope` — submit one envelope. Accepts either the byte form
   * or the wire JSON. Idempotent: re-POSTing the same envelope is `200`/`201`.
   */
  async postEnvelope(
    envelope: Envelope | EnvelopeJson,
    options?: { pow?: PowProof; payment?: PaymentProof },
  ): Promise<PostEnvelopeResult> {
    const envJson = "sig" in envelope && envelope.sig instanceof Uint8Array
      ? envelopeToJSON(envelope as Envelope)
      : (envelope as EnvelopeJson);
    const body = options && (options.pow || options.payment)
      ? ({ envelope: envJson, pow: options.pow, payment: options.payment } as SubmissionWrapper)
      : envJson;
    const { status, json } = await this.send("POST", "/envelope", body);
    const record = (json ?? {}) as { ok?: unknown; id?: unknown };
    const id = typeof record.id === "string" ? record.id : envJson.id;
    return { ok: record.ok !== false, id, status };
  }

  /**
   * `GET /v1/inbox/{comms_id}` — undelivered envelopes in relay arrival order
   * (oldest first).
   *
   * Per spec §9.7.2 a malformed `comms_id` is `400 bad_request` (we validate
   * locally before any request), a well-formed but unknown recipient is
   * `200 {"envelopes":[]}`, and `404` is unused in M1.
   */
  async getInbox(commsId: string, options: InboxOptions = {}): Promise<Envelope[]> {
    if (!HEX64.test(commsId)) {
      throw new RelayClientError(400, "bad_request", "comms_id must be 64 lowercase hex characters");
    }
    const params = new URLSearchParams();
    params.set("limit", String(clampLimit(options.limit)));
    if (options.since !== undefined) {
      if (!Number.isSafeInteger(options.since) || options.since < 0) {
        throw new RelayClientError(400, "bad_request", "since must be a non-negative integer");
      }
      params.set("since", String(options.since));
    }
    const result = await this.send("GET", `/inbox/${commsId}?${params.toString()}`);
    const record = (result.json ?? {}) as { envelopes?: unknown };
    if (!Array.isArray(record.envelopes)) {
      throw new RelayClientError(result.status, "internal", "relay inbox response missing envelopes");
    }
    return record.envelopes.map((entry) => envelopeFromJSON(entry));
  }

  /** `POST /v1/ack` — delete delivered envelopes for a recipient by id. */
  async ack(to: string, ids: readonly string[]): Promise<AckResult> {
    if (!HEX64.test(to)) {
      throw new RelayClientError(400, "bad_request", "to must be 64 lowercase hex characters");
    }
    const { json } = await this.send("POST", "/ack", { to, ids: [...ids] });
    const record = (json ?? {}) as { ok?: unknown; deleted?: unknown };
    const deleted = typeof record.deleted === "number" ? record.deleted : 0;
    return { ok: record.ok !== false, deleted };
  }

  /** `GET /v1/health`. */
  async health(): Promise<RelayHealth> {
    const { json } = await this.send("GET", "/health");
    const record = (json ?? {}) as { ok?: unknown; version?: unknown; envelopes?: unknown };
    return {
      ok: record.ok !== false,
      version: typeof record.version === "string" ? record.version : "",
      envelopes: typeof record.envelopes === "number" ? record.envelopes : 0,
    };
  }
}
