/**
 * Top-up provider adapters (M7) — **client-only / external**.
 *
 * The HTTP boundary is off-chain (`/v1`). Base URL and bearer token are
 * runtime-injected; amounts/expiries are decimal strings on the wire
 * (bigint-safe). Native KUNA only.
 *
 *   POST /v1/quote                 { sku }            -> TopupQuote
 *   POST /v1/orders                { quoteId, sku }   -> TopupOrder
 *   GET  /v1/orders/{id}                              -> TopupOrder
 *   POST /v1/orders/{id}/funded    FundingProof       -> TopupOrder
 *   POST /v1/orders/{id}/reveal    RevealProof        -> TopupOrder
 *   POST /v1/orders/{id}/cancel                       -> TopupOrder
 *   Error body: { error: { code, message } }
 *
 * Retry only network errors / 5xx / 429 (honoring `Retry-After`); never 4xx.
 * Secrets come from injected callbacks — no literals, no `process.env` reads.
 */

import { bytesToHex } from "@kovanica/signer";
import { hmac } from "@noble/hashes/hmac";
import { sha256 } from "@noble/hashes/sha256";

import {
  isTopupErrorCode,
  type CreateOrderRequest,
  type FundingProof,
  type QuoteRequest,
  type RevealProof,
  type TopupErrorCode,
  type TopupOrder,
  type TopupQuote,
  type TopupStatus,
  type WebhookEvent,
  TopupClientError,
} from "../topup.js";

export type { TopupStatus };

export interface CallOpts {
  timeoutMs?: number;
  signal?: AbortSignal;
  idempotencyKey?: string;
}

/** Case-insensitive header bag. Accepts a plain object or a `Headers`-like. */
export type HeadersLike = Record<string, string> | { get(name: string): string | null };

export interface RetryPolicy {
  /** Additional attempts after the first. Default 2. */
  retries?: number;
  /** Base backoff for exponential retry. Default 200 ms. */
  baseDelayMs?: number;
  /** Backoff ceiling. Default 2000 ms. */
  maxDelayMs?: number;
}

export interface TopupProvider {
  readonly id: string;
  quote(req: QuoteRequest, o?: CallOpts): Promise<TopupQuote>;
  createOrder(req: CreateOrderRequest, o?: CallOpts): Promise<TopupOrder>;
  getOrder(orderId: string, o?: CallOpts): Promise<TopupOrder>;
  cancelOrder(orderId: string, o?: CallOpts): Promise<TopupOrder>;
  notifyFunded(orderId: string, proof: FundingProof, o?: CallOpts): Promise<TopupOrder>;
  revealPreimage(orderId: string, reveal: RevealProof, o?: CallOpts): Promise<TopupOrder>;
  verifyWebhook(headers: HeadersLike, rawBody: string): WebhookEvent | null;
}

type FetchLike = (input: string, init?: RequestInit) => Promise<Response>;

export interface HttpTopupProviderOpts {
  baseUrl: string;
  providerId: string;
  /** Runtime secret; returns the bearer token. Never a literal. */
  authToken?: () => string | Promise<string>;
  /** Runtime secret; returns the webhook HMAC secret. Never a literal. */
  webhookSecret?: () => string;
  fetchImpl?: FetchLike;
  retry?: RetryPolicy;
  /** Default per-request timeout (ms). */
  timeoutMs?: number;
  /** Injectable backoff sleep (tests). Defaults to `setTimeout`. */
  sleep?: (ms: number) => Promise<void>;
}

/** Internal marker for a fetch rejection that is safe to retry. */
class NetworkError extends Error {
  constructor(cause: unknown) {
    super("provider network error");
    this.name = "TopupNetworkError";
    this.cause = cause;
  }
}

function defaultSleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function headerValue(headers: HeadersLike, name: string): string | null {
  if (typeof (headers as { get?: unknown }).get === "function") {
    return (headers as { get(n: string): string | null }).get(name);
  }
  const bag = headers as Record<string, string>;
  const wanted = name.toLowerCase();
  for (const key of Object.keys(bag)) {
    if (key.toLowerCase() === wanted) return bag[key];
  }
  return null;
}

/** `sha256=<hex>` HMAC-SHA256 of the raw body. */
export function signWebhook(secret: string, rawBody: string): string {
  const mac = hmac(sha256, new TextEncoder().encode(secret), new TextEncoder().encode(rawBody));
  return `sha256=${bytesToHex(mac)}`;
}

function timingSafeEqualHex(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i += 1) {
    diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return diff === 0;
}

/** Constant-time verification of the `X-Kovanica-Signature` header. */
export function verifyWebhookSignature(
  secret: string,
  headers: HeadersLike,
  rawBody: string,
): boolean {
  const header = headerValue(headers, "x-kovanica-signature");
  if (!header) return false;
  const provided = header.startsWith("sha256=") ? header.slice(7) : header;
  const expected = signWebhook(secret, rawBody).slice(7);
  return timingSafeEqualHex(provided, expected);
}

const TOPUP_STATUSES: readonly TopupStatus[] = [
  "quoted",
  "funded",
  "provisioned",
  "settled",
  "cancelled",
  "expired",
  "refundable",
  "failed",
];

function toBigInt(value: unknown, what: string): bigint {
  if (typeof value === "bigint") return value;
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value)) throw new TopupClientError(500, "internal", `${what} is not a safe integer`);
    return BigInt(value);
  }
  if (typeof value === "string" && /^-?\d+$/.test(value)) return BigInt(value);
  throw new TopupClientError(500, "internal", `${what} is not a decimal amount`);
}

function mapStatusToCode(status: number): TopupErrorCode {
  switch (status) {
    case 400:
      return "bad_request";
    case 401:
    case 403:
      return "unauthorized";
    case 404:
      return "not_found";
    case 409:
      return "conflict";
    case 410:
      return "expired";
    case 429:
      return "rate_limited";
    case 500:
      return "internal";
    default:
      return status >= 500 ? "provider_unavailable" : "internal";
  }
}

function parseRetryAfter(value: string | null): number | undefined {
  if (!value) return undefined;
  const seconds = Number(value);
  if (Number.isFinite(seconds) && seconds >= 0) return Math.round(seconds * 1000);
  const date = Date.parse(value);
  if (Number.isFinite(date)) return Math.max(0, date - Date.now());
  return undefined;
}

/** JSON-over-fetch provider. Transport is injectable (no live server in tests). */
export class HttpTopupProvider implements TopupProvider {
  readonly id: string;
  private readonly baseUrl: string;
  private readonly fetchImpl: FetchLike;
  private readonly authToken: (() => string | Promise<string>) | undefined;
  private readonly webhookSecret: (() => string) | undefined;
  private readonly retry: RetryPolicy;
  private readonly timeoutMs: number | undefined;
  private readonly sleep: (ms: number) => Promise<void>;

  constructor(opts: HttpTopupProviderOpts) {
    if (typeof opts.baseUrl !== "string" || opts.baseUrl.length === 0) {
      throw new Error("top-up provider base URL is required");
    }
    this.baseUrl = opts.baseUrl.replace(/\/+$/, "");
    this.id = opts.providerId;
    this.fetchImpl = opts.fetchImpl ?? ((input, init) => fetch(input, init));
    this.authToken = opts.authToken;
    this.webhookSecret = opts.webhookSecret;
    this.retry = opts.retry ?? {};
    this.timeoutMs = opts.timeoutMs;
    this.sleep = opts.sleep ?? defaultSleep;
  }

  private url(path: string): string {
    return `${this.baseUrl}/v1${path}`;
  }

  private async headers(o?: CallOpts): Promise<Record<string, string>> {
    const headers: Record<string, string> = {
      Accept: "application/json",
      "Content-Type": "application/json",
    };
    if (this.authToken) {
      const token = await this.authToken();
      if (token) headers.Authorization = `Bearer ${token}`;
    }
    if (o?.idempotencyKey) headers["Idempotency-Key"] = o.idempotencyKey;
    return headers;
  }

  private async attempt(
    method: string,
    path: string,
    body: unknown,
    o?: CallOpts,
  ): Promise<Response> {
    const controller = new AbortController();
    let timedOut = false;
    const timeoutMs = o?.timeoutMs ?? this.timeoutMs;
    const timer =
      timeoutMs && timeoutMs > 0
        ? setTimeout(() => {
            timedOut = true;
            controller.abort();
          }, timeoutMs)
        : undefined;
    const onAbort = () => controller.abort();
    if (o?.signal) {
      if (o.signal.aborted) controller.abort();
      else o.signal.addEventListener("abort", onAbort, { once: true });
    }
    try {
      const headers = await this.headers(o);
      const init: RequestInit = { method, headers, signal: controller.signal };
      if (body !== undefined) init.body = JSON.stringify(body);
      return await this.fetchImpl(this.url(path), init);
    } catch (err) {
      if (timedOut) {
        throw new TopupClientError(0, "provider_unavailable", "provider request timed out");
      }
      if ((err as { name?: string })?.name === "AbortError") {
        throw new TopupClientError(0, "provider_unavailable", "provider request aborted");
      }
      throw new NetworkError(err);
    } finally {
      if (timer) clearTimeout(timer);
      if (o?.signal) o.signal.removeEventListener("abort", onAbort);
    }
  }

  private errorFrom(status: number, text: string): TopupClientError {
    let code: TopupErrorCode = mapStatusToCode(status);
    let message = `provider HTTP ${status}`;
    if (text.length > 0) {
      try {
        const parsed = JSON.parse(text) as { error?: { code?: unknown; message?: unknown } };
        if (isTopupErrorCode(parsed.error?.code)) code = parsed.error.code;
        if (typeof parsed.error?.message === "string" && parsed.error.message.length > 0) {
          message = parsed.error.message;
        }
      } catch {
        // non-JSON body; keep the status-derived slug
      }
    }
    return new TopupClientError(status, code, message);
  }

  private retries(): number {
    return this.retry.retries ?? 2;
  }

  private backoff(attempt: number): number {
    const base = this.retry.baseDelayMs ?? 200;
    const max = this.retry.maxDelayMs ?? 2000;
    return Math.min(max, base * 2 ** Math.max(0, attempt - 1));
  }

  private async request<T>(
    method: string,
    path: string,
    body: unknown,
    o: CallOpts | undefined,
    parse: (json: unknown) => T,
  ): Promise<T> {
    let attempt = 0;
    for (;;) {
      let res: Response;
      try {
        res = await this.attempt(method, path, body, o);
      } catch (err) {
        if (err instanceof NetworkError && attempt < this.retries()) {
          attempt += 1;
          await this.sleep(this.backoff(attempt));
          continue;
        }
        throw err;
      }
      const text = await res.text();
      if (res.ok) {
        let json: unknown = null;
        if (text.length > 0) {
          try {
            json = JSON.parse(text);
          } catch {
            throw new TopupClientError(res.status, "internal", "provider returned invalid JSON");
          }
        }
        return parse(json);
      }
      const retryable = res.status === 429 || res.status >= 500;
      if (retryable && attempt < this.retries()) {
        const retryAfter = parseRetryAfter(res.headers.get("retry-after"));
        attempt += 1;
        await this.sleep(retryAfter ?? this.backoff(attempt));
        continue;
      }
      throw this.errorFrom(res.status, text);
    }
  }

  async quote(req: QuoteRequest, o?: CallOpts): Promise<TopupQuote> {
    return this.request("POST", "/quote", { sku: req.sku }, o, parseQuote);
  }

  async createOrder(req: CreateOrderRequest, o?: CallOpts): Promise<TopupOrder> {
    return this.request("POST", "/orders", { quoteId: req.quoteId, sku: req.sku }, o, parseOrder);
  }

  async getOrder(orderId: string, o?: CallOpts): Promise<TopupOrder> {
    return this.request("GET", `/orders/${encodeURIComponent(orderId)}`, undefined, o, parseOrder);
  }

  async cancelOrder(orderId: string, o?: CallOpts): Promise<TopupOrder> {
    return this.request(
      "POST",
      `/orders/${encodeURIComponent(orderId)}/cancel`,
      {},
      o,
      parseOrder,
    );
  }

  async notifyFunded(orderId: string, proof: FundingProof, o?: CallOpts): Promise<TopupOrder> {
    return this.request(
      "POST",
      `/orders/${encodeURIComponent(orderId)}/funded`,
      proof,
      o,
      parseOrder,
    );
  }

  async revealPreimage(orderId: string, reveal: RevealProof, o?: CallOpts): Promise<TopupOrder> {
    return this.request(
      "POST",
      `/orders/${encodeURIComponent(orderId)}/reveal`,
      reveal,
      o,
      parseOrder,
    );
  }

  /**
   * Verify the HMAC over the raw body. Returns null for unsigned/mismatched
   * webhooks. Webhook fields are never authoritative — re-GET the order.
   */
  verifyWebhook(headers: HeadersLike, rawBody: string): WebhookEvent | null {
    const secret = this.webhookSecret?.();
    if (!secret) return null;
    if (!verifyWebhookSignature(secret, headers, rawBody)) return null;
    let parsed: unknown;
    try {
      parsed = JSON.parse(rawBody);
    } catch {
      return null;
    }
    const rec = parsed as Record<string, unknown> | null;
    if (!rec || typeof rec.orderId !== "string") return null;
    if (typeof rec.status !== "string" || !TOPUP_STATUSES.includes(rec.status as TopupStatus)) {
      return null;
    }
    const ts = typeof rec.ts === "number" ? rec.ts : Number(rec.ts);
    if (!Number.isFinite(ts)) return null;
    return { orderId: rec.orderId, status: rec.status as TopupStatus, ts };
  }
}

function parseQuote(json: unknown): TopupQuote {
  const rec = json as Record<string, unknown> | null;
  if (!rec || typeof rec.quoteId !== "string" || typeof rec.claimerAddr !== "string") {
    throw new TopupClientError(500, "internal", "provider quote response is malformed");
  }
  return {
    quoteId: rec.quoteId,
    providerId: typeof rec.providerId === "string" ? rec.providerId : "",
    sku: typeof rec.sku === "string" ? rec.sku : "",
    currency: "KUNA",
    amountAtoms: toBigInt(rec.amountAtoms, "quote amount"),
    claimerAddr: rec.claimerAddr,
    htlcExpiryMs: toBigInt(rec.htlcExpiryMs, "quote expiry"),
    quoteExpiresAt: typeof rec.quoteExpiresAt === "number" ? rec.quoteExpiresAt : Number(rec.quoteExpiresAt),
    issuedAt: typeof rec.issuedAt === "number" ? rec.issuedAt : Number(rec.issuedAt),
  };
}

function parseOrder(json: unknown): TopupOrder {
  const rec = json as Record<string, unknown> | null;
  if (!rec || typeof rec.orderId !== "string" || typeof rec.quoteId !== "string") {
    throw new TopupClientError(500, "internal", "provider order response is malformed");
  }
  const status = typeof rec.status === "string" && TOPUP_STATUSES.includes(rec.status as TopupStatus)
    ? (rec.status as TopupStatus)
    : "failed";
  const order: TopupOrder = {
    orderId: rec.orderId,
    quoteId: rec.quoteId,
    providerId: typeof rec.providerId === "string" ? rec.providerId : "",
    status,
    currency: "KUNA",
    amountAtoms: toBigInt(rec.amountAtoms, "order amount"),
    claimerAddr: typeof rec.claimerAddr === "string" ? rec.claimerAddr : "",
    createdAt: typeof rec.createdAt === "number" ? rec.createdAt : Number(rec.createdAt),
    updatedAt: typeof rec.updatedAt === "number" ? rec.updatedAt : Number(rec.updatedAt),
  };
  if (typeof rec.htlcId === "string") order.htlcId = rec.htlcId;
  if (typeof rec.fundingTxId === "string") order.fundingTxId = rec.fundingTxId;
  if (typeof rec.senderAddr === "string") order.senderAddr = rec.senderAddr;
  if (typeof rec.activationCode === "string") order.activationCode = rec.activationCode;
  return order;
}
