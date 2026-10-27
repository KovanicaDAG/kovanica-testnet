/**
 * Deterministic mock top-up provider (M7) — **client-only**.
 *
 * In-memory orders, injectable deterministic clock, and scripted failure modes
 * (status / timeout). No live network. Used by tests and local demos.
 */

import {
  type CreateOrderRequest,
  type FundingProof,
  type QuoteRequest,
  type RevealProof,
  type TopupErrorCode,
  type TopupOrder,
  type TopupQuote,
  type WebhookEvent,
  TopupClientError,
} from "../topup.js";
import { signWebhook, type TopupProvider } from "./provider.js";

export type MockMethod =
  | "quote"
  | "createOrder"
  | "getOrder"
  | "cancelOrder"
  | "notifyFunded"
  | "revealPreimage";

export type MockFailure =
  | { kind: "timeout"; message?: string }
  | { kind: "status"; status: number; code?: TopupErrorCode; retryAfterMs?: number };

export interface MockTopupProviderOpts {
  providerId?: string;
  now?: () => number;
  /** Default quote parameters. */
  amountAtoms?: bigint;
  claimerAddr?: string;
  htlcExpiryMs?: bigint;
  quoteExpiresAt?: number;
  activationCode?: string;
  /** Overrides merged into every quote (used to exercise client validation). */
  quoteOverrides?: Partial<TopupQuote>;
  /** Scripted failures, consumed per method in order. */
  failures?: Partial<Record<MockMethod, MockFailure[]>>;
  /** Runtime webhook secret; never a literal. */
  webhookSecret?: () => string;
}

const DEFAULT_CLAIMER = "11".repeat(32);

export class MockTopupProvider implements TopupProvider {
  readonly id: string;
  private readonly now: () => number;
  private readonly amountAtoms: bigint;
  private readonly claimerAddr: string;
  private readonly htlcExpiryMs: bigint;
  private readonly quoteExpiresAt: number;
  private readonly activationCode: string;
  private readonly quoteOverrides: Partial<TopupQuote>;
  private readonly failures: Partial<Record<MockMethod, MockFailure[]>>;
  private readonly webhookSecret: (() => string) | undefined;

  private readonly quotes = new Map<string, TopupQuote>();
  private readonly orders = new Map<string, TopupOrder>();
  private seq = 0;

  constructor(opts: MockTopupProviderOpts = {}) {
    this.id = opts.providerId ?? "mock";
    this.now = opts.now ?? (() => Date.now());
    this.amountAtoms = opts.amountAtoms ?? 5_000_000_000n;
    this.claimerAddr = opts.claimerAddr ?? DEFAULT_CLAIMER;
    this.htlcExpiryMs = opts.htlcExpiryMs ?? BigInt(this.now() + 3_600_000);
    this.quoteExpiresAt = opts.quoteExpiresAt ?? this.now() + 600_000;
    this.activationCode = opts.activationCode ?? "ACTIVATION-CODE";
    this.quoteOverrides = opts.quoteOverrides ?? {};
    this.failures = opts.failures ?? {};
    this.webhookSecret = opts.webhookSecret;
  }

  /** Queue one failure for the next call to `method`. */
  failNext(method: MockMethod, failure: MockFailure): void {
    const queue = this.failures[method] ?? [];
    queue.push(failure);
    this.failures[method] = queue;
  }

  private takeFailure(method: MockMethod): MockFailure | undefined {
    const queue = this.failures[method];
    if (!queue || queue.length === 0) return undefined;
    return queue.shift();
  }

  private throwIfFailure(method: MockMethod): void {
    const failure = this.takeFailure(method);
    if (!failure) return;
    if (failure.kind === "timeout") {
      throw new TopupClientError(504, "provider_unavailable", "mock provider timed out");
    }
    const code = failure.code ?? (failure.status >= 500 ? "provider_unavailable" : "bad_request");
    throw new TopupClientError(failure.status, code, "mock provider error");
  }

  async quote(req: QuoteRequest): Promise<TopupQuote> {
    this.throwIfFailure("quote");
    this.seq += 1;
    const quote: TopupQuote = {
      quoteId: `q-${this.seq}`,
      providerId: this.id,
      sku: req.sku,
      currency: "KUNA",
      amountAtoms: this.amountAtoms,
      claimerAddr: this.claimerAddr,
      htlcExpiryMs: this.htlcExpiryMs,
      quoteExpiresAt: this.quoteExpiresAt,
      issuedAt: this.now(),
      ...this.quoteOverrides,
    };
    this.quotes.set(quote.quoteId, quote);
    return quote;
  }

  async createOrder(req: CreateOrderRequest): Promise<TopupOrder> {
    this.throwIfFailure("createOrder");
    const quote = this.quotes.get(req.quoteId);
    const amountAtoms = quote?.amountAtoms ?? this.amountAtoms;
    const claimerAddr = quote?.claimerAddr ?? this.claimerAddr;
    this.seq += 1;
    const order: TopupOrder = {
      orderId: `o-${this.seq}`,
      quoteId: req.quoteId,
      providerId: this.id,
      status: "quoted",
      currency: "KUNA",
      amountAtoms,
      claimerAddr,
      createdAt: this.now(),
      updatedAt: this.now(),
    };
    this.orders.set(order.orderId, order);
    return order;
  }

  async getOrder(orderId: string): Promise<TopupOrder> {
    this.throwIfFailure("getOrder");
    const order = this.orders.get(orderId);
    if (!order) throw new TopupClientError(404, "not_found", "unknown order");
    return order;
  }

  async cancelOrder(orderId: string): Promise<TopupOrder> {
    this.throwIfFailure("cancelOrder");
    const order = await this.getOrder(orderId);
    const next: TopupOrder = { ...order, status: "cancelled", updatedAt: this.now() };
    this.orders.set(orderId, next);
    return next;
  }

  async notifyFunded(orderId: string, proof: FundingProof): Promise<TopupOrder> {
    this.throwIfFailure("notifyFunded");
    const order = await this.getOrder(orderId);
    // Idempotent: re-notifying the same funding tx returns the same order.
    if (order.status === "provisioned" || order.status === "settled") return order;
    const next: TopupOrder = {
      ...order,
      status: "provisioned",
      htlcId: proof.htlcId,
      fundingTxId: proof.txId,
      senderAddr: proof.senderAddr,
      activationCode: this.activationCode,
      updatedAt: this.now(),
    };
    this.orders.set(orderId, next);
    return next;
  }

  async revealPreimage(orderId: string, _reveal: RevealProof): Promise<TopupOrder> {
    this.throwIfFailure("revealPreimage");
    const order = await this.getOrder(orderId);
    if (order.status === "settled") return order;
    if (order.status !== "provisioned") {
      throw new TopupClientError(409, "conflict", "order is not provisioned");
    }
    const next: TopupOrder = { ...order, status: "settled", updatedAt: this.now() };
    this.orders.set(orderId, next);
    return next;
  }

  verifyWebhook(headers: Record<string, string> | { get(name: string): string | null }, rawBody: string): WebhookEvent | null {
    const secret = this.webhookSecret?.();
    if (!secret) return null;
    const header =
      typeof (headers as { get?: unknown }).get === "function"
        ? (headers as { get(n: string): string | null }).get("x-kovanica-signature")
        : (headers as Record<string, string>)["x-kovanica-signature"] ?? null;
    if (!header) return null;
    if (header !== signWebhook(secret, rawBody)) return null;
    let parsed: unknown;
    try {
      parsed = JSON.parse(rawBody);
    } catch {
      return null;
    }
    const rec = parsed as { orderId?: unknown; status?: unknown; ts?: unknown } | null;
    if (!rec || typeof rec.orderId !== "string" || typeof rec.status !== "string") return null;
    const ts = typeof rec.ts === "number" ? rec.ts : Number(rec.ts);
    if (!Number.isFinite(ts)) return null;
    return { orderId: rec.orderId, status: rec.status as TopupOrder["status"], ts };
  }
}
