/**
 * Top-up / eSIM client (M7) — client-only orchestration + ledger-safe payment leg.
 *
 * Layer classification:
 *  - data model + {@link TopupClient} orchestration: **client-only**
 *  - HTLC funding leg: **ledger-safe** (reuses the M2 builders in `./payments`)
 *  - provider HTTP adapters: **client-only / external** (see `./topup/provider`)
 *  - eSIM profile issuance: **external** — off-chain; the chain never sees the profile
 *
 * Trust model (posture **A** — client-controlled preimage, reveal-on-delivery):
 *  The client picks a 32-byte preimage `P`, computes `H = BLAKE3(P)`, and funds an
 *  HTLC to a provider-controlled claimer. The provider verifies the HTLC on-chain
 *  and releases the activation code; the client then reveals `P` so the provider
 *  can claim. Residual risks: a client can receive the code and withhold `P`; a
 *  provider can refuse to release after funding. Both are bounded by the HTLC
 *  expiry (the client can refund) and the certified-partner relationship (plan R7).
 *  The activation secret is **never** placed on-chain.
 *
 * Environment (non-secret): `KOVANICA_TOPUP_PROVIDER_BASE_URL`,
 * `KOVANICA_TOPUP_PROVIDER_ID`, `KOVANICA_TOPUP_REQUEST_TIMEOUT_MS`,
 * `KOVANICA_TOPUP_MAX_ATOMS`, `KOVANICA_TOPUP_EXPIRY_MARGIN_MS`. Secrets
 * (`KOVANICA_TOPUP_API_TOKEN`, `KOVANICA_TOPUP_WEBHOOK_SECRET`) are resolved at runtime by
 * the injected callbacks — never read from `process.env` here and never committed.
 *
 * This module never logs; thrown messages carry slugs/status only (no preimage,
 * activation code, bearer token, or full order payloads).
 */

import { bytesToHex, encodeAddress, hexToBytes } from "@kovanica/signer";

import {
  bytesToBase64,
  computeHtlcHashLock,
  computeHtlcId,
  encodeHtlcCreateRaw,
} from "./payments.js";
import type { RetryPolicy, TopupProvider } from "./topup/provider.js";

export type TopupCurrency = "KUNA";

export type TopupStatus =
  | "quoted"
  | "funded"
  | "provisioned"
  | "settled"
  | "cancelled"
  | "expired"
  | "refundable"
  | "failed";

/** Error slugs returned by a provider (HTTP boundary, `/v1`). */
export type TopupErrorCode =
  | "bad_request"
  | "unauthorized"
  | "not_found"
  | "conflict"
  | "rate_limited"
  | "expired"
  | "provider_unavailable"
  | "internal";

const TOPUP_ERROR_CODES: readonly string[] = [
  "bad_request",
  "unauthorized",
  "not_found",
  "conflict",
  "rate_limited",
  "expired",
  "provider_unavailable",
  "internal",
];

/** Thrown for any non-2xx provider response or client-side validation failure. */
export class TopupClientError extends Error {
  constructor(
    public readonly status: number,
    public readonly code: TopupErrorCode,
    message: string,
  ) {
    super(message);
    this.name = "TopupClientError";
  }
}

export function isTopupErrorCode(value: unknown): value is TopupErrorCode {
  return typeof value === "string" && TOPUP_ERROR_CODES.includes(value);
}

export interface TopupQuote {
  quoteId: string;
  providerId: string;
  sku: string;
  currency: "KUNA";
  amountAtoms: bigint;
  claimerAddr: string;
  htlcExpiryMs: bigint;
  quoteExpiresAt: number;
  issuedAt: number;
}

export interface TopupOrder {
  orderId: string;
  quoteId: string;
  providerId: string;
  status: TopupStatus;
  currency: "KUNA";
  amountAtoms: bigint;
  claimerAddr: string;
  htlcId?: string;
  fundingTxId?: string;
  senderAddr?: string;
  activationCode?: string;
  createdAt: number;
  updatedAt: number;
}

export interface FundingProof {
  htlcId: string;
  txId: string;
  senderAddr: string;
  hashLock: string;
}

/** Preimage reveal. `preimage` is base64 (32 bytes). */
export interface RevealProof {
  preimage: string;
}

export interface QuoteRequest {
  sku: string;
}

export interface CreateOrderRequest {
  quoteId: string;
  sku: string;
}

export interface WebhookEvent {
  orderId: string;
  status: TopupStatus;
  ts: number;
}

export interface OrderStore {
  get(orderId: string): Promise<TopupOrder | undefined>;
  put(o: TopupOrder): Promise<void>;
  list(): Promise<TopupOrder[]>;
}

/** In-memory default store. Order metadata only; no secrets. */
export class InMemoryOrderStore implements OrderStore {
  private readonly orders = new Map<string, TopupOrder>();

  async get(orderId: string): Promise<TopupOrder | undefined> {
    return this.orders.get(orderId);
  }

  async put(o: TopupOrder): Promise<void> {
    this.orders.set(o.orderId, o);
  }

  async list(): Promise<TopupOrder[]> {
    return [...this.orders.values()];
  }
}

/** Minimal chain surface used by the funding leg; `KovanicaRpcClient` satisfies it. */
export interface TopupRpc {
  getNonce(address: string): Promise<bigint>;
  sendRawTransaction(rawHex: string): Promise<string>;
}

/**
 * Signer material for the funding leg. `publicKey`/`seed` are 32-byte hex.
 * The `seed` is client-side only and is never transmitted.
 */
export interface TopupSignerKey {
  publicKey: string;
  seed: string;
}

/** Resolution policy applied to every quote before funding. */
export interface TopupPolicy {
  maxAtoms?: bigint;
  minExpiryMarginMs?: number;
}

export interface TopupClientOpts {
  provider: TopupProvider;
  rpc: TopupRpc;
  signerKey: TopupSignerKey;
  chainId: number;
  store?: OrderStore;
  clock?: () => number;
  requestTimeoutMs?: number;
  /**
   * Retry policy for the client's own read-only provider calls (`quote`,
   * `getOrder`). Defaults to no client-side retry; the HTTP adapter retries
   * transport errors itself.
   */
  retry?: RetryPolicy;
  policy?: TopupPolicy;
  /** Flat fee (atoms) for the funding HTLC transaction. Default 0n. */
  feeAtoms?: bigint;
  /** Injectable randomness (tests). Defaults to `crypto.getRandomValues`. */
  randomBytes?: (n: number) => Uint8Array;
  /** Injectable backoff sleep (tests). Defaults to `setTimeout`. */
  sleep?: (ms: number) => Promise<void>;
}

export const DEFAULT_MAX_ATOMS = 100_000_000_000n;
export const DEFAULT_MIN_EXPIRY_MARGIN_MS = 120_000;

const HEX64 = /^[0-9a-f]{64}$/;
const TERMINAL_STATUSES: ReadonlySet<TopupStatus> = new Set(["settled", "cancelled", "failed"]);

interface ResolvedPolicy {
  maxAtoms: bigint;
  minExpiryMarginMs: number;
}

function isTerminal(status: TopupStatus): boolean {
  return TERMINAL_STATUSES.has(status);
}

/**
 * Validate a quote before it is ever funded. Throws {@link TopupClientError}
 * (`bad_request` / `expired`) on any violation. Never echoes secret material.
 */
export function validateQuote(quote: TopupQuote, now: number, policy: ResolvedPolicy): TopupQuote {
  if (quote.currency !== "KUNA") {
    throw new TopupClientError(400, "bad_request", "unsupported quote currency");
  }
  if (quote.amountAtoms <= 0n) {
    throw new TopupClientError(400, "bad_request", "quote amount must be positive");
  }
  if (quote.amountAtoms > policy.maxAtoms) {
    throw new TopupClientError(400, "bad_request", "quote amount exceeds policy limit");
  }
  if (!HEX64.test(quote.claimerAddr)) {
    throw new TopupClientError(400, "bad_request", "quote claimer address is malformed");
  }
  if (!Number.isFinite(quote.quoteExpiresAt) || quote.quoteExpiresAt <= now) {
    throw new TopupClientError(400, "expired", "quote has expired");
  }
  const requiredExpiry = BigInt(now) + BigInt(policy.minExpiryMarginMs);
  if (quote.htlcExpiryMs < requiredExpiry) {
    throw new TopupClientError(400, "bad_request", "quote HTLC expiry is too short");
  }
  if (!Number.isFinite(quote.issuedAt)) {
    throw new TopupClientError(400, "bad_request", "quote is missing an issue time");
  }
  return quote;
}

/**
 * Local self-check: the hash lock the provider will verify must equal
 * `BLAKE3(P)` for the client's own preimage. Never trust a server hash lock
 * without recomputing it locally.
 */
export function verifyHashLock(preimage: Uint8Array, hashLockHex: string): void {
  const expected = bytesToHex(computeHtlcHashLock(preimage));
  if (expected !== hashLockHex.toLowerCase()) {
    throw new TopupClientError(400, "bad_request", "hash lock does not match the client preimage");
  }
}

function defaultRandomBytes(n: number): Uint8Array {
  const out = new Uint8Array(n);
  crypto.getRandomValues(out);
  return out;
}

function defaultSleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function isRetryableError(err: unknown): boolean {
  if (!(err instanceof TopupClientError)) return true;
  return err.status === 0 || err.status === 429 || err.status >= 500;
}

function backoffMs(attempt: number, policy: RetryPolicy | undefined): number {
  const base = policy?.baseDelayMs ?? 200;
  const max = policy?.maxDelayMs ?? 2000;
  return Math.min(max, base * 2 ** Math.max(0, attempt - 1));
}

/**
 * Client-side top-up flow. `purchase` runs quote → createOrder → HTLC create →
 * sign → submit → notifyFunded; `fulfill` reveals the preimage after the
 * provider provisions the order. All state transitions are monotonic and the
 * terminal states (`settled`/`cancelled`/`failed`) are idempotent on re-fetch.
 */
export class TopupClient {
  private readonly provider: TopupProvider;
  private readonly rpc: TopupRpc;
  private readonly signer: TopupSignerKey;
  private readonly chainId: number;
  private readonly store: OrderStore;
  private readonly now: () => number;
  private readonly timeoutMs: number | undefined;
  private readonly policy: ResolvedPolicy;
  private readonly feeAtoms: bigint;
  private readonly randomBytes: (n: number) => Uint8Array;
  private readonly sleep: (ms: number) => Promise<void>;
  private readonly retryPolicy: RetryPolicy | undefined;
  /** quoteId → outstanding order id (one HTLC per quote). */
  private readonly orderByQuote = new Map<string, string>();
  /** sku → most recent quote id (idempotent repeat purchase). */
  private readonly quoteBySku = new Map<string, string>();
  private readonly quotes = new Map<string, TopupQuote>();
  /** Client-side secret; never transmitted until reveal. */
  private readonly preimages = new Map<string, Uint8Array>();

  constructor(opts: TopupClientOpts) {
    this.provider = opts.provider;
    this.rpc = opts.rpc;
    this.signer = opts.signerKey;
    this.chainId = opts.chainId;
    this.store = opts.store ?? new InMemoryOrderStore();
    this.now = opts.clock ?? (() => Date.now());
    this.timeoutMs = opts.requestTimeoutMs;
    this.policy = {
      maxAtoms: opts.policy?.maxAtoms ?? DEFAULT_MAX_ATOMS,
      minExpiryMarginMs: opts.policy?.minExpiryMarginMs ?? DEFAULT_MIN_EXPIRY_MARGIN_MS,
    };
    this.feeAtoms = opts.feeAtoms ?? 0n;
    this.randomBytes = opts.randomBytes ?? defaultRandomBytes;
    this.sleep = opts.sleep ?? defaultSleep;
    this.retryPolicy = opts.retry;
  }

  private callOpts(idempotencyKey: string): { timeoutMs?: number; idempotencyKey: string } {
    const out: { timeoutMs?: number; idempotencyKey: string } = { idempotencyKey };
    if (this.timeoutMs !== undefined) out.timeoutMs = this.timeoutMs;
    return out;
  }

  private async retryable<T>(op: () => Promise<T>): Promise<T> {
    const retries = this.retryPolicy?.retries ?? 0;
    let attempt = 0;
    for (;;) {
      try {
        return await op();
      } catch (err) {
        if (attempt >= retries || !isRetryableError(err)) throw err;
        attempt += 1;
        await this.sleep(backoffMs(attempt, this.retryPolicy));
      }
    }
  }

  /** `POST /v1/quote` (cached per sku until it expires). */
  async quote(sku: string): Promise<TopupQuote> {
    const cachedId = this.quoteBySku.get(sku);
    const cached = cachedId ? this.quotes.get(cachedId) : undefined;
    if (cached && cached.quoteExpiresAt > this.now()) return cached;
    const raw = await this.retryable(() =>
      this.provider.quote({ sku }, this.callOpts(`quote:${sku}`)),
    );
    const quote = validateQuote(raw, this.now(), this.policy);
    this.quotes.set(quote.quoteId, quote);
    this.quoteBySku.set(sku, quote.quoteId);
    return quote;
  }

  /** quote → createOrder → HTLC create → sign → submit → notifyFunded. */
  async purchase(sku: string): Promise<TopupOrder> {
    let quote = await this.quote(sku);

    const priorId = this.orderByQuote.get(quote.quoteId);
    if (priorId) {
      const prior = await this.store.get(priorId);
      if (prior && prior.fundingTxId && !isTerminal(prior.status)) return prior;
      if (prior && isTerminal(prior.status)) {
        // Allow a fresh purchase for the same sku once the prior order is terminal.
        this.orderByQuote.delete(quote.quoteId);
        this.preimages.delete(priorId);
        this.quoteBySku.delete(sku);
        quote = await this.quote(sku);
      }
    }

    const preimage = this.randomBytes(32);
    const hashLock = computeHtlcHashLock(preimage);
    const hashLockHex = bytesToHex(hashLock);
    const sender = hexToBytes(this.signer.publicKey);
    const claimer = hexToBytes(quote.claimerAddr);
    const senderAddr = encodeAddress(sender);

    const created = await this.provider.createOrder(
      { quoteId: quote.quoteId, sku },
      this.callOpts(`order:${quote.quoteId}`),
    );
    this.orderByQuote.set(quote.quoteId, created.orderId);
    this.preimages.set(created.orderId, preimage);
    await this.store.put(created);

    const nonce = await this.rpc.getNonce(senderAddr);
    const raw = await encodeHtlcCreateRaw({
      sender,
      claimer,
      preimage,
      amountAtoms: quote.amountAtoms,
      expiryMs: quote.htlcExpiryMs,
      nonce,
      fee: this.feeAtoms,
      chainId: this.chainId,
      senderSeed: hexToBytes(this.signer.seed),
    });
    const txId = await this.rpc.sendRawTransaction(raw);
    verifyHashLock(preimage, hashLockHex);

    const htlcId = bytesToHex(
      computeHtlcId({
        sender,
        claimer,
        amountAtoms: quote.amountAtoms,
        hashLock,
        expiryMs: quote.htlcExpiryMs,
      }),
    );
    const proof: FundingProof = { htlcId, txId, senderAddr, hashLock: hashLockHex };

    let notified: TopupOrder;
    try {
      notified = await this.provider.notifyFunded(
        created.orderId,
        proof,
        this.callOpts(`fund:${created.orderId}:${txId}`),
      );
    } catch {
      // Provider verification failed/timed out after the funding tx was submitted.
      // Mark refundable and do NOT re-issue a new HTLC (double-spend hazard).
      const refundable: TopupOrder = {
        ...created,
        status: "refundable",
        htlcId,
        fundingTxId: txId,
        senderAddr,
        updatedAt: this.now(),
      };
      await this.store.put(refundable);
      return refundable;
    }

    const saved = this.merge(created, notified, { htlcId, fundingTxId: txId, senderAddr });
    await this.store.put(saved);
    return saved;
  }

  /** Local order view (`GET /v1/orders/{id}` is only used by {@link refresh}). */
  async status(orderId: string): Promise<TopupOrder> {
    return this.requireOrder(orderId);
  }

  /** Reveal the preimage after the order is provisioned. */
  async fulfill(orderId: string): Promise<TopupOrder> {
    const order = await this.requireOrder(orderId);
    if (order.status === "settled") return order;
    if (order.status !== "provisioned") {
      throw new TopupClientError(409, "conflict", "order is not provisioned");
    }
    const preimage = this.preimages.get(orderId);
    if (!preimage) {
      throw new TopupClientError(409, "conflict", "no local preimage for order");
    }
    const reveal: RevealProof = { preimage: bytesToBase64(preimage) };
    const updated = await this.provider.revealPreimage(
      orderId,
      reveal,
      this.callOpts(`reveal:${orderId}`),
    );
    const merged = this.merge(order, updated, {});
    await this.store.put(merged);
    return merged;
  }

  /** Cancel via the provider (no-op if already terminal). */
  async cancel(orderId: string): Promise<TopupOrder> {
    const order = await this.requireOrder(orderId);
    if (isTerminal(order.status)) return order;
    const updated = await this.provider.cancelOrder(orderId, this.callOpts(`cancel:${orderId}`));
    const merged = this.merge(order, updated, {});
    await this.store.put(merged);
    return merged;
  }

  /** Re-GET the order and refresh the local store. */
  async refresh(orderId: string): Promise<TopupOrder> {
    const order = await this.requireOrder(orderId);
    const updated = await this.retryable(() =>
      this.provider.getOrder(orderId, this.callOpts(`get:${orderId}`)),
    );
    const merged = this.merge(order, updated, {});
    await this.store.put(merged);
    return merged;
  }

  private async requireOrder(orderId: string): Promise<TopupOrder> {
    const order = await this.store.get(orderId);
    if (!order) throw new TopupClientError(404, "not_found", "unknown order");
    return order;
  }

  private merge(
    prev: TopupOrder,
    next: TopupOrder,
    extra: Partial<Pick<TopupOrder, "htlcId" | "fundingTxId" | "senderAddr">>,
  ): TopupOrder {
    return {
      ...prev,
      ...next,
      status: isTerminal(prev.status) ? prev.status : next.status,
      htlcId: next.htlcId ?? extra.htlcId ?? prev.htlcId,
      fundingTxId: next.fundingTxId ?? extra.fundingTxId ?? prev.fundingTxId,
      senderAddr: next.senderAddr ?? extra.senderAddr ?? prev.senderAddr,
      updatedAt: this.now(),
    };
  }
}
