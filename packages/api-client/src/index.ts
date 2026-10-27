/**
 * Typed fetch client for a kovanica-node JSON-RPC endpoint.
 *
 * The caller passes the full URL, including `/rpc`. A loopback node you
 * started yourself is `http://127.0.0.1:8545/rpc`. The console does not
 * use that default: production builds only talk to the pinned networks.
 *
 * Quantities on the wire are `0x`-prefixed hex strings. Balances are
 * returned as `bigint` because KUNA amounts do not fit in a safe integer
 * (9 decimals).
 *
 * Signed contract calls are not built here. Argument bytes for
 * `TransactionKind::Call` come from `kovanica_execution::call_args` and must
 * match `ENTRY_POINTS`. The node's `htlc_*` / `vault_*` / `token_*` RPC
 * names execute inside the process with a fixed zero caller; they are not
 * this client.
 */

export const ENTRY_POINTS = [
  "htlc_create",
  "htlc_claim",
  "htlc_refund",
  "vault_create",
  "vault_claim",
  "vault_cancel",
  "multisig_create",
  "multisig_propose",
  "multisig_confirm",
  "multisig_execute",
  "token_create",
  "token_transfer",
  "token_approve",
  "token_transfer_from",
  "token_mint",
  "token_burn",
] as const;

export type EntryPoint = (typeof ENTRY_POINTS)[number];

export interface BlockResponse {
  hash: string;
  round: number;
  parent_hashes: string[];
  transactions: Array<{ hash: string; raw: string } | string>;
}

export interface ValidatorInfo {
  address: string;
  /** Hex quantity from the node, parsed. */
  stake: bigint;
  commission_bps: number;
  active: boolean;
  payout_address: string;
}

interface RpcRequest {
  jsonrpc: "2.0";
  method: string;
  params?: unknown[];
  id?: number | string;
}

interface RpcErrorBody {
  message?: string;
}

/** Decode a 32-byte hex string into the JSON byte array the node accepts. */
export function bytes32(hex: string): number[] {
  const raw = hex.startsWith("0x") ? hex.slice(2) : hex;
  if (!/^[0-9a-fA-F]{64}$/.test(raw)) {
    throw new Error("expected 32 bytes of hex");
  }
  const out: number[] = [];
  for (let i = 0; i < raw.length; i += 2) {
    out.push(Number.parseInt(raw.slice(i, i + 2), 16));
  }
  return out;
}

/** Parse an `0x` quantity. Accepts a JSON number only when it is a safe integer. */
export function parseQuantity(value: unknown): bigint {
  if (typeof value === "bigint") return value;
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value)) {
      throw new Error("quantity exceeds Number.MAX_SAFE_INTEGER; expected a hex string");
    }
    return BigInt(value);
  }
  if (typeof value === "string") {
    const raw = value.startsWith("0x") || value.startsWith("0X") ? value : `0x${value}`;
    return BigInt(raw);
  }
  throw new Error(`expected a hex quantity, got ${typeof value}`);
}

export class KovanicaRpcClient {
  /** @param url Full JSON-RPC URL, including `/rpc`. */
  constructor(private url: string) {
    if (url.length === 0) throw new Error("RPC URL is required");
  }

  private async call<T>(method: string, params?: unknown[]): Promise<T> {
    const req: RpcRequest = { jsonrpc: "2.0", method, params, id: 1 };
    const res = await fetch(this.url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(req),
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const json = (await res.json()) as { result?: T; error?: RpcErrorBody };
    if (json.error) throw new Error(json.error.message || "RPC error");
    return json.result as T;
  }

  async blockNumber(): Promise<bigint> {
    return parseQuantity(await this.call<unknown>("kovanica_blockNumber"));
  }

  getBlockByHash(hash: string, fullTransactions = false): Promise<BlockResponse | null> {
    return this.call<BlockResponse | null>("kovanica_getBlockByHash", [hash, fullTransactions]);
  }

  async getBalance(address: string): Promise<bigint> {
    return parseQuantity(await this.call<unknown>("kovanica_getBalance", [address]));
  }

  async getValidators(): Promise<ValidatorInfo[]> {
    const rows = await this.call<Array<Omit<ValidatorInfo, "stake"> & { stake: unknown }>>(
      "kovanica_getValidators",
    );
    return rows.map((row) => ({ ...row, stake: parseQuantity(row.stake) }));
  }

  sendRawTransaction(rawHex: string): Promise<string> {
    return this.call<string>("kovanica_sendRawTransaction", [rawHex]);
  }

  /**
   * The node currently returns an empty list. `Mempool` has no
   * non-destructive pending-hash listing yet.
   */
  getPendingTransactions(): Promise<string[]> {
    return this.call<string[]>("kovanica_getPendingTransactions");
  }

  async estimateFee(): Promise<bigint> {
    return parseQuantity(await this.call<unknown>("kovanica_estimateFee"));
  }

  async getNonce(address: string): Promise<bigint> {
    return parseQuantity(await this.call<unknown>("kovanica_getNonce", [address]));
  }

  async getStake(address: string): Promise<bigint> {
    return parseQuantity(await this.call<unknown>("kovanica_getStake", [address]));
  }

  /**
   * Cumulative rewards. The node currently reports 0 for every address
   * because per-address reward accounting is not stored yet.
   */
  async getRewards(address: string): Promise<bigint> {
    return parseQuantity(await this.call<unknown>("kovanica_getRewards", [address]));
  }

  getBlockByNumber(number: bigint, fullTransactions = false): Promise<BlockResponse | null> {
    return this.call<BlockResponse | null>("kovanica_getBlockByNumber", [
      `0x${number.toString(16)}`,
      fullTransactions,
    ]);
  }

  async getTransactionByHash(hash: string): Promise<Record<string, unknown> | null> {
    return this.call<Record<string, unknown> | null>("kovanica_getTransactionByHash", [hash]);
  }

  async getTransactionReceipt(hash: string): Promise<TransactionReceipt | null> {
    const row = await this.call<RawReceipt | null>("kovanica_getTransactionReceipt", [hash]);
    if (row == null) return null;
    return {
      transactionHash: row.transactionHash,
      blockHash: row.blockHash,
      blockNumber: parseQuantity(row.blockNumber),
      transactionIndex:
        row.transactionIndex == null ? null : parseQuantity(row.transactionIndex),
      status: row.status,
      success: row.success,
    };
  }

  async getLeaderSchedule(count = 8): Promise<LeaderSlot[]> {
    const rows = await this.call<RawLeader[]>( "kovanica_getLeaderSchedule", [count]);
    return rows.map((row) => ({
      round: parseQuantity(row.round),
      leaderIndex: row.leader_index,
      leaderAddress: row.leader_address,
    }));
  }

  async getCommittee(): Promise<CommitteeMember[]> {
    const rows = await this.call<RawMember[]>("kovanica_getCommittee");
    return rows.map((row) => ({
      index: row.index,
      address: row.address,
      stake: parseQuantity(row.stake),
      networkAddress: row.network_address,
    }));
  }

  /** `GET /health` on the same host as the JSON-RPC URL. */
  async health(): Promise<HealthStatus> {
    const root = this.url.replace(/\/rpc\/?$/, "");
    const res = await fetch(`${root}/health`);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const body = (await res.json()) as { status?: string; peer_count?: number };
    return {
      status: body.status ?? "unknown",
      peerCount: typeof body.peer_count === "number" ? body.peer_count : 0,
    };
  }
}

export interface TransactionReceipt {
  transactionHash: string;
  blockHash: string;
  blockNumber: bigint;
  transactionIndex: bigint | null;
  status: string;
  success: boolean;
}

export interface LeaderSlot {
  round: bigint;
  leaderIndex: number;
  leaderAddress: string;
}

export interface CommitteeMember {
  index: number;
  address: string;
  stake: bigint;
  networkAddress: string;
}

export interface HealthStatus {
  status: string;
  peerCount: number;
}

interface RawReceipt {
  transactionHash: string;
  blockHash: string;
  blockNumber: unknown;
  transactionIndex: unknown;
  status: string;
  success: boolean;
}

interface RawLeader {
  round: unknown;
  leader_index: number;
  leader_address: string;
}

interface RawMember {
  index: number;
  address: string;
  stake: unknown;
  network_address: string;
}

/** Pull a `newHeads` payload out of a WebSocket notification, or null. */
export function subscriptionHead(message: unknown): unknown | null {
  if (!message || typeof message !== "object") return null;
  const msg = message as { method?: string; params?: { result?: unknown } };
  if (msg.method !== "kovanica_subscription") return null;
  return msg.params?.result ?? null;
}

/**
 * Subscribe to `newHeads`. Returns a function that closes the socket.
 * The node pushes a block object on each accepted block.
 */
export function subscribeNewHeads(
  wsUrl: string,
  onHead: (head: unknown) => void,
  onError?: (error: Event) => void,
): () => void {
  const ws = new WebSocket(wsUrl);
  let subscription: string | null = null;
  ws.onopen = () => {
    ws.send(
      JSON.stringify({
        jsonrpc: "2.0",
        id: 1,
        method: "subscribe",
        params: ["newHeads"],
      }),
    );
  };
  ws.onmessage = (event) => {
    let message: unknown;
    try {
      message = JSON.parse(String(event.data));
    } catch {
      return;
    }
    if (
      message &&
      typeof message === "object" &&
      (message as { id?: number }).id === 1 &&
      typeof (message as { result?: unknown }).result === "string"
    ) {
      subscription = (message as { result: string }).result;
      return;
    }
    const head = subscriptionHead(message);
    if (head != null) onHead(head);
  };
  ws.onerror = (event) => onError?.(event);
  return () => {
    if (ws.readyState === WebSocket.OPEN && subscription) {
      ws.send(
        JSON.stringify({
          jsonrpc: "2.0",
          id: 2,
          method: "unsubscribe",
          params: [subscription],
        }),
      );
    }
    ws.close();
  };
}
