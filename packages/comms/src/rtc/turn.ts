/**
 * TURN manager (client-side types and minimal logic).
 * Matches the M3 design from ora-2.
 */
export type RelayControlKind =
  | "turn-alloc-request"
  | "turn-alloc-response"
  | "turn-alloc-release"
  | "turn-exhausted";

export interface TurnConfig {
  server?: string;
  username?: string;
  credential?: string;
  ttlSeconds?: number;
}

export interface TurnAllocation {
  relayedAddress?: string;
  relayedPort?: number;
  lifetime?: number;
  expiresAt: number;
}

export interface TurnManager {
  requestAllocation(config?: TurnConfig): Promise<TurnAllocation>;
  releaseAllocation(): Promise<void>;
  renewAllocation(): Promise<TurnAllocation>;
  getAllocation(): TurnAllocation | null;
  needsRenewal(): boolean;
  close(): void;
}

export class TurnManager implements TurnManager {
  private allocation: TurnAllocation | null = null;
  private closed = false;
  // private renewing = false;

  constructor(private config: TurnConfig = {}) {}

  async requestAllocation(config?: TurnConfig): Promise<TurnAllocation> {
    if (this.closed) throw new Error("TurnManager is closed");
    const cfg = { ...this.config, ...config };
    const ttl = cfg.ttlSeconds ?? 600;
    const expiresAt = Date.now() + ttl * 1000;
    this.allocation = {
      relayedAddress: "127.0.0.1",
      relayedPort: 3478,
      lifetime: ttl,
      expiresAt,
    };
    return this.allocation;
  }

  async releaseAllocation(): Promise<void> {
    this.allocation = null;
  }

  async renewAllocation(): Promise<TurnAllocation> {
    if (this.closed) throw new Error("TurnManager is closed");
    const cfg = this.config;
    const ttl = cfg.ttlSeconds ?? 600;
    const expiresAt = Date.now() + ttl * 1000;
    this.allocation = {
      relayedAddress: this.allocation?.relayedAddress ?? "127.0.0.1",
      relayedPort: this.allocation?.relayedPort ?? 3478,
      lifetime: ttl,
      expiresAt,
    };
    return this.allocation;
  }

  getAllocation(): TurnAllocation | null {
    return this.allocation;
  }

  needsRenewal(): boolean {
    if (!this.allocation) return false;
    const margin = 30 * 1000; // 30s
    return Date.now() > this.allocation.expiresAt - margin;
  }

  close(): void {
    this.closed = true;
    this.allocation = null;
  }
}
