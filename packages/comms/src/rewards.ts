/**
 * Relay incentives & decentralization (M5) — minimal client helpers.
 *
 * Discovery priority: override > registry > fallback (backward compatible).
 * All operations are ledger-safe and do not assume chain polling in request paths.
 */

export type Address = string;
export type CommsId = string;

export interface Endpoint {
  scheme: 0 | 1 | 2 | 3 | 4; // 0=http,1=ws,2=rtc,3=p2p,4=other
  host: string;
  port: number;
  path?: string;
  tls: boolean;
}

export interface FeeSchedule {
  unit: 0 | 1 | 2 | 3; // 0=msg,1=byte,2=sec,3=window
  rateAtoms: bigint;
  minAtoms: bigint;
  maxAtoms: bigint;
  currencyNative: boolean;
  validFrom: number;
}

export interface Rep {
  ok: bigint;
  rej: bigint;
  claimed: bigint;
  ts: number;
}

export type Status = "Active" | "Inactive" | "Jailed" | "Unbonding";

export interface Operator {
  owner: Address;
  bond: bigint;
  endpoints: Endpoint[];
  fee: FeeSchedule;
  status: Status;
  rep: Rep;
  version: number;
  updatedAt: number;
  meta?: Uint8Array | null;
}

export interface RelayChoice {
  relayId: Address;
  endpoints: Endpoint[];
  fee: FeeSchedule;
  bond: bigint;
  rep: Rep;
  status: Status;
  source: "override" | "registry" | "fallback";
}

export interface SelectRelayOptions {
  prefer?: Address | null;
  minBond?: bigint | null;
  maxRateAtomsPerUnit?: bigint | null;
  schemeAllow?: (0 | 1 | 2 | 3 | 4)[] | null;
  repMinOkRatio?: number | null; // advisory
}

export interface RegistryClient {
  getRegistryParams(): Promise<unknown>;
  getRelay(addr: Address): Promise<Operator | null>;
  listActive(opts: { limit: number; offset: number }): Promise<Array<[Address, Operator]>>;
}

export interface RelayDiscoveryConfig {
  overrideRelayId?: Address | null;
  overrideEndpoints?: Endpoint[] | null;
  registry?: RegistryClient | null;
  fallbackRelays?: Array<{ relayId: Address; endpoints: Endpoint[]; fee: FeeSchedule }>;
}

/** Default fallback (content-blind self-hosted shape). */
const DEFAULT_FALLBACK: NonNullable<RelayDiscoveryConfig["fallbackRelays"]> = [];

export class RelayDiscovery {
  private readonly cfg: RelayDiscoveryConfig;

  constructor(cfg: RelayDiscoveryConfig = {}) {
    this.cfg = cfg;
  }

  private filterByScheme(endpoints: Endpoint[], allow?: SelectRelayOptions["schemeAllow"] | null): Endpoint[] {
    if (!allow || allow.length === 0) return endpoints;
    const set = new Set<Endpoint["scheme"]>(allow);
    return endpoints.filter((e) => set.has(e.scheme));
  }

  private meetsMinBond(bond: bigint, minBond?: bigint | null): boolean {
    if (minBond == null) return true;
    return bond >= minBond;
  }

  async selectRelay(opts: SelectRelayOptions = {}): Promise<RelayChoice> {
    // 1) override
    if (this.cfg.overrideRelayId || this.cfg.overrideEndpoints) {
      return {
        relayId: this.cfg.overrideRelayId ?? "override",
        endpoints: this.cfg.overrideEndpoints ?? [],
        fee: {
          unit: 0,
          rateAtoms: 0n,
          minAtoms: 0n,
          maxAtoms: 0n,
          currencyNative: true,
          validFrom: 0,
        },
        bond: 0n,
        rep: { ok: 0n, rej: 0n, claimed: 0n, ts: 0 },
        status: "Active",
        source: "override",
      };
    }

    // 2) registry
    if (this.cfg.registry) {
      const active = await this.cfg.registry.listActive({ limit: 50, offset: 0 });
      for (const [addr, op] of active) {
        if (op.status !== "Active") continue;
        if (!this.meetsMinBond(op.bond, opts.minBond)) continue;
        if (opts.maxRateAtomsPerUnit != null && op.fee.rateAtoms > opts.maxRateAtomsPerUnit) continue;
        const endpoints = this.filterByScheme(op.endpoints, opts.schemeAllow);
        if (endpoints.length === 0) continue;
        return {
          relayId: addr,
          endpoints,
          fee: op.fee,
          bond: op.bond,
          rep: op.rep,
          status: op.status,
          source: "registry",
        };
      }
    }

    // 3) fallback
    const fb = this.cfg.fallbackRelays ?? DEFAULT_FALLBACK;
    if (fb.length > 0) {
      const first = fb[0];
      return {
        relayId: first.relayId,
        endpoints: first.endpoints,
        fee: first.fee,
        bond: 0n,
        rep: { ok: 0n, rej: 0n, claimed: 0n, ts: 0 },
        status: "Active",
        source: "fallback",
      };
    }

    throw new Error("No relay available (override/registry/fallback empty)");
  }
}
