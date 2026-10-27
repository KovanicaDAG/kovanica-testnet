export type NetworkId = "testnet" | "mainnet" | "local";

export interface Network {
  id: NetworkId;
  label: string;
  chainId: number;
  /** JSON-RPC URL including the `/rpc` path. */
  rpcUrl: string;
  wsUrl: string;
  /** `POST` target. Null hides the faucet. */
  faucetUrl: string | null;
  enabled: boolean;
  soon?: string;
}

export const TESTNET: Network = {
  id: "testnet",
  label: "Testnet",
  // Chain ids: mainnet 1, public testnet 4, devnet 3, local 1337.
  chainId: 4,
  rpcUrl: "https://rpc-testnet.kovanica.online/rpc",
  wsUrl: "wss://rpc-testnet.kovanica.online/ws",
  faucetUrl: "https://seed3.kovanica.online/faucet",
  enabled: true,
};

export const MAINNET: Network = {
  id: "mainnet",
  label: "Mainnet",
  chainId: 1,
  rpcUrl: "https://rpc.kovanica.online/rpc",
  wsUrl: "wss://rpc.kovanica.online/ws",
  faucetUrl: null,
  enabled: false,
  soon: "Mainnet is not open yet.",
};

export const LOCAL: Network = {
  id: "local",
  label: "Local",
  chainId: 1337,
  rpcUrl: "http://127.0.0.1:8545/rpc",
  wsUrl: "ws://127.0.0.1:8545/ws",
  faucetUrl: "http://127.0.0.1:8080/faucet",
  enabled: true,
};

/** Production builds omit the local node. Mainnet stays listed and disabled. */
export function networksFor(production: boolean): Network[] {
  return production ? [TESTNET, MAINNET] : [TESTNET, MAINNET, LOCAL];
}

export function resolveNetwork(
  requested: string | null,
  stored: string | null,
  networks: Network[],
): Network {
  for (const id of [requested, stored, "testnet"]) {
    const found = networks.find((network) => network.id === id && network.enabled);
    if (found) return found;
  }
  const fallback = networks.find((network) => network.enabled);
  if (!fallback) throw new Error("no enabled network");
  return fallback;
}

/** Message when a requested id exists but cannot be selected. */
export function rejectionMessage(id: string | null, networks: Network[]): string | null {
  if (!id) return null;
  const found = networks.find((network) => network.id === id);
  if (!found || found.enabled) return null;
  return found.soon ?? "That network is not open yet.";
}

export function rpcHost(rpcUrl: string): string {
  return new URL(rpcUrl).host;
}

export const NETWORK_STORAGE_KEY = "kovanica.console.network";

export function activityStorageKey(networkId: NetworkId): string {
  return `kovanica.console.activity.${networkId}`;
}
