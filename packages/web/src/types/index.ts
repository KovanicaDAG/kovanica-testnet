// Kovanica Web App Types

export interface Block {
  hash: string;
  round: number;
  parent_hashes: string[];
  transactions: Transaction[];
  author: number;
  timestamp: number;
}

export interface ExplorerBlock {
  hash: string;
  round: number;
  parent_hashes: string[];
  transactions: ExplorerTransaction[];
  author: number;
  timestamp: number;
}

export interface ExplorerTransaction {
  hash: string;
  sender: string;
  nonce: number;
  fee: string;
  kind: TransactionKind;
  timestamp?: number;
}

export interface Transaction {
  hash: string;
  raw?: string;
  sender: string;
  nonce: number;
  fee: number;
  kind: TransactionKind;
  timestamp?: number;
}

export type TransactionKind =
  | { type: 'Transfer'; to: string; amount: string }
  | { type: 'Stake'; amount: string }
  | { type: 'Unstake'; amount: string }
  | { type: 'Delegate'; validator: string; amount: string }
  | { type: 'ClaimRewards'; validator?: string }
  | { type: 'Deploy'; code: string }
  | { type: 'Call'; contract: string; method: string; args: string[] }
  | { type: 'Other'; data: string };

export interface Account {
  address: string;
  balance: string;
  nonce: number;
  code_hash?: string;
  is_contract: boolean;
}

export interface Validator {
  address: string;
  stake: string;
  commission_bps: number;
  active: boolean;
  payout_address: string;
  public_key?: string;
}

export interface NetworkStatus {
  block_height: number;
  peer_count: number;
  mempool_size: number;
  latest_block_hash: string;
  latest_block_time: number;
  validators_active: number;
  validators_total: number;
}

export interface RpcConfig {
  url: string;
  chain_id: number;
}

export const DEFAULT_RPC_URL = ((import.meta as unknown as { env?: Record<string, string> }).env?.VITE_RPC_URL) || 'https://rpc-testnet.kovanica.online';
export const DEFAULT_CHAIN_ID = Number((import.meta as unknown as { env?: Record<string, string> }).env?.VITE_CHAIN_ID) || 4;

export function formatAddress(address: string): string {
  if (address.length <= 16) return address;
  return `${address.slice(0, 8)}...${address.slice(-8)}`;
}

export function formatAmount(amount: string, decimals = 9): string {
  const num = BigInt(amount);
  const divisor = BigInt(10 ** decimals);
  const whole = num / divisor;
  const frac = num % divisor;
  if (frac === 0n) return whole.toString();
  const fracStr = frac.toString().padStart(decimals, '0').replace(/0+$/, '');
  return `${whole}.${fracStr}`;
}

export function formatTimestamp(ts: number): string {
  return new Date(ts).toLocaleString();
}

export function formatRelativeTime(ts: number): string {
  const diff = Date.now() - ts;
  if (diff < 60000) return `${Math.floor(diff / 1000)}s ago`;
  if (diff < 3600000) return `${Math.floor(diff / 60000)}m ago`;
  if (diff < 86400000) return `${Math.floor(diff / 3600000)}h ago`;
  return `${Math.floor(diff / 86400000)}d ago`;
}