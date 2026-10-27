import { activityStorageKey, type NetworkId } from "./network";

export interface ActivityItem {
  hash: string;
  networkId: NetworkId;
  summary: string;
  fee: string;
  submittedAt: number;
  status: "pending" | "committed";
}

export function loadActivity(networkId: NetworkId): ActivityItem[] {
  const raw = localStorage.getItem(activityStorageKey(networkId));
  if (!raw) return [];
  try {
    const parsed = JSON.parse(raw) as ActivityItem[];
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}

export function saveActivity(networkId: NetworkId, items: ActivityItem[]): void {
  localStorage.setItem(activityStorageKey(networkId), JSON.stringify(items.slice(0, 50)));
}

export function rememberActivity(item: ActivityItem): ActivityItem[] {
  const next = [item, ...loadActivity(item.networkId).filter((row) => row.hash !== item.hash)];
  saveActivity(item.networkId, next);
  return next;
}
