/**
 * Display model for the connection screen.
 *
 * Amounts and counters arrive as decimal strings from the Rust backend.
 * This module never parses them into numbers.
 */

export interface PeerRow {
  peerId: string;
  reportedTipRound: string | null;
}

export interface NodeStatus {
  chainId: string | null;
  chainNote: string;
  height: string;
  leaderRound: string | null;
  epoch: string | null;
  peerCount: string;
  peers: PeerRow[];
}

export interface ConnectionConfig {
  rpcUrl: string;
  endpointLabel: string;
}

export interface StatusRow {
  label: string;
  value: string;
}

/** A value the console did not prove. The screen says where it came from. */
function reportedByNode(label: string): string {
  return `${label} (reported by node)`;
}

/** Rows for the node panel, in the order the screen shows them. */
export function statusRows(status: NodeStatus): StatusRow[] {
  const proven = status.chainId !== null;
  return [
    { label: "Chain id", value: status.chainId ?? "Unknown" },
    { label: "Chain check", value: status.chainNote },
    { label: reportedByNode("Height"), value: status.height },
    {
      label: proven ? "Leader round" : reportedByNode("Leader round"),
      value: status.leaderRound ?? "—",
    },
    { label: proven ? "Epoch" : reportedByNode("Epoch"), value: status.epoch ?? "—" },
    { label: reportedByNode("Peers"), value: status.peerCount },
  ];
}

/** One line per connected peer. An empty list is a sentence, not a blank. */
export function peerLines(peers: PeerRow[]): string[] {
  if (peers.length === 0) {
    return ["No connected peers"];
  }
  return peers.map((peer) =>
    peer.reportedTipRound === null
      ? peer.peerId
      : `${peer.peerId} · tip ${peer.reportedTipRound}`,
  );
}

/** Where the status screen says it is talking, without parsing the URL. */
export function endpointLine(label: string): string {
  return `Talking to ${label}`;
}
