import { describe, expect, it } from "vitest";

import { endpointLine, peerLines, statusRows, type NodeStatus } from "./connection";

function status(overrides: Partial<NodeStatus> = {}): NodeStatus {
  return {
    chainId: "4",
    chainNote: "Proven by commit seals.",
    height: "1200",
    leaderRound: "3600",
    epoch: "0",
    peerCount: "2",
    peers: [{ peerId: "12D3KooWexample", reportedTipRound: "3601" }],
    ...overrides,
  };
}

describe("connection screen", () => {
  it("shows chain id, height, leader round, epoch, and peers as text", () => {
    const rows = statusRows(status());
    expect(rows.map((row) => row.label)).toEqual([
      "Chain id",
      "Chain check",
      "Height (reported by node)",
      "Leader round",
      "Epoch",
      "Peers (reported by node)",
    ]);
    expect(rows.map((row) => row.value)).toEqual([
      "4",
      "Proven by commit seals.",
      "1200",
      "3600",
      "0",
      "2",
    ]);
  });

  it("keeps a height that does not fit in a safe integer", () => {
    const height = "9007199254740993";
    const rows = statusRows(status({ height }));
    expect(rows.find((row) => row.label === "Height (reported by node)")?.value).toBe(height);
  });

  it("does not invent a chain id or a leader round", () => {
    const rows = statusRows(
      status({
        chainId: null,
        chainNote: "The node has not sealed a leader yet, so the chain id is not proven.",
        leaderRound: null,
        epoch: null,
        peers: [],
      }),
    );
    expect(rows.find((row) => row.label === "Chain id")?.value).toBe("Unknown");
    expect(rows.find((row) => row.label === "Leader round (reported by node)")?.value).toBe("—");
    expect(rows.find((row) => row.label === "Epoch (reported by node)")?.value).toBe("—");
    expect(rows.find((row) => row.label === "Height (reported by node)")?.value).toBe("1200");
    expect(rows.find((row) => row.label === "Peers (reported by node)")?.value).toBe("2");
    expect(peerLines([])).toEqual(["No connected peers"]);
  });

  it("prints a peer tip only when the node reported one", () => {
    expect(
      peerLines([
        { peerId: "12D3KooWexample", reportedTipRound: "3601" },
        { peerId: "12D3KooWother", reportedTipRound: null },
      ]),
    ).toEqual(["12D3KooWexample · tip 3601", "12D3KooWother"]);
  });

  it("names the endpoint from the label the backend already chose", () => {
    expect(endpointLine("rpc-testnet.kovanica.online")).toBe(
      "Talking to rpc-testnet.kovanica.online",
    );
  });
});
