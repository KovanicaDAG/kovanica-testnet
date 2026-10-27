import { describe, expect, it } from "vitest";
import { RelayDiscovery } from "./rewards.js";

describe("rewards", () => {
  it("uses override > registry > fallback", async () => {
    const disc = new RelayDiscovery({
      overrideRelayId: "override-123",
      overrideEndpoints: [
        { scheme: 0, host: "relay.local", port: 8080, tls: false },
      ],
    });
    const choice = await disc.selectRelay();
    expect(choice.source).toBe("override");
    expect(choice.relayId).toBe("override-123");
  });

  it("falls back when nothing available", async () => {
    const disc = new RelayDiscovery({ fallbackRelays: [] });
    await expect(disc.selectRelay()).rejects.toThrow("No relay available");
  });
});
