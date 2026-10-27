import { describe, expect, it } from "vitest";
import { MockSfu, type SfuJoinOpts } from "./sfu.js";

describe("MockSfu", () => {
  it("joins and emits state changes", async () => {
    const sfu = new MockSfu();
    const states: string[] = [];
    sfu.onStateChange((s) => states.push(s));
    await sfu.join({ roomId: "r1", userId: "u1" } as SfuJoinOpts);
    expect(sfu.getState()).toBe("joined");
    expect(states).toContain("joining");
    expect(states).toContain("joined");
    await sfu.leave();
    expect(sfu.getState()).toBe("left");
  });

  it("handles peer join/leave events", async () => {
    const sfu = new MockSfu();
    const joins: string[] = [];
    const leaves: string[] = [];
    sfu.onPeerJoin((p) => joins.push(p));
    sfu.onPeerLeave((p) => leaves.push(p));
    await sfu.join({ roomId: "r1", userId: "u1" } as SfuJoinOpts);
    sfu.simulatePeerJoin("p2");
    expect(joins).toContain("p2");
    sfu.simulatePeerLeave("p2");
    expect(leaves).toContain("p2");
  });

  it("subscribe triggers peer join", async () => {
    const sfu = new MockSfu();
    const joins: string[] = [];
    sfu.onPeerJoin((p) => joins.push(p));
    await sfu.subscribe({} as any, "peer3");
    expect(joins).toContain("peer3");
  });

  it("publish is no-op", async () => {
    const sfu = new MockSfu();
    await expect(sfu.publish({} as any)).resolves.toBeUndefined();
  });
});
