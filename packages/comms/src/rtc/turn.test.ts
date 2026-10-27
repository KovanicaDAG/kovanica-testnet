import { describe, expect, it } from "vitest";
import { TurnManager } from "./turn.js";

describe("TurnManager", () => {
  it("requests allocation and returns allocation info", async () => {
    const tm = new TurnManager();
    const alloc = await tm.requestAllocation({ ttlSeconds: 120 });
    expect(alloc).toBeTruthy();
    expect(alloc.lifetime).toBe(120);
    expect(alloc.expiresAt).toBeGreaterThan(Date.now());
    expect(tm.getAllocation()).toEqual(alloc);
  });

  it("renewal updates expiry", async () => {
    const tm = new TurnManager({ ttlSeconds: 60 });
    const a1 = await tm.requestAllocation();
    const before = a1.expiresAt;
    await new Promise((r) => setTimeout(r, 2));
    const a2 = await tm.renewAllocation();
    expect(a2.expiresAt).toBeGreaterThanOrEqual(before);
    expect(tm.getAllocation()).toBe(a2);
  });

  it("releaseAllocation clears allocation", async () => {
    const tm = new TurnManager();
    await tm.requestAllocation();
    expect(tm.getAllocation()).not.toBeNull();
    await tm.releaseAllocation();
    expect(tm.getAllocation()).toBeNull();
  });

  it("needsRenewal detects near expiry", async () => {
    const tm = new TurnManager({ ttlSeconds: 10 });
    await tm.requestAllocation();
    // Mock expiry in past
    (tm as any).allocation.expiresAt = Date.now() - 1000;
    expect(tm.needsRenewal()).toBe(true);
    await tm.releaseAllocation();
    expect(tm.needsRenewal()).toBe(false);
  });
});
