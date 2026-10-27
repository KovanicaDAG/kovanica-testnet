import { describe, expect, it } from "vitest";
import { MockMlsBackend, type MlsMsg } from "./mls.js";

describe("MockMlsBackend", () => {
  it("creates group, adds/removes members, encrypts/decrypts", async () => {
    const backend = new MockMlsBackend();
    const state = await backend.createGroup();
    expect(state.epoch).toBe(0);
    expect(state.members).toEqual([]);

    const afterAdd = await backend.addMember({ id: "alice" });
    expect(afterAdd.members.length).toBe(1);
    expect(afterAdd.epoch).toBe(1);

    const afterRemove = await backend.removeMember("alice");
    expect(afterRemove.members.length).toBe(0);
    expect(afterRemove.epoch).toBe(2);

    const ct = await backend.encrypt("hello");
    expect(ct).toBeInstanceOf(Uint8Array);
    const pt = await backend.decrypt(ct);
    expect(pt).toBeInstanceOf(Uint8Array);

    const ct2 = await backend.encrypt(new Uint8Array([1, 2, 3]));
    expect(ct2).toEqual(new Uint8Array([1, 2, 3]));

    const st = await backend.getState();
    expect(st).toBeDefined();

    await backend.processCommit({ type: "commit", data: "" } as MlsMsg);
    await backend.processWelcome({ type: "welcome", data: "" } as MlsMsg);
    await backend.joinGroup({} as unknown);
    const secret = await backend.exportEpochSecret();
    expect(secret).toBeDefined();

    await backend.closeGroup();
  });

  it("getState returns a copy", async () => {
    const backend = new MockMlsBackend();
    await backend.createGroup();
    await backend.addMember({ id: "bob" });
    const s1 = await backend.getState();
    const s2 = await backend.getState();
    expect(s1).not.toBe(s2);
    expect(s1.members).not.toBe(s2.members);
  });
});
