import { describe, expect, it, vi } from "vitest";
import { SignalChannel } from "./signal.js";

describe("SignalChannel", () => {
  it("serializes and correlates by callId", async () => {
    const sendEnvelope = vi.fn(async (_to: string, _env: any) => {});
    const ch = new SignalChannel(sendEnvelope);
    const payload = {
      kind: "webrtc-signal" as const,
      type: "offer" as const,
      callId: "call-123",
      sdp: "v=0",
    };
    await ch.send("to-abc", payload);
    expect(sendEnvelope).toHaveBeenCalledTimes(1);
    const calls = sendEnvelope.mock.calls as Array<[string, any]>;
    expect(calls.length).toBe(1);
    const [to, env] = calls[0];
    expect(to).toBe("to-abc");
    expect(env.kind).toBe("webrtc-signal");
    const parsed = JSON.parse(env.body);
    expect(parsed.callId).toBe("call-123");
    expect(parsed.type).toBe("offer");
  });

  it("validates callId and kind", async () => {
    const sendEnvelope = vi.fn(async () => {});
    const ch = new SignalChannel(sendEnvelope);
    await expect(
      ch.send("to", { kind: "webrtc-signal", type: "offer", callId: "" } as any),
    ).rejects.toThrow("callId is required");
  });

  it("receives and emits signal events", () => {
    const sendEnvelope = vi.fn(async () => {});
    const ch = new SignalChannel(sendEnvelope);
    const received: any[] = [];
    const unsub = ch.onSignal((evt) => received.push(evt));
    const payload = {
      kind: "webrtc-signal" as const,
      body: JSON.stringify({
        kind: "webrtc-signal",
        type: "answer" as const,
        callId: "call-1",
        sdp: "v=0",
      }),
      ts: Date.now(),
    };
    ch.receive(payload, "from-1");
    expect(received.length).toBe(1);
    expect(received[0].payload.callId).toBe("call-1");
    expect(received[0].payload.type).toBe("answer");
    expect(received[0].from).toBe("from-1");
    unsub();
    ch.receive(payload, "from-2");
    expect(received.length).toBe(1);
  });

  it("unsubscribes listeners", () => {
    const sendEnvelope = vi.fn(async () => {});
    const ch = new SignalChannel(sendEnvelope);
    const received: any[] = [];
    const unsub = ch.onSignal((evt) => received.push(evt));
    unsub();
    ch.receive(
      {
        kind: "webrtc-signal",
        body: JSON.stringify({ kind: "webrtc-signal", type: "bye", callId: "x" }),
        ts: Date.now(),
      },
      "f",
    );
    expect(received.length).toBe(0);
  });
});
