/**
 * WebRTC signalling channel (E2E over kovanica comms).
 * Matches the M3 design from ora-2.
 */
import type { Payload } from "../messaging.js";

export type SignalType = "offer" | "answer" | "candidate" | "rollback" | "bye";

export interface WebRTCSignalPayload {
  kind: "webrtc-signal";
  type: SignalType;
  callId: string;
  sdp?: string;
  candidate?: RTCIceCandidateInit;
  ice?: RTCIceCandidateInit;
  [key: string]: unknown;
}

export interface SignalOptions {
  maxRetries?: number;
  retryMs?: number;
}

export type SignalEvent = {
  payload: WebRTCSignalPayload;
  from?: string;
};

export type SignalListener = (evt: SignalEvent) => void;

export interface SignalChannel {
  onSignal(listener: SignalListener): () => void;
  send(to: string, payload: WebRTCSignalPayload): Promise<void>;
  close(): void;
}

export class SignalChannel implements SignalChannel {
  private listeners = new Set<SignalListener>();
  private closed = false;

  constructor(
    private sendEnvelope: (to: string, payload: Payload) => Promise<void>,
    _options: SignalOptions = {},
  ) {}

  onSignal(listener: SignalListener): () => void {
    if (this.closed) return () => {};
    this.listeners.add(listener);
    return () => {
      this.listeners.delete(listener);
    };
  }

  protected emit(evt: SignalEvent): void {
    if (this.closed) return;
    for (const listener of this.listeners) {
      try {
        listener(evt);
      } catch (err) {
        // Ignore listener errors
        void err;
      }
    }
  }

  async send(to: string, payload: WebRTCSignalPayload): Promise<void> {
    if (this.closed) {
      throw new Error("SignalChannel is closed");
    }
    if (payload.kind !== "webrtc-signal") {
      throw new Error("Invalid payload kind");
    }
    if (!payload.callId) {
      throw new Error("callId is required");
    }
    const envPayload: Payload = {
      kind: payload.kind,
      body: JSON.stringify(payload),
      ts: Date.now(),
    };
    await this.sendEnvelope(to, envPayload);
  }

  receive(payload: Payload, from?: string): void {
    if (this.closed) return;
    if (payload.kind !== "webrtc-signal") return;
    try {
      const parsed = JSON.parse(payload.body) as Partial<WebRTCSignalPayload>;
      if (parsed.kind !== "webrtc-signal") return;
      if (typeof parsed.callId !== "string" || !parsed.callId) return;
      if (typeof parsed.type !== "string") return;
      const allowed: SignalType[] = ["offer", "answer", "candidate", "rollback", "bye"];
      if (!allowed.includes(parsed.type as SignalType)) return;
      const evtPayload: WebRTCSignalPayload = {
        kind: "webrtc-signal",
        type: parsed.type as SignalType,
        callId: parsed.callId,
        ...parsed,
      };
      this.emit({ payload: evtPayload, from });
    } catch {
      // Ignore malformed signal
    }
  }

  close(): void {
    this.closed = true;
    this.listeners.clear();
  }
}
