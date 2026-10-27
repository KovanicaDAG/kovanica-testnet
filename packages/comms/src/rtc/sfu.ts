/**
 * Minimal SFU client interface (client-only, stubbed).
 * Uses PeerConnection conceptually; keep minimal and testable.
 */

import type { PeerConnection } from "./peer.js";

export interface SfuJoinOpts {
  roomId: string;
  userId: string;
  audio?: boolean;
  video?: boolean;
  [key: string]: unknown;
}

export type SfuState = "idle" | "joining" | "joined" | "left" | "error";

export interface SfuClient {
  join(opts: SfuJoinOpts): Promise<void>;
  leave(): Promise<void>;
  publish(pc: PeerConnection): Promise<void>;
  subscribe(pc: PeerConnection, peerId: string): Promise<void>;
  getState(): SfuState;
  onStateChange(handler: (state: SfuState) => void): () => void;
  onPeerJoin(handler: (peerId: string) => void): () => void;
  onPeerLeave(handler: (peerId: string) => void): () => void;
}

export class MockSfu implements SfuClient {
  private state: SfuState = "idle";
  private stateHandlers: ((s: SfuState) => void)[] = [];
  private joinHandlers: ((peerId: string) => void)[] = [];
  private leaveHandlers: ((peerId: string) => void)[] = [];
  private peers: Set<string> = new Set();

  private setState(s: SfuState): void {
    this.state = s;
    for (const h of this.stateHandlers) {
      try {
        h(s);
      } catch {}
    }
  }

  async join(opts: SfuJoinOpts): Promise<void> {
    this.setState("joining");
    // minimal mock behavior
    if (opts.userId) {
      this.peers.add(opts.userId);
    }
    this.setState("joined");
  }

  async leave(): Promise<void> {
    this.setState("left");
  }

  async publish(_pc: PeerConnection): Promise<void> {
    // no-op
  }

  async subscribe(_pc: PeerConnection, peerId: string): Promise<void> {
    this.peers.add(peerId);
    for (const h of this.joinHandlers) {
      try {
        h(peerId);
      } catch {}
    }
  }

  getState(): SfuState {
    return this.state;
  }

  onStateChange(handler: (state: SfuState) => void): () => void {
    this.stateHandlers.push(handler);
    return () => {
      const idx = this.stateHandlers.indexOf(handler);
      if (idx !== -1) this.stateHandlers.splice(idx, 1);
    };
  }

  onPeerJoin(handler: (peerId: string) => void): () => void {
    this.joinHandlers.push(handler);
    return () => {
      const idx = this.joinHandlers.indexOf(handler);
      if (idx !== -1) this.joinHandlers.splice(idx, 1);
    };
  }

  onPeerLeave(handler: (peerId: string) => void): () => void {
    this.leaveHandlers.push(handler);
    return () => {
      const idx = this.leaveHandlers.indexOf(handler);
      if (idx !== -1) this.leaveHandlers.splice(idx, 1);
    };
  }

  simulatePeerJoin(peerId: string): void {
    this.peers.add(peerId);
    for (const h of this.joinHandlers) {
      try {
        h(peerId);
      } catch {}
    }
  }

  simulatePeerLeave(peerId: string): void {
    this.peers.delete(peerId);
    for (const h of this.leaveHandlers) {
      try {
        h(peerId);
      } catch {}
    }
  }
}
