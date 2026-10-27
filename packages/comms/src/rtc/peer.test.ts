import { describe, expect, it, vi } from "vitest";
import { PeerConnection, type PeerState } from "./peer.js";

class MockRTCPeerConnection {
  connectionState: RTCPeerConnectionState = "new";
  localDescription: RTCSessionDescriptionInit | null = null;
  remoteDescription: RTCSessionDescriptionInit | null = null;
  ontrack?: (e: RTCTrackEvent) => void;
  onicecandidate?: (e: RTCPeerConnectionIceEvent) => void;
  onconnectionstatechange?: () => void;
  onsignalingstatechange?: () => void;
  oniceconnectionstatechange?: () => void;

  addTrack = vi.fn();
  createOffer = vi.fn(async () => ({ type: "offer", sdp: "offer" } as RTCSessionDescriptionInit));
  createAnswer = vi.fn(async () => ({ type: "answer", sdp: "answer" } as RTCSessionDescriptionInit));
  setLocalDescription = vi.fn(async (desc: RTCSessionDescriptionInit) => {
    this.localDescription = desc;
  });
  setRemoteDescription = vi.fn(async (desc: RTCSessionDescriptionInit) => {
    this.remoteDescription = desc;
  });
  addIceCandidate = vi.fn(async () => {});
  close = vi.fn();
  getSenders = vi.fn(() => []);
  getReceivers = vi.fn(() => []);

  // Helpers
  triggerTrack(track: any) {
    this.ontrack?.({ track } as any);
  }
  triggerIce(candidate: RTCIceCandidateInit) {
    this.onicecandidate?.({ candidate: { toJSON: () => candidate } } as any);
  }
  triggerConnection(state: RTCPeerConnectionState) {
    this.connectionState = state;
    this.onconnectionstatechange?.();
  }
}

// @ts-ignore
(globalThis as any).RTCPeerConnection = MockRTCPeerConnection;

describe("PeerConnection", () => {
  it("maps states and handles basic lifecycle", async () => {
    const pc = new PeerConnection();
    const states: PeerState[] = [];
    pc.onStateChange((s) => states.push(s));
    const ice: RTCIceCandidateInit[] = [];
    pc.onIceCandidate((c) => ice.push(c));
    const tracks: any[] = [];
    pc.onTrack((t) => tracks.push(t));

    expect(pc.getState()).toBe("idle");
    const offer = await pc.startCall();
    expect(offer.type).toBe("offer");
    expect(states[0]).toBe("connecting");

    // Simulate remote track
    (pc as any).pc.triggerTrack({ kind: "audio" });
    expect(tracks.length).toBe(1);

    // Simulate ICE
    (pc as any).pc.triggerIce({ candidate: "1", sdpMLineIndex: 0 });
    expect(ice.length).toBe(1);

    // Simulate connected
    (pc as any).pc.triggerConnection("connected");
    expect(pc.getState()).toBe("connected");

    pc.hangup();
    expect(pc.getState()).toBe("closed");
  });

  it("acceptOffer sets remote desc and creates answer", async () => {
    const pc = new PeerConnection();
    const offer = { type: "offer", sdp: "offer" } as RTCSessionDescriptionInit;
    const answer = await pc.acceptOffer(offer);
    expect(answer.type).toBe("answer");
    expect((pc as any).pc.setRemoteDescription).toHaveBeenCalledWith(offer);
    expect((pc as any).pc.createAnswer).toHaveBeenCalled();
    expect((pc as any).pc.setLocalDescription).toHaveBeenCalledWith(answer);
  });

  it("buffers candidates until remote description set (initiator setAnswer path)", async () => {
    const pc = new PeerConnection();
    await pc.startCall();
    const c = { candidate: "c1", sdpMLineIndex: 0 };
    await pc.addCandidate(c);
    // Not added yet
    expect((pc as any).pc.addIceCandidate).toHaveBeenCalledTimes(0);
    await pc.setAnswer({ type: "answer", sdp: "a" });
    expect((pc as any).pc.addIceCandidate).toHaveBeenCalledTimes(1);
  });

  it("buffers candidates when accepting offer then flushed on accept", async () => {
    const pc = new PeerConnection();
    const c = { candidate: "c2", sdpMLineIndex: 0 };
    await pc.addCandidate(c); // buffer before remote desc
    const offer = { type: "offer", sdp: "o" } as RTCSessionDescriptionInit;
    await pc.acceptOffer(offer);
    // Buffered candidate flushed after setting remote desc
    expect((pc as any).pc.addIceCandidate).toHaveBeenCalledWith(c);
  });

  it("supports video path with options and methods", async () => {
    const pc = new PeerConnection({ audio: true, video: true });
    const offer = await pc.startCall();
    expect(offer.type).toBe("offer");
    expect((pc as any).pc.createOffer).toHaveBeenCalledWith(
      expect.objectContaining({ offerToReceiveAudio: true, offerToReceiveVideo: true }),
    );

    pc.offerToReceiveVideo(false);
    await pc.startCall();
    expect((pc as any).pc.createOffer).toHaveBeenCalledWith(
      expect.objectContaining({ offerToReceiveAudio: true, offerToReceiveVideo: false }),
    );

    const mockTrack = { kind: "video" } as any;
    const sender = { replaceTrack: vi.fn() } as any;
    (pc as any).pc.getSenders.mockReturnValueOnce([sender]);
    await pc.replaceTrack(null, mockTrack);
    // If no sender matches oldTrack null, it should add track
    expect((pc as any).pc.addTrack).toHaveBeenCalledWith(mockTrack);

    pc.getSenders();
    pc.getReceivers();
    expect((pc as any).pc.getSenders).toHaveBeenCalled();
    expect((pc as any).pc.getReceivers).toHaveBeenCalled();
  });
});
