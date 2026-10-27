/**
 * WebRTC peer connection wrapper (audio-only).
 * Matches the M3 design from ora-2.
 */
export type PeerState =
  | "idle"
  | "connecting"
  | "connected"
  | "failed"
  | "closed"
  | "disconnected";

export interface PeerOptions {
  iceServers?: RTCIceServer[];
  audio?: boolean;
  video?: boolean;
}

export type TrackHandler = (track: MediaStreamTrack) => void;
export type StateChangeHandler = (state: PeerState) => void;
export type IceCandidateHandler = (candidate: RTCIceCandidateInit) => void;
export type ErrorHandler = (err: unknown) => void;

export class PeerConnection {
  private pc: RTCPeerConnection;
  private state: PeerState = "idle";
  private remoteDescSet = false;
  private candidates: RTCIceCandidateInit[] = [];
  private tracks: MediaStreamTrack[] = [];
  private onTrackHandlers: TrackHandler[] = [];
  private onStateHandlers: StateChangeHandler[] = [];
  private onIceHandlers: IceCandidateHandler[] = [];
  private onErrorHandlers: ErrorHandler[] = [];
  private options: PeerOptions;

  constructor(options: PeerOptions = {}) {
    this.options = options;
    const pcConfig: RTCConfiguration = {
      iceServers: options.iceServers ?? [{ urls: "stun:stun.l.google.com:19302" }],
    };
    this.pc = new RTCPeerConnection(pcConfig);
    this.pc.ontrack = (event) => {
      const track = event.track;
      this.tracks.push(track);
      for (const h of this.onTrackHandlers) {
        try {
          h(track);
        } catch (err) {
          this.emitError(err);
        }
      }
    };
    this.pc.onicecandidate = (event) => {
      if (event.candidate) {
        for (const h of this.onIceHandlers) {
          try {
            h(event.candidate.toJSON());
          } catch (err) {
            this.emitError(err);
          }
        }
      }
    };
    this.pc.onconnectionstatechange = () => {
      this.updateState(this.mapState(this.pc.connectionState));
    };
    this.pc.onsignalingstatechange = () => {
      // no-op, but keep for completeness
    };
    this.pc.oniceconnectionstatechange = () => {
      // track via connection state
    };
    this.updateState("idle");
  }

  private mapState(state: RTCPeerConnectionState): PeerState {
    switch (state) {
      case "new":
      case "connecting":
        return "connecting";
      case "connected":
        return "connected";
      case "disconnected":
        return "disconnected";
      case "failed":
        return "failed";
      case "closed":
        return "closed";
      default:
        return "idle";
    }
  }

  private updateState(s: PeerState): void {
    this.state = s;
    for (const h of this.onStateHandlers) {
      try {
        h(s);
      } catch (err) {
        this.emitError(err);
      }
    }
  }

  private emitError(err: unknown): void {
    for (const h of this.onErrorHandlers) {
      try {
        h(err);
      } catch {}
    }
  }

  getState(): PeerState {
    return this.state;
  }

  onTrack(handler: TrackHandler): () => void {
    this.onTrackHandlers.push(handler);
    return () => {
      const idx = this.onTrackHandlers.indexOf(handler);
      if (idx !== -1) this.onTrackHandlers.splice(idx, 1);
    };
  }

  onStateChange(handler: StateChangeHandler): () => void {
    this.onStateHandlers.push(handler);
    return () => {
      const idx = this.onStateHandlers.indexOf(handler);
      if (idx !== -1) this.onStateHandlers.splice(idx, 1);
    };
  }

  onIceCandidate(handler: IceCandidateHandler): () => void {
    this.onIceHandlers.push(handler);
    return () => {
      const idx = this.onIceHandlers.indexOf(handler);
      if (idx !== -1) this.onIceHandlers.splice(idx, 1);
    };
  }

  onError(handler: ErrorHandler): () => void {
    this.onErrorHandlers.push(handler);
    return () => {
      const idx = this.onErrorHandlers.indexOf(handler);
      if (idx !== -1) this.onErrorHandlers.splice(idx, 1);
    };
  }

  async startCall(localStream?: MediaStream): Promise<RTCSessionDescriptionInit> {
    this.updateState("connecting");
    if (localStream) {
      for (const track of localStream.getTracks()) {
        this.pc.addTrack(track);
      }
    } else {
      // If no stream provided, do not add tracks; flags apply to receive direction
    }
    const audio = this.options.audio !== false;
    const video = this.options.video === true;
    const offer = await this.pc.createOffer({
      offerToReceiveAudio: audio,
      offerToReceiveVideo: video,
    });
    await this.pc.setLocalDescription(offer);
    return offer;
  }

  async acceptOffer(offer: RTCSessionDescriptionInit, localStream?: MediaStream): Promise<RTCSessionDescriptionInit> {
    this.updateState("connecting");
    await this.pc.setRemoteDescription(offer);
    this.remoteDescSet = true;
    // Flush buffered candidates
    for (const c of this.candidates) {
      try {
        await this.pc.addIceCandidate(c);
      } catch (err) {
        this.emitError(err);
      }
    }
    this.candidates = [];
    if (localStream) {
      for (const track of localStream.getTracks()) {
        this.pc.addTrack(track);
      }
    }
    const answer = await this.pc.createAnswer();
    await this.pc.setLocalDescription(answer);
    return answer;
  }

  async setAnswer(answer: RTCSessionDescriptionInit): Promise<void> {
    if (!this.remoteDescSet) {
      // Set remote desc if not set? But typically initiator sets after getting answer
      await this.pc.setRemoteDescription(answer);
      this.remoteDescSet = true;
      for (const c of this.candidates) {
        try {
          await this.pc.addIceCandidate(c);
        } catch (err) {
          this.emitError(err);
        }
      }
      this.candidates = [];
      return;
    }
    await this.pc.setRemoteDescription(answer);
  }

  async addCandidate(candidate: RTCIceCandidateInit): Promise<void> {
    if (!this.remoteDescSet) {
      this.candidates.push(candidate);
      return;
    }
    try {
      await this.pc.addIceCandidate(candidate);
    } catch (err) {
      this.emitError(err);
    }
  }

  setMuted(muted: boolean): void {
    for (const track of this.tracks) {
      if (track.kind === "audio") {
        track.enabled = !muted;
      }
    }
    // Also mute local senders if present
    for (const sender of this.pc.getSenders()) {
      const track = sender.track;
      if (track && track.kind === "audio") {
        track.enabled = !muted;
      }
    }
  }

  hangup(): void {
    this.updateState("closed");
    for (const track of this.tracks) {
      try {
        track.stop();
      } catch {}
    }
    this.tracks = [];
    try {
      this.pc.close();
    } catch {}
  }

  addTrack(track: MediaStreamTrack, ...streams: MediaStream[]): RTCRtpSender {
    return this.pc.addTrack(track, ...streams);
  }

  async replaceTrack(oldTrack: MediaStreamTrack | null, newTrack: MediaStreamTrack | null): Promise<void> {
    const senders = this.pc.getSenders();
    let replaced = false;
    for (const sender of senders) {
      if (sender.track === oldTrack) {
        await sender.replaceTrack(newTrack);
        replaced = true;
        break;
      }
    }
    if (!replaced && newTrack) {
      this.pc.addTrack(newTrack);
    }
  }

  getSenders(): RTCRtpSender[] {
    return this.pc.getSenders();
  }

  getReceivers(): RTCRtpReceiver[] {
    return this.pc.getReceivers();
  }

  offerToReceiveVideo(offer: boolean): void {
    this.options.video = offer;
  }
}
