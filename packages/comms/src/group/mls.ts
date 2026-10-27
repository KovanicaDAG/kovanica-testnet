/**
 * Minimal MLS-like wrapper interface (client-only, stubbed).
 * No external MLS calls yet - implementations can be mocked for tests.
 */

export type GroupId = Uint8Array | string;
export type MemberId = Uint8Array | string;
export type Epoch = number;

export interface GroupMember {
  id: MemberId;
  [key: string]: unknown;
}

export interface GroupState {
  groupId: GroupId;
  epoch: Epoch;
  members: GroupMember[];
  [key: string]: unknown;
}

export interface MlsMsg {
  type: string;
  data: Uint8Array | string;
  [key: string]: unknown;
}

export interface MlsBackend {
  createGroup(): Promise<GroupState>;
  joinGroup(invite: MlsMsg | unknown): Promise<GroupState>;
  addMember(member: GroupMember | MemberId): Promise<GroupState>;
  removeMember(member: GroupMember | MemberId): Promise<GroupState>;
  encrypt(plaintext: Uint8Array | string): Promise<Uint8Array>;
  decrypt(ciphertext: Uint8Array): Promise<Uint8Array | string>;
  processCommit(commit: MlsMsg): Promise<GroupState>;
  processWelcome(welcome: MlsMsg): Promise<GroupState>;
  exportEpochSecret(): Promise<Uint8Array | string>;
  getState(): Promise<GroupState>;
  closeGroup(): Promise<void>;
}

export class MockMlsBackend implements MlsBackend {
  private state: GroupState = {
    groupId: "mock-group",
    epoch: 0,
    members: [],
  };

  async createGroup(): Promise<GroupState> {
    this.state = { ...this.state, epoch: 0, members: [] };
    return this.getState();
  }

  async joinGroup(_invite: MlsMsg | unknown): Promise<GroupState> {
    this.state = { ...this.state, epoch: this.state.epoch + 1 };
    return this.getState();
  }

  async addMember(member: GroupMember | MemberId): Promise<GroupState> {
    if (typeof member === "object" && member !== null && "id" in (member as any)) {
      const gm = member as GroupMember;
      this.state = {
        ...this.state,
        members: [...this.state.members, { ...gm }],
        epoch: this.state.epoch + 1,
      };
    } else {
      this.state = {
        ...this.state,
        members: [...this.state.members, { id: member as MemberId }],
        epoch: this.state.epoch + 1,
      };
    }
    return this.getState();
  }

  async removeMember(member: GroupMember | MemberId): Promise<GroupState> {
    const targetId = typeof member === "object" && member !== null && "id" in (member as any)
      ? (member as any).id
      : member;
    this.state = {
      ...this.state,
      members: this.state.members.filter((x) => x.id !== targetId),
      epoch: this.state.epoch + 1,
    };
    return this.getState();
  }

  async encrypt(plaintext: Uint8Array | string): Promise<Uint8Array> {
    if (plaintext instanceof Uint8Array) {
      return plaintext;
    }
    return new TextEncoder().encode(plaintext);
  }

  async decrypt(ciphertext: Uint8Array): Promise<Uint8Array | string> {
    return ciphertext;
  }

  async processCommit(_commit: MlsMsg): Promise<GroupState> {
    this.state = { ...this.state, epoch: this.state.epoch + 1 };
    return this.getState();
  }

  async processWelcome(_welcome: MlsMsg): Promise<GroupState> {
    this.state = { ...this.state, epoch: this.state.epoch + 1 };
    return this.getState();
  }

  async exportEpochSecret(): Promise<Uint8Array | string> {
    return new Uint8Array([1, 2, 3, 4]);
  }

  async getState(): Promise<GroupState> {
    return { ...this.state, members: [...this.state.members] };
  }

  async closeGroup(): Promise<void> {
    // no-op
  }
}
