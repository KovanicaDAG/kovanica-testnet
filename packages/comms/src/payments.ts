// Side-effect: install the SHA-512 hook on this package's `@noble/ed25519`
// before any synchronous Ed25519 call site runs (module init order matters).
import "./ed25519.js";

import { blake3 } from "@noble/hashes/blake3";
import {
  encodeRawTransaction,
  signTransaction,
  type SignedTx,
  type TxKind,
  type UnsignedTx,
} from "@kovanica/signer";
import { bytesToHex, hexToBytes } from "@kovanica/signer";

const DOMAIN_HTLC_ID = new TextEncoder().encode("htlc/id");

export function u64leBytes(n: bigint): Uint8Array {
  const out = new Uint8Array(8);
  for (let i = 0; i < 8; i += 1) {
    out[i] = Number((n >> BigInt(i * 8)) & 0xffn);
  }
  return out;
}

export function bytesToBytes32(bytes: Uint8Array): Uint8Array {
  if (bytes.length !== 32) {
    throw new Error("expected 32 bytes");
  }
  return bytes;
}

export function hexToBytes32(hex: string): Uint8Array {
  const bytes = hexToBytes(hex);
  if (bytes.length !== 32) {
    throw new Error("expected 32 bytes");
  }
  return bytes;
}

function bytesToBase64Local(bytes: Uint8Array): string {
  let binary = "";
  for (let i = 0; i < bytes.length; i += 1) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

function base64ToBytesLocal(value: string): Uint8Array {
  if (typeof value !== "string") {
    throw new Error("invalid base64");
  }
  let binary: string;
  try {
    binary = atob(value);
  } catch {
    throw new Error("invalid base64");
  }
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) {
    out[i] = binary.charCodeAt(i);
  }
  return out;
}

export { bytesToBase64Local as bytesToBase64, base64ToBytesLocal as base64ToBytes };
export { bytesToHex, hexToBytes };

export function computeHtlcHashLock(preimage: Uint8Array | string): Uint8Array {
  const preimageBytes =
    typeof preimage === "string"
      ? new TextEncoder().encode(preimage)
      : new Uint8Array(preimage);
  return blake3(preimageBytes);
}

export interface HtlcIdParams {
  sender: Uint8Array;
  claimer: Uint8Array;
  amountAtoms: bigint;
  hashLock: Uint8Array;
  expiryMs: bigint;
}

export function computeHtlcId(params: HtlcIdParams): Uint8Array {
  const sender = bytesToBytes32(params.sender);
  const claimer = bytesToBytes32(params.claimer);
  const hashLock = bytesToBytes32(params.hashLock);
  const input = new Uint8Array(
    DOMAIN_HTLC_ID.length + 32 + 32 + 8 + 32 + 8,
  );
  let off = 0;
  input.set(DOMAIN_HTLC_ID, off);
  off += DOMAIN_HTLC_ID.length;
  input.set(sender, off);
  off += 32;
  input.set(claimer, off);
  off += 32;
  input.set(u64leBytes(params.amountAtoms), off);
  off += 8;
  input.set(hashLock, off);
  off += 32;
  input.set(u64leBytes(params.expiryMs), off);
  off += 8;
  return blake3(input);
}

export interface PaymentProof {
  htlcId: string;
  preimage: string;
  amountAtoms: bigint;
  expiry: bigint;
  senderAddr?: string;
  claimerAddr: string;
}

export interface BuildPaymentProofParams extends HtlcIdParams {
  preimage?: Uint8Array | string;
  senderAddr?: string;
}

export function buildPaymentProof(
  preimage: Uint8Array | string,
  params: BuildPaymentProofParams,
): PaymentProof {
  const preimageBytes =
    typeof preimage === "string"
      ? base64ToBytesLocal(preimage)
      : new Uint8Array(preimage);
  const hashLock = params.hashLock ?? computeHtlcHashLock(preimageBytes);
  const id = computeHtlcId({
    sender: params.sender,
    claimer: params.claimer,
    amountAtoms: params.amountAtoms,
    hashLock,
    expiryMs: params.expiryMs,
  });
  const senderAddr = params.senderAddr ?? bytesToHex(bytesToBytes32(params.sender));
  return {
    htlcId: bytesToHex(id),
    preimage: bytesToBase64Local(preimageBytes),
    amountAtoms: params.amountAtoms,
    expiry: params.expiryMs,
    senderAddr,
    claimerAddr: bytesToHex(bytesToBytes32(params.claimer)),
  };
}

export interface CreateHtlcCallParams {
  sender: Uint8Array;
  claimer: Uint8Array;
  hashLock: Uint8Array;
  amountAtoms: bigint;
  expiryMs: bigint;
}

export function buildHtlcCallArgs(
  sender: Uint8Array,
  claimer: Uint8Array,
  hashLock: Uint8Array,
  amountAtoms: bigint,
  expiryMs: bigint,
): Uint8Array {
  const s = bytesToBytes32(sender);
  const c = bytesToBytes32(claimer);
  const h = bytesToBytes32(hashLock);
  const out = new Uint8Array(32 + 32 + 32 + 8 + 8);
  let off = 0;
  out.set(s, off);
  off += 32;
  out.set(c, off);
  off += 32;
  out.set(h, off);
  off += 32;
  out.set(u64leBytes(amountAtoms), off);
  off += 8;
  out.set(u64leBytes(expiryMs), off);
  off += 8;
  return out;
}

export interface CreateHtlcOptions {
  sender: Uint8Array;
  claimer: Uint8Array;
  preimage: Uint8Array | string;
  amountAtoms: bigint;
  expiryMs: bigint;
  nonce: bigint;
  fee: bigint;
  chainId: number;
  senderSeed: Uint8Array;
  gasLimit?: bigint;
}

export async function createHtlcTx(
  options: CreateHtlcOptions,
): Promise<SignedTx> {
  const preimageBytes =
    typeof options.preimage === "string"
      ? new TextEncoder().encode(options.preimage)
      : new Uint8Array(options.preimage);
  const hashLock = computeHtlcHashLock(preimageBytes);
  const kind: TxKind = {
    type: "call",
    contract: bytesToBytes32(options.claimer),
    value: options.amountAtoms,
    method: "create",
    args: buildHtlcCallArgs(
      options.sender,
      options.claimer,
      hashLock,
      options.amountAtoms,
      options.expiryMs,
    ),
    gasLimit: options.gasLimit ?? 100_000n,
  };
  const unsigned: UnsignedTx = {
    sender: bytesToBytes32(options.sender),
    nonce: options.nonce,
    kind,
    fee: options.fee,
  };
  return signTransaction(unsigned, options.chainId, options.senderSeed);
}

export async function encodeHtlcCreateRaw(
  options: CreateHtlcOptions,
): Promise<string> {
  const tx = await createHtlcTx(options);
  return encodeRawTransaction(tx);
}
