import { blake3 } from "@noble/hashes/blake3";
import { getPublicKey, sign } from "@noble/ed25519";

import { concat, u32le, u64le } from "./bytes.js";

const TX_DOMAIN = asciiPad("KUNA/tx/v1", 16);
const TX_KEY = asciiPad("KUNA-TX-v1", 32);

/**
 * Transaction kinds the console can sign.
 *
 * `signingTag` is the byte in the signature preimage (`docs/SIGNATURE_FORMAT.md`).
 * `wireIndex` is the bincode 1.3 variant index, which is the Rust declaration
 * order and is not the same number.
 */
export type TxKind =
  | { type: "transfer"; to: Uint8Array; amount: bigint }
  | { type: "stake"; amount: bigint }
  | { type: "unstake"; amount: bigint }
  | { type: "delegate"; validator: Uint8Array; amount: bigint }
  | { type: "claimRewards"; validator: Uint8Array | null }
  | {
      type: "call";
      contract: Uint8Array;
      value: bigint;
      method: string;
      args: Uint8Array;
      gasLimit: bigint;
    };

export interface UnsignedTx {
  sender: Uint8Array;
  nonce: bigint;
  kind: TxKind;
  fee: bigint;
}

export interface SignedTx extends UnsignedTx {
  signature: Uint8Array;
  hash: Uint8Array;
}

function asciiPad(text: string, size: number): Uint8Array {
  const out = new Uint8Array(size);
  const bytes = new TextEncoder().encode(text);
  if (bytes.length > size) {
    throw new Error(`${text} does not fit in ${size} bytes`);
  }
  out.set(bytes);
  return out;
}

function address(bytes: Uint8Array, what: string): Uint8Array {
  if (bytes.length !== 32) {
    throw new Error(`${what} must be 32 bytes`);
  }
  return bytes;
}

/** Kind bytes inside the signature preimage. Tags are not bincode indexes. */
function signingKind(kind: TxKind): Uint8Array {
  switch (kind.type) {
    case "transfer":
      return concat([Uint8Array.of(0), address(kind.to, "recipient"), u64le(kind.amount)]);
    case "stake":
      return concat([Uint8Array.of(1), u64le(kind.amount)]);
    case "unstake":
      return concat([Uint8Array.of(2), u64le(kind.amount)]);
    case "call": {
      const methodBytes = new TextEncoder().encode(kind.method);
      if (methodBytes.length === 0) {
        throw new Error("method must not be empty");
      }
      if (kind.value < 0n || kind.value > 0xffffffffffffffffn) {
        throw new Error("value is out of u64 range");
      }
      if (kind.gasLimit < 0n || kind.gasLimit > 0xffffffffffffffffn) {
        throw new Error("gasLimit is out of u64 range");
      }
      return concat([
        Uint8Array.of(4),
        address(kind.contract, "contract"),
        u64le(kind.value),
        u64le(BigInt(methodBytes.length)),
        methodBytes,
        u64le(BigInt(kind.args.length)),
        kind.args,
        u64le(kind.gasLimit),
      ]);
    }
    case "delegate":
      return concat([
        Uint8Array.of(5),
        address(kind.validator, "validator"),
        u64le(kind.amount),
      ]);
    case "claimRewards":
      if (kind.validator === null) return Uint8Array.of(6, 0);
      return concat([Uint8Array.of(6, 1), address(kind.validator, "validator")]);
  }
}

/**
 * BLAKE3 keyed with `KUNA-TX-v1` over the v1 preimage.
 * `chainId` is the selected network. Epoch is not part of a transaction.
 */
export function signingHash(tx: UnsignedTx, chainId: number): Uint8Array {
  if (!Number.isInteger(chainId) || chainId < 0) {
    throw new Error("chain id must be a non-negative integer");
  }
  const preimage = concat([
    TX_DOMAIN,
    u64le(BigInt(chainId)),
    address(tx.sender, "sender"),
    u64le(tx.nonce),
    signingKind(tx.kind),
    u64le(tx.fee),
  ]);
  return blake3(preimage, { key: TX_KEY });
}

/**
 * Bincode 1.3 body of a signed transaction, hex-encoded with no `0x` prefix.
 *
 * `Signature` uses serde `serialize_bytes`, so the signature is a u64 length
 * plus 64 bytes. Address and hash are raw fixed arrays. `Call` is hashed by
 * {@link signingHash} but not submitted by this console release.
 */
export function encodeRawTransaction(tx: SignedTx): string {
  if (tx.signature.length !== 64) {
    throw new Error("signature must be 64 bytes");
  }
  if (tx.hash.length !== 32) {
    throw new Error("hash must be 32 bytes");
  }
  const body = concat([
    address(tx.sender, "sender"),
    u64le(tx.nonce),
    wireKind(tx.kind),
    u64le(tx.fee),
    u64le(64n),
    tx.signature,
    tx.hash,
  ]);
  return [...body].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

function wireKind(kind: TxKind): Uint8Array {
  switch (kind.type) {
    case "transfer":
      return concat([u32le(0), address(kind.to, "recipient"), u64le(kind.amount)]);
    case "stake":
      return concat([u32le(1), u64le(kind.amount)]);
    case "unstake":
      return concat([u32le(2), u64le(kind.amount)]);
    case "delegate":
      return concat([u32le(3), address(kind.validator, "validator"), u64le(kind.amount)]);
    case "claimRewards":
      // Serde Option is a u8 tag in bincode 1.3, not a u32 variant index.
      if (kind.validator === null) return concat([u32le(4), Uint8Array.of(0)]);
      return concat([u32le(4), Uint8Array.of(1), address(kind.validator, "validator")]);
    case "call": {
      if (kind.contract.length !== 32) {
        throw new Error("contract must be 32 bytes");
      }
      const methodBytes = new TextEncoder().encode(kind.method);
      if (methodBytes.length === 0) {
        throw new Error("method must not be empty");
      }
      if (kind.value < 0n || kind.value > 0xffffffffffffffffn) {
        throw new Error("value is out of u64 range");
      }
      if (kind.gasLimit < 0n || kind.gasLimit > 0xffffffffffffffffn) {
        throw new Error("gasLimit is out of u64 range");
      }
      return concat([
        u32le(6),
        address(kind.contract, "contract"),
        u64le(kind.value),
        u64le(BigInt(methodBytes.length)),
        methodBytes,
        u64le(BigInt(kind.args.length)),
        kind.args,
        u64le(kind.gasLimit),
      ]);
    }  }
}

/** Byte length of the bincode body. The fee is fixed-width, so it does not change the size. */
export function rawTransactionSize(tx: UnsignedTx): number {
  const placeholder: SignedTx = {
    ...tx,
    signature: new Uint8Array(64),
    hash: new Uint8Array(32),
  };
  return encodeRawTransaction(placeholder).length / 2;
}

/**
 * Fee in atoms. `rate` is atoms per byte from `kovanica_estimateFee`.
 * The mempool rejects a zero fee and a rate below its minimum.
 */
export function feeForRate(tx: Omit<UnsignedTx, "fee">, rate: bigint): bigint {
  if (rate < 1n) {
    throw new Error("fee rate must be at least 1 atom per byte");
  }
  const size = rawTransactionSize({ ...tx, fee: 0n });
  return rate * BigInt(size);
}

/** Sign `tx` for `chainId`. The private seed never leaves this call. */
export async function signTransaction(
  tx: UnsignedTx,
  chainId: number,
  seed: Uint8Array,
): Promise<SignedTx> {
  if (seed.length !== 32) {
    throw new Error("seed must be 32 bytes");
  }
  const hash = signingHash(tx, chainId);
  const signature = await sign(hash, seed);
  const publicKey = await getPublicKey(seed);
  if (!equalBytes(publicKey, tx.sender)) {
    throw new Error("seed does not match the sender");
  }
  return { ...tx, hash, signature };
}

function equalBytes(left: Uint8Array, right: Uint8Array): boolean {
  if (left.length !== right.length) return false;
  let diff = 0;
  for (let i = 0; i < left.length; i += 1) {
    diff |= left[i] ^ right[i];
  }
  return diff === 0;
}
