import { getPublicKey } from "@noble/ed25519";
import { entropyToMnemonic, mnemonicToEntropy, validateMnemonic } from "@scure/bip39";
import { wordlist } from "@scure/bip39/wordlists/english";

import { encodeAddress } from "./address.js";
import { bytesToHex, hexToBytes } from "./bytes.js";

export interface AccountKey {
  /** 32-byte Ed25519 seed. Wipe it when the wallet locks. */
  seed: Uint8Array;
  publicKey: Uint8Array;
  /** Canonical `kvnc…dag` address. The address bytes are the public key. */
  address: string;
}

/** New key. Uses `crypto.getRandomValues`. */
export async function generateKey(): Promise<AccountKey> {
  const seed = new Uint8Array(32);
  crypto.getRandomValues(seed);
  return keyFromSeed(seed);
}

export async function keyFromSeed(seed: Uint8Array): Promise<AccountKey> {
  if (seed.length !== 32) {
    throw new Error("seed must be 32 bytes");
  }
  const publicKey = await getPublicKey(seed);
  return { seed, publicKey, address: encodeAddress(publicKey) };
}

/** 32-byte hex seed, with or without `0x`. This is the CLI `import-key --format raw` input. */
export async function keyFromHexSeed(hex: string): Promise<AccountKey> {
  return keyFromSeed(hexToBytes(hex.trim()));
}

/**
 * 24-word English BIP-39 phrase. The entropy is the Ed25519 seed.
 * There is no BIP-39 passphrase and no HD derivation, matching `kovanica import-key`.
 */
export async function keyFromMnemonic(phrase: string): Promise<AccountKey> {
  const normalized = phrase.trim().toLowerCase().split(/\s+/).join(" ");
  const words = normalized.split(" ");
  if (words.length !== 24) {
    throw new Error("key phrase must contain exactly 24 English words");
  }
  if (!validateMnemonic(normalized, wordlist)) {
    throw new Error("invalid English BIP-39 phrase");
  }
  const entropy = mnemonicToEntropy(normalized, wordlist);
  if (entropy.length !== 32) {
    throw new Error("key phrase must encode exactly 32 bytes");
  }
  return keyFromSeed(entropy);
}

/** 24-word phrase for a seed, matching `kovanica export --format mnemonic`. */
export function seedToMnemonic(seed: Uint8Array): string {
  if (seed.length !== 32) {
    throw new Error("seed must be 32 bytes");
  }
  return entropyToMnemonic(seed, wordlist);
}

export function seedToHex(seed: Uint8Array): string {
  return bytesToHex(seed);
}
