import { bytesToHex, hexToBytes, keyFromSeed } from "@kovanica/signer";

/** PBKDF2-SHA256 iterations. This file is not a CLI keystore. */
export const BACKUP_ITERATIONS = 600_000;

export interface BackupFile {
  version: 1;
  kdf: "PBKDF2-SHA256";
  iterations: number;
  salt: string;
  iv: string;
  ciphertext: string;
  address: string;
}

export async function encryptBackup(
  seed: Uint8Array,
  passphrase: string,
  address: string,
  iterations = BACKUP_ITERATIONS,
): Promise<BackupFile> {
  if (passphrase.length < 8) {
    throw new Error("passphrase must be at least 8 characters");
  }
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await deriveKey(passphrase, salt, iterations, ["encrypt"]);
  const ciphertext = new Uint8Array(
    await crypto.subtle.encrypt({ name: "AES-GCM", iv: bytes(iv) }, key, bytes(seed)),
  );
  return {
    version: 1,
    kdf: "PBKDF2-SHA256",
    iterations,
    salt: bytesToHex(salt),
    iv: bytesToHex(iv),
    ciphertext: bytesToHex(ciphertext),
    address,
  };
}

export async function decryptBackup(file: BackupFile, passphrase: string): Promise<Uint8Array> {
  if (file.version !== 1 || file.kdf !== "PBKDF2-SHA256") {
    throw new Error("unrecognised backup file");
  }
  const key = await deriveKey(passphrase, hexToBytes(file.salt), file.iterations, ["decrypt"]);
  let plain: ArrayBuffer;
  try {
    plain = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: bytes(hexToBytes(file.iv)) },
      key,
      bytes(hexToBytes(file.ciphertext)),
    );
  } catch {
    throw new Error("wrong passphrase");
  }
  const seed = new Uint8Array(plain);
  const account = await keyFromSeed(seed);
  if (account.address !== file.address) {
    seed.fill(0);
    throw new Error("backup address does not match the key");
  }
  return seed;
}

/** Copy into a fresh ArrayBuffer so WebCrypto accepts the view. */
function bytes(view: Uint8Array): ArrayBuffer {
  return view.buffer.slice(view.byteOffset, view.byteOffset + view.byteLength) as ArrayBuffer;
}

async function deriveKey(
  passphrase: string,
  salt: Uint8Array,
  iterations: number,
  usages: KeyUsage[],
): Promise<CryptoKey> {
  const material = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(passphrase),
    "PBKDF2",
    false,
    ["deriveKey"],
  );
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", salt: bytes(salt), iterations, hash: "SHA-256" },
    material,
    { name: "AES-GCM", length: 256 },
    false,
    usages,
  );
}
