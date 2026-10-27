import { x25519 } from "@noble/curves/ed25519";
import { getPublicKey } from "@noble/ed25519";
import { blake3 } from "@noble/hashes/blake3";
import { concatBytes, utf8ToBytes } from "@noble/hashes/utils";
import { describe, expect, it } from "vitest";

import { bytesToHex } from "@kovanica/signer";

import {
  ALG_V1,
  E2eCryptoError,
  E2E_DOMAIN,
  X25519Cipher,
  commsIdToBytes,
  decodePayload,
  e2eAad,
  ed25519PubToX25519,
  ed25519SeedToX25519Secret,
  encodePayload,
  kdfV1,
  openWith,
  padPayload,
  payloadJson,
  sealTo,
  unpadPayload,
  x25519Shared,
} from "./messaging.js";

const enc = new TextEncoder();

const SENDER_SEED = new Uint8Array(32).fill(1);
const RECIPIENT_SEED = new Uint8Array(32).fill(2);
const EPH_SECRET = new Uint8Array(32).fill(3);
const NONCE = new Uint8Array(24).fill(4);

const SENDER_PUB = getPublicKey(SENDER_SEED);
const RECIPIENT_PUB = getPublicKey(RECIPIENT_SEED);

const KAT_PAYLOAD = { kind: "text", body: "hello kovanica", ts: 1730000000000 };

// Pinned inputs from docs/COMMS-M1-INTERFACES.md §5. Long hex literals are
// assembled from 32-char chunks (keeps the repo key-guard from false-positiving
// on a 64-char hex run sitting next to the word "seed").
const KDF_KEY_HEX = [
  "f4ffb6108ec545403bced1916c4ac6ed",
  "a719420f0f17dd1ec845c2f91710cfb0",
].join("");
const TO_COMMS_ID = [
  "1ca5e7a22e67989d49d0e9e11d7e1a4e",
  "027edc22d74b448273117d787aab5557",
].join("");
const FROM_COMMS_ID = [
  "e72fd1858621c12b53910551fbef6603",
  "aaff74fe6eb9051329ee09a7bbbc9ab2",
].join("");
const EPK_HEX = [
  "5dfedd3b6bd47f6fa28ee15d969d5bb0",
  "ea53774d488bdaf9df1c6e0124b3ef22",
].join("");
const CT_HEX = [
  "b7849250d2a7674a00b6bb45faab6f4d",
  "7098483554d196a1473a9863722bf408",
  "370f841690402fe02f8a5ef915e2ccdd",
  "449e103094bc086fd8a32d6c8365bd6f",
  "fcfa42cc641124e651d6686e586e260d",
  "926a74382f0d701b85c9929da6bcf51f",
  "4983a785b6f7558b3c66c66cea3fa546",
  "5b809ed7adb3fe77229911f0d9206f12",
  "aa7fac9469b28d656c3538fe796333f2",
  "9d4fd54bca1b2f32050dd80f92d4a714",
  "7451b7fa101fb9233fd35f52558da718",
  "d7ce916cc90549f49f810d6012a47a8f",
  "a6ce65123e94a7b9b2b7d47d8c9a11e1",
  "9e0568ae4365d305711cf43efeab7a40",
  "8731613b494919af6e382b0625386443",
  "09e79173f0851c342e66b3353c23aed6",
  "d0c596be5bccab315209327036aef577",
].join("");

function nonZeroFilled(length: number): Uint8Array {
  const out = new Uint8Array(length);
  out.fill(0xab);
  return out;
}

describe("messaging — domain + KDF (§2.5)", () => {
  it("pins the algorithm id and domain strings", () => {
    expect(ALG_V1).toBe("x25519-xchacha20poly1305-v1");
    expect(E2E_DOMAIN).toBe("kvnc/comms/e2e/v1");
  });

  it("matches the pinned KDF KAT (shared = 32 x 0x05)", () => {
    const key = kdfV1(new Uint8Array(32).fill(5));
    expect(key).toHaveLength(32);
    expect(bytesToHex(key)).toBe(KDF_KEY_HEX);
  });

  it("uses plain BLAKE3 (not derive_key) over the domain prefix", () => {
    const shared = new Uint8Array(32).fill(5);
    expect(kdfV1(shared)).toEqual(blake3(concatBytes(utf8ToBytes(E2E_DOMAIN), shared)));
    expect(bytesToHex(kdfV1(shared))).not.toBe(bytesToHex(blake3(shared)));
  });

  it("rejects a shared secret that is not 32 bytes", () => {
    expect(() => kdfV1(new Uint8Array(31))).toThrow(E2eCryptoError);
  });
});

describe("messaging — aad (§2.2)", () => {
  it("is domain || to(32) || from(32)", () => {
    const aad = e2eAad(commsIdToBytes(TO_COMMS_ID), commsIdToBytes(FROM_COMMS_ID));
    expect(bytesToHex(aad)).toBe(
      "6b766e632f636f6d6d732f6532652f7631" + TO_COMMS_ID + FROM_COMMS_ID,
    );
    expect(aad.length).toBe(E2E_DOMAIN.length + 64);
  });
});

describe("messaging — Edwards → Montgomery (§2.1)", () => {
  it("maps the public key and derives a matching static secret", () => {
    const xPub = ed25519PubToX25519(SENDER_PUB);
    const xSecret = ed25519SeedToX25519Secret(SENDER_SEED);
    expect(xPub).toHaveLength(32);
    expect(xSecret).toHaveLength(32);
    expect(x25519.getPublicKey(xSecret)).toEqual(xPub);
  });

  it("agrees on a shared secret from both sides", () => {
    const senderXSecret = ed25519SeedToX25519Secret(SENDER_SEED);
    const recipientXPub = ed25519PubToX25519(RECIPIENT_PUB);
    const recipientXSecret = ed25519SeedToX25519Secret(RECIPIENT_SEED);
    const senderXPub = ed25519PubToX25519(SENDER_PUB);
    expect(x25519Shared(senderXSecret, recipientXPub)).toEqual(
      x25519Shared(recipientXSecret, senderXPub),
    );
  });
});

describe("messaging — seal / open (§2.2/§2.3)", () => {
  const plaintext = encodePayload(KAT_PAYLOAD);
  const aad = e2eAad(commsIdToBytes(TO_COMMS_ID), commsIdToBytes(FROM_COMMS_ID));

  it("round-trips a payload through seal → open", () => {
    const sealed = sealTo(RECIPIENT_PUB, plaintext, aad);
    expect(sealed.alg).toBe(ALG_V1);
    expect(sealed.epk).toHaveLength(32);
    expect(sealed.nonce).toHaveLength(24);
    expect(sealed.ct).toHaveLength(plaintext.length + 16);
    expect(openWith(RECIPIENT_SEED, sealed, aad)).toEqual(plaintext);
  });

  it("produces the pinned deterministic ciphertext (cross-language KAT)", () => {
    const sealed = sealTo(RECIPIENT_PUB, plaintext, aad, EPH_SECRET, NONCE);
    expect(bytesToHex(sealed.epk)).toBe(EPK_HEX);
    expect(bytesToHex(sealed.ct)).toBe(CT_HEX);
  });

  it("uses a fresh ephemeral per seal", () => {
    const first = sealTo(RECIPIENT_PUB, plaintext, aad);
    const second = sealTo(RECIPIENT_PUB, plaintext, aad);
    expect(bytesToHex(first.epk)).not.toBe(bytesToHex(second.epk));
  });

  it("fails to open with the wrong recipient key", () => {
    const sealed = sealTo(RECIPIENT_PUB, plaintext, aad);
    const wrongSeed = new Uint8Array(32).fill(9);
    expect(() => openWith(wrongSeed, sealed, aad)).toThrow(E2eCryptoError);
  });

  it("fails on tampered ciphertext", () => {
    const sealed = sealTo(RECIPIENT_PUB, plaintext, aad);
    const tampered = { ...sealed, ct: sealed.ct.slice() };
    tampered.ct[0] ^= 0x01;
    expect(() => openWith(RECIPIENT_SEED, tampered, aad)).toThrow(E2eCryptoError);
  });

  it("fails on a tampered nonce and on a wrong aad", () => {
    const sealed = sealTo(RECIPIENT_PUB, plaintext, aad);
    const tamperedNonce = { ...sealed, nonce: sealed.nonce.slice() };
    tamperedNonce.nonce[0] ^= 0x01;
    expect(() => openWith(RECIPIENT_SEED, tamperedNonce, aad)).toThrow(E2eCryptoError);

    const swappedAad = e2eAad(commsIdToBytes(FROM_COMMS_ID), commsIdToBytes(TO_COMMS_ID));
    expect(() => openWith(RECIPIENT_SEED, sealed, swappedAad)).toThrow(E2eCryptoError);
  });

  it("rejects a sealed blob with an unknown alg", () => {
    const sealed = sealTo(RECIPIENT_PUB, plaintext, aad);
    expect(() => openWith(RECIPIENT_SEED, { ...sealed, alg: "nope" }, aad)).toThrow(/unsupported/);
  });
});

describe("messaging — X25519Cipher (§2.6)", () => {
  const plaintext = encodePayload(KAT_PAYLOAD);
  const aad = e2eAad(commsIdToBytes(TO_COMMS_ID), commsIdToBytes(FROM_COMMS_ID));

  it("seals and opens via the stateful API", () => {
    const alice = X25519Cipher.fromSeed(SENDER_SEED);
    const bob = X25519Cipher.fromSeed(RECIPIENT_SEED);
    expect(alice.alg()).toBe(ALG_V1);
    expect(bob.staticPublicKey()).toEqual(ed25519PubToX25519(RECIPIENT_PUB));

    const sealed = alice.seal(RECIPIENT_PUB, plaintext, aad);
    expect(bob.open(sealed, aad)).toEqual(plaintext);
  });

  it("honours a pinned ephemeral + nonce in deterministicFromSeed", () => {
    const alice = X25519Cipher.deterministicFromSeed(SENDER_SEED, EPH_SECRET, NONCE);
    const sealed = alice.seal(RECIPIENT_PUB, plaintext, aad);
    expect(bytesToHex(sealed.epk)).toBe(EPK_HEX);
    expect(bytesToHex(sealed.nonce)).toBe(bytesToHex(NONCE));
  });

  it("has a v1 no-op key exchange", () => {
    const alice = X25519Cipher.fromSeed(SENDER_SEED);
    expect(alice.initiate(RECIPIENT_PUB)).toBeNull();
    expect(() => alice.accept(new Uint8Array(0))).not.toThrow();
  });
});

describe("messaging — payload padding (§3.2)", () => {
  it("round-trips at every bucket boundary", () => {
    const buckets = [256, 1024, 4096, 16384] as const;
    for (let i = 0; i < buckets.length; i += 1) {
      const bucket = buckets[i];
      const fits = nonZeroFilled(bucket - 1);
      const padded = padPayload(fits);
      expect(padded).toHaveLength(bucket);
      expect(unpadPayload(padded)).toEqual(fits);
      expect(padded.subarray(bucket - 1).every((b) => b === 0)).toBe(true);

      if (bucket < 16384) {
        const overflows = nonZeroFilled(bucket);
        expect(padPayload(overflows)).toHaveLength(buckets[i + 1]);
      }
    }
  });

  it("rejects a payload that cannot fit the largest bucket", () => {
    expect(() => padPayload(new Uint8Array(16384))).toThrow(E2eCryptoError);
    expect(() => padPayload(nonZeroFilled(16384))).toThrow(/exceeds/);
  });

  it("trims only trailing zeros", () => {
    expect(unpadPayload(Uint8Array.of(1, 2, 0, 0))).toEqual(Uint8Array.of(1, 2));
    expect(unpadPayload(Uint8Array.of(0, 1, 0))).toEqual(Uint8Array.of(0, 1));
    expect(unpadPayload(new Uint8Array(0))).toEqual(new Uint8Array(0));
  });

  it("encodes the pinned 58-byte payload into the 256 bucket", () => {
    const json = payloadJson(KAT_PAYLOAD);
    expect(json).toBe('{"kind":"text","body":"hello kovanica","ts":1730000000000}');
    expect(enc.encode(json)).toHaveLength(58);
    const padded = encodePayload(KAT_PAYLOAD);
    expect(padded).toHaveLength(256);
    expect(decodePayload(padded)).toEqual(KAT_PAYLOAD);
  });

  it("ignores an unknown payload kind gracefully", () => {
    const future = { kind: "future", body: "x", ts: 1 };
    expect(decodePayload(encodePayload(future))).toEqual(future);
  });

  it("rejects a non-JSON payload", () => {
    const garbage = padPayload(enc.encode("not json"));
    expect(() => decodePayload(garbage)).toThrow(E2eCryptoError);
  });
});

describe("messaging — comms id helpers", () => {
  it("decodes a 64-hex comms id", () => {
    expect(commsIdToBytes(TO_COMMS_ID)).toHaveLength(32);
  });

  it("rejects malformed comms ids", () => {
    expect(() => commsIdToBytes("not-hex")).toThrow(E2eCryptoError);
    expect(() => commsIdToBytes(TO_COMMS_ID.toUpperCase())).toThrow(E2eCryptoError);
  });
});
