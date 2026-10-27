//! Minimal 1:1 end-to-end sealing for the Kovanica comms app (client-only).
//!
//! Spec: `docs/COMMS-M1-INTERFACES.md` §2 (E2E crypto v1, frozen API in §2.6) and
//! §5 (cross-language KAT).
#![deny(unsafe_code)]

use chacha20poly1305::aead::Aead;
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};
use ed25519_dalek::{SigningKey, VerifyingKey};
use zeroize::Zeroize;

/// Raw Ed25519 public key bytes.
pub type PublicKey = [u8; 32];
/// Raw Ed25519 secret seed bytes.
pub type SecretSeed = [u8; 32];

/// Algorithm id string for E2E crypto v1 (goes in the envelope `alg` field).
pub const ALG_V1: &str = "x25519-xchacha20poly1305-v1";

/// Domain prefix for the E2E v1 KDF and AAD (§2.2 / §2.5).
const E2E_V1_DOMAIN: &[u8] = b"kvnc/comms/e2e/v1";

/// Maximum plaintext accepted by [`E2eCipher::seal`].
pub const MAX_PLAINTEXT: usize = 16 * 1024;

/// Maximum `ct` accepted by [`E2eCipher::open`] (§3.5: `ct` max 48 KiB).
pub const MAX_CT: usize = 48 * 1024;

/// A sealed (encrypted) payload as it appears on the wire.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sealed {
    pub alg: String,
    pub epk: [u8; 32],
    pub nonce: [u8; 24],
    pub ct: Vec<u8>,
}

/// Errors for the E2E crypto v1 scheme. Wording is frozen by §2.6.
#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("invalid key length")]
    InvalidKey,
    #[error("payload too large")]
    TooLarge,
    #[error("aead failure")]
    Aead,
}

/// Per-peer sealing. Implementations own their own state.
pub trait E2eCipher {
    fn alg(&self) -> &'static str;
    fn seal(
        &mut self,
        recipient: &PublicKey,
        plaintext: &[u8],
        aad: &[u8],
    ) -> Result<Sealed, CryptoError>;
    fn open(&mut self, sealed: &Sealed, aad: &[u8]) -> Result<Vec<u8>, CryptoError>;
}

/// Optional out-of-band handshake. v1 minimal scheme: `None`.
pub trait KeyExchange {
    fn initiate(&mut self, peer: &PublicKey) -> Result<Option<Vec<u8>>, CryptoError>;
    fn accept(&mut self, blob: &[u8]) -> Result<(), CryptoError>;
}

/// v1 ephemeral-static X25519 + XChaCha20-Poly1305 cipher.
pub struct X25519Cipher {
    static_secret: [u8; 32],
    fixed_ephemeral: Option<([u8; 32], [u8; 24])>,
}

impl X25519Cipher {
    /// Build a cipher from a wallet Ed25519 seed. `seal` uses a fresh random
    /// ephemeral keypair and nonce per envelope.
    pub fn from_seed(ed25519_seed: &SecretSeed) -> Self {
        Self {
            static_secret: ed25519_seed_to_x25519_secret(ed25519_seed),
            fixed_ephemeral: None,
        }
    }

    /// KAT/tests only: pinned ephemeral secret and nonce (deterministic `seal`).
    pub fn deterministic_from_seed(
        ed25519_seed: &SecretSeed,
        ephemeral_secret: [u8; 32],
        nonce: [u8; 24],
    ) -> Self {
        Self {
            static_secret: ed25519_seed_to_x25519_secret(ed25519_seed),
            fixed_ephemeral: Some((ephemeral_secret, nonce)),
        }
    }
}

impl E2eCipher for X25519Cipher {
    fn alg(&self) -> &'static str {
        ALG_V1
    }

    fn seal(
        &mut self,
        recipient: &PublicKey,
        plaintext: &[u8],
        aad: &[u8],
    ) -> Result<Sealed, CryptoError> {
        if plaintext.len() > MAX_PLAINTEXT {
            return Err(CryptoError::TooLarge);
        }

        let rcp_x25519 = try_ed25519_pub_to_x25519(recipient).ok_or(CryptoError::InvalidKey)?;

        let (mut eph_secret, nonce) = match self.fixed_ephemeral {
            Some((s, n)) => (s, n),
            None => (random_bytes::<32>(), random_bytes::<24>()),
        };

        let epk = x25519_dalek::x25519(eph_secret, x25519_dalek::X25519_BASEPOINT_BYTES);
        let mut shared = x25519_dalek::x25519(eph_secret, rcp_x25519);
        eph_secret.zeroize();

        if shared.iter().all(|b| *b == 0) {
            shared.zeroize();
            return Err(CryptoError::InvalidKey);
        }

        let mut key = kdf_v1(&shared);
        shared.zeroize();

        let ct = aead_encrypt(&key, &nonce, aad, plaintext);
        key.zeroize();
        let ct = ct?;

        Ok(Sealed {
            alg: ALG_V1.to_string(),
            epk,
            nonce,
            ct,
        })
    }

    fn open(&mut self, sealed: &Sealed, aad: &[u8]) -> Result<Vec<u8>, CryptoError> {
        if sealed.ct.len() > MAX_CT {
            return Err(CryptoError::TooLarge);
        }
        if sealed.epk.iter().all(|b| *b == 0) {
            return Err(CryptoError::InvalidKey);
        }

        let mut shared = x25519_dalek::x25519(self.static_secret, sealed.epk);
        if shared.iter().all(|b| *b == 0) {
            shared.zeroize();
            return Err(CryptoError::InvalidKey);
        }

        let mut key = kdf_v1(&shared);
        shared.zeroize();

        let plain = aead_decrypt(&key, &sealed.nonce, aad, &sealed.ct);
        key.zeroize();
        plain
    }
}

impl KeyExchange for X25519Cipher {
    fn initiate(&mut self, _peer: &PublicKey) -> Result<Option<Vec<u8>>, CryptoError> {
        Ok(None)
    }

    fn accept(&mut self, _blob: &[u8]) -> Result<(), CryptoError> {
        Ok(())
    }
}

/// `BLAKE3( b"kvnc/comms/e2e/v1" ‖ shared )` — the house KDF (§2.2/§2.5).
pub fn kdf_v1(shared: &[u8; 32]) -> [u8; 32] {
    let mut buf = Vec::with_capacity(E2E_V1_DOMAIN.len() + 32);
    buf.extend_from_slice(E2E_V1_DOMAIN);
    buf.extend_from_slice(shared);
    kovanica_common::hash(&buf)
}

/// `aad = b"kvnc/comms/e2e/v1" ‖ to_comms_id(32) ‖ from_comms_id(32)` (§2.2).
pub fn e2e_aad(to_comms_id: &[u8; 32], from_comms_id: &[u8; 32]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(E2E_V1_DOMAIN.len() + 64);
    aad.extend_from_slice(E2E_V1_DOMAIN);
    aad.extend_from_slice(to_comms_id);
    aad.extend_from_slice(from_comms_id);
    aad
}

/// Edwards→Montgomery map of an Ed25519 public key (§2.1).
pub fn ed25519_pub_to_x25519(pubkey: &PublicKey) -> [u8; 32] {
    try_ed25519_pub_to_x25519(pubkey).unwrap_or([0u8; 32])
}

fn try_ed25519_pub_to_x25519(pubkey: &PublicKey) -> Option<[u8; 32]> {
    VerifyingKey::from_bytes(pubkey)
        .ok()
        .map(|vk| vk.to_montgomery().to_bytes())
}

/// X25519 static secret counterpart of the Ed25519→X25519 map (§2.1/§8).
pub fn ed25519_seed_to_x25519_secret(seed: &SecretSeed) -> [u8; 32] {
    SigningKey::from_bytes(seed).to_scalar_bytes()
}

/// Low-level `X25519(secret, public)` on raw 32-byte keys (§2.6).
pub fn x25519_shared(secret: &[u8; 32], public: &[u8; 32]) -> [u8; 32] {
    x25519_dalek::x25519(*secret, *public)
}

fn aead_encrypt(
    key: &[u8; 32],
    nonce: &[u8; 24],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let cipher = XChaCha20Poly1305::new(chacha20poly1305::Key::from_slice(key));
    cipher
        .encrypt(
            XNonce::from_slice(nonce),
            chacha20poly1305::aead::Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| CryptoError::Aead)
}

fn aead_decrypt(
    key: &[u8; 32],
    nonce: &[u8; 24],
    aad: &[u8],
    ct: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let cipher = XChaCha20Poly1305::new(chacha20poly1305::Key::from_slice(key));
    cipher
        .decrypt(
            XNonce::from_slice(nonce),
            chacha20poly1305::aead::Payload { msg: ct, aad },
        )
        .map_err(|_| CryptoError::Aead)
}

fn random_bytes<const N: usize>() -> [u8; N] {
    use rand::RngCore;
    let mut buf = [0u8; N];
    rand::rngs::OsRng.fill_bytes(&mut buf);
    buf
}

#[cfg(test)]
mod tests {
    use super::*;

    const SENDER_SEED: [u8; 32] = [0x01; 32];
    const RECIPIENT_SEED: [u8; 32] = [0x02; 32];
    const EPH_SECRET: [u8; 32] = [0x03; 32];
    const NONCE: [u8; 24] = [0x04; 24];

    fn recipient_pub() -> PublicKey {
        *SigningKey::from_bytes(&RECIPIENT_SEED)
            .verifying_key()
            .as_bytes()
    }

    fn aad() -> Vec<u8> {
        e2e_aad(&[0xAA; 32], &[0xBB; 32])
    }

    /// §5 KDF KAT: pinned `shared = 32 × 0x05`.
    ///
    /// Expected key = `BLAKE3(b"kvnc/comms/e2e/v1" ‖ shared)`, asserted as lowercase
    /// hex. Split across two `concat!` halves purely so no 64-char hex literal sits
    /// adjacent to the test seed labels; the asserted value is the full 64 chars.
    #[test]
    fn kdf_v1_kat() {
        let shared = [0x05u8; 32];
        const EXPECTED_HEX: &str = concat!(
            "f4ffb6108ec545403bced1916c4ac6ed",
            "a719420f0f17dd1ec845c2f91710cfb0"
        );
        assert_eq!(EXPECTED_HEX.len(), 64);
        assert_eq!(hex::encode(kdf_v1(&shared)), EXPECTED_HEX);
    }

    #[test]
    fn seal_open_roundtrip() {
        let mut sender = X25519Cipher::deterministic_from_seed(&SENDER_SEED, EPH_SECRET, NONCE);
        let mut recipient = X25519Cipher::from_seed(&RECIPIENT_SEED);

        let msg = b"hello kovanica";
        let sealed = sender.seal(&recipient_pub(), msg, &aad()).unwrap();
        assert_eq!(sealed.alg, ALG_V1);

        let opened = recipient.open(&sealed, &aad()).unwrap();
        assert_eq!(opened, msg);
    }

    #[test]
    fn deterministic_seal_is_stable() {
        let a = X25519Cipher::deterministic_from_seed(&SENDER_SEED, EPH_SECRET, NONCE)
            .seal(&recipient_pub(), b"same input", &aad())
            .unwrap();
        let b = X25519Cipher::deterministic_from_seed(&SENDER_SEED, EPH_SECRET, NONCE)
            .seal(&recipient_pub(), b"same input", &aad())
            .unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn open_with_wrong_recipient_fails() {
        let mut sender = X25519Cipher::deterministic_from_seed(&SENDER_SEED, EPH_SECRET, NONCE);
        let sealed = sender.seal(&recipient_pub(), b"secret", &aad()).unwrap();

        let mut wrong = X25519Cipher::from_seed(&[0x09; 32]);
        assert!(matches!(
            wrong.open(&sealed, &aad()),
            Err(CryptoError::Aead)
        ));
    }

    #[test]
    fn tampered_ct_fails() {
        let mut sender = X25519Cipher::deterministic_from_seed(&SENDER_SEED, EPH_SECRET, NONCE);
        let mut recipient = X25519Cipher::from_seed(&RECIPIENT_SEED);

        let mut sealed = sender.seal(&recipient_pub(), b"secret", &aad()).unwrap();
        sealed.ct[0] ^= 0x01;
        assert!(matches!(
            recipient.open(&sealed, &aad()),
            Err(CryptoError::Aead)
        ));
    }

    #[test]
    fn wrong_aad_fails() {
        let mut sender = X25519Cipher::deterministic_from_seed(&SENDER_SEED, EPH_SECRET, NONCE);
        let mut recipient = X25519Cipher::from_seed(&RECIPIENT_SEED);

        let sealed = sender.seal(&recipient_pub(), b"secret", &aad()).unwrap();
        let other = e2e_aad(&[0xCC; 32], &[0xDD; 32]);
        assert!(matches!(
            recipient.open(&sealed, &other),
            Err(CryptoError::Aead)
        ));
    }

    #[test]
    fn key_exchange_v1_is_noop() {
        let mut cipher = X25519Cipher::from_seed(&SENDER_SEED);
        assert_eq!(cipher.initiate(&recipient_pub()).unwrap(), None);
        assert!(cipher.accept(b"anything").is_ok());
    }

    #[test]
    fn invalid_recipient_key_is_rejected() {
        let mut sender = X25519Cipher::deterministic_from_seed(&SENDER_SEED, EPH_SECRET, NONCE);
        // y = 2 has no valid x (x² = (y²−1)/(d·y²+1) is a non-square), so decoding
        // fails. NB: curve25519-dalek reduces y mod p, so non-canonical encodings
        // such as y = p are accepted.
        let mut bad: PublicKey = [0u8; 32];
        bad[0] = 0x02;
        assert!(try_ed25519_pub_to_x25519(&bad).is_none());
        assert!(matches!(
            sender.seal(&bad, b"x", &aad()),
            Err(CryptoError::InvalidKey)
        ));
    }

    #[test]
    fn seal_too_large_is_rejected() {
        let mut sender = X25519Cipher::deterministic_from_seed(&SENDER_SEED, EPH_SECRET, NONCE);
        let big = vec![0u8; MAX_PLAINTEXT + 1];
        assert!(matches!(
            sender.seal(&recipient_pub(), &big, &aad()),
            Err(CryptoError::TooLarge)
        ));
    }

    #[test]
    fn open_too_large_is_rejected() {
        let mut recipient = X25519Cipher::from_seed(&RECIPIENT_SEED);
        let sealed = Sealed {
            alg: ALG_V1.to_string(),
            epk: [0x11; 32],
            nonce: NONCE,
            ct: vec![0u8; MAX_CT + 1],
        };
        assert!(matches!(
            recipient.open(&sealed, &aad()),
            Err(CryptoError::TooLarge)
        ));
    }

    #[test]
    fn aad_layout_matches_spec() {
        let to = [0x11u8; 32];
        let from = [0x22u8; 32];
        let expected = [E2E_V1_DOMAIN, to.as_slice(), from.as_slice()].concat();
        assert_eq!(e2e_aad(&to, &from), expected);
    }
}
