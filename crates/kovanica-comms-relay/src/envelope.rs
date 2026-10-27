//! Envelope wire format v1 — `docs/COMMS-M1-INTERFACES.md` §3.
//!
//! The `Envelope` struct mirrors §3.1 field-for-field. Byte fields are held as
//! raw `Vec<u8>` in memory and rendered as **standard base64** (`A–Z a–z 0–9 + /`
//! with `=` padding) on the wire — see §1. Unknown extra JSON keys are ignored
//! for forward compatibility; missing or wrongly-typed required keys are
//! rejected by serde.

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use kovanica_comms_crypto::{e2e_aad, E2eCipher, PublicKey, SecretSeed, X25519Cipher};
use serde::{Deserialize, Serialize};

use crate::{EnvelopeError, ALG_V1};

/// Envelope wire version carried in the `v` field (§3.1). Always `1` for v1.
pub const ENVELOPE_VERSION: u8 = 1;

/// Domain prefix of the envelope signature (§3.3).
pub const ENV_SIG_DOMAIN: &[u8] = b"kvnc/comms/env/v1";

/// Domain prefix of the envelope id (§3.4).
pub const ENV_ID_DOMAIN: &[u8] = b"kvnc/comms/env-id/v1";

/// Domain prefix of a comms id (§1 / `kovanica-comms-core`).
pub const COMMS_ID_DOMAIN: &[u8] = b"kvnc/comms/id";

/// Maximum accepted envelope JSON size in bytes (§3.5).
pub const MAX_ENVELOPE_JSON: usize = 64 * 1024;

/// Maximum accepted `ct` length in bytes (§3.5).
pub const MAX_CT: usize = 48 * 1024;

/// Compute the 32-byte comms id for a raw Ed25519 public key.
///
/// `BLAKE3(b"kvnc/comms/id" ‖ pubkey)` — identical to
/// `kovanica_comms_core::comms_id` (§0/§1). Kept local to avoid an extra dependency;
/// a test pins it against the canonical cross-language vector.
pub fn comms_id_bytes(public_key: &PublicKey) -> [u8; 32] {
    let mut input = Vec::with_capacity(COMMS_ID_DOMAIN.len() + public_key.len());
    input.extend_from_slice(COMMS_ID_DOMAIN);
    input.extend_from_slice(public_key);
    kovanica_common::hash(&input)
}

/// Render a raw 32-byte comms id as 64 lowercase hex characters (§1).
pub fn comms_id_hex(id: &[u8; 32]) -> String {
    hex::encode(id)
}

/// Decode a comms id from 64 **lowercase** hex characters (§1).
///
/// Rejects wrong length, uppercase, and non-hex input.
pub fn comms_id_from_hex(s: &str) -> Result<[u8; 32], EnvelopeError> {
    if s.len() != 64
        || !s
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(EnvelopeError::BadHex(format!(
            "comms id must be 64 lowercase hex characters (got {} chars)",
            s.len()
        )));
    }
    let bytes = hex::decode(s)?;
    bytes
        .as_slice()
        .try_into()
        .map_err(|_| EnvelopeError::BadHex("comms id must be 32 bytes".to_string()))
}

/// Base64 (standard, padded) serde adapter for `Vec<u8>` fields (§1).
mod base64_bytes {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine as _;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &Vec<u8>, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&STANDARD.encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        STANDARD
            .decode(s.as_bytes())
            .map_err(serde::de::Error::custom)
    }
}

/// Envelope wire format v1 (§3.1).
///
/// Field names map to the JSON keys `v,id,to,from,sentAt,expiresAt,alg,epk,
/// nonce,ct,sig`. The byte fields (`epk`, `nonce`, `ct`, `sig`) are base64 on
/// the wire. Unknown extra JSON keys are ignored on decode.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Envelope {
    /// Version, always [`ENVELOPE_VERSION`].
    pub v: u8,
    /// Envelope id (64 lowercase hex), see [`Envelope::compute_id`].
    pub id: String,
    /// Recipient comms id (64 hex); the relay routes on this.
    pub to: String,
    /// Sender comms id (64 hex).
    #[serde(rename = "from")]
    pub from: String,
    /// Client send time in ms (untrusted clock).
    #[serde(rename = "sentAt")]
    pub sent_at: u64,
    /// Relay expiry in ms; the relay drops the envelope after this.
    #[serde(rename = "expiresAt")]
    pub expires_at: u64,
    /// Algorithm id, must equal [`ALG_V1`].
    pub alg: String,
    /// Ephemeral X25519 public key (32 bytes, base64).
    #[serde(with = "base64_bytes")]
    pub epk: Vec<u8>,
    /// XChaCha20-Poly1305 nonce (24 bytes, base64).
    #[serde(with = "base64_bytes")]
    pub nonce: Vec<u8>,
    /// XChaCha20-Poly1305 ciphertext (base64).
    #[serde(with = "base64_bytes")]
    pub ct: Vec<u8>,
    /// Ed25519 signature over [`Envelope::signing_bytes`] (64 bytes, base64).
    #[serde(with = "base64_bytes")]
    pub sig: Vec<u8>,
}

impl Envelope {
    /// Decode the `to`/`from` comms ids, validating the hex form.
    fn decode_ids(&self) -> Result<([u8; 32], [u8; 32]), EnvelopeError> {
        Ok((comms_id_from_hex(&self.to)?, comms_id_from_hex(&self.from)?))
    }

    /// The exact byte layout signed by the sender (§3.3).
    ///
    /// ```text
    /// b"kvnc/comms/env/v1"
    ///   ‖ to(32) ‖ from(32)
    ///   ‖ sentAt(u64 LE) ‖ expiresAt(u64 LE)
    ///   ‖ alg_utf8 ‖ 0x00
    ///   ‖ epk(32) ‖ nonce(24) ‖ ct(..)
    /// ```
    pub fn signing_bytes(&self) -> Result<Vec<u8>, EnvelopeError> {
        let (to, from) = self.decode_ids()?;
        let mut out = Vec::with_capacity(
            ENV_SIG_DOMAIN.len()
                + 32
                + 32
                + 8
                + 8
                + self.alg.len()
                + 1
                + self.epk.len()
                + self.nonce.len()
                + self.ct.len(),
        );
        out.extend_from_slice(ENV_SIG_DOMAIN);
        out.extend_from_slice(&to);
        out.extend_from_slice(&from);
        out.extend_from_slice(&self.sent_at.to_le_bytes());
        out.extend_from_slice(&self.expires_at.to_le_bytes());
        out.extend_from_slice(self.alg.as_bytes());
        out.push(0);
        out.extend_from_slice(&self.epk);
        out.extend_from_slice(&self.nonce);
        out.extend_from_slice(&self.ct);
        Ok(out)
    }

    /// The envelope id: `lowercase_hex(BLAKE3(b"kvnc/comms/env-id/v1" ‖
    /// signing_bytes))` (§3.4).
    pub fn compute_id(&self) -> Result<String, EnvelopeError> {
        let sb = self.signing_bytes()?;
        let mut input = Vec::with_capacity(ENV_ID_DOMAIN.len() + sb.len());
        input.extend_from_slice(ENV_ID_DOMAIN);
        input.extend_from_slice(&sb);
        Ok(hex::encode(kovanica_common::hash(&input)))
    }

    /// Validate the fields the relay can check without the sender's public key:
    /// version, alg, `epk`/`nonce` lengths and the `to`/`from` hex forms.
    pub fn validate_shape(&self) -> Result<(), EnvelopeError> {
        if self.v != ENVELOPE_VERSION {
            return Err(EnvelopeError::UnsupportedVersion(self.v));
        }
        if self.alg != ALG_V1 {
            return Err(EnvelopeError::AlgMismatch(self.alg.clone()));
        }
        if self.epk.len() != 32 {
            return Err(EnvelopeError::BadLength {
                field: "epk",
                expected: 32,
                got: self.epk.len(),
            });
        }
        if self.nonce.len() != 24 {
            return Err(EnvelopeError::BadLength {
                field: "nonce",
                expected: 24,
                got: self.nonce.len(),
            });
        }
        self.decode_ids()?;
        Ok(())
    }

    /// Set [`Envelope::id`] and sign the envelope with the sender's key (§3.3).
    pub fn sign(&mut self, signing_key: &SigningKey) -> Result<(), EnvelopeError> {
        self.id = self.compute_id()?;
        let sig = signing_key.sign(&self.signing_bytes()?);
        self.sig = sig.to_bytes().to_vec();
        Ok(())
    }

    /// Verify the envelope against the sender's Ed25519 public key.
    ///
    /// Checks, in order: shape (§ version/alg/lengths), signature length, that
    /// `from` equals the comms id of `from_pubkey`, `id` consistency, and the
    /// Ed25519 signature. The relay cannot run this (it has no public keys), but
    /// recipients can.
    pub fn verify(&self, from_pubkey: &PublicKey) -> Result<(), EnvelopeError> {
        self.validate_shape()?;
        if self.sig.len() != 64 {
            return Err(EnvelopeError::BadLength {
                field: "sig",
                expected: 64,
                got: self.sig.len(),
            });
        }
        if comms_id_bytes(from_pubkey) != self.decode_ids()?.1 {
            return Err(EnvelopeError::SenderMismatch);
        }
        if self.compute_id()? != self.id {
            return Err(EnvelopeError::IdMismatch);
        }
        let sig_bytes: [u8; 64] = self
            .sig
            .as_slice()
            .try_into()
            .map_err(|_| EnvelopeError::InvalidSignature)?;
        let sig = Signature::from_bytes(&sig_bytes);
        let verifying_key =
            VerifyingKey::from_bytes(from_pubkey).map_err(|_| EnvelopeError::InvalidSignature)?;
        verifying_key
            .verify(&self.signing_bytes()?, &sig)
            .map_err(|_| EnvelopeError::InvalidSignature)
    }

    /// Serialize to JSON (base64 for `epk`/`nonce`/`ct`/`sig`).
    pub fn to_json(&self) -> Result<String, EnvelopeError> {
        Ok(serde_json::to_string(self)?)
    }

    /// Serialize to compact JSON bytes.
    pub fn to_json_bytes(&self) -> Result<Vec<u8>, EnvelopeError> {
        Ok(serde_json::to_vec(self)?)
    }

    /// Parse from JSON bytes. Unknown keys are ignored; missing/wrong-typed
    /// required keys are rejected.
    pub fn from_json(json: &[u8]) -> Result<Envelope, EnvelopeError> {
        Ok(serde_json::from_slice(json)?)
    }
}

/// Seal a payload for a recipient and sign the resulting envelope in one step.
///
/// Uses a fresh ephemeral X25519 key and nonce per envelope
/// ([`X25519Cipher::from_seed`]). `payload_json` must be **compact** JSON
/// (§3.2); it is zero-padded to the next bucket by [`crate::pad_payload`].
pub fn seal_and_sign(
    sender_seed: &SecretSeed,
    recipient_ed25519_pub: &PublicKey,
    payload_json: &[u8],
    sent_at: u64,
    expires_at: u64,
) -> Result<Envelope, EnvelopeError> {
    let mut cipher = X25519Cipher::from_seed(sender_seed);
    seal_and_sign_with_cipher(
        &mut cipher,
        sender_seed,
        recipient_ed25519_pub,
        payload_json,
        sent_at,
        expires_at,
    )
}

/// Like [`seal_and_sign`] but with a caller-supplied cipher, so tests can pin
/// the ephemeral secret and nonce (`X25519Cipher::deterministic_from_seed`).
pub fn seal_and_sign_with_cipher<C: E2eCipher>(
    cipher: &mut C,
    sender_seed: &SecretSeed,
    recipient_ed25519_pub: &PublicKey,
    payload_json: &[u8],
    sent_at: u64,
    expires_at: u64,
) -> Result<Envelope, EnvelopeError> {
    let signing_key = SigningKey::from_bytes(sender_seed);
    let from_id = comms_id_bytes(&signing_key.verifying_key().to_bytes());
    let to_id = comms_id_bytes(recipient_ed25519_pub);
    let aad = e2e_aad(&to_id, &from_id);
    let padded = crate::pad_payload(payload_json)?;
    let sealed = cipher.seal(recipient_ed25519_pub, &padded, &aad)?;
    let mut envelope = Envelope {
        v: ENVELOPE_VERSION,
        id: String::new(),
        to: comms_id_hex(&to_id),
        from: comms_id_hex(&from_id),
        sent_at,
        expires_at,
        alg: sealed.alg.clone(),
        epk: sealed.epk.to_vec(),
        nonce: sealed.nonce.to_vec(),
        ct: sealed.ct,
        sig: Vec::new(),
    };
    envelope.sign(&signing_key)?;
    Ok(envelope)
}

/// Base64 (standard, padded) the `epk`/`nonce`/`ct`/`sig` fields manually.
/// Exposed for callers that build envelopes incrementally.
pub fn base64_encode(bytes: &[u8]) -> String {
    STANDARD.encode(bytes)
}
