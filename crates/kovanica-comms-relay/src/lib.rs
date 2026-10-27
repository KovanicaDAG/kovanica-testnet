//! Kovanica comms relay (M1 + M2) — store-and-forward for opaque envelopes.
//!
//! M1 spec: `docs/COMMS-M1-INTERFACES.md` §3 (§4 HTTP). M2 spec:
//! `docs/COMMS-M2-INTERFACES.md` — PoW bound to envelope `id` and prepaid
//! credit via HTLC payment proof. Wrapper submission preserves M1 `v=1` wire.

#![deny(unsafe_code)]

#[cfg(feature = "client")]
pub mod client;
pub mod envelope;
pub mod payload;
#[cfg(feature = "server")]
pub mod server;
pub mod store;

#[cfg(feature = "client")]
pub use client::{ClientError, HealthResponse, RelayClient};
pub use envelope::{
    comms_id_bytes, comms_id_from_hex, comms_id_hex, Envelope, ENVELOPE_VERSION, ENV_ID_DOMAIN,
    ENV_SIG_DOMAIN, MAX_CT, MAX_ENVELOPE_JSON,
};
pub use payload::{pad_payload, trim_payload, MAX_PAYLOAD, PAYLOAD_BUCKETS};
#[cfg(feature = "server")]
pub use server::{router, RelayServer};
pub use store::{
    Credit, InsertOutcome, Store, StoreError, DEFAULT_INBOX_LIMIT, DEFAULT_TTL_MS, MAX_INBOX_LIMIT,
    MAX_PER_RECIPIENT, MAX_TTL_MS,
};

/// Algorithm id string for E2E crypto v1 (§2), re-exported from the crypto lane
/// so the envelope `alg` field and the cipher can never drift apart.
pub use kovanica_comms_crypto::ALG_V1;

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Errors raised while encoding, decoding, validating or signing an envelope.
#[derive(Debug, Error)]
pub enum EnvelopeError {
    /// The JSON document could not be parsed or produced.
    #[error("invalid envelope json: {0}")]
    Json(#[from] serde_json::Error),
    /// A base64 field is not valid standard base64.
    #[error("invalid base64: {0}")]
    Base64(#[from] base64::DecodeError),
    /// A comms-id hex field is not valid hex.
    #[error("invalid hex: {0}")]
    Hex(#[from] hex::FromHexError),
    /// A comms id is not 64 lowercase hex characters.
    #[error("{0}")]
    BadHex(String),
    /// A fixed-width field has the wrong length.
    #[error("invalid length for {field}: expected {expected}, got {got}")]
    BadLength {
        field: &'static str,
        expected: usize,
        got: usize,
    },
    /// The envelope declares a version other than [`ENVELOPE_VERSION`].
    #[error("unsupported envelope version {0}")]
    UnsupportedVersion(u8),
    /// The envelope `alg` is not [`ALG_V1`].
    #[error("unsupported alg {0}")]
    AlgMismatch(String),
    /// The stored `id` does not match [`Envelope::compute_id`].
    #[error("envelope id does not match its contents")]
    IdMismatch,
    /// The `from` comms id does not match the supplied sender public key.
    #[error("sender comms id does not match the supplied public key")]
    SenderMismatch,
    /// The Ed25519 signature did not verify.
    #[error("invalid signature")]
    InvalidSignature,
    /// The payload is larger than the largest padding bucket.
    #[error("payload too large")]
    PayloadTooLarge,
    /// The padded payload could not be interpreted as compact JSON.
    #[error("invalid payload")]
    InvalidPayload,
    /// The E2E cipher failed.
    #[error("crypto error: {0}")]
    Crypto(#[from] kovanica_comms_crypto::CryptoError),
}

/// M2: PoW proof bound to envelope `id` (Hashcash-style).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PowProof {
    pub nonce: String, // hex
    pub bits: u8,
}

/// M2: HTLC payment proof to fund prepaid credit.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaymentProof {
    pub htlc_id: String,
    pub preimage: String, // base64 (or hex acceptable if parsed; store as string)
    pub amount_atoms: u64,
    pub expiry: u64,
    #[serde(default)]
    pub sender_addr: Option<String>,
    pub claimer_addr: String,
}

/// M2: Submission wrapper to preserve M1 `v=1` envelope wire.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubmissionWrapper {
    pub envelope: Envelope,
    #[serde(default)]
    pub pow: Option<PowProof>,
    #[serde(default)]
    pub payment: Option<PaymentProof>,
}

/// Count leading zero bits in the first `bytes` of a byte slice.
pub fn leading_zero_bits(h: &[u8]) -> u32 {
    let mut bits = 0u32;
    for &b in h.iter() {
        match b {
            0 => {
                bits += 8;
            }
            v => {
                bits += v.leading_zeros();
                break;
            }
        }
    }
    bits
}

/// M2 PoW verify: `BLAKE3(nonce_bytes || id_bytes)` must have >= `bits` leading zero bits.
pub fn pow_verify(id_hex: &str, nonce_hex: &str, bits: u8) -> bool {
    if bits == 0 {
        return false;
    }
    let id_bytes = match hex::decode(id_hex) {
        Ok(v) if v.len() == 32 => v,
        _ => return false,
    };
    let nonce_bytes = match hex::decode(nonce_hex) {
        Ok(v) => v,
        Err(_) => return false,
    };
    let mut input = Vec::with_capacity(nonce_bytes.len() + id_bytes.len());
    input.extend_from_slice(&nonce_bytes);
    input.extend_from_slice(&id_bytes);
    let h = kovanica_common::hash(&input);
    (leading_zero_bits(&h) as u8) >= bits
}

/// Decode base64 string (standard) to bytes; empty string → empty vec.
pub fn b64_decode(s: &str) -> Result<Vec<u8>, base64::DecodeError> {
    if s.is_empty() {
        return Ok(Vec::new());
    }
    STANDARD.decode(s.as_bytes())
}

/// Wall-clock milliseconds since the Unix epoch.
pub fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}
