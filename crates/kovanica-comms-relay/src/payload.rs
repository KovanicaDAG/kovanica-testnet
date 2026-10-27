//! Plaintext payload padding — `docs/COMMS-M1-INTERFACES.md` §3.2.
//!
//! The plaintext inside `ct` is compact JSON (`serde_json::to_vec` /
//! `JSON.stringify`), then zero-padded up to the next bucket. The receiver
//! strips trailing `0x00` bytes (unambiguous: compact JSON always ends with
//! `}`) and JSON-parses the remainder. There is **no `pad` field** in v1.

use crate::EnvelopeError;

/// Padding buckets, ascending (§3.2). Every padded payload is exactly one of
/// these lengths.
pub const PAYLOAD_BUCKETS: [usize; 4] = [256, 1024, 4096, 16384];

/// Largest bucket, i.e. the maximum padded payload size (§3.2).
pub const MAX_PAYLOAD: usize = 16384;

/// The bucket a `json_len`-byte payload pads to, or `None` if it does not fit.
///
/// The payload needs at least one trailing `0x00`, so the bucket must be
/// strictly greater than `json_len` (`≥ json_len + 1`).
pub fn bucket_for(json_len: usize) -> Option<usize> {
    PAYLOAD_BUCKETS
        .iter()
        .copied()
        .find(|bucket| *bucket > json_len)
}

/// Zero-pad a compact-JSON payload to the next bucket (§3.2).
///
/// Errors with [`EnvelopeError::PayloadTooLarge`] when `json` does not fit in
/// the largest bucket (i.e. `json.len() >= 16384`).
pub fn pad_payload(json: &[u8]) -> Result<Vec<u8>, EnvelopeError> {
    let bucket = bucket_for(json.len()).ok_or(EnvelopeError::PayloadTooLarge)?;
    let mut out = Vec::with_capacity(bucket);
    out.extend_from_slice(json);
    out.resize(bucket, 0);
    Ok(out)
}

/// Strip trailing `0x00` bytes and JSON-parse the remainder (§3.2).
///
/// Errors with [`EnvelopeError::InvalidPayload`] if the input is empty or all
/// zeroes.
pub fn trim_payload(padded: &[u8]) -> Result<serde_json::Value, EnvelopeError> {
    let end = padded
        .iter()
        .rposition(|b| *b != 0)
        .map(|i| i + 1)
        .ok_or(EnvelopeError::InvalidPayload)?;
    Ok(serde_json::from_slice::<serde_json::Value>(&padded[..end])?)
}
