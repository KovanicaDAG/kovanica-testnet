//! Account address type.

use crate::crypto::PublicKey;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;

/// Human-readable prefix of a canonical Kovanica address string.
pub const ADDRESS_PREFIX: &str = "kvnc";
/// Human-readable suffix of a canonical Kovanica address string.
pub const ADDRESS_SUFFIX: &str = "dag";
/// Size of the address payload in bytes (raw public key).
const ADDRESS_PAYLOAD_LEN: usize = 32;
/// Size of the blake3 checksum of the legacy `kvnc<hex>dag` form, in bytes.
const LEGACY_CHECKSUM_LEN: usize = 4;
/// Checksum bits of the canonical base32 form: the first 29 bits of
/// `blake3(key)`.
pub const ADDRESS_CHECKSUM_BITS: usize = 29;
/// Base32 characters between the prefix and the suffix:
/// `(256 + 29) / 5 = 57` (285 bits, no padding).
pub const ADDRESS_BODY_CHARS: usize = (ADDRESS_PAYLOAD_LEN * 8 + ADDRESS_CHECKSUM_BITS) / 5;
/// Length of a canonical address string: `kvnc` + 57 + `dag` = 64.
pub const ADDRESS_LEN: usize = ADDRESS_PREFIX.len() + ADDRESS_BODY_CHARS + ADDRESS_SUFFIX.len();
/// The bech32 data alphabet (BIP-173), lower case only.
const BASE32_ALPHABET: &[u8; 32] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";

/// Whether the legacy hex forms (`kvnc<72 hex>dag` and a bare or
/// `0x`-prefixed 64-hex key) are accepted on `chain_id`.
///
/// Toni, 2026-10-23: dev chains stay lenient, and chain 4 stays lenient so
/// existing tooling keeps working. Accepted on devnet (`3`), chain `4`, and
/// local (`1337`). Refused on mainnet (`1`), on the other public testnet
/// (`2`), and on every chain id that is not one of those three.
#[must_use]
pub fn legacy_address_allowed(chain_id: u64) -> bool {
    matches!(
        chain_id,
        crate::signing::chain_id::DEVNET
            | crate::signing::chain_id::LOCAL
            | crate::signing::chain_id::TESTNET_V2
    )
}

/// Errors produced while parsing an [`Address`].
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum AddressError {
    /// The string did not start with [`ADDRESS_PREFIX`] and end with
    /// [`ADDRESS_SUFFIX`].
    #[error("address must start with `{ADDRESS_PREFIX}` and end with `{ADDRESS_SUFFIX}`")]
    MissingAffix,
    /// The payload was not valid hexadecimal (legacy forms).
    #[error("address payload is not valid hex")]
    InvalidHex,
    /// A character outside the lower-case bech32 alphabet.
    #[error("address contains a character outside the base32 alphabet")]
    InvalidBase32,
    /// The decoded payload had the wrong length.
    #[error("address payload must be {ADDRESS_PAYLOAD_LEN} bytes, got {0}")]
    InvalidLength(usize),
    /// The string has the affixes but is not the canonical 64 characters.
    #[error("address must be {ADDRESS_LEN} characters, got {0}")]
    InvalidStringLength(usize),
    /// The checksum did not match the payload.
    #[error("address checksum mismatch")]
    ChecksumMismatch,
    /// A legacy hex address on a chain that accepts only base32.
    #[error("legacy hex addresses are not accepted on chain {0}; use the {ADDRESS_LEN}-character kvnc…dag form")]
    LegacyNotAllowed(u64),
}

/// 32-byte account address (raw Ed25519 public key).
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize, Default)]
pub struct Address(pub [u8; 32]);

impl Address {
    /// Derive address from a public key.
    ///
    /// Kovanica uses the raw 32-byte Ed25519 public key as the account address so
    /// that [`crate::transaction::Transaction::verify_signature`] can verify the
    /// signature directly against `sender` (which it treats as the public key).
    pub fn from_public_key(pk: &PublicKey) -> Self {
        Self(pk.0)
    }

    /// Return the address as a bare hex string (no affixes).
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    /// Canonical encoding (PRO-21, Toni 2026-10-23): `kvnc` + 57 base32
    /// characters (bech32 alphabet) + `dag`, 64 characters in total.
    ///
    /// The 57 characters carry 285 bits, most significant bit first: the
    /// 32-byte key followed by the first 29 bits of `blake3(key)`. No padding.
    pub fn encode(&self) -> String {
        let check = Self::checksum29(&self.0);
        let mut bits = BitWriter::default();
        for byte in self.0 {
            bits.push(u32::from(byte), 8);
        }
        bits.push(check, ADDRESS_CHECKSUM_BITS);
        debug_assert_eq!(bits.out.len(), ADDRESS_BODY_CHARS);
        let mut out = String::with_capacity(ADDRESS_LEN);
        out.push_str(ADDRESS_PREFIX);
        out.extend(
            bits.out
                .iter()
                .map(|&v| BASE32_ALPHABET[v as usize] as char),
        );
        out.push_str(ADDRESS_SUFFIX);
        out
    }

    /// Decode the canonical 64-character form, verifying the checksum.
    ///
    /// The 57-character body is the lowercase bech32 alphabet. An uppercase
    /// letter is [`AddressError::InvalidBase32`]. Legacy hex forms are
    /// rejected here; see [`Self::parse_for_chain`].
    pub fn decode(value: &str) -> Result<Self, AddressError> {
        let body = value
            .strip_prefix(ADDRESS_PREFIX)
            .and_then(|rest| rest.strip_suffix(ADDRESS_SUFFIX))
            .ok_or(AddressError::MissingAffix)?;
        if value.len() != ADDRESS_LEN {
            return Err(AddressError::InvalidStringLength(value.len()));
        }
        let mut acc: u64 = 0;
        let mut nbits = 0usize;
        let mut payload = [0u8; ADDRESS_PAYLOAD_LEN];
        let mut filled = 0usize;
        for c in body.bytes() {
            let v = BASE32_ALPHABET
                .iter()
                .position(|&a| a == c)
                .ok_or(AddressError::InvalidBase32)? as u64;
            acc = (acc << 5) | v;
            nbits += 5;
            if filled < ADDRESS_PAYLOAD_LEN && nbits >= 8 {
                nbits -= 8;
                payload[filled] = ((acc >> nbits) & 0xff) as u8;
                filled += 1;
                acc &= (1u64 << nbits) - 1;
            }
        }
        // After the 256 key bits, exactly 29 checksum bits remain (the
        // length check above guarantees it).
        debug_assert!(filled == ADDRESS_PAYLOAD_LEN && nbits == ADDRESS_CHECKSUM_BITS);
        let check = acc as u32;
        if check != Self::checksum29(&payload) {
            return Err(AddressError::ChecksumMismatch);
        }
        Ok(Self(payload))
    }

    /// Parse an address typed or sent for `chain_id`: the canonical base32
    /// form on every chain; the legacy hex forms (`kvnc<hex>dag` with its
    /// 4-byte checksum, bare or `0x` hex) only where
    /// [`legacy_address_allowed`] says so (devnet 3, chain 4, local 1337).
    pub fn parse_for_chain(value: &str, chain_id: u64) -> Result<Self, AddressError> {
        let value = value.trim();
        if value.len() == ADDRESS_LEN
            && value.starts_with(ADDRESS_PREFIX)
            && value.ends_with(ADDRESS_SUFFIX)
        {
            return Self::decode(value);
        }
        let legacy = Self::parse_legacy(value)?;
        if !legacy_address_allowed(chain_id) {
            return Err(AddressError::LegacyNotAllowed(chain_id));
        }
        Ok(legacy)
    }

    /// The legacy hex forms. Chain-independent; callers decide whether they
    /// are allowed.
    ///
    /// Hex digits are case-insensitive (`a-f` and `A-F`). The `kvnc` and
    /// `dag` affixes, and the `0x` prefix, are lowercase only. The canonical
    /// base32 body is a different alphabet and is strictly lowercase.
    fn parse_legacy(value: &str) -> Result<Self, AddressError> {
        if value.starts_with(ADDRESS_PREFIX) || value.ends_with(ADDRESS_SUFFIX) {
            let body = value
                .strip_prefix(ADDRESS_PREFIX)
                .and_then(|rest| rest.strip_suffix(ADDRESS_SUFFIX))
                .ok_or(AddressError::MissingAffix)?;
            if !body.bytes().all(|b| b.is_ascii_hexdigit()) {
                // Not hex: report it as a malformed canonical address.
                return Err(Self::decode(value)
                    .err()
                    .unwrap_or(AddressError::InvalidStringLength(value.len())));
            }
            let bytes = hex::decode(body).map_err(|_| AddressError::InvalidHex)?;
            if bytes.len() != ADDRESS_PAYLOAD_LEN + LEGACY_CHECKSUM_LEN {
                return Err(AddressError::InvalidLength(bytes.len()));
            }
            let mut payload = [0u8; ADDRESS_PAYLOAD_LEN];
            payload.copy_from_slice(&bytes[..ADDRESS_PAYLOAD_LEN]);
            if bytes[ADDRESS_PAYLOAD_LEN..] != Self::legacy_checksum(&payload) {
                return Err(AddressError::ChecksumMismatch);
            }
            return Ok(Self(payload));
        }
        let raw = value.strip_prefix("0x").unwrap_or(value);
        let bytes = hex::decode(raw).map_err(|_| AddressError::InvalidHex)?;
        if bytes.len() != ADDRESS_PAYLOAD_LEN {
            return Err(AddressError::InvalidLength(bytes.len()));
        }
        let mut payload = [0u8; ADDRESS_PAYLOAD_LEN];
        payload.copy_from_slice(&bytes);
        Ok(Self(payload))
    }

    /// Legacy `kvnc<hex>dag` encoding (key + 4-byte blake3 checksum, hex).
    ///
    /// Tooling on chains 3, 4, and 1337. Never the default display. [`FromStr`]
    /// does not read this form; use [`Self::parse_for_chain`].
    pub fn encode_legacy_hex(&self) -> String {
        let mut bytes = [0u8; ADDRESS_PAYLOAD_LEN + LEGACY_CHECKSUM_LEN];
        bytes[..ADDRESS_PAYLOAD_LEN].copy_from_slice(&self.0);
        bytes[ADDRESS_PAYLOAD_LEN..].copy_from_slice(&Self::legacy_checksum(&self.0));
        format!("{ADDRESS_PREFIX}{}{ADDRESS_SUFFIX}", hex::encode(bytes))
    }

    /// First 29 bits of `blake3(key)`, as the low 29 bits of a `u32`.
    fn checksum29(payload: &[u8; ADDRESS_PAYLOAD_LEN]) -> u32 {
        let d = blake3::hash(payload);
        let b = d.as_bytes();
        u32::from_be_bytes([b[0], b[1], b[2], b[3]]) >> (32 - ADDRESS_CHECKSUM_BITS)
    }

    fn legacy_checksum(payload: &[u8; ADDRESS_PAYLOAD_LEN]) -> [u8; LEGACY_CHECKSUM_LEN] {
        let digest = blake3::hash(payload);
        let mut checksum = [0u8; LEGACY_CHECKSUM_LEN];
        checksum.copy_from_slice(&digest.as_bytes()[..LEGACY_CHECKSUM_LEN]);
        checksum
    }
}

/// MSB-first bit packer producing 5-bit groups.
#[derive(Default)]
struct BitWriter {
    acc: u64,
    nbits: usize,
    out: Vec<u8>,
}

impl BitWriter {
    fn push(&mut self, value: u32, bits: usize) {
        self.acc = (self.acc << bits) | u64::from(value);
        self.nbits += bits;
        while self.nbits >= 5 {
            self.nbits -= 5;
            self.out.push(((self.acc >> self.nbits) & 31) as u8);
        }
        self.acc &= (1u64 << self.nbits) - 1;
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.encode())
    }
}

impl fmt::Debug for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Address({})", self.to_hex())
    }
}

impl FromStr for Address {
    type Err = AddressError;

    /// The canonical 64-character base32 form only: `kvnc` + 57 lowercase
    /// bech32 characters + `dag`.
    ///
    /// Legacy hex is not accepted here. Callers that know a chain use
    /// [`Address::parse_for_chain`]. That is lenient (legacy hex allowed) on
    /// devnet 3, chain 4, and local 1337, and base32-only on mainnet 1 and
    /// every other chain id.
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::decode(value.trim())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signing::chain_id;

    const KAT_ZERO: &str = "kvncqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqz4k5rcdag";
    const KAT_SAMPLE: &str = "kvncqqqsyqcyq5rqwzqfpg9scrgwpugpzysnzs23v9ccrydpk8qarc07228f2dag";

    fn sample() -> Address {
        let mut bytes = [0u8; 32];
        for (i, byte) in bytes.iter_mut().enumerate() {
            *byte = i as u8;
        }
        Address(bytes)
    }

    #[test]
    fn canonical_form_is_64_chars_kvnc_57_dag() {
        assert_eq!(ADDRESS_BODY_CHARS, 57);
        assert_eq!(ADDRESS_LEN, 64);
        let encoded = sample().encode();
        assert_eq!(encoded.len(), 64);
        assert!(encoded.starts_with("kvnc") && encoded.ends_with("dag"));
        let body = &encoded[4..61];
        assert!(body.bytes().all(|c| BASE32_ALPHABET.contains(&c)), "{body}");
    }

    /// Known answer, computed independently (Python blake3 + bech32
    /// alphabet, MSB-first, key ‖ first 29 bits of blake3(key)).
    #[test]
    fn canonical_known_answers() {
        assert_eq!(Address([0u8; 32]).encode(), KAT_ZERO);
        assert_eq!(sample().encode(), KAT_SAMPLE);
        assert_eq!(Address::decode(KAT_SAMPLE).unwrap(), sample());
    }

    #[test]
    fn canonical_encoding_round_trips() {
        for seed in 0u8..=40 {
            let address = Address([seed.wrapping_mul(37); 32]);
            let encoded = address.encode();
            assert_eq!(Address::decode(&encoded).unwrap(), address);
            assert_eq!(encoded.parse::<Address>().unwrap(), address);
            for chain in [chain_id::MAINNET, chain_id::TESTNET_V2, chain_id::LOCAL] {
                assert_eq!(Address::parse_for_chain(&encoded, chain).unwrap(), address);
            }
        }
        let address = sample();
        assert_eq!(address.to_string(), address.encode());
    }

    #[test]
    fn checksum_mismatch_is_detected() {
        let encoded = sample().encode();
        // Change every body character in turn to another alphabet character.
        for pos in 4..61 {
            let mut bytes = encoded.clone().into_bytes();
            let cur = BASE32_ALPHABET
                .iter()
                .position(|&a| a == bytes[pos])
                .unwrap();
            bytes[pos] = BASE32_ALPHABET[(cur + 1) % 32];
            let tampered = String::from_utf8(bytes).unwrap();
            assert_eq!(
                Address::decode(&tampered),
                Err(AddressError::ChecksumMismatch),
                "position {pos}"
            );
        }
    }

    #[test]
    fn wrong_length_prefix_suffix_and_alphabet_are_rejected() {
        let encoded = sample().encode();
        let body = &encoded[4..61];
        assert_eq!(
            Address::decode(&format!("kvnc{}dag", &body[..56])),
            Err(AddressError::InvalidStringLength(63))
        );
        assert_eq!(
            Address::decode(&format!("kvnc{body}qdag")),
            Err(AddressError::InvalidStringLength(65))
        );
        assert_eq!(
            Address::decode(&format!("kvnx{body}dag")),
            Err(AddressError::MissingAffix)
        );
        assert_eq!(
            Address::decode(&format!("kvnc{body}dax")),
            Err(AddressError::MissingAffix)
        );
        assert_eq!(Address::decode(body), Err(AddressError::MissingAffix));
        // 'b', 'i', 'o', '1' and upper case are not in the alphabet.
        for bad in ['b', 'i', 'o', '1', 'Q'] {
            let mut s = encoded.clone();
            s.replace_range(10..11, &bad.to_string());
            assert_eq!(
                Address::decode(&s),
                Err(AddressError::InvalidBase32),
                "{bad}"
            );
        }
    }

    /// Legacy hex forms follow [`legacy_address_allowed`]: accepted on devnet
    /// (3), chain 4, and local (1337); refused on mainnet (1), testnet (2),
    /// and any other chain id. [`FromStr`] is base32 only, on every chain.
    #[test]
    fn legacy_hex_policy_covers_known_and_unknown_chains() {
        let address = sample();
        let legacy = [
            address.encode_legacy_hex(),
            address.to_hex(),
            format!("0x{}", address.to_hex()),
        ];
        assert_eq!(legacy[0].len(), 4 + 72 + 3);
        let allowed = [chain_id::DEVNET, chain_id::TESTNET_V2, chain_id::LOCAL];
        let refused = [chain_id::MAINNET, chain_id::TESTNET, 0, 42];
        for chain in allowed {
            assert!(legacy_address_allowed(chain), "chain {chain}");
        }
        for chain in refused {
            assert!(!legacy_address_allowed(chain), "chain {chain}");
        }
        assert!(!legacy_address_allowed(u64::MAX));
        for form in &legacy {
            for chain in allowed {
                assert_eq!(
                    Address::parse_for_chain(form, chain).unwrap(),
                    address,
                    "{form} on chain {chain}"
                );
            }
            for chain in refused {
                assert_eq!(
                    Address::parse_for_chain(form, chain),
                    Err(AddressError::LegacyNotAllowed(chain)),
                    "{form} on chain {chain}"
                );
            }
            let err = form.parse::<Address>().expect_err("FromStr is base32 only");
            assert!(
                matches!(
                    err,
                    AddressError::InvalidStringLength(_) | AddressError::MissingAffix
                ),
                "{form}: {err:?}"
            );
        }
        assert_eq!(address.encode().parse::<Address>().unwrap(), address);
    }

    #[test]
    fn legacy_checksum_and_length_errors_are_still_reported() {
        let mut legacy = sample().encode_legacy_hex();
        let flip_at = legacy.len() - ADDRESS_SUFFIX.len() - LEGACY_CHECKSUM_LEN * 2 - 1;
        let replacement = if &legacy[flip_at..flip_at + 1] == "0" {
            "1"
        } else {
            "0"
        };
        legacy.replace_range(flip_at..flip_at + 1, replacement);
        assert_eq!(
            Address::parse_for_chain(&legacy, chain_id::TESTNET_V2),
            Err(AddressError::ChecksumMismatch)
        );
        // Short legacy strings still report a length error on a lenient chain.
        // `FromStr` never reaches that parser: it only decodes base32.
        assert!(matches!(
            Address::parse_for_chain("kvnc00dag", chain_id::TESTNET_V2),
            Err(AddressError::InvalidLength(_))
        ));
        assert!(matches!(
            Address::parse_for_chain("0x1234", chain_id::TESTNET_V2),
            Err(AddressError::InvalidLength(_))
        ));
        assert!(matches!(
            "kvnc00dag".parse::<Address>(),
            Err(AddressError::InvalidStringLength(9))
        ));
        assert!(matches!(
            "0x1234".parse::<Address>(),
            Err(AddressError::MissingAffix)
        ));
    }

    /// Legacy hex digits accept `A-F`. Base32 does not: the alphabet is lowercase.
    #[test]
    fn legacy_hex_digits_are_case_insensitive_and_base32_is_lowercase() {
        let address = sample();
        let encoded = address.encode();
        let ch = encoded.as_bytes()[10];
        assert!(ch.is_ascii_lowercase());
        let mut upper_body = encoded.clone();
        upper_body.replace_range(10..11, &char::from(ch).to_ascii_uppercase().to_string());
        assert_eq!(
            upper_body.parse::<Address>(),
            Err(AddressError::InvalidBase32)
        );
        assert_eq!(
            Address::parse_for_chain(&upper_body, chain_id::MAINNET),
            Err(AddressError::InvalidBase32)
        );

        let legacy = address.encode_legacy_hex();
        let body = &legacy[ADDRESS_PREFIX.len()..legacy.len() - ADDRESS_SUFFIX.len()];
        let upper_legacy = format!(
            "{ADDRESS_PREFIX}{}{ADDRESS_SUFFIX}",
            body.to_ascii_uppercase()
        );
        for chain in [chain_id::DEVNET, chain_id::TESTNET_V2, chain_id::LOCAL] {
            assert_eq!(
                Address::parse_for_chain(&upper_legacy, chain).unwrap(),
                address,
                "chain {chain}"
            );
        }
        assert_eq!(
            Address::parse_for_chain(&upper_legacy, chain_id::MAINNET),
            Err(AddressError::LegacyNotAllowed(chain_id::MAINNET))
        );
        assert_eq!(
            Address::parse_for_chain(&upper_legacy, chain_id::TESTNET),
            Err(AddressError::LegacyNotAllowed(chain_id::TESTNET))
        );
        assert!(upper_legacy.parse::<Address>().is_err());

        let upper_bare = address.to_hex().to_ascii_uppercase();
        assert_eq!(
            Address::parse_for_chain(&upper_bare, chain_id::TESTNET_V2).unwrap(),
            address
        );
        assert_eq!(
            Address::parse_for_chain(&format!("0x{upper_bare}"), chain_id::TESTNET_V2).unwrap(),
            address
        );
        assert_eq!(
            Address::parse_for_chain(&format!("0X{upper_bare}"), chain_id::TESTNET_V2),
            Err(AddressError::InvalidHex)
        );
        assert_eq!(
            Address::parse_for_chain(&legacy.to_ascii_uppercase(), chain_id::TESTNET_V2),
            Err(AddressError::InvalidHex)
        );
    }

    #[test]
    fn display_debug_are_distinct() {
        let address = sample();
        assert_eq!(
            format!("{address:?}"),
            format!("Address({})", address.to_hex())
        );
        assert_eq!(format!("{address}"), address.encode());
    }
}
