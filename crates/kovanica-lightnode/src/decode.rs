//! JSON shapes returned by the full node's light RPC.
//!
//! Field names match `kovanica-rpc` `leader_header_json`, `seal_json`,
//! `handle_get_committee`, and `handle_get_account_proof`.

use anyhow::{anyhow, bail, Context, Result};
use kovanica_light::committee_from_members;
use kovanica_types::{
    Address, CommitSeal, Committee, Hash, LeaderHeader, PublicKey, Signature, StateProof,
};
use serde_json::Value;

/// Parse a `0x` quantity or a JSON integer.
pub fn parse_quantity(value: &Value, what: &str) -> Result<u64> {
    if let Some(n) = value.as_u64() {
        return Ok(n);
    }
    let raw = value
        .as_str()
        .ok_or_else(|| anyhow!("{what}: expected an integer quantity, got {value}"))?;
    let raw = raw.strip_prefix("0x").unwrap_or(raw);
    if raw.is_empty() {
        bail!("{what}: empty quantity");
    }
    u64::from_str_radix(raw, 16).with_context(|| format!("{what}: invalid quantity `{value}`"))
}

fn field<'a>(value: &'a Value, name: &str) -> Result<&'a Value> {
    value.get(name).ok_or_else(|| anyhow!("missing `{name}`"))
}

fn qty(value: &Value, name: &str) -> Result<u64> {
    parse_quantity(field(value, name)?, name)
}

fn parse_bytes(value: &Value, what: &str, len: usize) -> Result<Vec<u8>> {
    let raw = value
        .as_str()
        .ok_or_else(|| anyhow!("{what}: expected a hex string"))?;
    let raw = raw.strip_prefix("0x").unwrap_or(raw);
    let bytes = hex::decode(raw).with_context(|| format!("{what}: invalid hex"))?;
    if bytes.len() != len {
        bail!("{what}: expected {len} bytes, got {}", bytes.len());
    }
    Ok(bytes)
}

pub(crate) fn parse_hash(value: &Value, what: &str) -> Result<Hash> {
    let bytes = parse_bytes(value, what, 32)?;
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(Hash(out))
}

fn hash_field(value: &Value, name: &str) -> Result<Hash> {
    parse_hash(field(value, name)?, name)
}

/// Decode `kovanica_getLeaderHeader`. `null` is not a header.
pub fn leader_header_from_json(value: &Value) -> Result<LeaderHeader> {
    if value.is_null() {
        bail!("leader header is null");
    }
    let author = field(value, "leaderAuthor")?
        .as_u64()
        .ok_or_else(|| anyhow!("leaderAuthor: expected an integer"))?;
    let author = u16::try_from(author).context("leaderAuthor does not fit in u16")?;
    Ok(LeaderHeader {
        committed_height: qty(value, "committedHeight")?,
        leader_round: qty(value, "leaderRound")?,
        leader_digest: hash_field(value, "leaderDigest")?,
        leader_author: author,
        parent_leader_digest: hash_field(value, "parentLeaderDigest")?,
        tx_merkle_root: hash_field(value, "txMerkleRoot")?,
        executed_tx_root: hash_field(value, "executedTxRoot")?,
        non_blue_root: hash_field(value, "nonBlueRoot")?,
        blue_root: hash_field(value, "blueRoot")?,
        mysticghost: field(value, "mysticghost")?
            .as_bool()
            .ok_or_else(|| anyhow!("mysticghost: expected a boolean"))?,
        state_root: hash_field(value, "stateRoot")?,
        epoch: qty(value, "epoch")?,
        committee_hash: hash_field(value, "committeeHash")?,
        timestamp: qty(value, "timestamp")?,
    })
}

/// Decode the `seals` array from `kovanica_getCommitSeals`.
pub fn seals_from_json(value: &Value) -> Result<Vec<CommitSeal>> {
    let seals = value
        .get("seals")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("commit seals: missing `seals` array"))?;
    seals
        .iter()
        .map(|seal| {
            let index = field(seal, "authorityIndex")?
                .as_u64()
                .ok_or_else(|| anyhow!("authorityIndex: expected an integer"))?;
            let index = u16::try_from(index).context("authorityIndex does not fit in u16")?;
            let bytes = parse_bytes(field(seal, "signature")?, "signature", 64)?;
            let mut signature = [0u8; 64];
            signature.copy_from_slice(&bytes);
            Ok(CommitSeal {
                authority_index: index,
                signature: Signature(signature),
            })
        })
        .collect()
}

/// Decode `kovanica_getCommittee` into a seal committee for `epoch`.
///
/// The RPC does not return the epoch. Callers pass the configured epoch
/// (0 until rotation is live). A member whose public key is not its address
/// is rejected.
pub fn committee_from_json(epoch: u64, value: &Value) -> Result<Committee> {
    let members = value
        .as_array()
        .ok_or_else(|| anyhow!("committee: expected an array"))?;
    let mut rows = Vec::with_capacity(members.len());
    for member in members {
        let index = field(member, "index")?
            .as_u64()
            .ok_or_else(|| anyhow!("committee index: expected an integer"))?;
        let index = u16::try_from(index).context("committee index does not fit in u16")?;
        let key_bytes = parse_bytes(field(member, "publicKey")?, "publicKey", 32)?;
        let mut key = [0u8; 32];
        key.copy_from_slice(&key_bytes);
        let public_key = PublicKey::from_bytes(key);
        let stake = qty(member, "stake")?;
        let address_raw = field(member, "address")?
            .as_str()
            .ok_or_else(|| anyhow!("committee address: expected a string"))?;
        let address: Address = address_raw
            .parse()
            .map_err(|err| anyhow!("committee address: {err}"))?;
        if Address::from_public_key(&public_key) != address {
            bail!("committee member {index} public key does not match its address");
        }
        rows.push((index, public_key, stake, address));
    }
    Ok(committee_from_members(epoch, &rows))
}

/// Decode `kovanica_getAccountProof`. The height is the latest committed height.
pub fn account_proof_from_json(value: &Value) -> Result<(u64, StateProof)> {
    let siblings_json = field(value, "siblings")?
        .as_array()
        .ok_or_else(|| anyhow!("siblings: expected an array"))?;
    let mut siblings = Vec::with_capacity(siblings_json.len());
    for sibling in siblings_json {
        siblings.push(parse_hash(sibling, "sibling")?);
    }
    let address_raw = field(value, "address")?
        .as_str()
        .ok_or_else(|| anyhow!("address: expected a string"))?;
    let address: Address = address_raw
        .parse()
        .map_err(|err| anyhow!("address: {err}"))?;
    Ok((
        qty(value, "height")?,
        StateProof {
            state_root: hash_field(value, "stateRoot")?,
            address,
            balance: qty(value, "balance")?,
            nonce: qty(value, "nonce")?,
            present: field(value, "present")?
                .as_bool()
                .ok_or_else(|| anyhow!("present: expected a boolean"))?,
            siblings,
        },
    ))
}

/// Encode one header the way `kovanica_getLeaderHeader` does, for tests.
pub fn leader_header_json(header: &LeaderHeader) -> Value {
    serde_json::json!({
        "committedHeight": format!("0x{:x}", header.committed_height),
        "leaderRound": format!("0x{:x}", header.leader_round),
        "leaderDigest": format!("0x{}", hex::encode(header.leader_digest.0)),
        "leaderAuthor": header.leader_author,
        "parentLeaderDigest": format!("0x{}", hex::encode(header.parent_leader_digest.0)),
        "txMerkleRoot": format!("0x{}", hex::encode(header.tx_merkle_root.0)),
        "executedTxRoot": format!("0x{}", hex::encode(header.executed_tx_root.0)),
        "nonBlueRoot": format!("0x{}", hex::encode(header.non_blue_root.0)),
        "blueRoot": format!("0x{}", hex::encode(header.blue_root.0)),
        "mysticghost": header.mysticghost,
        "stateRoot": format!("0x{}", hex::encode(header.state_root.0)),
        "epoch": format!("0x{:x}", header.epoch),
        "committeeHash": format!("0x{}", hex::encode(header.committee_hash.0)),
        "timestamp": format!("0x{:x}", header.timestamp),
        "hash": format!("0x{}", hex::encode(header.hash().0)),
    })
}

/// Encode seals the way `kovanica_getCommitSeals` does.
pub fn seals_json(height: u64, header_hash: Option<Hash>, seals: &[CommitSeal]) -> Value {
    serde_json::json!({
        "height": format!("0x{height:x}"),
        "headerHash": header_hash.map(|hash| format!("0x{}", hex::encode(hash.0))),
        "seals": seals.iter().map(|seal| serde_json::json!({
            "authorityIndex": seal.authority_index,
            "signature": format!("0x{}", hex::encode(seal.signature.0)),
        })).collect::<Vec<_>>(),
    })
}
