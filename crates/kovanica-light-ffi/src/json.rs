//! JSON shapes shared with `kovanica_getLeaderHeader`, `kovanica_getCommitSeals`,
//! `kovanica_getCommittee`, and `kovanica_getAccountProof`.

use anyhow::{anyhow, bail, Context, Result};
use kovanica_light::committee_from_members;
use kovanica_types::{
    Address, CommitSeal, Committee, Hash, LeaderHeader, PublicKey, Signature, StateProof,
};
use serde_json::Value;

fn parse_quantity(value: &Value, what: &str) -> Result<u64> {
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
    u64::from_str_radix(raw, 16).with_context(|| format!("{what}: invalid quantity"))
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

fn parse_hash(value: &Value, what: &str) -> Result<Hash> {
    let bytes = parse_bytes(value, what, 32)?;
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(Hash(out))
}

fn hash_field(value: &Value, name: &str) -> Result<Hash> {
    parse_hash(field(value, name)?, name)
}

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

pub fn parse_json(text: &str) -> Result<Value> {
    serde_json::from_str(text).context("parsing JSON")
}
