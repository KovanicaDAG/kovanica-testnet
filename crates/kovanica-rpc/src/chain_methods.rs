//! Standard chain / transaction / account / staking / mempool / consensus
//! JSON-RPC methods.
//!
//! These handlers are backed by the real node state carried in [`RpcState`]:
//! the redb [`Storage`](kovanica_storage::Storage) for blocks/accounts/consensus,
//! the [`Mempool`](kovanica_mempool::Mempool) for pending transactions, the shared
//! [`StakingState`](kovanica_staking::StakingState) for validator queries and the
//! [`CommitteeInfo`](kovanica_consensus::CommitteeInfo) for leader selection.
//!
//! Response shapes follow the Ethereum JSON-RPC conventions where a Kovanica
//! equivalent exists: 32-byte values and byte blobs are `0x`-prefixed hex
//! strings, while integer quantities (height, balance, nonce, fee, stake) are
//! `0x`-prefixed minimal hex ("quantity") strings.

use crate::{RpcError, RpcState};
use kovanica_storage::{
    query_tx_history, AddressTxIndexError, BlockStoreError, TxDirection, TxHistoryQuery,
};
use kovanica_types::{
    block::StatementBlock,
    hash::Hash,
    light_client::{LightClientCheckpoint, WaveCommitCertificate},
    merkle::{self, MerkleProof, MerkleStep},
    transaction::{Transaction, TransactionKind},
    Address, CommitSeal, LeaderHeader, WAVE_LENGTH,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::sync::{atomic::Ordering, Arc};

/// Default number of rounds returned by `kovanica_getLeaderSchedule` when the
/// caller does not specify a count.
const DEFAULT_LEADER_SCHEDULE_LEN: u64 = 16;
/// Largest `count` accepted by `kovanica_getLeaderSchedule`; larger requests
/// would let one call allocate and serialize an arbitrarily long schedule.
pub const MAX_LEADER_SCHEDULE_LEN: u64 = 1024;

/// Default suggested fee rate (atoms per byte) when the mempool is empty.
const DEFAULT_FEE_RATE: u64 = 1;

/// Largest number of committed-leader heights a single `kovanica_getLogs`
/// call may scan. Keeps the query bounded (and cheap) on a long chain.
pub const MAX_GET_LOGS_BLOCK_RANGE: u64 = 500;

/// Largest number of log entries a single `kovanica_getLogs` call may return.
pub const MAX_GET_LOGS_RESULTS: usize = 2_000;

/// Maximum time (in milliseconds) to spend scanning logs before returning
/// a partial result. Prevents long-running queries from blocking the server.
pub const MAX_GET_LOGS_SCAN_MS: u64 = 200;

// ============================================================================
// Helpers
// ============================================================================

/// Format a byte slice as a `0x`-prefixed hex string.
fn to_hex(bytes: &[u8]) -> String {
    format!("0x{}", hex::encode(bytes))
}

/// Format an integer as an Ethereum-style minimal hex "quantity".
fn quantity<T: std::fmt::LowerHex>(value: T) -> Value {
    Value::String(format!("0x{value:x}"))
}

/// Normalise JSON-RPC `params` into a positional argument list.
///
/// Supports the Ethereum-style array form (`[a, b]`), a bare scalar
/// (`"0x..."`) and the empty/absent form (`null`).
fn params_vec(params: &Value) -> Vec<Value> {
    match params {
        Value::Array(items) => items.clone(),
        Value::Null => Vec::new(),
        other => vec![other.clone()],
    }
}

/// Borrow the `index`-th positional argument, or fail with a clear error.
fn required<'a>(args: &'a [Value], index: usize, what: &str) -> Result<&'a Value, RpcError> {
    args.get(index)
        .ok_or_else(|| RpcError::InvalidParams(format!("missing parameter: {what}")))
}

/// Decode a `0x`-prefixed (or bare) hex string into exactly 32 bytes.
fn parse_bytes32(value: &Value, what: &str) -> Result<[u8; 32], RpcError> {
    let raw = value
        .as_str()
        .ok_or_else(|| RpcError::InvalidParams(format!("{what}: expected a hex string")))?;
    let raw = raw.strip_prefix("0x").unwrap_or(raw);
    let bytes = hex::decode(raw)
        .map_err(|e| RpcError::InvalidParams(format!("{what}: invalid hex: {e}")))?;
    if bytes.len() != 32 {
        return Err(RpcError::InvalidParams(format!(
            "{what}: expected 32 bytes, got {}",
            bytes.len()
        )));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

/// Parse a block/transaction hash parameter.
fn parse_hash(value: &Value, what: &str) -> Result<Hash, RpcError> {
    Ok(Hash(parse_bytes32(value, what)?))
}

/// Parse an account address parameter for `chain_id`.
///
/// The canonical 64-character `kvnc…dag` base32 form is accepted on every
/// chain. The legacy hex forms (`kvnc<hex>dag`, bare or `0x` hex) only where
/// `kovanica_types::address::legacy_address_allowed` is true (devnet 3, chain
/// 4, local 1337).
fn parse_address(value: &Value, what: &str, chain_id: u64) -> Result<Address, RpcError> {
    let raw = value
        .as_str()
        .ok_or_else(|| RpcError::InvalidParams(format!("{what}: expected an address string")))?;
    Address::parse_for_chain(raw, chain_id)
        .map_err(|e| RpcError::InvalidParams(format!("{what}: {e}")))
}

/// Chain id this node serves (the mempool's signing context).
fn served_chain_id(state: &RpcState) -> u64 {
    state.mempool.signing_context().chain_id
}

/// Parse an integer parameter accepted as either a JSON number or a
/// `0x`-prefixed quantity string.
fn parse_u64(value: &Value, what: &str) -> Result<u64, RpcError> {
    if let Some(n) = value.as_u64() {
        return Ok(n);
    }
    if let Some(raw) = value.as_str() {
        let raw = raw.strip_prefix("0x").unwrap_or(raw);
        return u64::from_str_radix(raw, 16)
            .map_err(|e| RpcError::InvalidParams(format!("{what}: invalid number: {e}")));
    }
    Err(RpcError::InvalidParams(format!(
        "{what}: expected an integer"
    )))
}

/// Parse a contract storage slot.
///
/// Accepts either a full 32-byte hex key or a small integer (Ethereum-style
/// slot number) which is left-padded big-endian into 32 bytes.
fn parse_storage_key(value: &Value, what: &str) -> Result<[u8; 32], RpcError> {
    if value.is_number() || value.as_str().map(|s| s.len() <= 18).unwrap_or(false) {
        if let Ok(slot) = parse_u64(value, what) {
            let mut key = [0u8; 32];
            key[24..].copy_from_slice(&slot.to_be_bytes());
            return Ok(key);
        }
    }
    parse_bytes32(value, what)
}

/// Map an internal storage/state error onto the JSON-RPC internal-error code.
fn internal<E: std::fmt::Display>(e: E) -> RpcError {
    RpcError::InternalError(e.to_string())
}

/// Serialise a transaction kind into a tagged JSON object.
fn kind_to_json(kind: &TransactionKind) -> Value {
    match kind {
        TransactionKind::Transfer { to, amount } => json!({
            "type": "transfer",
            "to": to.to_string(),
            "amount": quantity(*amount),
        }),
        TransactionKind::Stake { amount } => json!({
            "type": "stake",
            "amount": quantity(*amount),
        }),
        TransactionKind::Unstake { amount } => json!({
            "type": "unstake",
            "amount": quantity(*amount),
        }),
        TransactionKind::Delegate { validator, amount } => json!({
            "type": "delegate",
            "validator": validator.to_string(),
            "amount": quantity(*amount),
        }),
        TransactionKind::ClaimRewards { validator } => json!({
            "type": "claim_rewards",
            "validator": validator.map(|v| v.to_string()),
        }),
        TransactionKind::Deploy { code } => json!({
            "type": "deploy",
            "code": to_hex(code),
        }),
        TransactionKind::Call {
            contract,
            method,
            args,
            gas_limit,
            value,
        } => json!({
            "type": "call",
            "contract": contract.to_string(),
            "value": value,
            "method": method,
            "args": to_hex(args),
            "gas_limit": quantity(*gas_limit),
        }),
        TransactionKind::RegisterLightNode {
            vrf_public_key,
            stake,
        } => json!({
            "type": "register_light_node",
            "vrfPublicKey": to_hex(vrf_public_key.as_bytes()),
            "stake": quantity(*stake),
        }),
        TransactionKind::ExitLightNode => json!({
            "type": "exit_light_node",
        }),
        TransactionKind::SubmitLightWitness {
            epoch,
            vrf_hash,
            vrf_proof,
        } => json!({
            "type": "submit_light_witness",
            "epoch": quantity(*epoch),
            "vrfHash": to_hex(vrf_hash),
            "vrfProof": to_hex(vrf_proof),
        }),
        TransactionKind::SetCommission {
            validator,
            commission_bps,
        } => json!({
            "type": "set_commission",
            "validator": validator.to_string(),
            "commission_bps": quantity(*commission_bps as u64),
        }),
        TransactionKind::ClaimTreasury { amount } => json!({
            "type": "claim_treasury",
            "amount": quantity(*amount),
        }),
        TransactionKind::Evidence { evidence } => json!({
            "type": "evidence",
            "author": evidence.header_a.author.to_string(),
            "round": quantity(evidence.round()),
            "digest_a": to_hex(&evidence.header_a.digest.0),
            "digest_b": to_hex(&evidence.header_b.digest.0),
        }),
    }
}

/// Serialise a transaction into JSON (without block context).
pub(crate) fn transaction_to_json(tx: &Transaction) -> Value {
    json!({
        "hash": to_hex(&tx.hash.0),
        "sender": tx.sender.to_string(),
        "nonce": quantity(tx.nonce),
        "fee": quantity(tx.fee),
        "kind": kind_to_json(&tx.kind),
        "signature": to_hex(&tx.signature.0),
    })
}

/// Serialise a block into JSON.
pub(crate) fn block_to_json(block: &StatementBlock) -> Value {
    json!({
        "hash": to_hex(&block.digest.0),
        "digest": to_hex(&block.digest.0),
        "author": block.author,
        "number": quantity(block.round),
        "round": quantity(block.round),
        "parents": block
            .parents
            .iter()
            .map(|p| to_hex(&p.digest.0))
            .collect::<Vec<_>>(),
        "transactions": block
            .transactions
            .iter()
            .map(transaction_to_json)
            .collect::<Vec<_>>(),
        "statements": to_hex(&block.statements),
        "signature": to_hex(&block.signature.0),
    })
}

// ============================================================================
// Chain methods
// ============================================================================

/// `kovanica_blockNumber` — latest committed leader height.
pub async fn handle_block_number(_params: Value, state: RpcState) -> Result<Value, RpcError> {
    let height = state
        .consensus_store
        .get_committed_leader_height()
        .map_err(internal)?;
    Ok(quantity(height))
}

/// `kovanica_getBlockByHash(hash, full_transactions)` — block by digest.
pub async fn handle_get_block_by_hash(params: Value, state: RpcState) -> Result<Value, RpcError> {
    let args = params_vec(&params);
    let hash = parse_hash(required(&args, 0, "block hash")?, "block hash")?;

    let txn = state.storage.begin_read().map_err(internal)?;
    match state.storage.blocks().get_block(&txn, &hash) {
        Ok(block) => Ok(block_to_json(&block)),
        Err(BlockStoreError::NotFound(_)) => Ok(Value::Null),
        Err(e) => Err(internal(e)),
    }
}

/// `kovanica_getBlockByNumber(number, full_transactions)` — block by height/round.
pub async fn handle_get_block_by_number(params: Value, state: RpcState) -> Result<Value, RpcError> {
    let args = params_vec(&params);
    let number = parse_u64(required(&args, 0, "block number")?, "block number")?;

    let txn = state.storage.begin_read().map_err(internal)?;
    match state
        .storage
        .blocks()
        .get_block_by_height(&txn, number)
        .map_err(internal)?
    {
        Some(block) => Ok(block_to_json(&block)),
        None => Ok(Value::Null),
    }
}

// ============================================================================
// Transaction methods
// ============================================================================

/// `kovanica_sendRawTransaction(raw_hex)` — decode and submit a signed tx.
pub async fn handle_send_raw_transaction(
    params: Value,
    state: RpcState,
) -> Result<Value, RpcError> {
    let args = params_vec(&params);
    let raw = required(&args, 0, "raw transaction")?
        .as_str()
        .ok_or_else(|| RpcError::InvalidParams("raw transaction: expected a hex string".into()))?;
    let raw = raw.strip_prefix("0x").unwrap_or(raw);
    let bytes = hex::decode(raw)
        .map_err(|e| RpcError::InvalidParams(format!("raw transaction: invalid hex: {e}")))?;
    let tx: Transaction = bincode::deserialize(&bytes)
        .map_err(|e| RpcError::InvalidParams(format!("raw transaction: invalid encoding: {e}")))?;

    let hash = tx.hash;
    let event_tx = tx.clone();
    state
        .mempool
        .add_transaction(tx)
        .map_err(|e| RpcError::ExecutionError(e.to_string()))?;
    // Only transactions the mempool accepted reach this point; publish them
    // on gossip so other validators can include them. A closed channel
    // (node shutting down) is not an RPC error: the tx is already pooled.
    if let Some(gossip) = &state.tx_gossip {
        let _ = gossip.send(event_tx.clone());
    }
    state.events.publish_pending_transaction(&event_tx);

    Ok(json!(to_hex(&hash.0)))
}

/// `kovanica_getTransactionReceipt(hash)` — receipt for a mined transaction.
///
/// Once the block carrying the transaction has been executed, the receipt
/// reports the **real** outcome: `status`/`success` say whether the
/// transaction body succeeded (a contract call can fail — e.g. out of gas —
/// while fee and nonce are still charged) and `gasUsed` is the interpreter
/// fuel the transaction actually burned (`0` for native kinds).
///
/// When the block is known but no receipt row exists yet — the transaction is
/// in a block whose committed sub-DAG has not been executed, or the storage
/// predates the per-hash receipt index — the pre-existing optimistic shape is
/// preserved so clients that only need inclusion keep working.
pub async fn handle_get_transaction_receipt(
    params: Value,
    state: RpcState,
) -> Result<Value, RpcError> {
    let args = params_vec(&params);
    let hash = parse_hash(required(&args, 0, "transaction hash")?, "transaction hash")?;

    // Scoped so no read transaction is held while the receipt index is
    // queried (and never across an await point).
    let (block_hash, block_round, index) = {
        let txn = state.storage.begin_read().map_err(internal)?;
        let Some(block_hash) = state
            .storage
            .blocks()
            .get_block_for_transaction(&txn, &hash)
            .map_err(internal)?
        else {
            return Ok(Value::Null);
        };

        let block = state
            .storage
            .blocks()
            .get_block(&txn, &block_hash)
            .map_err(internal)?;
        let index = block.transactions.iter().position(|t| t.hash == hash);
        (block_hash, block.round, index)
    };

    let receipt =
        kovanica_execution::receipt_by_tx_hash(&state.storage, &hash).map_err(internal)?;
    let (status, success, gas_used) = match receipt {
        Some(receipt) => (
            if receipt.success { "0x1" } else { "0x0" },
            receipt.success,
            quantity(receipt.gas_used),
        ),
        None => ("0x1", true, quantity(0u64)),
    };

    Ok(json!({
        "transactionHash": to_hex(&hash.0),
        "blockHash": to_hex(&block_hash.0),
        "blockNumber": quantity(block_round),
        "transactionIndex": index.map(|i| quantity(i as u64)).unwrap_or(Value::Null),
        "status": status,
        "success": success,
        "gasUsed": gas_used,
    }))
}

/// `kovanica_getTransactionByHash(hash)` — transaction with block context.
pub async fn handle_get_transaction_by_hash(
    params: Value,
    state: RpcState,
) -> Result<Value, RpcError> {
    let args = params_vec(&params);
    let hash = parse_hash(required(&args, 0, "transaction hash")?, "transaction hash")?;

    let txn = state.storage.begin_read().map_err(internal)?;
    let Some(block_hash) = state
        .storage
        .blocks()
        .get_block_for_transaction(&txn, &hash)
        .map_err(internal)?
    else {
        // Not in a blue block yet: a pooled tx (fresh, or returned from a
        // non-blue block, #13) is reported as pending, without block context.
        return Ok(match state.mempool.get(&hash) {
            Some(tx) => {
                let mut value = transaction_to_json(&tx);
                if let Value::Object(ref mut map) = value {
                    map.insert("blockHash".into(), Value::Null);
                    map.insert("blockNumber".into(), Value::Null);
                    map.insert("transactionIndex".into(), Value::Null);
                    map.insert("status".into(), json!("pending"));
                }
                value
            }
            None => Value::Null,
        });
    };

    let block = state
        .storage
        .blocks()
        .get_block(&txn, &block_hash)
        .map_err(internal)?;
    let Some(index) = block.transactions.iter().position(|t| t.hash == hash) else {
        return Ok(Value::Null);
    };
    let tx = &block.transactions[index];

    let mut value = transaction_to_json(tx);
    if let Value::Object(ref mut map) = value {
        map.insert("blockHash".into(), json!(to_hex(&block_hash.0)));
        map.insert("blockNumber".into(), quantity(block.round));
        map.insert("transactionIndex".into(), quantity(index as u64));
    }
    Ok(value)
}

/// `kovanica_getTransactionHistory` — newest-first committed transactions
/// that touch an address.
///
/// Params is one object (or a one-element array containing that object):
///
/// - `address` (required): canonical `kvnc…dag` or a 32-byte hex address,
///   parsed by the same chain-aware helper as the other account methods.
/// - `limit` (optional): page size. Default 20. Values above 100 are clamped
///   to 100. `0` returns an empty page. A string is a hex quantity, matching
///   other integer parameters.
/// - `cursor` (optional): opaque cursor from a previous `next_cursor`.
///   A malformed cursor is `-32602`.
/// - `direction` (optional): `sent`, `received`, or `all` (the default).
///
/// The read walks only that address's index and stops after one page.
/// Block rewards are not transactions and are not in the history.
/// `timestamp` is the leader-header producer time when it is non-zero, and
/// `null` when the header is missing or still carries the consensus
/// placeholder `0`. `amount` is atoms (`0` when the kind has no KUNA amount).
/// `status` is `success` or `failed`.
pub async fn handle_get_transaction_history(
    params: Value,
    state: RpcState,
) -> Result<Value, RpcError> {
    let args = params_vec(&params);
    let obj = match args.first() {
        Some(Value::Object(map)) => map,
        Some(_) => {
            return Err(RpcError::InvalidParams(
                "getTransactionHistory: expected an object".into(),
            ))
        }
        None => {
            return Err(RpcError::InvalidParams(
                "getTransactionHistory: missing parameters".into(),
            ))
        }
    };

    let address = parse_address(
        obj.get("address")
            .ok_or_else(|| RpcError::InvalidParams("missing parameter: address".into()))?,
        "address",
        served_chain_id(&state),
    )?;
    let limit = match obj.get("limit") {
        None | Some(Value::Null) => None,
        Some(value) => Some(parse_u64(value, "limit")?),
    };
    let cursor = match obj.get("cursor") {
        None | Some(Value::Null) => None,
        Some(Value::String(raw)) => Some(raw.clone()),
        Some(_) => return Err(RpcError::InvalidParams("cursor: expected a string".into())),
    };
    let direction = match obj.get("direction") {
        None | Some(Value::Null) => TxDirection::All,
        Some(Value::String(raw)) => match raw.as_str() {
            "sent" => TxDirection::Sent,
            "received" => TxDirection::Received,
            "all" => TxDirection::All,
            _ => {
                return Err(RpcError::InvalidParams(
                    "direction: expected sent, received, or all".into(),
                ))
            }
        },
        Some(_) => {
            return Err(RpcError::InvalidParams(
                "direction: expected sent, received, or all".into(),
            ))
        }
    };

    let txn = state.storage.begin_read().map_err(internal)?;
    let page = query_tx_history(
        &txn,
        &TxHistoryQuery {
            address,
            limit,
            cursor,
            direction,
        },
    )
    .map_err(|err| match err {
        AddressTxIndexError::InvalidCursor => {
            RpcError::InvalidParams("cursor: invalid transaction history cursor".into())
        }
        other => internal(other),
    })?;

    let mut timestamps: Vec<(u64, Value)> = Vec::new();
    let mut entries = Vec::with_capacity(page.entries.len());
    for entry in page.entries {
        let timestamp = if let Some((_, ts)) = timestamps.iter().find(|(h, _)| *h == entry.height) {
            ts.clone()
        } else {
            let ts = match state
                .storage
                .state()
                .get_leader_header(&txn, entry.height)
                .map_err(internal)?
            {
                Some(header) if header.timestamp != 0 => quantity(header.timestamp),
                _ => Value::Null,
            };
            timestamps.push((entry.height, ts.clone()));
            ts
        };
        let to = match entry.to {
            Some(addr) => Value::String(addr.to_string()),
            None => Value::Null,
        };
        entries.push(json!({
            "hash": to_hex(&entry.tx_hash.0),
            "height": quantity(entry.height),
            "timestamp": timestamp,
            "from": entry.from.to_string(),
            "to": to,
            "amount": quantity(entry.amount),
            "fee": quantity(entry.fee),
            "kind": entry.kind,
            "status": if entry.success { "success" } else { "failed" },
        }));
    }

    Ok(json!({
        "entries": entries,
        "next_cursor": page.next_cursor,
    }))
}

// ============================================================================
// Log query methods
// ============================================================================

/// `kovanica_getLogs(filter)` — query transaction logs (contract events).
///
/// The single `filter` argument mirrors the Ethereum JSON-RPC `eth_getLogs`
/// shape:
///
/// - `fromBlock` / `toBlock`: `"latest"` (the default), `"earliest"`,
///   `"pending"` or a hex quantity. These are **committed-leader heights** —
///   the same counter `kovanica_blockNumber` returns and the value the
///   per-height receipt list is keyed by.
/// - `address`: an address or an array of addresses. A log matches when the
///   event's emitting address is one of them.
/// - `topics`: an array of positions, each `null` (wildcard), a topic string,
///   or an array of alternatives (OR). Events carry a single topic, so only
///   the first position can match.
///
/// The query is bounded: the requested range is limited to
/// [`MAX_GET_LOGS_BLOCK_RANGE`] heights and the response to
/// [`MAX_GET_LOGS_RESULTS`] logs; larger requests are rejected with an
/// invalid-params error rather than scanning an unbounded amount of storage.
/// Heights with no stored receipts are skipped, so a range spanning pruned or
/// never-executed blocks returns what exists.
pub async fn handle_get_logs(params: Value, state: RpcState) -> Result<Value, RpcError> {
    let args = params_vec(&params);
    let filter = args.into_iter().next().unwrap_or(Value::Null);
    if !filter.is_object() && !filter.is_null() {
        return Err(RpcError::InvalidParams(
            "getLogs: filter must be an object".into(),
        ));
    }

    // Same source as `kovanica_blockNumber`, so the range default and the
    // `"latest"` tag agree with the height clients already track.
    let latest = state
        .consensus_store
        .get_committed_leader_height()
        .map_err(internal)?;

    let from = match filter.get("fromBlock") {
        Some(value) if !value.is_null() => parse_block_ref(value, latest, "fromBlock")?,
        _ => latest,
    };
    let to = match filter.get("toBlock") {
        Some(value) if !value.is_null() => parse_block_ref(value, latest, "toBlock")?,
        _ => latest,
    };

    if from > to {
        return Ok(json!([]));
    }
    if to - from + 1 > MAX_GET_LOGS_BLOCK_RANGE {
        return Err(RpcError::InvalidParams(format!(
            "getLogs: block range {} exceeds the maximum of {MAX_GET_LOGS_BLOCK_RANGE} blocks",
            to - from + 1
        )));
    }

    let addresses = parse_address_filter(filter.get("address"), served_chain_id(&state))?;
    let topics = parse_topics_filter(filter.get("topics"))?;

    let scanned =
        kovanica_execution::receipts_in_height_range(&state.storage, from, to).map_err(internal)?;

    let mut logs: Vec<Value> = Vec::new();
    let scan_start = std::time::Instant::now();
    for (height, receipts) in scanned {
        // Timeout check to prevent long-running queries from blocking the server
        if scan_start.elapsed().as_millis() > MAX_GET_LOGS_SCAN_MS as u128 {
            return Err(RpcError::InvalidParams(format!(
                "getLogs: scan timeout after {} ms; narrow the block range or filters",
                MAX_GET_LOGS_SCAN_MS
            )));
        }
        // `logIndex` is per block, matching the Ethereum convention.
        let mut log_index: u64 = 0;
        for (tx_index, receipt) in receipts.iter().enumerate() {
            for event in &receipt.events {
                if let Some(addresses) = &addresses {
                    if !addresses.contains(&event.address) {
                        continue;
                    }
                }
                if !topics_match(&topics, &event.topic) {
                    continue;
                }
                logs.push(json!({
                    "address": event.address.to_string(),
                    "topics": [to_hex(&event.topic)],
                    "data": to_hex(&event.data),
                    "blockNumber": quantity(height),
                    "blockHash": Value::Null,
                    "transactionHash": to_hex(&receipt.tx_hash.0),
                    "transactionIndex": quantity(tx_index as u64),
                    "logIndex": quantity(log_index),
                    "removed": false,
                }));
                log_index += 1;
                if logs.len() > MAX_GET_LOGS_RESULTS {
                    return Err(RpcError::InvalidParams(format!(
                        "getLogs: more than {MAX_GET_LOGS_RESULTS} logs match; narrow the block range or filters"
                    )));
                }
            }
        }
    }

    Ok(Value::Array(logs))
}

/// Resolve a block reference (`"latest"`, `"earliest"`, `"pending"`, a `0x`
/// hex quantity or a number) to a committed-leader height.
fn parse_block_ref(value: &Value, latest: u64, what: &str) -> Result<u64, RpcError> {
    if let Some(tag) = value.as_str() {
        match tag {
            "latest" | "pending" | "safe" | "finalized" => return Ok(latest),
            "earliest" => return Ok(0),
            _ => {}
        }
    }
    parse_u64(value, what)
}

/// Decode one log-topic element. `null` is a wildcard and yields `None`.
///
/// Accepts a `0x`-prefixed hex string (raw topic bytes) or a plain UTF-8
/// string, so a caller can match either the raw bytes or the human-readable
/// topic name (e.g. `"transfer"`).
fn parse_topic(value: &Value, what: &str) -> Result<Option<Vec<u8>>, RpcError> {
    match value {
        Value::Null => Ok(None),
        Value::String(raw) => match raw.strip_prefix("0x").or_else(|| raw.strip_prefix("0X")) {
            Some(hex_str) => hex::decode(hex_str)
                .map(Some)
                .map_err(|e| RpcError::InvalidParams(format!("{what}: invalid hex: {e}"))),
            None => Ok(Some(raw.as_bytes().to_vec())),
        },
        _ => Err(RpcError::InvalidParams(format!(
            "{what}: expected a topic string or null"
        ))),
    }
}

/// Parse the `address` filter: a single address, an array of addresses, or
/// absent/null for "no address constraint".
fn parse_address_filter(
    value: Option<&Value>,
    chain_id: u64,
) -> Result<Option<Vec<Address>>, RpcError> {
    match value {
        None | Some(Value::Null) => Ok(None),
        Some(value @ Value::String(_)) => {
            Ok(Some(vec![parse_address(value, "address", chain_id)?]))
        }
        Some(Value::Array(items)) => Ok(Some(
            items
                .iter()
                .map(|item| parse_address(item, "address", chain_id))
                .collect::<Result<Vec<_>, _>>()?,
        )),
        Some(_) => Err(RpcError::InvalidParams(
            "address: expected an address or an array of addresses".into(),
        )),
    }
}

/// Parse the `topics` filter into per-position alternatives.
fn parse_topics_filter(value: Option<&Value>) -> Result<Vec<Option<Vec<Vec<u8>>>>, RpcError> {
    match value {
        None | Some(Value::Null) => Ok(Vec::new()),
        Some(Value::Array(items)) => items.iter().map(parse_topic_position).collect(),
        Some(_) => Err(RpcError::InvalidParams("topics: expected an array".into())),
    }
}

/// Decode one position of the `topics` filter: `null` (wildcard), a single
/// topic, or an array of alternatives (OR).
fn parse_topic_position(value: &Value) -> Result<Option<Vec<Vec<u8>>>, RpcError> {
    match value {
        Value::Null => Ok(None),
        Value::Array(options) => {
            let mut alternatives = Vec::with_capacity(options.len());
            for option in options {
                let Some(bytes) = parse_topic(option, "topics")? else {
                    return Err(RpcError::InvalidParams(
                        "topics: nested null is not allowed".into(),
                    ));
                };
                alternatives.push(bytes);
            }
            Ok(Some(alternatives))
        }
        other => {
            let bytes = parse_topic(other, "topics")?
                .ok_or_else(|| RpcError::InvalidParams("topics: expected a topic".into()))?;
            Ok(Some(vec![bytes]))
        }
    }
}

/// Whether an event's single topic satisfies the parsed `topics` filter.
///
/// An event carries exactly one topic, so a non-wildcard filter at any
/// position beyond the first can never match.
fn topics_match(filter: &[Option<Vec<Vec<u8>>>], topic: &[u8]) -> bool {
    if filter.is_empty() {
        return true;
    }
    if filter.len() > 1 && filter[1..].iter().any(|position| position.is_some()) {
        return false;
    }
    match &filter[0] {
        None => true,
        Some(options) => options.iter().any(|option| option.as_slice() == topic),
    }
}

// ============================================================================
// Account methods
// ============================================================================

/// `kovanica_getBalance(address)` — native KUNA balance in atoms.
pub async fn handle_get_balance(params: Value, state: RpcState) -> Result<Value, RpcError> {
    let args = params_vec(&params);
    let address = parse_address(
        required(&args, 0, "address")?,
        "address",
        served_chain_id(&state),
    )?;

    let txn = state.storage.begin_read().map_err(internal)?;
    let account = state
        .storage
        .state()
        .get_account_or_default(&txn, &address)
        .map_err(internal)?;
    Ok(quantity(account.balance))
}

/// `kovanica_getNonce(address)` — account nonce.
pub async fn handle_get_nonce(params: Value, state: RpcState) -> Result<Value, RpcError> {
    let args = params_vec(&params);
    let address = parse_address(
        required(&args, 0, "address")?,
        "address",
        served_chain_id(&state),
    )?;

    let txn = state.storage.begin_read().map_err(internal)?;
    let account = state
        .storage
        .state()
        .get_account_or_default(&txn, &address)
        .map_err(internal)?;
    Ok(quantity(account.nonce))
}

/// `kovanica_getCode(address)` — contract bytecode as hex.
pub async fn handle_get_code(params: Value, state: RpcState) -> Result<Value, RpcError> {
    let args = params_vec(&params);
    let address = parse_address(
        required(&args, 0, "address")?,
        "address",
        served_chain_id(&state),
    )?;

    let txn = state.storage.begin_read().map_err(internal)?;
    let account = state
        .storage
        .state()
        .get_account_or_default(&txn, &address)
        .map_err(internal)?;

    let code = if account.code_hash == [0u8; 32] {
        Vec::new()
    } else {
        state
            .storage
            .state()
            .get_contract_code(&txn, &account.code_hash)
            .map_err(internal)?
            .unwrap_or_default()
    };
    Ok(json!(to_hex(&code)))
}

/// `kovanica_getStorageAt(address, key)` — raw contract storage slot as hex.
pub async fn handle_get_storage_at(params: Value, state: RpcState) -> Result<Value, RpcError> {
    let args = params_vec(&params);
    let address = parse_address(
        required(&args, 0, "address")?,
        "address",
        served_chain_id(&state),
    )?;
    let key = parse_storage_key(required(&args, 1, "storage key")?, "storage key")?;

    let txn = state.storage.begin_read().map_err(internal)?;
    let value = state
        .storage
        .state()
        .get_storage(&txn, &address, &key)
        .map_err(internal)?
        .unwrap_or_default();
    Ok(json!(to_hex(&value)))
}

// ============================================================================
// Staking methods
// ============================================================================

/// `kovanica_getValidators()` — active validator set.
pub async fn handle_get_validators(_params: Value, state: RpcState) -> Result<Value, RpcError> {
    let staking = state.staking.read().await;
    let validators: Vec<Value> = staking
        .validators
        .iter()
        .map(|v| {
            json!({
                "address": v.address.to_string(),
                "stake": quantity(v.stake),
                "commission_bps": v.commission_bps,
                "active": v.active,
                "payout_address": v.payout_address.to_string(),
            })
        })
        .collect();
    Ok(Value::Array(validators))
}

/// `kovanica_getStake(address)` — total stake attributable to an address.
///
/// Sums the address's own validator stake (if any) and any delegations it
/// has made.
pub async fn handle_get_stake(params: Value, state: RpcState) -> Result<Value, RpcError> {
    let args = params_vec(&params);
    let address = parse_address(
        required(&args, 0, "address")?,
        "address",
        served_chain_id(&state),
    )?;

    let staking = state.staking.read().await;
    let own_stake: u64 = staking
        .validators
        .iter()
        .filter(|v| v.address == address)
        .map(|v| v.stake)
        .sum();
    let delegated: u64 = staking
        .delegations
        .iter()
        .filter(|d| d.delegator == address)
        .map(|d| d.amount)
        .sum();
    Ok(quantity(own_stake.saturating_add(delegated)))
}

/// `kovanica_getRewards(address)` — cumulative rewards for an address.
pub async fn handle_get_rewards(params: Value, state: RpcState) -> Result<Value, RpcError> {
    let args = params_vec(&params);
    let address = parse_address(
        required(&args, 0, "address")?,
        "address",
        served_chain_id(&state),
    )?;
    let rewards = state.staking.read().await.reward_total(&address);
    Ok(quantity(rewards as u128))
}

// ============================================================================
// Mempool methods
// ============================================================================

/// `kovanica_getPendingTransactions()` — hashes of transactions in the mempool.
pub async fn handle_get_pending_transactions(
    _params: Value,
    state: RpcState,
) -> Result<Value, RpcError> {
    let hashes = state.mempool.pending_hashes();
    let mut out = Vec::with_capacity(hashes.len());
    for h in hashes {
        out.push(Value::String(format!("0x{}", hex::encode(h.0))));
    }
    Ok(Value::Array(out))
}

/// `kovanica_estimateFee()` — suggested fee rate in atoms per byte.
pub async fn handle_estimate_fee(_params: Value, state: RpcState) -> Result<Value, RpcError> {
    let stats = state.mempool.stats();
    let rate = stats
        .fee_rates
        .iter()
        .map(|(rate, _)| *rate)
        .min()
        .unwrap_or(DEFAULT_FEE_RATE)
        .max(DEFAULT_FEE_RATE);
    Ok(quantity(rate))
}

// ============================================================================
// Consensus methods
// ============================================================================

/// Returns the next `count` LEADER rounds strictly after `anchor_round`.
///
/// Leader rounds are the multiples of `WAVE_LENGTH`. `anchor_round` is the last
/// already-decided round (any round, not just a leader round); the first
/// returned round is the first leader round strictly greater than it.
///
/// All arithmetic is saturating so a near-`u64::MAX` anchor cannot panic.
pub fn leader_schedule_rounds(anchor_round: u64, count: usize) -> Vec<u64> {
    if count == 0 {
        return Vec::new();
    }
    // The anchor's own leader slot is already behind us, so step to the
    // following multiple of the wave length. `saturating_*` keeps this safe
    // for anchors close to `u64::MAX`.
    let first = (anchor_round / WAVE_LENGTH)
        .saturating_add(1)
        .saturating_mul(WAVE_LENGTH);
    (0..count)
        .map(|offset| first.saturating_add((offset as u64).saturating_mul(WAVE_LENGTH)))
        .collect()
}

/// `kovanica_getLeaderSchedule(count)` — upcoming round leaders.
///
/// The schedule is the **round-robin** leader, i.e. [`CommitteeInfo::leader`],
/// and is therefore **provisional**: it is *not* the canonical leader
/// assignment and must not be treated as authoritative. Under VRF leader
/// election (tracked as PRO-7) the real leader of round `L` is only
/// determined from committed data at round `L-6`, so this method can never be
/// exact for future rounds.
///
/// Only **leader rounds** are returned — the multiples of `WAVE_LENGTH` — and
/// they start at the first leader round strictly after the highest already
/// decided round. Each entry has the shape
/// `{ "round", "leader_index", "leader_address" }`.
pub async fn handle_get_leader_schedule(params: Value, state: RpcState) -> Result<Value, RpcError> {
    let args = params_vec(&params);
    let count = match args.first() {
        Some(value) => parse_u64(value, "count")?,
        None => DEFAULT_LEADER_SCHEDULE_LEN,
    };
    if count > MAX_LEADER_SCHEDULE_LEN {
        return Err(RpcError::InvalidParams(format!(
            "count: at most {MAX_LEADER_SCHEDULE_LEN}, got {count}"
        )));
    }

    // Anchor on the highest already decided ROUND (not on the committed
    // leader height, which counts committed leaders and is a different unit).
    let anchor = {
        let decided = state
            .consensus_store
            .get_decided_rounds(u64::MAX)
            .map_err(internal)?;
        match decided.iter().copied().max() {
            Some(max) => max,
            // Nothing decided yet: fall back to the local DAG tip round.
            None => state
                .consensus_store
                .max_dag_round()
                .map_err(internal)?
                .unwrap_or(0),
        }
    };

    let rounds = leader_schedule_rounds(anchor, count as usize);

    let committee = committee_from_state(&state).await;
    let schedule: Vec<Value> = rounds
        .into_iter()
        .map(|round| {
            let leader_index = committee.leader(round);
            let leader_address = committee
                .get_by_index(leader_index)
                .map(|a| a.address.to_string())
                .unwrap_or_default();
            json!({
                "round": quantity(round),
                "leader_index": leader_index,
                "leader_address": leader_address,
            })
        })
        .collect();
    Ok(Value::Array(schedule))
}

/// JSON for a sealed leader header and the seals stored at its height.
pub fn sealed_header_json(header: &LeaderHeader, seals: &[CommitSeal]) -> Value {
    json!({
        "header": leader_header_json(header),
        "seals": seals.iter().map(seal_json).collect::<Vec<_>>(),
    })
}

fn leader_header_json(header: &LeaderHeader) -> Value {
    json!({
        "committedHeight": quantity(header.committed_height),
        "leaderRound": quantity(header.leader_round),
        "leaderDigest": to_hex(header.leader_digest.as_ref()),
        "leaderAuthor": header.leader_author,
        "parentLeaderDigest": to_hex(header.parent_leader_digest.as_ref()),
        "txMerkleRoot": to_hex(header.tx_merkle_root.as_ref()),
        "executedTxRoot": to_hex(header.executed_tx_root.as_ref()),
        "nonBlueRoot": to_hex(header.non_blue_root.as_ref()),
        "blueRoot": to_hex(header.blue_root.as_ref()),
        "mysticghost": header.mysticghost,
        "stateRoot": to_hex(header.state_root.as_ref()),
        "epoch": quantity(header.epoch),
        "committeeHash": to_hex(header.committee_hash.as_ref()),
        "timestamp": quantity(header.timestamp),
        "hash": to_hex(header.hash().as_ref()),
    })
}

fn seal_json(seal: &CommitSeal) -> Value {
    json!({
        "authorityIndex": seal.authority_index,
        "signature": to_hex(seal.signature.as_bytes()),
    })
}

fn proof_json(index: usize, proof: &MerkleProof) -> Value {
    json!({
        "index": quantity(index as u64),
        "steps": proof.steps.iter().map(step_json).collect::<Vec<_>>(),
    })
}

fn step_json(step: &MerkleStep) -> Value {
    match step {
        MerkleStep::Promote => json!({"type": "promote"}),
        MerkleStep::Sibling { hash, is_left } => json!({
            "type": "sibling",
            "hash": to_hex(hash.as_ref()),
            "isLeft": is_left,
        }),
    }
}

/// `kovanica_getLeaderHeader(height?)` — sealed header at `height`, or the latest.
///
/// Missing headers are JSON `null`. Historical headers are returned as stored.
pub async fn handle_get_leader_header(params: Value, state: RpcState) -> Result<Value, RpcError> {
    let args = params_vec(&params);
    let txn = state.storage.begin_read().map_err(internal)?;
    let header = if let Some(value) = args.first() {
        let height = parse_u64(value, "height")?;
        state
            .storage
            .state()
            .get_leader_header(&txn, height)
            .map_err(internal)?
    } else {
        state
            .storage
            .state()
            .get_latest_leader_header(&txn)
            .map_err(internal)?
    };
    Ok(header
        .map(|header| leader_header_json(&header))
        .unwrap_or(Value::Null))
}

/// `kovanica_getCommitSeals(height)` — seals stored for one committed height.
pub async fn handle_get_commit_seals(params: Value, state: RpcState) -> Result<Value, RpcError> {
    let args = params_vec(&params);
    let height = parse_u64(required(&args, 0, "height")?, "height")?;
    let txn = state.storage.begin_read().map_err(internal)?;
    let header = state
        .storage
        .state()
        .get_leader_header(&txn, height)
        .map_err(internal)?;
    let seals = state
        .storage
        .state()
        .seals_for(&txn, height)
        .map_err(internal)?;
    Ok(json!({
        "height": quantity(height),
        "headerHash": header.as_ref().map(|header| to_hex(header.hash().as_ref())),
        "seals": seals.iter().map(seal_json).collect::<Vec<_>>(),
    }))
}

/// `kovanica_getTxProof(height, txHash)` — inclusion in the executed-tx root.
///
/// A leader-block proof is included when the leader block is still in the
/// DAG and its stored merkle root matches the header.
pub async fn handle_get_tx_proof(params: Value, state: RpcState) -> Result<Value, RpcError> {
    let args = params_vec(&params);
    let height = parse_u64(required(&args, 0, "height")?, "height")?;
    let tx_hash = parse_hash(required(&args, 1, "txHash")?, "txHash")?;
    let txn = state.storage.begin_read().map_err(internal)?;
    let Some(header) = state
        .storage
        .state()
        .get_leader_header(&txn, height)
        .map_err(internal)?
    else {
        return Ok(Value::Null);
    };
    let hashes = state
        .storage
        .state()
        .get_executed_tx_hashes(&txn, height)
        .map_err(internal)?
        .unwrap_or_default();
    if merkle::root(&hashes) != header.executed_tx_root {
        return Err(internal(
            "executed transaction list does not match the header root",
        ));
    }
    let executed = hashes
        .iter()
        .position(|hash| *hash == tx_hash)
        .and_then(|index| merkle::proof(&hashes, index).map(|proof| proof_json(index, &proof)));
    let leader = leader_tx_proof(&state, &header, &tx_hash);
    Ok(json!({
        "header": leader_header_json(&header),
        "executed": executed,
        "leader": leader,
    }))
}

fn leader_tx_proof(state: &RpcState, header: &LeaderHeader, tx_hash: &Hash) -> Value {
    let block = match state.consensus_store.get_block(&header.leader_digest) {
        Ok(block) => block,
        Err(_) => return Value::Null,
    };
    if block.merkle_root != header.tx_merkle_root {
        return Value::Null;
    }
    let hashes: Vec<Hash> = block.transactions.iter().map(|tx| tx.hash).collect();
    if merkle::root(&hashes) != header.tx_merkle_root {
        return Value::Null;
    }
    let Some(index) = hashes.iter().position(|hash| hash == tx_hash) else {
        return Value::Null;
    };
    let Some(proof) = merkle::proof(&hashes, index) else {
        return Value::Null;
    };
    proof_json(index, &proof)
}

/// `kovanica_getAccountProof(address, height?)` — balance and nonce at the latest height.
///
/// Only the latest committed height is honest: older heights keep the root,
/// not the account rows. A requested older height is rejected.
pub async fn handle_get_account_proof(params: Value, state: RpcState) -> Result<Value, RpcError> {
    let args = params_vec(&params);
    let address = parse_address(
        required(&args, 0, "address")?,
        "address",
        served_chain_id(&state),
    )?;
    let requested = match args.get(1) {
        Some(value) => Some(parse_u64(value, "height")?),
        None => None,
    };
    let txn = state.storage.begin_read().map_err(internal)?;
    let Some((latest_height, saved_root)) = state
        .storage
        .state()
        .get_latest_state_root(&txn)
        .map_err(internal)?
    else {
        return Ok(Value::Null);
    };
    if let Some(height) = requested {
        if height != latest_height {
            return Err(RpcError::InvalidParams(format!(
                "account proofs are served only at the latest committed height 0x{latest_height:x}"
            )));
        }
    }
    let proof = state
        .storage
        .state()
        .prove_account(&txn, &address)
        .map_err(internal)?;
    if proof.state_root != saved_root {
        return Err(internal(
            "live account tree does not match the stored state root",
        ));
    }
    if !proof.verify() {
        return Err(internal("account proof did not verify against its root"));
    }
    Ok(json!({
        "height": quantity(latest_height),
        "stateRoot": to_hex(proof.state_root.as_ref()),
        "address": address.to_string(),
        "balance": quantity(proof.balance),
        "nonce": quantity(proof.nonce),
        "present": proof.present,
        "siblings": proof.siblings.iter().map(|hash| to_hex(hash.as_ref())).collect::<Vec<_>>(),
    }))
}

/// `kovanica_getLightSet()` — registered light nodes and the epoch beacon.
///
/// `rewardBps` is [`kovanica_staking::LIGHT_REWARD_BPS`] (20% of `block_reward`).
pub async fn handle_get_light_set(_params: Value, state: RpcState) -> Result<Value, RpcError> {
    let txn = state.storage.begin_read().map_err(internal)?;
    let height = match state.storage.state().load_staking_state(&txn) {
        Ok(staking) => staking.committed_leader_height,
        Err(_) => 0,
    };
    // Light-set epoch is derived from the committed leader HEIGHT, matching
    // execution's beacon indexing (`note_light_beacon` / `pay_light_escrow`
    // index the light set by `epoch_for_height(committed_height)`). It is a
    // deliberately distinct unit from the round-based committee epoch: the
    // light-set beacon must line up with the height at which execution wrote
    // it, not with the leader round of any seal. The arithmetic is the same
    // 8 h epoch length (2 400 heights); using the shared helper keeps the
    // divisor canonical.
    let epoch = kovanica_types::epoch_for_height(height);
    let Some(set) = state
        .storage
        .state()
        .load_light_set(&txn)
        .map_err(internal)?
    else {
        return Ok(json!({
            "rewardBps": kovanica_staking::LIGHT_REWARD_BPS,
            "epoch": quantity(epoch),
            "beacon": Value::Null,
            "nodes": [],
        }));
    };
    let beacon = set.beacon(epoch).map(|hash| to_hex(hash.as_ref()));
    let winners = set.winners(epoch);
    let nodes: Vec<Value> = set
        .nodes()
        .iter()
        .map(|node| {
            let witnessed = set
                .witnesses(epoch)
                .iter()
                .any(|witness| witness.address == node.address);
            json!({
                "address": node.address.to_string(),
                "stake": quantity(node.stake),
                "vrfPublicKey": to_hex(node.vrf_public_key.as_bytes()),
                "effectiveEpoch": quantity(node.effective_epoch),
                "exitEpoch": node.exit_epoch.map(quantity),
                "active": node.effective_epoch <= epoch
                    && node.exit_epoch.map(|end| epoch <= end).unwrap_or(true),
                "witnessed": witnessed,
                "selected": winners.contains(&node.address),
            })
        })
        .collect();
    Ok(json!({
        "rewardBps": kovanica_staking::LIGHT_REWARD_BPS,
        "epoch": quantity(epoch),
        "beacon": beacon,
        "nodes": nodes,
    }))
}

/// Serialise a committee's authorities into the member-row shape shared by
/// [`handle_get_committee`] and [`handle_get_committee_info`]. Kept in one
/// place so both methods stay byte-identical.
fn committee_members_json(committee: &kovanica_consensus::CommitteeInfo) -> Vec<Value> {
    committee
        .authorities()
        .iter()
        .map(|a| {
            json!({
                "index": a.index,
                "address": a.address.to_string(),
                "stake": quantity(a.stake),
                "publicKey": to_hex(a.public_key.as_bytes()),
                "network_address": a.network_address,
            })
        })
        .collect::<Vec<Value>>()
}

/// Dereference the committee from the RPC state's RwLock.
async fn committee_from_state(
    state: &RpcState,
) -> tokio::sync::RwLockReadGuard<'_, kovanica_consensus::CommitteeInfo> {
    state.committee.read().await
}

/// `kovanica_getCommittee(epoch?)` — current consensus committee.
///
/// Returns a bare JSON array of member rows; the Android client parses the
/// no-param response directly as a `JSONArray`, so that shape is preserved.
/// Committee history is not retained by the node: when an optional `epoch`
/// parameter is supplied and does not match the live committee epoch this
/// returns an invalid-params error rather than silently answering with the
/// wrong epoch's committee.
pub async fn handle_get_committee(params: Value, state: RpcState) -> Result<Value, RpcError> {
    let committee = committee_from_state(&state).await;
    let args = params_vec(&params);
    if let Some(requested) = args.first() {
        let requested = parse_u64(requested, "epoch")?;
        let current = committee.epoch();
        if requested != current {
            return Err(RpcError::InvalidParams(format!(
                "committee history is not retained; only the current epoch ({current}) is available"
            )));
        }
    }
    Ok(Value::Array(committee_members_json(&committee)))
}

/// `kovanica_getCommitteeInfo()` — current committee together with its epoch.
///
/// Object form of [`handle_get_committee`]: `{ epoch, members }`, where
/// `members` is exactly the same row array. A light client needs the epoch to
/// recompute `committee_seal_hash(epoch, members)` against a sealed leader
/// header's `committee_hash`.
pub async fn handle_get_committee_info(_params: Value, state: RpcState) -> Result<Value, RpcError> {
    let committee = committee_from_state(&state).await;
    Ok(json!({
        "epoch": quantity(committee.epoch()),
        "members": committee_members_json(&committee),
    }))
}

// ============================================================================
// Light Client (client-only / read-only) — P15 B-lane
// ============================================================================

/// Minimal read-only light-client checkpoint endpoint.
/// Accepts block hash or height; returns existing [`LightClientCheckpoint`]
/// structure plus a verification-status flag. No consensus rule changed.
pub async fn handle_light_client_checkpoint(
    params: Value,
    _state: RpcState,
) -> Result<Value, RpcError> {
    let args = params_vec(&params);
    let height = args
        .first()
        .and_then(|v| parse_u64(v, "height").ok())
        .unwrap_or(0);
    let hash_arg = args.get(1);
    let leader_hash = hash_arg
        .and_then(|v| parse_hash(v, "hash").ok())
        .unwrap_or(Hash::zero());
    // Minimal checkpoint built from existing types only (no new logic).
    let wave = WaveCommitCertificate::new(
        leader_hash,
        0,
        height,
        std::collections::BTreeMap::new(),
        Hash::zero(),
    );
    let checkpoint =
        LightClientCheckpoint::new(height, leader_hash, Hash::zero(), Hash::zero(), wave, 0);
    // Verification exposes existing verify_quorum / verify_colouring (client-only,
    // no new consensus logic). Callers supply a real Committee to run them.
    let verified = false;
    Ok(json!({
        "checkpoint": checkpoint,
        "verified": verified,
        "height": quantity(height),
        "hash": to_hex(leader_hash.as_ref()),
        "note": "read-only / client-only; no consensus change",
    }))
}

// ============================================================================
// Sync / catch-up status (read-only)
// ============================================================================

/// One connected peer as reported by `kovanica_syncStatus`.
///
/// Carries only non-sensitive transport metadata: the libp2p peer id, a last
/// known network address when one was learned, and the last DAG tip round the
/// peer advertised. No validator key or signing material is ever included.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SyncPeerStatus {
    /// libp2p peer id (transport identity, not the validator key).
    pub peer_id: String,
    /// Last DAG tip round the peer reported, if it has answered a probe.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reported_tip_round: Option<u64>,
}

/// Point-in-time sync / catch-up status of the node, returned by
/// `kovanica_syncStatus`.
///
/// All counters are plain JSON integers (this is an operator status surface,
/// like `/health`, not an Ethereum-compatible quantity endpoint). `None` means
/// "not known right now": the local DAG tip is `None` only when storage could
/// not be read, and `catch_up_target`/`behind_by` are `None` while the node is
/// not actively catching up.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SyncStatus {
    /// Local DAG tip round (`max_dag_round`); `None` if storage cannot be read.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub local_tip_round: Option<u64>,
    /// Latest committed leader height, when available.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub committed_height: Option<u64>,
    /// Local committed height (alias for committed_height for clarity).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub local_height: Option<u64>,
    /// Whether the node is actively pulling a peer's rounds (a catch-up session
    /// is in the `CatchingUp` phase; probing counts as not catching up).
    pub catching_up: bool,
    /// Highest peer-advertised tip round being chased, when catching up.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub catch_up_target: Option<u64>,
    /// How many rounds behind the catch-up target the local tip is, when both
    /// are known and the node is catching up.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub behind_by: Option<u64>,
    /// Number of connected peers (equals `peers.len()`).
    pub peer_count: usize,
    /// Connected peers, bounded by the node's `max_peers`.
    pub peers: Vec<SyncPeerStatus>,
    /// `<chain_id>-<first 16 hex chars of the genesis digest>`. The same
    /// string the node logs at startup (`network identity: peers must share
    /// this tag`). `None` only when the process has no sync-status source.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub network_tag: Option<String>,
}

/// Callable the node installs into [`RpcState`] to produce a fresh
/// [`SyncStatus`] from its live catch-up tracker, DAG store and peer set.
///
/// A closure (rather than a concrete shared type) keeps `kovanica-rpc`
/// independent of the node binary and the network crate while still reading
/// live state at call time. `None` disables `kovanica_syncStatus` beyond a bare
/// peer count (tests, RPC-only setups).
pub type SyncStatusSource = Arc<dyn Fn() -> SyncStatus + Send + Sync>;

/// `kovanica_syncStatus()` — read-only sync / catch-up and peer status.
///
/// Reports the local DAG tip, the committed height, whether the node is
/// catching up (and how far behind), the connected peers with their last
/// reported tip rounds, and this process's `networkTag`. No parameters; needs
/// no auth token (read-only).
pub async fn handle_sync_status(_params: Value, state: RpcState) -> Result<Value, RpcError> {
    let status = match &state.sync_status {
        Some(source) => source(),
        // Without an installed source still report the shared peer count so the
        // method never fails outright.
        None => SyncStatus {
            peer_count: state.peer_count.load(Ordering::Relaxed),
            ..SyncStatus::default()
        },
    };
    serde_json::to_value(&status).map_err(internal)
}

#[cfg(test)]
mod tests {
    use super::*;
    use kovanica_consensus::{AuthorityInfo, CommitteeInfo};
    use kovanica_dag::DagStore;
    use kovanica_mempool::{Mempool, MempoolConfig};
    use kovanica_staking::{StakingState, MIN_VALIDATOR_STAKE};
    use kovanica_storage::Storage;
    use kovanica_types::crypto::PublicKey;
    use kovanica_types::signing::chain_id::{DEVNET, LOCAL, MAINNET, TESTNET, TESTNET_V2};
    use std::sync::Arc;
    use tokio::sync::RwLock;

    fn hex32(byte: u8) -> String {
        format!("0x{}", hex::encode([byte; 32]))
    }

    /// Canonical (base32) address string. Every chain accepts this form.
    fn addr32(byte: u8) -> String {
        Address([byte; 32]).to_string()
    }

    fn test_state(storage: Arc<Storage>) -> RpcState {
        let authority = AuthorityInfo {
            index: 0,
            stake: MIN_VALIDATOR_STAKE,
            public_key: PublicKey([7u8; 32]),
            vrf_public_key: None,
            address: Address([9u8; 32]),
            network_address: "127.0.0.1:9000".to_string(),
        };
        RpcState {
            health: crate::NodeHealth::new(),
            consensus_store: Arc::new(DagStore::from_storage(storage.clone())),
            mempool: Arc::new(Mempool::new(
                MempoolConfig::default(),
                storage.clone(),
                kovanica_types::SigningContext::new(kovanica_types::signing::chain_id::LOCAL),
            )),
            storage,
            staking: Arc::new(RwLock::new(StakingState::new())),
            committee: Arc::new(RwLock::new(
                CommitteeInfo::try_new(0, vec![authority]).expect("test committee is valid"),
            )),
            peer_count: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            events: crate::EventBus::new(),
            rate_limiter: Arc::new(crate::RateLimiterState::new(
                crate::RateLimitConfig::default(),
            )),
            auth_config: Arc::new(crate::AuthConfig::default()),
            tx_gossip: None,
            sync_status: None,
        }
    }

    fn open_storage() -> (tempfile::TempDir, Arc<Storage>) {
        let dir = tempfile::tempdir().expect("tempdir");
        let storage = Arc::new(Storage::new(dir.path().join("state.db")).expect("storage"));
        (dir, storage)
    }

    #[test]
    fn parses_hash_and_address_hex() {
        let value = Value::String(hex32(0xab));
        assert_eq!(parse_hash(&value, "hash").unwrap(), Hash([0xab; 32]));
        assert_eq!(
            parse_address(&value, "address", TESTNET_V2).unwrap(),
            Address([0xab; 32])
        );

        assert!(parse_hash(&Value::String("0x1234".into()), "hash").is_err());
        assert!(parse_hash(&Value::String("not-hex".into()), "hash").is_err());
    }

    #[test]
    fn parses_canonical_and_hex_addresses() {
        let address = Address([0x2a; 32]);
        assert_eq!(address.to_string(), address.encode());
        assert_eq!(address.to_string().len(), 64);
        for chain in [MAINNET, TESTNET_V2, LOCAL] {
            assert_eq!(
                parse_address(&json!(address.to_string()), "address", chain).unwrap(),
                address
            );
        }
        // Legacy hex: devnet, chain 4, and local. Refused on mainnet and testnet.
        for legacy in [hex32(0x2a), address.encode_legacy_hex()] {
            for chain in [DEVNET, TESTNET_V2, LOCAL] {
                assert_eq!(
                    parse_address(&json!(legacy), "address", chain).unwrap(),
                    address,
                    "{legacy} on chain {chain}"
                );
            }
            for chain in [MAINNET, TESTNET] {
                let err = parse_address(&json!(legacy), "address", chain).unwrap_err();
                assert!(format!("{err:?}").contains("legacy"), "{err:?}");
            }
        }

        // Correct affixes but a wrong checksum must be rejected.
        let mut bad = address.encode();
        bad.replace_range(10..11, if &bad[10..11] == "q" { "p" } else { "q" });
        assert!(parse_address(&json!(bad), "address", MAINNET).is_err());
        let bad_legacy = json!(format!("kvnc{}dag", "00".repeat(36)));
        assert!(parse_address(&bad_legacy, "address", TESTNET_V2).is_err());
    }

    #[test]
    fn parses_quantities_in_decimal_and_hex() {
        assert_eq!(parse_u64(&json!(42), "n").unwrap(), 42);
        assert_eq!(parse_u64(&json!("0x2a"), "n").unwrap(), 42);
        assert!(parse_u64(&json!("nope"), "n").is_err());
        assert_eq!(quantity(0u64), json!("0x0"));
        assert_eq!(quantity(255u64), json!("0xff"));
    }

    #[test]
    fn parses_storage_key_as_slot_or_hash() {
        let mut expected = [0u8; 32];
        expected[31] = 5;
        assert_eq!(parse_storage_key(&json!(5), "key").unwrap(), expected);
        assert_eq!(
            parse_storage_key(&Value::String(hex32(0x01)), "key").unwrap(),
            [0x01u8; 32]
        );
    }

    #[test]
    fn normalises_params_forms() {
        assert_eq!(params_vec(&json!([1, 2])).len(), 2);
        assert_eq!(params_vec(&json!("x")), vec![json!("x")]);
        assert!(params_vec(&Value::Null).is_empty());
    }

    #[test]
    fn get_logs_filter_helpers_parse_and_match() {
        use kovanica_common::events;

        // Block references: tags and quantities.
        assert_eq!(parse_block_ref(&json!("latest"), 7, "b").unwrap(), 7);
        assert_eq!(parse_block_ref(&json!("earliest"), 7, "b").unwrap(), 0);
        assert_eq!(parse_block_ref(&json!("0x2a"), 0, "b").unwrap(), 42);
        assert!(parse_block_ref(&json!("nope"), 0, "b").is_err());

        // Address filter: single, list, absent, invalid.
        assert!(parse_address_filter(None, TESTNET_V2).unwrap().is_none());
        assert_eq!(
            parse_address_filter(Some(&json!(hex32(0x11))), TESTNET_V2)
                .unwrap()
                .unwrap(),
            vec![Address([0x11; 32])]
        );
        assert_eq!(
            parse_address_filter(Some(&json!([hex32(0x11), hex32(0x22)])), TESTNET_V2)
                .unwrap()
                .unwrap()
                .len(),
            2
        );
        assert!(parse_address_filter(Some(&json!(5)), TESTNET_V2).is_err());

        // Topic matching: empty/None wildcard, exact, and out-of-range position.
        assert!(topics_match(&[], events::TOKEN_TRANSFER));
        assert!(topics_match(&[None], events::TOKEN_TRANSFER));
        assert!(topics_match(
            &[Some(vec![events::TOKEN_TRANSFER.to_vec()])],
            events::TOKEN_TRANSFER
        ));
        assert!(!topics_match(
            &[Some(vec![events::TOKEN_MINT.to_vec()])],
            events::TOKEN_TRANSFER
        ));
        assert!(!topics_match(
            &[None, Some(vec![b"x".to_vec()])],
            events::TOKEN_TRANSFER
        ));

        // OR alternatives and hex decoding.
        let or = parse_topics_filter(Some(&json!([["mint", "transfer"]]))).unwrap();
        assert!(topics_match(&or, events::TOKEN_TRANSFER));
        assert_eq!(
            parse_topic(&json!("0x7472616e73666572"), "topics").unwrap(),
            Some(b"transfer".to_vec())
        );
        assert!(parse_topic(&json!(5), "topics").is_err());
    }

    #[tokio::test]
    async fn query_handlers_read_real_storage() {
        let (_dir, storage) = open_storage();
        let state = test_state(storage);

        assert_eq!(
            handle_block_number(Value::Null, state.clone())
                .await
                .unwrap(),
            json!("0x0")
        );
        assert_eq!(
            handle_get_balance(json!([addr32(0x11)]), state.clone())
                .await
                .unwrap(),
            json!("0x0")
        );
        assert_eq!(
            handle_get_nonce(json!([addr32(0x11)]), state.clone())
                .await
                .unwrap(),
            json!("0x0")
        );
        assert_eq!(
            handle_get_code(json!([addr32(0x11)]), state.clone())
                .await
                .unwrap(),
            json!("0x")
        );
        assert_eq!(
            handle_get_block_by_hash(json!([hex32(0x22)]), state.clone())
                .await
                .unwrap(),
            Value::Null
        );

        let committee = handle_get_committee(Value::Null, state.clone())
            .await
            .unwrap();
        assert_eq!(committee.as_array().unwrap().len(), 1);
        assert_eq!(
            committee[0]["address"],
            json!(Address([0x09; 32]).to_string())
        );

        let schedule = handle_get_leader_schedule(Value::Null, state.clone())
            .await
            .unwrap();
        assert_eq!(
            schedule.as_array().unwrap().len(),
            DEFAULT_LEADER_SCHEDULE_LEN as usize
        );
        let max = handle_get_leader_schedule(json!([MAX_LEADER_SCHEDULE_LEN]), state.clone())
            .await
            .unwrap();
        assert_eq!(
            max.as_array().unwrap().len(),
            MAX_LEADER_SCHEDULE_LEN as usize
        );
        assert!(matches!(
            handle_get_leader_schedule(json!([MAX_LEADER_SCHEDULE_LEN + 1]), state.clone()).await,
            Err(RpcError::InvalidParams(_))
        ));

        let validators = handle_get_validators(Value::Null, state.clone())
            .await
            .unwrap();
        assert!(validators.as_array().unwrap().is_empty());

        let pending = handle_get_pending_transactions(Value::Null, state.clone())
            .await
            .unwrap();
        assert!(pending.as_array().unwrap().is_empty());

        assert_eq!(
            handle_estimate_fee(Value::Null, state).await.unwrap(),
            json!("0x1")
        );
    }

    #[tokio::test]
    async fn committee_info_matches_committee_and_rejects_other_epochs() {
        let (_dir, storage) = open_storage();
        let state = test_state(storage);

        // `kovanica_getCommitteeInfo` reports the live epoch (0 in the fixture)
        // and the exact same member rows as the bare-array `kovanica_getCommittee`.
        let info = handle_get_committee_info(Value::Null, state.clone())
            .await
            .unwrap();
        assert_eq!(info["epoch"], json!("0x0"));
        let members = info["members"].as_array().expect("members is an array");
        assert_eq!(members.len(), 1);
        assert_eq!(
            members[0]["address"],
            json!(Address([0x09; 32]).to_string())
        );

        let committee = handle_get_committee(Value::Null, state.clone())
            .await
            .unwrap();
        assert_eq!(info["members"], committee);

        // The epoch-matching parameter behaves like the no-param call.
        let same = handle_get_committee(json!(["0x0"]), state.clone())
            .await
            .unwrap();
        assert_eq!(same, committee);

        // A different epoch is rejected instead of silently answering with the
        // current committee (history is not retained).
        assert!(matches!(
            handle_get_committee(json!(["0x5"]), state.clone()).await,
            Err(RpcError::InvalidParams(_))
        ));
    }

    #[tokio::test]
    async fn estimate_fee_uses_minimum_observed_rate_and_floor() {
        use kovanica_storage::state_store::Account;
        use kovanica_types::crypto::{Signature, SigningKey};

        let (_dir, storage) = open_storage();
        let state = test_state(storage.clone());

        // Two distinct funded senders so both fee-rate samples are admissible
        // (a valid signature is required now that addresses are public keys).
        let (sk_a, pk_a) = kovanica_crypto::generate_keypair();
        let (sk_b, pk_b) = kovanica_crypto::generate_keypair();
        let sender_a = Address::from_public_key(&pk_a);
        let sender_b = Address::from_public_key(&pk_b);

        let txn = storage.begin_write().unwrap();
        {
            let st = storage.state();
            let account = Account {
                balance: 1_000_000,
                nonce: 0,
                code_hash: [0; 32],
                code: Vec::new(),
            };
            st.set_account(&txn, &sender_a, &account).unwrap();
            st.set_account(&txn, &sender_b, &account).unwrap();
        }
        txn.commit().unwrap();

        let make_signed = |sender: Address, to: Address, fee: u64, sk: &SigningKey| {
            let mut tx = Transaction {
                sender,
                nonce: 0,
                kind: TransactionKind::Transfer { to, amount: 1 },
                fee,
                signature: Signature([0; 64]),
                hash: Hash::zero(),
            };
            let signing_hash = tx.signing_hash(&state.mempool.signing_context());
            tx.signature = kovanica_crypto::sign(sk, signing_hash.as_ref());
            tx.hash = signing_hash;
            tx
        };

        let low_rate_tx = make_signed(sender_a, Address([2; 32]), 1, &sk_a);
        let serialized_size = bincode::serialize(&low_rate_tx).unwrap().len() as u64;
        let higher_rate_tx = make_signed(sender_b, Address([3; 32]), serialized_size * 4, &sk_b);

        state
            .mempool
            .add_transaction(low_rate_tx)
            .expect("admit nonzero-fee transaction");
        state
            .mempool
            .add_transaction(higher_rate_tx)
            .expect("admit higher-fee transaction");

        assert_eq!(
            state.mempool.stats().fee_rates,
            vec![(0, 1), (4, 1)],
            "fixture must contain distinct observed rates"
        );
        assert_eq!(
            handle_estimate_fee(Value::Null, state).await.unwrap(),
            json!("0x1"),
            "the minimum observed zero rate is advisory and floored at 1 atom/byte"
        );
    }

    #[tokio::test]
    async fn send_raw_transaction_gossips_only_accepted_transactions() {
        use kovanica_storage::state_store::Account;
        use kovanica_types::crypto::Signature;

        let (_dir, storage) = open_storage();
        let mut state = test_state(storage.clone());
        let (gossip_tx, mut gossip_rx) = tokio::sync::mpsc::unbounded_channel();
        state.tx_gossip = Some(gossip_tx);

        let (sk, pk) = kovanica_crypto::generate_keypair();
        let sender = Address::from_public_key(&pk);
        let txn = storage.begin_write().unwrap();
        {
            let account = Account {
                balance: 1_000_000,
                nonce: 0,
                code_hash: [0; 32],
                code: Vec::new(),
            };
            storage
                .state()
                .set_account(&txn, &sender, &account)
                .unwrap();
        }
        txn.commit().unwrap();

        let mut tx = Transaction {
            sender,
            nonce: 0,
            kind: TransactionKind::Transfer {
                to: Address([3u8; 32]),
                amount: 1,
            },
            fee: 10_000,
            signature: Signature([0; 64]),
            hash: Hash::zero(),
        };
        let signing_hash = tx.signing_hash(&state.mempool.signing_context());
        tx.signature = kovanica_crypto::sign(&sk, signing_hash.as_ref());
        tx.hash = signing_hash;
        let raw = |tx: &Transaction| json!([to_hex(&bincode::serialize(tx).unwrap())]);

        // Rejected (bad signature): error, nothing gossiped.
        let mut forged = tx.clone();
        forged.signature = Signature([1; 64]);
        assert!(handle_send_raw_transaction(raw(&forged), state.clone())
            .await
            .is_err());
        assert!(
            gossip_rx.try_recv().is_err(),
            "rejected tx must not be gossiped"
        );

        // Accepted: gossiped exactly once.
        handle_send_raw_transaction(raw(&tx), state.clone())
            .await
            .expect("valid tx is accepted");
        assert_eq!(
            gossip_rx.try_recv().expect("accepted tx gossiped").hash,
            tx.hash
        );

        // Duplicate: mempool rejects (AlreadyExists), no second gossip.
        assert!(handle_send_raw_transaction(raw(&tx), state.clone())
            .await
            .is_err());
        assert!(
            gossip_rx.try_recv().is_err(),
            "duplicate must not be re-gossiped"
        );
    }

    #[tokio::test]
    async fn returned_transaction_is_pending_without_receipt() {
        use kovanica_storage::state_store::Account;
        use kovanica_types::crypto::Signature;

        let (_dir, storage) = open_storage();
        let state = test_state(storage.clone());
        let (sk, pk) = kovanica_crypto::generate_keypair();
        let sender = Address::from_public_key(&pk);
        let txn = storage.begin_write().unwrap();
        storage
            .state()
            .set_account(
                &txn,
                &sender,
                &Account {
                    balance: 1_000_000,
                    nonce: 0,
                    code_hash: [0; 32],
                    code: Vec::new(),
                },
            )
            .unwrap();
        txn.commit().unwrap();
        let mut tx = Transaction {
            sender,
            nonce: 0,
            kind: TransactionKind::Transfer {
                to: Address([3u8; 32]),
                amount: 1,
            },
            fee: 10_000,
            signature: Signature([0; 64]),
            hash: Hash::zero(),
        };
        let h = tx.signing_hash(&state.mempool.signing_context());
        tx.signature = kovanica_crypto::sign(&sk, h.as_ref());
        tx.hash = h;

        // Returned from a non-blue block (#13).
        let report = state.mempool.reinsert_returned(vec![tx.clone()], true);
        assert_eq!(
            report[0].outcome,
            kovanica_mempool::ReinsertOutcome::Accepted
        );

        let hash = json!([to_hex(&tx.hash.0)]);
        let receipt = handle_get_transaction_receipt(hash.clone(), state.clone())
            .await
            .unwrap();
        assert_eq!(receipt, Value::Null, "no receipt until in a blue block");
        let by_hash = handle_get_transaction_by_hash(hash, state.clone())
            .await
            .unwrap();
        assert_eq!(by_hash["status"], json!("pending"));
        assert_eq!(by_hash["blockHash"], Value::Null);

        // Unknown hash stays null.
        let unknown = handle_get_transaction_by_hash(json!([hex32(0x44)]), state)
            .await
            .unwrap();
        assert_eq!(unknown, Value::Null);
    }

    #[tokio::test]
    async fn transaction_receipt_reports_real_status_and_gas() {
        use kovanica_consensus::CommittedSubDag;
        use kovanica_storage::state_store::Account;
        use kovanica_types::block::BlockReference;
        use kovanica_types::crypto::Signature;

        let (_dir, storage) = open_storage();
        let state = test_state(storage.clone());

        let (sk, pk) = kovanica_crypto::generate_keypair();
        let sender = Address::from_public_key(&pk);

        // Fund the sender below the amount it will try to move.
        let txn = storage.begin_write().unwrap();
        storage
            .state()
            .set_account(
                &txn,
                &sender,
                &Account {
                    balance: 100_000,
                    nonce: 0,
                    code_hash: [0; 32],
                    code: Vec::new(),
                },
            )
            .unwrap();
        txn.commit().unwrap();

        // Signed transfer that must fail inside the body (overdraft).
        let mut failing = Transaction {
            sender,
            nonce: 0,
            kind: TransactionKind::Transfer {
                to: Address([3u8; 32]),
                amount: 200_000,
            },
            fee: 1,
            signature: Signature([0; 64]),
            hash: Hash::zero(),
        };
        let h = failing.signing_hash(&state.mempool.signing_context());
        failing.signature = kovanica_crypto::sign(&sk, h.as_ref());
        failing.hash = h;

        // Store the block that carries it (round 1, no parents).
        let block = StatementBlock {
            author: 0,
            round: 1,
            parents: Vec::new(),
            transactions: vec![failing.clone()],
            statements: Vec::new(),
            signature: Signature([0; 64]),
            digest: StatementBlock::compute_digest(0, 1, &[], &[failing.clone()]),
            merkle_root: StatementBlock::compute_merkle_root(&[failing.clone()]),
        };
        {
            let txn = storage.begin_write().unwrap();
            storage
                .blocks()
                .put_block(&txn, &block, &block.transactions)
                .unwrap();
            txn.commit().unwrap();
        }

        // Execute the committed sub-DAG carrying that block so a receipt is
        // written for the transaction (leader author 0 is the joined validator).
        let mut ctx = kovanica_execution::ExecutionContext::new();
        ctx.staking
            .join_validator(
                Address([9u8; 32]),
                MIN_VALIDATOR_STAKE,
                0,
                Some(Address([8u8; 32])),
                None,
                None,
            )
            .expect("join validator");
        let leader = StatementBlock {
            author: 0,
            round: 1,
            parents: Vec::new(),
            transactions: Vec::new(),
            statements: Vec::new(),
            signature: Signature([0; 64]),
            digest: StatementBlock::compute_digest(0, 1, &[], &[]),
            merkle_root: Default::default(),
        };
        let subdag = CommittedSubDag {
            leader,
            blocks: vec![block.clone()],
            leader_round: 1,
            leader_author: 0,
            non_blue: Vec::new(),
        };
        let executed = ctx
            .execute_committed_subdag(&subdag, &storage)
            .expect("execute committed subdag");
        assert!(
            !executed.receipts[0].success,
            "fixture transaction must fail: {:?}",
            executed.receipts[0].error
        );

        // The RPC answer now carries the real outcome instead of a hard-coded
        // success: failed body, native gas 0, same inclusion metadata.
        let receipt =
            handle_get_transaction_receipt(json!([to_hex(&failing.hash.0)]), state.clone())
                .await
                .unwrap();
        assert_eq!(receipt["status"], json!("0x0"));
        assert_eq!(receipt["success"], json!(false));
        assert_eq!(receipt["gasUsed"], json!("0x0"));
        assert_eq!(receipt["blockHash"], json!(to_hex(&block.digest.0)));
        assert_eq!(receipt["transactionIndex"], json!("0x0"));

        // Fallback: a transaction in a stored-but-not-executed block keeps the
        // pre-existing optimistic shape (status 0x1, gasUsed 0).
        let pending_tx = Transaction {
            sender: Address([4u8; 32]),
            nonce: 0,
            kind: TransactionKind::Transfer {
                to: Address([5u8; 32]),
                amount: 1,
            },
            fee: 1,
            signature: Signature([0; 64]),
            hash: Hash::new(b"rpc-receipt-fallback"),
        };
        let parents = vec![BlockReference {
            author: block.author,
            round: block.round,
            digest: block.digest,
        }];
        let digest =
            StatementBlock::compute_digest(0, 2, &parents, std::slice::from_ref(&pending_tx));
        let merkle_root = StatementBlock::compute_merkle_root(std::slice::from_ref(&pending_tx));
        let pending_block = StatementBlock {
            author: 0,
            round: 2,
            parents,
            transactions: vec![pending_tx.clone()],
            statements: Vec::new(),
            signature: Signature([0; 64]),
            digest,
            merkle_root,
        };
        {
            let txn = storage.begin_write().unwrap();
            storage
                .blocks()
                .put_block(&txn, &pending_block, &pending_block.transactions)
                .unwrap();
            txn.commit().unwrap();
        }
        let fallback = handle_get_transaction_receipt(json!([to_hex(&pending_tx.hash.0)]), state)
            .await
            .unwrap();
        assert_eq!(fallback["status"], json!("0x1"));
        assert_eq!(fallback["success"], json!(true));
        assert_eq!(fallback["gasUsed"], json!("0x0"));
    }

    #[tokio::test]
    async fn get_logs_queries_receipts_and_enforces_bounds() {
        use kovanica_storage::state_store::Account;
        use kovanica_types::crypto::Signature;

        let (_dir, storage) = open_storage();
        let state = test_state(storage.clone());

        let (sk, pk) = kovanica_crypto::generate_keypair();
        let sender = Address::from_public_key(&pk);
        let recipient = Address([0x33; 32]);

        let txn = storage.begin_write().unwrap();
        storage
            .state()
            .set_account(
                &txn,
                &sender,
                &Account {
                    balance: 1_000_000,
                    nonce: 0,
                    code_hash: [0; 32],
                    code: Vec::new(),
                },
            )
            .unwrap();
        txn.commit().unwrap();

        let mut tx = Transaction {
            sender,
            nonce: 0,
            kind: TransactionKind::Transfer {
                to: recipient,
                amount: 10,
            },
            fee: 100,
            signature: Signature([0; 64]),
            hash: Hash::zero(),
        };
        let h = tx.signing_hash(&state.mempool.signing_context());
        tx.signature = kovanica_crypto::sign(&sk, h.as_ref());
        tx.hash = h;

        // Execute the committed sub-DAG that carries it so a receipt is stored.
        let mut ctx = kovanica_execution::ExecutionContext::new();
        ctx.staking
            .join_validator(
                Address([9u8; 32]),
                MIN_VALIDATOR_STAKE,
                0,
                Some(Address([8u8; 32])),
                None,
                None,
            )
            .expect("join validator");
        let block = StatementBlock {
            author: 0,
            round: 1,
            parents: Vec::new(),
            transactions: vec![tx.clone()],
            statements: Vec::new(),
            signature: Signature([0; 64]),
            digest: StatementBlock::compute_digest(0, 1, &[], std::slice::from_ref(&tx)),
            merkle_root: StatementBlock::compute_merkle_root(std::slice::from_ref(&tx)),
        };
        let leader = StatementBlock {
            author: 0,
            round: 1,
            parents: Vec::new(),
            transactions: Vec::new(),
            statements: Vec::new(),
            signature: Signature([0; 64]),
            digest: StatementBlock::compute_digest(0, 1, &[], &[]),
            merkle_root: Default::default(),
        };
        let subdag = kovanica_consensus::CommittedSubDag {
            leader,
            blocks: vec![block],
            leader_round: 1,
            leader_author: 0,
            non_blue: Vec::new(),
        };
        let executed = ctx
            .execute_committed_subdag(&subdag, &storage)
            .expect("execute committed subdag");
        assert!(
            executed.receipts[0].success,
            "{:?}",
            executed.receipts[0].error
        );

        // Unfiltered range query returns the native transfer log.
        let logs = handle_get_logs(
            json!([{ "fromBlock": "0x0", "toBlock": "0x1" }]),
            state.clone(),
        )
        .await
        .unwrap();
        let logs = logs.as_array().unwrap();
        assert_eq!(logs.len(), 1);
        assert_eq!(logs[0]["address"], json!(sender.to_string()));
        assert_eq!(
            logs[0]["topics"],
            json!([to_hex(kovanica_common::events::TOKEN_TRANSFER)])
        );
        assert_eq!(logs[0]["transactionHash"], json!(to_hex(&tx.hash.0)));
        assert_eq!(logs[0]["logIndex"], json!("0x0"));
        assert_eq!(logs[0]["removed"], json!(false));

        // Address filter: the sender matches, a stranger does not.
        let by_addr = handle_get_logs(
            json!([{ "fromBlock": "0x0", "address": sender.to_string() }]),
            state.clone(),
        )
        .await
        .unwrap();
        assert_eq!(by_addr.as_array().unwrap().len(), 1);
        let stranger = handle_get_logs(
            json!([{ "fromBlock": "0x0", "address": addr32(0x77) }]),
            state.clone(),
        )
        .await
        .unwrap();
        assert!(stranger.as_array().unwrap().is_empty());

        // Topic filter: the plaintext topic matches, another one does not.
        let by_topic = handle_get_logs(
            json!([{ "fromBlock": "0x0", "topics": ["transfer"] }]),
            state.clone(),
        )
        .await
        .unwrap();
        assert_eq!(by_topic.as_array().unwrap().len(), 1);
        let wrong = handle_get_logs(
            json!([{ "fromBlock": "0x0", "topics": ["unstake"] }]),
            state.clone(),
        )
        .await
        .unwrap();
        assert!(wrong.as_array().unwrap().is_empty());

        // A range wider than the bound is rejected, not silently truncated.
        let too_wide = handle_get_logs(
            json!([{
                "fromBlock": "0x0",
                "toBlock": format!("0x{:x}", MAX_GET_LOGS_BLOCK_RANGE)
            }]),
            state.clone(),
        )
        .await;
        assert!(matches!(too_wide, Err(RpcError::InvalidParams(_))));

        // A malformed filter is rejected.
        assert!(matches!(
            handle_get_logs(json!([42]), state).await,
            Err(RpcError::InvalidParams(_))
        ));
    }

    #[tokio::test]
    async fn light_reads_follow_the_latest_account_root() {
        use kovanica_storage::state_store::Account;

        let (_dir, storage) = open_storage();
        let address = Address([4u8; 32]);
        let tx_hash = Hash::new([9u8]);
        let header = LeaderHeader {
            committed_height: 2,
            leader_round: 6,
            leader_digest: Hash::new([2u8]),
            leader_author: 0,
            parent_leader_digest: Hash::zero(),
            tx_merkle_root: Hash::zero(),
            executed_tx_root: merkle::root(&[tx_hash]),
            non_blue_root: Hash::zero(),
            blue_root: Hash::zero(),
            mysticghost: false,
            state_root: Hash::zero(),
            epoch: 0,
            committee_hash: Hash::zero(),
            timestamp: 0,
        };
        {
            let txn = storage.begin_write().unwrap();
            storage
                .state()
                .set_account(
                    &txn,
                    &address,
                    &Account {
                        balance: 5,
                        nonce: 1,
                        code_hash: [0; 32],
                        code: Vec::new(),
                    },
                )
                .unwrap();
            let root = storage.state().commit_account_smt(&txn, 2).unwrap();
            let mut header = header;
            header.state_root = root;
            storage.state().save_leader_header(&txn, &header).unwrap();
            storage
                .state()
                .save_executed_tx_hashes(&txn, 2, &[tx_hash])
                .unwrap();
            txn.commit().unwrap();
        }
        let state = test_state(storage);
        let got = handle_get_leader_header(json!([2]), state.clone())
            .await
            .unwrap();
        assert_eq!(got["committedHeight"], json!("0x2"));
        assert_eq!(got["timestamp"], json!("0x0"));
        assert!(handle_get_leader_header(json!([9]), state.clone())
            .await
            .unwrap()
            .is_null());
        let seals = handle_get_commit_seals(json!([2]), state.clone())
            .await
            .unwrap();
        assert_eq!(seals["seals"], json!([]));
        let proof = handle_get_tx_proof(
            json!([2, format!("0x{}", hex::encode(tx_hash.0))]),
            state.clone(),
        )
        .await
        .unwrap();
        assert!(proof["executed"].is_object());
        assert!(proof["leader"].is_null());
        let account = handle_get_account_proof(json!([address.to_string()]), state.clone())
            .await
            .unwrap();
        assert_eq!(account["height"], json!("0x2"));
        assert_eq!(account["present"], json!(true));
        assert_eq!(account["balance"], json!("0x5"));
        let err = handle_get_account_proof(json!([address.to_string(), "0x1"]), state.clone())
            .await
            .unwrap_err();
        assert!(err.to_string().contains("latest"));
        let set = handle_get_light_set(Value::Null, state).await.unwrap();
        assert_eq!(kovanica_staking::LIGHT_REWARD_BPS, 2_000);
        assert_eq!(set["rewardBps"], json!(2_000));
        assert_eq!(set["nodes"], json!([]));
    }

    // ------------------------------------------------------------------
    // kovanica_syncStatus
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn sync_status_without_a_source_reports_a_bare_peer_count() {
        let (_dir, storage) = open_storage();
        let mut state = test_state(storage);
        state.peer_count = Arc::new(std::sync::atomic::AtomicUsize::new(3));

        let got = handle_sync_status(Value::Null, state).await.unwrap();
        assert_eq!(got["peerCount"], json!(3));
        assert_eq!(got["catchingUp"], json!(false));
        assert_eq!(got["peers"], json!([]));
        // Absent optional fields are omitted rather than emitted as null.
        assert!(got.get("catchUpTarget").is_none());
        assert!(got.get("behindBy").is_none());
        assert!(got.get("networkTag").is_none());
    }

    #[tokio::test]
    async fn sync_status_reports_catch_up_and_peers() {
        let (_dir, storage) = open_storage();
        let mut state = test_state(storage);
        state.sync_status = Some(Arc::new(|| SyncStatus {
            local_tip_round: Some(120),
            committed_height: Some(300),
            local_height: Some(300),
            catching_up: true,
            catch_up_target: Some(200),
            behind_by: Some(80),
            peer_count: 2,
            peers: vec![
                SyncPeerStatus {
                    peer_id: "12D3KooWpeer-a".to_string(),
                    reported_tip_round: Some(200),
                },
                SyncPeerStatus {
                    peer_id: "12D3KooWpeer-b".to_string(),
                    reported_tip_round: None,
                },
            ],
            network_tag: Some("4-0123456789abcdef".to_string()),
        }));

        let got = handle_sync_status(Value::Null, state).await.unwrap();
        assert_eq!(got["localTipRound"], json!(120));
        assert_eq!(got["committedHeight"], json!(300));
        assert_eq!(got["localHeight"], json!(300));
        assert_eq!(got["catchingUp"], json!(true));
        assert_eq!(got["catchUpTarget"], json!(200));
        assert_eq!(got["behindBy"], json!(80));
        assert_eq!(got["peerCount"], json!(2));
        assert_eq!(got["peers"][0]["peerId"], json!("12D3KooWpeer-a"));
        assert_eq!(got["peers"][0]["reportedTipRound"], json!(200));
        assert_eq!(got["networkTag"], json!("4-0123456789abcdef"));
        // Peer b has no tip: those fields are omitted.
        assert!(got["peers"][1].get("reportedTipRound").is_none());
        // listenAddr should not be present
        assert!(got["peers"][0].get("listenAddr").is_none());
    }

    // ------------------------------------------------------------------
    // leader_schedule_rounds
    // ------------------------------------------------------------------

    #[test]
    fn leader_schedule_anchor_on_a_leader_round_returns_the_next_one() {
        // 3 and 6 are leader rounds (multiples of WAVE_LENGTH == 3).
        assert_eq!(leader_schedule_rounds(3, 1), vec![6]);
        assert_eq!(leader_schedule_rounds(6, 1), vec![9]);
        assert_eq!(
            leader_schedule_rounds(WAVE_LENGTH * 10, 1),
            vec![WAVE_LENGTH * 11]
        );
    }

    #[test]
    fn leader_schedule_anchor_on_a_non_leader_round_returns_the_next_leader_round() {
        // Rounds 4 and 5 are vote/decide rounds, not leader rounds.
        assert_eq!(leader_schedule_rounds(4, 1), vec![6]);
        assert_eq!(leader_schedule_rounds(5, 1), vec![6]);
        // The anchor itself must never be returned.
        assert!(leader_schedule_rounds(4, 8)
            .iter()
            .all(|r| *r % WAVE_LENGTH == 0));
        assert!(leader_schedule_rounds(4, 8).iter().all(|r| *r > 4));
    }

    #[test]
    fn leader_schedule_anchor_zero_starts_at_the_first_leader_round() {
        // Round 0 is already past, so the first leader round is WAVE_LENGTH.
        assert_eq!(leader_schedule_rounds(0, 1), vec![WAVE_LENGTH]);
        assert_eq!(
            leader_schedule_rounds(0, 3),
            vec![WAVE_LENGTH, WAVE_LENGTH * 2, WAVE_LENGTH * 3]
        );
    }

    #[test]
    fn leader_schedule_count_zero_is_empty() {
        assert!(leader_schedule_rounds(0, 0).is_empty());
        assert!(leader_schedule_rounds(42, 0).is_empty());
        assert!(leader_schedule_rounds(u64::MAX, 0).is_empty());
    }

    #[test]
    fn leader_schedule_entries_are_spaced_by_one_wave_length() {
        let rounds = leader_schedule_rounds(7, 10);
        assert_eq!(rounds.len(), 10);
        for pair in rounds.windows(2) {
            assert_eq!(pair[1] - pair[0], WAVE_LENGTH);
        }
        // Every entry is a leader round and strictly after the anchor.
        assert!(rounds.iter().all(|r| *r % WAVE_LENGTH == 0));
        assert!(rounds.iter().all(|r| *r > 7));
    }

    fn history_tx(
        sender: Address,
        to: Address,
        amount: u64,
        n: u64,
        success: bool,
    ) -> (kovanica_types::Transaction, bool) {
        let mut raw = [0u8; 32];
        raw[24..].copy_from_slice(&n.to_be_bytes());
        let tx = kovanica_types::Transaction {
            sender,
            nonce: n,
            kind: TransactionKind::Transfer { to, amount },
            fee: 9,
            signature: kovanica_types::Signature([0u8; 64]),
            hash: Hash(raw),
        };
        (tx, success)
    }

    fn index_rows(storage: &Storage, rows: &[(u64, kovanica_types::Transaction, bool)]) {
        let mut by_height: Vec<(u64, Vec<(&kovanica_types::Transaction, bool)>)> = Vec::new();
        for (height, tx, success) in rows {
            if let Some(group) = by_height.iter_mut().find(|(h, _)| h == height) {
                group.1.push((tx, *success));
            } else {
                by_height.push((*height, vec![(tx, *success)]));
            }
        }
        for (height, txs) in by_height {
            let txn = storage.begin_write().unwrap();
            kovanica_storage::index_committed_txs(&txn, height, &txs).unwrap();
            txn.commit().unwrap();
        }
    }

    #[tokio::test]
    async fn transaction_history_pages_filters_and_rejects_bad_input() {
        let (_dir, storage) = open_storage();
        let alice = Address([0x11; 32]);
        let bob = Address([0x22; 32]);
        let mut owned = Vec::new();
        for n in 1..=110u64 {
            let (tx, success) = history_tx(alice, bob, n, n, n != 110);
            owned.push((n, tx, success));
        }
        let stake = kovanica_types::Transaction {
            sender: alice,
            nonce: 200,
            kind: TransactionKind::Stake { amount: 8 },
            fee: 2,
            signature: kovanica_types::Signature([0u8; 64]),
            hash: Hash([0xab; 32]),
        };
        owned.push((111, stake, true));
        index_rows(
            &storage,
            &owned
                .iter()
                .map(|(h, tx, ok)| (*h, tx.clone(), *ok))
                .collect::<Vec<_>>(),
        );

        let state = test_state(storage.clone());
        let params = json!({
            "address": alice.to_string(),
            "limit": 2,
            "direction": "sent",
        });
        let first = handle_get_transaction_history(params, state.clone())
            .await
            .unwrap();
        assert_eq!(first["entries"].as_array().unwrap().len(), 2);
        assert_eq!(first["entries"][0]["height"], json!("0x6f"));
        assert_eq!(first["entries"][0]["kind"], json!("stake"));
        assert_eq!(first["entries"][0]["status"], json!("success"));
        assert_eq!(first["entries"][0]["to"], Value::Null);
        assert_eq!(first["entries"][0]["timestamp"], Value::Null);
        assert_eq!(first["entries"][0]["from"], json!(alice.to_string()));
        assert!(first["next_cursor"].is_string());

        let mut cursor = first["next_cursor"].as_str().unwrap().to_string();
        let mut seen = vec![
            first["entries"][0]["hash"].as_str().unwrap().to_string(),
            first["entries"][1]["hash"].as_str().unwrap().to_string(),
        ];
        loop {
            let page = handle_get_transaction_history(
                json!({
                    "address": hex32(0x11),
                    "limit": 10,
                    "cursor": cursor,
                    "direction": "sent",
                }),
                state.clone(),
            )
            .await
            .unwrap();
            let entries = page["entries"].as_array().unwrap();
            assert!(entries.len() <= 10);
            for entry in entries {
                let hash = entry["hash"].as_str().unwrap().to_string();
                assert!(!seen.contains(&hash), "duplicate {hash}");
                seen.push(hash);
            }
            match page["next_cursor"].as_str() {
                Some(next) => cursor = next.to_string(),
                None => break,
            }
        }
        assert_eq!(seen.len(), 111);

        let received = handle_get_transaction_history(
            json!([{ "address": bob.to_string(), "direction": "received" }]),
            state.clone(),
        )
        .await
        .unwrap();
        assert_eq!(received["entries"].as_array().unwrap().len(), 20);
        assert!(received["next_cursor"].is_string());
        assert_eq!(received["entries"][0]["kind"], json!("transfer"));
        assert_eq!(received["entries"][0]["to"], json!(bob.to_string()));
        assert_eq!(received["entries"][0]["amount"], json!("0x6e"));
        assert_eq!(received["entries"][0]["status"], json!("failed"));
        assert!(received["entries"]
            .as_array()
            .unwrap()
            .iter()
            .all(|e| e["kind"] == json!("transfer")));

        let clamped = handle_get_transaction_history(
            json!({ "address": alice.to_string(), "limit": 10_000 }),
            state.clone(),
        )
        .await
        .unwrap();
        assert_eq!(clamped["entries"].as_array().unwrap().len(), 100);
        assert!(clamped["next_cursor"].is_string());

        let zero = handle_get_transaction_history(
            json!({ "address": alice.to_string(), "limit": 0 }),
            state.clone(),
        )
        .await
        .unwrap();
        assert!(zero["entries"].as_array().unwrap().is_empty());
        assert!(zero["next_cursor"].is_null());

        assert!(matches!(
            handle_get_transaction_history(json!({ "address": "not-an-address" }), state.clone())
                .await,
            Err(RpcError::InvalidParams(_))
        ));
        let bad_checksum = format!("kvnc{}dag", "00".repeat(36));
        assert!(matches!(
            handle_get_transaction_history(json!({ "address": bad_checksum }), state.clone()).await,
            Err(RpcError::InvalidParams(_))
        ));
        assert!(matches!(
            handle_get_transaction_history(
                json!({ "address": alice.to_string(), "cursor": "zz" }),
                state.clone()
            )
            .await,
            Err(RpcError::InvalidParams(_))
        ));
        assert!(matches!(
            handle_get_transaction_history(
                json!({ "address": alice.to_string(), "direction": "outgoing" }),
                state.clone()
            )
            .await,
            Err(RpcError::InvalidParams(_))
        ));
        assert!(matches!(
            handle_get_transaction_history(json!(["0x11"]), state.clone()).await,
            Err(RpcError::InvalidParams(_))
        ));

        // A non-zero leader-header timestamp is returned; the placeholder 0 is not.
        {
            let txn = storage.begin_write().unwrap();
            storage
                .state()
                .save_leader_header(
                    &txn,
                    &LeaderHeader {
                        committed_height: 111,
                        leader_round: 3,
                        leader_digest: Hash([1u8; 32]),
                        leader_author: 0,
                        parent_leader_digest: Hash([0u8; 32]),
                        tx_merkle_root: Hash([0u8; 32]),
                        executed_tx_root: Hash([0u8; 32]),
                        non_blue_root: Hash([0u8; 32]),
                        blue_root: Hash([0u8; 32]),
                        mysticghost: false,
                        state_root: Hash([2u8; 32]),
                        epoch: 0,
                        committee_hash: Hash([3u8; 32]),
                        timestamp: 42,
                    },
                )
                .unwrap();
            txn.commit().unwrap();
        }
        let stamped = handle_get_transaction_history(
            json!({ "address": alice.to_string(), "limit": 1 }),
            state,
        )
        .await
        .unwrap();
        assert_eq!(stamped["entries"][0]["timestamp"], json!("0x2a"));
        assert_eq!(stamped["entries"][0]["fee"], json!("0x2"));
        assert_eq!(stamped["entries"][0]["amount"], json!("0x8"));
    }

    #[tokio::test]
    async fn transaction_history_follows_an_executed_commit() {
        let (_dir, storage) = open_storage();
        let key = kovanica_types::SigningKey::from_bytes(&[0x31; 32]);
        let sender = Address(key.verifying_key().to_bytes());
        let bob = Address([0x44; 32]);
        {
            let txn = storage.begin_write().unwrap();
            storage
                .state()
                .set_account(
                    &txn,
                    &sender,
                    &kovanica_storage::state_store::Account {
                        balance: 1_000,
                        ..Default::default()
                    },
                )
                .unwrap();
            txn.commit().unwrap();
        }
        let sign_ctx =
            kovanica_types::SigningContext::new(kovanica_types::signing::chain_id::LOCAL);
        let mut transfer = kovanica_types::Transaction {
            sender,
            nonce: 0,
            kind: TransactionKind::Transfer {
                to: bob,
                amount: 15,
            },
            fee: 1,
            signature: kovanica_types::Signature([0u8; 64]),
            hash: Hash([0u8; 32]),
        };
        transfer.hash = transfer.signing_hash(&sign_ctx);
        transfer.signature = kovanica_crypto::sign(&key, &transfer.signing_hash(&sign_ctx).0);
        let parents = Vec::new();
        let txs = vec![transfer.clone()];
        let digest = StatementBlock::compute_digest(0, 1, &parents, &txs);
        let block = StatementBlock {
            author: 0,
            round: 1,
            parents,
            transactions: txs,
            statements: Vec::new(),
            signature: kovanica_types::Signature([0u8; 64]),
            digest,
            merkle_root: Hash([0u8; 32]),
        };
        let leader_digest = StatementBlock::compute_digest(0, 1, &[], &[]);
        let leader = StatementBlock {
            author: 0,
            round: 1,
            parents: Vec::new(),
            transactions: Vec::new(),
            statements: Vec::new(),
            signature: kovanica_types::Signature([0u8; 64]),
            digest: leader_digest,
            merkle_root: Hash([0u8; 32]),
        };
        let subdag = kovanica_types::CommittedSubDag {
            blocks: vec![block],
            leader,
            leader_round: 1,
            leader_author: 0,
            non_blue: Vec::new(),
        };
        kovanica_execution::ExecutionContext::new()
            .execute_committed_subdag(&subdag, &storage)
            .expect("execute");

        let state = test_state(storage);
        let page = handle_get_transaction_history(
            json!({ "address": sender.to_string(), "direction": "sent" }),
            state.clone(),
        )
        .await
        .unwrap();
        assert_eq!(page["entries"].as_array().unwrap().len(), 1);
        assert_eq!(page["entries"][0]["kind"], json!("transfer"));
        assert_eq!(page["entries"][0]["amount"], json!("0xf"));
        assert_eq!(page["entries"][0]["fee"], json!("0x1"));
        assert_eq!(page["entries"][0]["status"], json!("success"));
        assert_eq!(page["entries"][0]["from"], json!(sender.to_string()));
        assert_eq!(page["entries"][0]["to"], json!(bob.to_string()));
        assert_eq!(page["entries"][0]["height"], json!("0x0"));
        assert!(page["next_cursor"].is_null());

        let bob_page = handle_get_transaction_history(
            json!({ "address": bob.to_string(), "direction": "received" }),
            state,
        )
        .await
        .unwrap();
        assert_eq!(bob_page["entries"].as_array().unwrap().len(), 1);
        assert_eq!(
            bob_page["entries"][0]["hash"],
            json!(to_hex(&transfer.hash.0))
        );
    }

    #[test]
    fn leader_schedule_saturates_instead_of_panicking_near_u64_max() {
        let rounds = leader_schedule_rounds(u64::MAX, 4);
        assert_eq!(rounds.len(), 4);
        assert!(rounds.iter().all(|r| *r >= u64::MAX - WAVE_LENGTH));
        // A round that is itself a multiple of WAVE_LENGTH must not overflow.
        let rounds = leader_schedule_rounds(u64::MAX - 1, 3);
        assert_eq!(rounds.len(), 3);
        assert!(rounds.windows(2).all(|p| p[1] >= p[0]));
    }
}
