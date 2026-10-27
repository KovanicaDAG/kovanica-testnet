//! Transfer history and balance as the node reported them.
//!
//! Nothing here is proven by commit seals. The screen says so.

use kovanica_types::Address;
use serde::Serialize;
use serde_json::{json, Value};

use crate::amount::format_kuna_atoms;
use crate::connection::{parse_qty, Rpc};

/// How many committed heights `kovanica_getLogs` may cover.
const HISTORY_WINDOW: u64 = 500;

/// How many pooled hashes are looked up.
const PENDING_CAP: usize = 16;

/// Heading for the history list.
pub const HISTORY_LABEL: &str = "History (reported by node)";

/// Heading for the balance.
pub const BALANCE_LABEL: &str = "Balance (reported by node)";

/// One transfer the node reported.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TransferRow {
    /// `in`, `out`, or `self`.
    pub direction: String,
    /// The other party, as Rust encodes the address.
    pub counterparty: String,
    /// Amount in atoms.
    pub amount_atoms: String,
    /// Amount in KUNA.
    pub amount_display: String,
    /// Committed height. Empty while the transfer is still pooled.
    pub height: Option<String>,
    /// Transaction hash, `0x` hex when the node sent it that way.
    pub transaction_hash: String,
    /// True when the node still lists the transfer as pending.
    pub pending: bool,
}

/// History for one address.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HistoryPage {
    /// Visible label. The rows are not proven.
    pub label: String,
    /// Newest committed transfers after any pending rows.
    pub transfers: Vec<TransferRow>,
}

/// Balance the node reported for one address.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ReportedBalance {
    /// Atoms, decimal.
    pub atoms: String,
    /// KUNA text from the integer formatter.
    pub display: String,
    /// Visible label. The figure is not proven.
    pub label: String,
}

/// Read balance. The address string is passed through to the node.
pub fn reported_balance(rpc: &impl Rpc, wallet: &str) -> Result<ReportedBalance, String> {
    let value = rpc
        .call("kovanica_getBalance", json!([wallet]))
        .map_err(|err| err.to_string())?;
    let atoms = parse_qty(&value).map_err(|_| "The node did not return a balance.".to_string())?;
    Ok(ReportedBalance {
        atoms: atoms.to_string(),
        display: format_kuna_atoms(atoms),
        label: BALANCE_LABEL.to_string(),
    })
}

/// Transfers to or from `wallet` in the last [`HISTORY_WINDOW`] heights, plus
/// a short look at the pool.
pub fn reported_history(
    rpc: &impl Rpc,
    wallet: &str,
    chain_id: Option<u64>,
) -> Result<HistoryPage, String> {
    let owner = parse_owner(wallet, chain_id)?;
    let height_value = rpc
        .call("kovanica_blockNumber", json!([]))
        .map_err(|err| err.to_string())?;
    let height =
        parse_qty(&height_value).map_err(|_| "The node did not return a height.".to_string())?;
    let from = height.saturating_sub(HISTORY_WINDOW - 1);
    let logs = rpc
        .call(
            "kovanica_getLogs",
            json!([{
                "fromBlock": format!("0x{from:x}"),
                "toBlock": format!("0x{height:x}"),
                "topics": ["transfer"],
            }]),
        )
        .map_err(|err| err.to_string())?;
    let Some(items) = logs.as_array() else {
        return Err("The node did not return a history.".to_string());
    };
    let mut transfers = Vec::new();
    for item in items {
        if let Some(row) = row_from_log(item, owner) {
            transfers.push(row);
        }
    }
    if let Ok(pending) = rpc.call("kovanica_getPendingTransactions", json!([])) {
        if let Some(hashes) = pending.as_array() {
            for hash in hashes.iter().take(PENDING_CAP) {
                let Some(hash) = hash.as_str() else {
                    continue;
                };
                let Ok(tx) = rpc.call("kovanica_getTransactionByHash", json!([hash])) else {
                    continue;
                };
                if let Some(row) = row_from_pending(&tx, owner, hash, chain_id) {
                    transfers.push(row);
                }
            }
        }
    }
    transfers.sort_by(|left, right| match (left.pending, right.pending) {
        (true, false) => std::cmp::Ordering::Less,
        (false, true) => std::cmp::Ordering::Greater,
        _ => height_of(right).cmp(&height_of(left)),
    });
    Ok(HistoryPage {
        label: HISTORY_LABEL.to_string(),
        transfers,
    })
}

fn height_of(row: &TransferRow) -> u64 {
    row.height
        .as_deref()
        .and_then(|text| text.parse().ok())
        .unwrap_or(0)
}

fn row_from_log(item: &Value, owner: Address) -> Option<TransferRow> {
    let data = item.get("data")?.as_str()?;
    let (from, to, amount) = decode_event(data)?;
    let (direction, counterparty) = placement(owner, from, to)?;
    let height = parse_qty(item.get("blockNumber")?).ok()?;
    let transaction_hash = item.get("transactionHash")?.as_str()?.to_string();
    Some(TransferRow {
        direction,
        counterparty,
        amount_atoms: amount.to_string(),
        amount_display: format_kuna_atoms(amount),
        height: Some(height.to_string()),
        transaction_hash,
        pending: false,
    })
}

fn row_from_pending(
    tx: &Value,
    owner: Address,
    requested_hash: &str,
    chain_id: Option<u64>,
) -> Option<TransferRow> {
    if tx.is_null() {
        return None;
    }
    let status = tx.get("status").and_then(Value::as_str);
    let block_missing = match tx.get("blockNumber") {
        None => true,
        Some(value) => value.is_null(),
    };
    if status != Some("pending") && !block_missing {
        return None;
    }
    let kind = tx.get("kind")?;
    if kind.get("type").and_then(Value::as_str) != Some("transfer") {
        return None;
    }
    let from = kind_address(tx.get("sender")?, chain_id)?;
    let to = kind_address(kind.get("to")?, chain_id)?;
    let amount = parse_qty(kind.get("amount")?).ok()?;
    let (direction, counterparty) = placement(owner, from, to)?;
    let transaction_hash = tx
        .get("hash")
        .and_then(Value::as_str)
        .unwrap_or(requested_hash)
        .to_string();
    Some(TransferRow {
        direction,
        counterparty,
        amount_atoms: amount.to_string(),
        amount_display: format_kuna_atoms(amount),
        height: None,
        transaction_hash,
        pending: true,
    })
}

fn kind_address(value: &Value, chain_id: Option<u64>) -> Option<Address> {
    let text = value.as_str()?;
    match chain_id {
        Some(chain) => Address::parse_for_chain(text, chain).ok(),
        None => text.parse().ok(),
    }
}

/// Decimal chain id from a node status field.
///
/// Missing, blank, or non-numeric text means the chain is unknown. History
/// then accepts only the canonical base32 address.
pub fn proven_chain_id(chain_id: Option<&str>) -> Option<u64> {
    chain_id
        .map(str::trim)
        .filter(|text| !text.is_empty())
        .and_then(|text| text.parse().ok())
}

fn parse_owner(wallet: &str, chain_id: Option<u64>) -> Result<Address, String> {
    match chain_id {
        Some(chain) => match Address::parse_for_chain(wallet, chain) {
            Ok(address) => Ok(address),
            Err(_) if legacy_label_refused(wallet, chain) => Err(format!(
                "A legacy address label is not accepted on chain {chain}."
            )),
            Err(_) => Err("The wallet address could not be read.".to_string()),
        },
        None => wallet
            .parse()
            .map_err(|_| "The wallet address could not be read.".to_string()),
    }
}

/// A keystore label in the legacy hex form, on a chain that only accepts base32.
fn legacy_label_refused(wallet: &str, chain_id: u64) -> bool {
    if kovanica_types::address::legacy_address_allowed(chain_id) {
        return false;
    }
    wallet.parse::<Address>().is_err()
        && Address::parse_for_chain(wallet, kovanica_types::signing::chain_id::TESTNET_V2).is_ok()
}

fn placement(owner: Address, from: Address, to: Address) -> Option<(String, String)> {
    if from == owner && to == owner {
        Some(("self".to_string(), owner.to_string()))
    } else if from == owner {
        Some(("out".to_string(), to.to_string()))
    } else if to == owner {
        Some(("in".to_string(), from.to_string()))
    } else {
        None
    }
}

fn decode_event(data: &str) -> Option<(Address, Address, u64)> {
    let body = data
        .strip_prefix("0x")
        .or_else(|| data.strip_prefix("0X"))
        .unwrap_or(data);
    let bytes = hex::decode(body).ok()?;
    bincode::deserialize(&bytes).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::connection::ConnError;
    use std::sync::Mutex;

    struct HistRpc {
        calls: Mutex<Vec<(String, Value)>>,
        height: u64,
        logs: Value,
        pending: Value,
        lookups: Mutex<usize>,
        balance: u64,
    }

    impl HistRpc {
        fn new(height: u64, logs: Value, pending: Value) -> Self {
            Self {
                calls: Mutex::new(Vec::new()),
                height,
                logs,
                pending,
                lookups: Mutex::new(0),
                balance: 1_000_000_000,
            }
        }
    }

    impl Rpc for HistRpc {
        fn call(&self, method: &str, params: Value) -> Result<Value, ConnError> {
            self.calls
                .lock()
                .expect("calls")
                .push((method.to_string(), params.clone()));
            match method {
                "kovanica_blockNumber" => Ok(json!(format!("0x{:x}", self.height))),
                "kovanica_getLogs" => Ok(self.logs.clone()),
                "kovanica_getPendingTransactions" => Ok(self.pending.clone()),
                "kovanica_getTransactionByHash" => {
                    *self.lookups.lock().expect("lookups") += 1;
                    Ok(Value::Null)
                }
                "kovanica_getBalance" => Ok(json!(format!("0x{:x}", self.balance))),
                other => panic!("unexpected {other}"),
            }
        }
    }

    fn event_data(from: Address, to: Address, amount: u64) -> String {
        let bytes = bincode::serialize(&(from, to, amount)).unwrap();
        format!("0x{}", hex::encode(bytes))
    }

    fn log(from: Address, to: Address, amount: u64, height: u64, hash: &str) -> Value {
        json!({
            "address": from.to_string(),
            "topics": ["0x7472616e73666572"],
            "data": event_data(from, to, amount),
            "blockNumber": format!("0x{height:x}"),
            "transactionHash": hash,
        })
    }

    #[test]
    fn history_keeps_transfers_for_the_wallet_and_labels_the_source() {
        let wallet = Address([1; 32]);
        let other = Address([2; 32]);
        let stranger = Address([3; 32]);
        let logs = json!([
            log(other, wallet, 1, 4, "0xaa"),
            log(wallet, other, 1_000_000_000, 9, "0xbb"),
            log(wallet, wallet, 5, 2, "0xcc"),
            log(stranger, other, 7, 8, "0xdd"),
            { "data": "0x00", "blockNumber": "0x1", "transactionHash": "0xee" },
        ]);
        let pending = json!((0..20).map(|i| format!("0x{i:x}")).collect::<Vec<_>>());
        let rpc = HistRpc::new(600, logs, pending);
        let page = reported_history(&rpc, &wallet.to_string(), Some(4)).unwrap();
        assert_eq!(page.label, HISTORY_LABEL);
        assert_eq!(page.transfers.len(), 3);
        assert_eq!(page.transfers[0].direction, "out");
        assert_eq!(page.transfers[0].height.as_deref(), Some("9"));
        assert_eq!(page.transfers[0].amount_atoms, "1000000000");
        assert_eq!(page.transfers[0].amount_display, "1");
        assert_eq!(page.transfers[0].counterparty, other.to_string());
        assert_eq!(page.transfers[1].direction, "in");
        assert_eq!(page.transfers[1].counterparty, other.to_string());
        assert_eq!(page.transfers[1].amount_atoms, "1");
        assert_eq!(page.transfers[2].direction, "self");
        assert_eq!(*rpc.lookups.lock().unwrap(), PENDING_CAP);
        let calls = rpc.calls.lock().unwrap();
        let logs_call = calls
            .iter()
            .find(|(method, _)| method == "kovanica_getLogs")
            .unwrap();
        let filter = &logs_call.1[0];
        assert_eq!(filter["fromBlock"], "0x65");
        assert_eq!(filter["toBlock"], "0x258");
        assert_eq!(filter["topics"][0], "transfer");
    }

    #[test]
    fn a_pending_transfer_is_listed_ahead_of_committed_ones() {
        let wallet = Address([4; 32]);
        let other = Address([5; 32]);
        let logs = json!([log(wallet, other, 2, 3, "0xab")]);
        let hash = "0xpending";
        let pending_tx = json!({
            "hash": hash,
            "sender": other.to_string(),
            "status": "pending",
            "blockNumber": null,
            "kind": {
                "type": "transfer",
                "to": wallet.to_string(),
                "amount": "0x2a",
            }
        });
        struct OnePending {
            inner: HistRpc,
            tx: Value,
        }
        impl Rpc for OnePending {
            fn call(&self, method: &str, params: Value) -> Result<Value, ConnError> {
                if method == "kovanica_getTransactionByHash" {
                    return Ok(self.tx.clone());
                }
                self.inner.call(method, params)
            }
        }
        let rpc = OnePending {
            inner: HistRpc::new(3, logs, json!([hash])),
            tx: pending_tx,
        };
        let page = reported_history(&rpc, &wallet.to_string(), Some(4)).unwrap();
        assert_eq!(page.transfers.len(), 2);
        assert!(page.transfers[0].pending);
        assert_eq!(page.transfers[0].direction, "in");
        assert_eq!(page.transfers[0].amount_atoms, "42");
        assert_eq!(page.transfers[0].transaction_hash, hash);
        assert!(!page.transfers[1].pending);
    }

    #[test]
    fn legacy_history_addresses_follow_the_chain_policy() {
        use kovanica_types::signing::chain_id;

        let wallet = Address([4; 32]);
        let other = Address([5; 32]);
        let logs = json!([log(wallet, other, 2, 3, "0xab")]);
        let hash = "0xpending";
        let pending_tx = json!({
            "hash": hash,
            "sender": other.encode_legacy_hex(),
            "status": "pending",
            "blockNumber": null,
            "kind": {
                "type": "transfer",
                "to": wallet.encode_legacy_hex(),
                "amount": "0x2a",
            }
        });

        struct OnePending {
            inner: HistRpc,
            tx: Value,
        }
        impl Rpc for OnePending {
            fn call(&self, method: &str, params: Value) -> Result<Value, ConnError> {
                if method == "kovanica_getTransactionByHash" {
                    return Ok(self.tx.clone());
                }
                self.inner.call(method, params)
            }
        }
        let page_for = |chain: Option<u64>, wallet_text: &str| {
            let rpc = OnePending {
                inner: HistRpc::new(3, logs.clone(), json!([hash])),
                tx: pending_tx.clone(),
            };
            reported_history(&rpc, wallet_text, chain)
        };

        let on_v2 = page_for(Some(chain_id::TESTNET_V2), &wallet.encode_legacy_hex()).unwrap();
        assert_eq!(on_v2.transfers.len(), 2);
        assert!(on_v2.transfers[0].pending);
        assert_eq!(on_v2.transfers[0].direction, "in");
        assert_eq!(on_v2.transfers[0].counterparty, other.to_string());

        let legacy = wallet.encode_legacy_hex();
        let refused = page_for(Some(chain_id::MAINNET), &legacy).unwrap_err();
        assert_eq!(
            refused,
            "A legacy address label is not accepted on chain 1."
        );
        let unknown = page_for(None, &legacy).unwrap_err();
        assert_eq!(unknown, "The wallet address could not be read.");
        assert_eq!(
            parse_owner(&legacy, Some(chain_id::MAINNET)).unwrap_err(),
            "A legacy address label is not accepted on chain 1."
        );
        assert!(parse_owner(&legacy, Some(chain_id::TESTNET_V2)).is_ok());
        assert!(parse_owner(&wallet.to_string(), Some(chain_id::MAINNET)).is_ok());
        assert_eq!(
            parse_owner("not-an-address", Some(chain_id::MAINNET)).unwrap_err(),
            "The wallet address could not be read."
        );

        let base32_only = page_for(None, &wallet.to_string()).unwrap();
        assert_eq!(base32_only.transfers.len(), 1);
        assert!(!base32_only.transfers[0].pending);

        assert_eq!(proven_chain_id(Some("4")), Some(4));
        assert_eq!(proven_chain_id(Some(" 1337 ")), Some(1337));
        assert_eq!(proven_chain_id(Some("")), None);
        assert_eq!(proven_chain_id(Some("nope")), None);
        assert_eq!(proven_chain_id(None), None);
    }

    #[test]
    fn balance_is_atoms_and_says_the_node_reported_it() {
        let rpc = HistRpc::new(0, json!([]), json!([]));
        let balance = reported_balance(&rpc, &Address([1; 32]).to_string()).unwrap();
        assert_eq!(balance.atoms, "1000000000");
        assert_eq!(balance.display, "1");
        assert_eq!(balance.label, BALANCE_LABEL);
    }
}
