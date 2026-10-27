//! Quote a KUNA transfer before the keystore is decrypted.
//!
//! The recipient, amount, fee, and chain id are fixed into the quote. Signing
//! uses that quote. Chain 1 is refused until the caller confirms it, and that
//! check happens before the keystore is read.

use std::path::Path;
use std::time::Instant;

use kovanica_types::signing::chain_id;
use kovanica_types::{Address, Hash, Signature, SigningContext, Transaction, TransactionKind};
use serde::Serialize;
use serde_json::{json, Value};
use zeroize::{Zeroize, Zeroizing};

use crate::amount::{format_kuna_atoms, parse_kuna_atoms};
use crate::connection::{fetch_status, parse_qty, NodeStatus, Rpc};
use crate::wallet::{self, WalletStore};

const CHAIN_NOT_PROVEN: &str = "The chain id is not proven, so this wallet will not sign.";
const CHAIN_MISMATCH: &str = "The chain id does not match the connection screen.";
const MAINNET_CONFIRM: &str = "Chain 1 needs an extra confirmation before this wallet will sign.";
const REVIEW_AGAIN: &str = "Review the transfer again.";
const QUOTE_STALE: &str = "The quote is out of date. Review the transfer again.";
const BAD_RECIPIENT: &str = "That recipient is not a Kovanica address.";
const SIGN_FAILED: &str = "The transfer could not be signed.";
const ZERO_AMOUNT: &str = "Enter an amount greater than 0.";

/// Values the screen showed when it asked for a quote or a signature.
pub struct TransferDraft<'a> {
    /// Chain id currently shown on the connection screen.
    pub shown_chain_id: Option<&'a str>,
    /// Extra confirmation. Required when the quote is chain 1.
    pub confirm_mainnet: bool,
    /// Recipient text from the form.
    pub recipient: &'a str,
    /// KUNA amount text from the form.
    pub amount: &'a str,
}

/// A transfer the user can still reject. Amounts are decimal atom strings.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TransferQuote {
    /// Canonical recipient from `kovanica-types`.
    pub recipient: String,
    /// Amount in atoms.
    pub amount_atoms: String,
    /// Amount in KUNA, from the integer formatter.
    pub amount_display: String,
    /// Fee in atoms.
    pub fee_atoms: String,
    /// Fee in KUNA.
    pub fee_display: String,
    /// Chain id the quote was built for.
    pub chain_id: String,
    /// Account nonce the quote was built for.
    pub nonce: String,
    /// Atoms per byte the quote was built for.
    pub fee_rate: String,
    /// Recipient text the form had when the quote was made.
    pub draft_recipient: String,
    /// Amount text the form had when the quote was made.
    pub draft_amount: String,
}

/// Hash returned by `kovanica_sendRawTransaction`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SendReceipt {
    /// `0x` + hex, as the node reported it.
    pub transaction_hash: String,
}

/// Shown and proven chain ids must be the same decimal string.
pub fn require_same_chain(shown: Option<&str>, proven: Option<&str>) -> Result<u64, String> {
    let shown = nonempty(shown);
    let proven = nonempty(proven);
    match (shown, proven) {
        (Some(shown), Some(proven)) if shown == proven => shown
            .parse::<u64>()
            .map_err(|_| CHAIN_NOT_PROVEN.to_string()),
        (Some(_), Some(_)) => Err(CHAIN_MISMATCH.to_string()),
        _ => Err(CHAIN_NOT_PROVEN.to_string()),
    }
}

/// Price a transfer from integers already checked by the caller.
pub fn build_quote(
    sender: Address,
    draft_recipient: &str,
    draft_amount: &str,
    chain: u64,
    nonce: u64,
    fee_rate: u64,
) -> Result<TransferQuote, String> {
    let recipient = canonical_recipient(draft_recipient, chain)?;
    let amount = parse_kuna_atoms(draft_amount)?;
    if amount == 0 {
        return Err(ZERO_AMOUNT.to_string());
    }
    let len = transfer_len(sender, recipient, amount, nonce)?;
    let fee = fee_rate.saturating_mul(len as u64).max(1);
    Ok(TransferQuote {
        recipient: recipient.to_string(),
        amount_atoms: amount.to_string(),
        amount_display: format_kuna_atoms(amount),
        fee_atoms: fee.to_string(),
        fee_display: format_kuna_atoms(fee),
        chain_id: chain.to_string(),
        nonce: nonce.to_string(),
        fee_rate: fee_rate.to_string(),
        draft_recipient: draft_recipient.to_string(),
        draft_amount: draft_amount.to_string(),
    })
}

impl WalletStore {
    /// Build a quote from the node. Does not decrypt the keystore.
    pub fn quote_on(
        &mut self,
        rpc: &impl Rpc,
        endpoint: &str,
        draft: TransferDraft<'_>,
        now: Instant,
    ) -> Result<TransferQuote, String> {
        self.session(now)?;
        let status = fetch_status(rpc, endpoint).map_err(|err| err.to_string())?;
        self.quote_from_status(rpc, &status, draft, now)
    }

    /// Build a quote from a status this process already fetched.
    pub fn quote_from_status(
        &mut self,
        rpc: &impl Rpc,
        status: &NodeStatus,
        draft: TransferDraft<'_>,
        now: Instant,
    ) -> Result<TransferQuote, String> {
        let chain = require_same_chain(draft.shown_chain_id, status.chain_id.as_deref())?;
        let open = self.session(now)?;
        let sender = wallet_address(&open.address, chain)?;
        let nonce = read_nonce(rpc, &open.address)?;
        let rate = read_fee_rate(rpc)?;
        let quote = build_quote(sender, draft.recipient, draft.amount, chain, nonce, rate)?;
        open.quote = Some(quote.clone());
        Ok(quote)
    }

    /// Sign a stored quote. Chain 1 without `confirm_mainnet` returns before
    /// any RPC call and before the keystore is read.
    pub fn send_prepared(
        &mut self,
        rpc: &impl Rpc,
        path: &Path,
        status: &NodeStatus,
        draft: TransferDraft<'_>,
        now: Instant,
    ) -> Result<SendReceipt, String> {
        let quote = {
            let open = self.session(now)?;
            let quote = open.quote.clone().ok_or_else(|| REVIEW_AGAIN.to_string())?;
            if quote.draft_recipient != draft.recipient || quote.draft_amount != draft.amount {
                return Err(REVIEW_AGAIN.to_string());
            }
            if needs_mainnet_confirm(&quote.chain_id) && !draft.confirm_mainnet {
                return Err(MAINNET_CONFIRM.to_string());
            }
            quote
        };
        let proven = require_same_chain(draft.shown_chain_id, status.chain_id.as_deref())?;
        if proven.to_string() != quote.chain_id {
            if let Ok(open) = self.session(now) {
                open.quote = None;
            }
            return Err(QUOTE_STALE.to_string());
        }
        let open = self.session(now)?;
        let nonce = read_nonce(rpc, &open.address)?;
        let rate = read_fee_rate(rpc)?;
        if nonce.to_string() != quote.nonce || rate.to_string() != quote.fee_rate {
            open.quote = None;
            return Err(QUOTE_STALE.to_string());
        }
        let mut json = wallet::read_keystore(path)?;
        let mut passphrase = Zeroizing::new(open.passphrase.to_string());
        let raw = kovanica_light_ffi::sign_transfer_raw(
            json.clone(),
            passphrase.to_string(),
            proven,
            quote.recipient.clone(),
            parse_atoms(&quote.amount_atoms)?,
            nonce,
            rate,
        )
        .map_err(|err| wallet::map_ffi_error(&err))?;
        passphrase.zeroize();
        json.zeroize();
        let tx = decode_raw(&raw)?;
        if tx.fee.to_string() != quote.fee_atoms
            || !tx.verify_signature(&SigningContext::new(proven))
            || tx.sender.to_string() != open.address
            || !transfer_matches(&tx, &quote)
        {
            return Err(SIGN_FAILED.to_string());
        }
        let result = rpc
            .call("kovanica_sendRawTransaction", json!([raw]))
            .map_err(|err| err.to_string())?;
        let transaction_hash = accept_hash(&result)?;
        open.quote = None;
        Ok(SendReceipt { transaction_hash })
    }
}

fn needs_mainnet_confirm(chain_id_text: &str) -> bool {
    chain_id_text == chain_id::MAINNET.to_string()
}

fn nonempty(value: Option<&str>) -> Option<&str> {
    value.map(str::trim).filter(|text| !text.is_empty())
}

fn canonical_recipient(raw: &str, chain_id: u64) -> Result<Address, String> {
    Address::parse_for_chain(raw.trim(), chain_id).map_err(|_| BAD_RECIPIENT.to_string())
}

fn wallet_address(text: &str, chain_id: u64) -> Result<Address, String> {
    match Address::parse_for_chain(text, chain_id) {
        Ok(address) => Ok(address),
        Err(_) if legacy_label_refused(text, chain_id) => Err(format!(
            "A legacy address label is not accepted on chain {chain_id}."
        )),
        Err(_) => Err("The wallet address could not be read.".to_string()),
    }
}

/// A keystore label in the legacy hex form, on a chain that only accepts base32.
fn legacy_label_refused(text: &str, chain_id: u64) -> bool {
    if kovanica_types::address::legacy_address_allowed(chain_id) {
        return false;
    }
    // Canonical base32 parses on every chain. Success on a lenient chain and
    // failure as base32 means the label is legacy hex.
    text.parse::<Address>().is_err() && Address::parse_for_chain(text, chain_id::TESTNET_V2).is_ok()
}

fn transfer_len(sender: Address, to: Address, amount: u64, nonce: u64) -> Result<usize, String> {
    let tx = Transaction {
        sender,
        nonce,
        kind: TransactionKind::Transfer { to, amount },
        fee: 1,
        signature: Signature([0u8; 64]),
        hash: Hash::zero(),
    };
    bincode::serialize(&tx)
        .map(|bytes| bytes.len())
        .map_err(|_| SIGN_FAILED.to_string())
}

fn parse_atoms(text: &str) -> Result<u64, String> {
    if text.is_empty() || !text.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(SIGN_FAILED.to_string());
    }
    text.parse::<u64>().map_err(|_| SIGN_FAILED.to_string())
}

fn transfer_matches(tx: &Transaction, quote: &TransferQuote) -> bool {
    if tx.nonce.to_string() != quote.nonce {
        return false;
    }
    match &tx.kind {
        TransactionKind::Transfer { to, amount } => {
            to.to_string() == quote.recipient && amount.to_string() == quote.amount_atoms
        }
        _ => false,
    }
}

fn decode_raw(raw: &str) -> Result<Transaction, String> {
    let body = raw
        .strip_prefix("0x")
        .or_else(|| raw.strip_prefix("0X"))
        .unwrap_or(raw);
    let bytes = hex::decode(body).map_err(|_| SIGN_FAILED.to_string())?;
    bincode::deserialize(&bytes).map_err(|_| SIGN_FAILED.to_string())
}

fn accept_hash(value: &Value) -> Result<String, String> {
    let Some(text) = value.as_str() else {
        return Err("The node did not accept the transfer.".to_string());
    };
    let Some(body) = text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) else {
        return Err("The node did not accept the transfer.".to_string());
    };
    if body.is_empty() || body.len() > 64 || !body.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("The node did not accept the transfer.".to_string());
    }
    Ok(text.to_string())
}

fn read_nonce(rpc: &impl Rpc, address: &str) -> Result<u64, String> {
    let value = rpc
        .call("kovanica_getNonce", json!([address]))
        .map_err(|err| err.to_string())?;
    parse_qty(&value).map_err(|_| "The node did not return a nonce.".to_string())
}

fn read_fee_rate(rpc: &impl Rpc) -> Result<u64, String> {
    let value = rpc
        .call("kovanica_estimateFee", json!([]))
        .map_err(|err| err.to_string())?;
    parse_qty(&value).map_err(|_| "The node did not return a fee.".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::connection::ConnError;
    use std::sync::Mutex;
    use std::time::Duration;

    fn fresh_status(chain: Option<&str>) -> NodeStatus {
        NodeStatus {
            chain_id: chain.map(str::to_string),
            chain_note: "test".to_string(),
            height: "0".to_string(),
            leader_round: None,
            epoch: None,
            peer_count: "0".to_string(),
            peers: Vec::new(),
        }
    }

    struct PanicRpc;

    impl Rpc for PanicRpc {
        fn call(&self, method: &str, _: Value) -> Result<Value, ConnError> {
            panic!("rpc was called for {method}");
        }
    }

    struct ScriptRpc {
        calls: Mutex<Vec<String>>,
        sent: Mutex<Vec<String>>,
        nonce: u64,
        fee_rate: u64,
        height_only: bool,
    }

    impl ScriptRpc {
        fn account(nonce: u64, fee_rate: u64) -> Self {
            Self {
                calls: Mutex::new(Vec::new()),
                sent: Mutex::new(Vec::new()),
                nonce,
                fee_rate,
                height_only: false,
            }
        }

        fn unproven() -> Self {
            Self {
                calls: Mutex::new(Vec::new()),
                sent: Mutex::new(Vec::new()),
                nonce: 0,
                fee_rate: 1,
                height_only: true,
            }
        }
    }

    impl Rpc for ScriptRpc {
        fn call(&self, method: &str, params: Value) -> Result<Value, ConnError> {
            self.calls.lock().expect("calls").push(method.to_string());
            if self.height_only {
                return match method {
                    "kovanica_blockNumber" => Ok(json!("0x0")),
                    "kovanica_syncStatus" => Ok(json!({"peers": [], "peerCount": "0x0"})),
                    "kovanica_getLeaderHeader" => Ok(Value::Null),
                    _ => panic!("unproven node was asked for {method}"),
                };
            }
            match method {
                "kovanica_getNonce" => Ok(json!(format!("0x{:x}", self.nonce))),
                "kovanica_estimateFee" => Ok(json!(format!("0x{:x}", self.fee_rate))),
                "kovanica_sendRawTransaction" => {
                    let raw = params
                        .as_array()
                        .and_then(|items| items.first())
                        .and_then(Value::as_str)
                        .unwrap_or("")
                        .to_string();
                    self.sent.lock().expect("sent").push(raw);
                    Ok(json!("0x11"))
                }
                other => panic!("unexpected {other}"),
            }
        }
    }

    fn draft<'a>(
        shown: Option<&'a str>,
        confirm: bool,
        recipient: &'a str,
        amount: &'a str,
    ) -> TransferDraft<'a> {
        TransferDraft {
            shown_chain_id: shown,
            confirm_mainnet: confirm,
            recipient,
            amount,
        }
    }

    #[test]
    fn chain_ids_must_both_be_present_and_equal() {
        assert_eq!(require_same_chain(Some("4"), Some("4")).unwrap(), 4);
        assert_eq!(
            require_same_chain(Some("1"), Some("4")).unwrap_err(),
            CHAIN_MISMATCH
        );
        assert_eq!(
            require_same_chain(None, Some("4")).unwrap_err(),
            CHAIN_NOT_PROVEN
        );
        assert_eq!(
            require_same_chain(Some("4"), None).unwrap_err(),
            CHAIN_NOT_PROVEN
        );
        assert_eq!(
            require_same_chain(Some("  "), Some("4")).unwrap_err(),
            CHAIN_NOT_PROVEN
        );
    }

    #[test]
    fn a_bad_recipient_is_not_echoed() {
        let marker = "zzzz-secret-input";
        let err = build_quote(Address([2; 32]), marker, "1", 4, 0, 1).unwrap_err();
        assert_eq!(err, BAD_RECIPIENT);
        assert!(!err.contains(marker));
    }

    #[test]
    fn the_fee_is_the_priced_length_in_atoms() {
        let sender = Address([2; 32]);
        let recipient = Address([3; 32]).to_string();
        let quote = build_quote(sender, &recipient, "1", 4, 0, 2).unwrap();
        let len = transfer_len(sender, Address([3; 32]), 1_000_000_000, 0).unwrap();
        assert_eq!(quote.fee_atoms, (2 * len as u64).to_string());
        assert_eq!(quote.amount_atoms, "1000000000");
        assert_eq!(quote.amount_display, "1");
        let free = build_quote(sender, &recipient, "0.000000001", 4, 0, 0).unwrap();
        assert_eq!(free.fee_atoms, "1");
    }

    #[test]
    fn a_zero_amount_is_rejected_before_a_quote() {
        let sender = Address([1; 32]);
        let recipient = Address([3; 32]).to_string();
        for amount in ["0", "0.0", "0.000000000", " 0 "] {
            let err = build_quote(sender, &recipient, amount, 4, 7, 1).unwrap_err();
            assert_eq!(err, ZERO_AMOUNT, "{amount}");
        }
        assert!(build_quote(sender, &recipient, "0.000000001", 4, 7, 1).is_ok());

        let mut store = WalletStore::new();
        let now = Instant::now();
        store.open_for_test(sender.to_string(), now);
        let err = store
            .quote_from_status(
                &ScriptRpc::account(7, 1),
                &fresh_status(Some("4")),
                draft(Some("4"), false, &recipient, "0"),
                now,
            )
            .unwrap_err();
        assert_eq!(err, ZERO_AMOUNT);
        assert!(!store.has_quote());
    }

    #[test]
    fn an_unproven_node_does_not_get_a_quote() {
        let mut store = WalletStore::new();
        let now = Instant::now();
        store.open_for_test(Address([1; 32]).to_string(), now);
        let rpc = ScriptRpc::unproven();
        let err = store
            .quote_on(
                &rpc,
                "https://rpc.test/rpc",
                draft(Some("4"), false, &Address([3; 32]).to_string(), "1"),
                now,
            )
            .unwrap_err();
        assert_eq!(err, CHAIN_NOT_PROVEN);
        assert!(!store.has_quote());
        let calls = rpc.calls.lock().expect("calls");
        assert!(!calls.iter().any(|call| call == "kovanica_getNonce"));
        assert!(!calls
            .iter()
            .any(|call| call == "kovanica_sendRawTransaction"));
    }

    #[test]
    fn chain_one_is_refused_before_the_node_or_the_keystore() {
        let mut store = WalletStore::new();
        let now = Instant::now();
        let recipient = Address([3; 32]).to_string();
        store.open_for_test(Address([1; 32]).to_string(), now);
        let quote =
            build_quote(Address([1; 32]), &recipient, "1", chain_id::MAINNET, 1, 1).unwrap();
        store.session(now).expect("open").quote = Some(quote);
        let err = store
            .send_prepared(
                &PanicRpc,
                Path::new("missing-keystore"),
                &fresh_status(Some("1")),
                draft(Some("1"), false, &recipient, "1"),
                now,
            )
            .unwrap_err();
        assert_eq!(err, MAINNET_CONFIRM);
        assert!(store.has_quote());
    }

    #[test]
    fn a_stale_nonce_drops_the_quote_without_signing() {
        let mut store = WalletStore::new();
        let now = Instant::now();
        let sender = Address([1; 32]);
        let recipient = Address([3; 32]).to_string();
        store.open_for_test(sender.to_string(), now);
        let quote = build_quote(sender, &recipient, "1", 4, 7, 3).unwrap();
        store.session(now).expect("open").quote = Some(quote);
        let rpc = ScriptRpc::account(8, 3);
        let err = store
            .send_prepared(
                &rpc,
                Path::new("missing-keystore"),
                &fresh_status(Some("4")),
                draft(Some("4"), false, &recipient, "1"),
                now,
            )
            .unwrap_err();
        assert_eq!(err, QUOTE_STALE);
        assert!(!store.has_quote());
        assert!(rpc.sent.lock().expect("sent").is_empty());
    }

    #[test]
    fn a_signed_transfer_uses_the_quoted_fee_and_chain() {
        let dir =
            std::env::temp_dir().join(format!("kovanica-console-sign-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(crate::wallet::KEYSTORE_FILE);
        let mut store = WalletStore::new();
        let now = Instant::now();
        let created = match store.create(&path, "quote-password", now) {
            Ok(created) => created,
            Err(err) => panic!("{err}"),
        };
        let sender: Address = created.address.parse().unwrap();
        let recipient = Address([9; 32]).to_string();
        let quote = build_quote(sender, &recipient, "1.5", 4, 7, 3).unwrap();
        store.session(now).expect("open").quote = Some(quote.clone());
        let rpc = ScriptRpc::account(7, 3);
        let receipt = match store.send_prepared(
            &rpc,
            &path,
            &fresh_status(Some("4")),
            draft(Some("4"), false, &recipient, "1.5"),
            now,
        ) {
            Ok(receipt) => receipt,
            Err(err) => panic!("{err}"),
        };
        assert_eq!(receipt.transaction_hash, "0x11");
        let raw = rpc.sent.lock().expect("sent").pop().expect("raw");
        let tx = decode_raw(&raw).unwrap();
        assert_eq!(tx.fee.to_string(), quote.fee_atoms);
        assert!(tx.verify_signature(&SigningContext::new(4)));
        assert!(!tx.verify_signature(&SigningContext::new(1)));
        assert!(transfer_matches(&tx, &quote));
        assert!(!store.has_quote());
        assert_eq!(store.last_active_for_test(), Some(now));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn quote_does_not_move_the_idle_deadline() {
        let mut store = WalletStore::new();
        let now = Instant::now();
        let sender = Address([1; 32]);
        store.open_for_test(sender.to_string(), now);
        let recipient = Address([3; 32]).to_string();
        let later = now + Duration::from_secs(30);
        store
            .quote_from_status(
                &ScriptRpc::account(4, 1),
                &fresh_status(Some("4")),
                draft(Some("4"), false, &recipient, "1"),
                later,
            )
            .expect("quote");
        assert_eq!(store.last_active_for_test(), Some(now));
        assert!(store.has_quote());
    }

    #[test]
    fn jarvis_changed_form_or_chain_is_not_signed() {
        let mut store = WalletStore::new();
        let now = Instant::now();
        let sender = Address([1; 32]);
        let recipient = Address([3; 32]).to_string();
        store.open_for_test(sender.to_string(), now);
        let quote = build_quote(sender, &recipient, "1", 4, 7, 3).unwrap();
        store.session(now).unwrap().quote = Some(quote);
        let e = store
            .send_prepared(
                &PanicRpc,
                Path::new("missing"),
                &fresh_status(Some("4")),
                draft(Some("4"), false, &recipient, "2"),
                now,
            )
            .unwrap_err();
        assert_eq!(e, REVIEW_AGAIN);
        let other = Address([4; 32]).to_string();
        let e = store
            .send_prepared(
                &PanicRpc,
                Path::new("missing"),
                &fresh_status(Some("4")),
                draft(Some("4"), false, &other, "1"),
                now,
            )
            .unwrap_err();
        assert_eq!(e, REVIEW_AGAIN);
        // node now proves chain 2 while screen still shows 4 -> mismatch, before nonce RPC
        let e = store
            .send_prepared(
                &PanicRpc,
                Path::new("missing"),
                &fresh_status(Some("2")),
                draft(Some("4"), false, &recipient, "1"),
                now,
            )
            .unwrap_err();
        assert_eq!(e, CHAIN_MISMATCH);
        // screen and node both switched to 2: quote for 4 is stale
        let e = store
            .send_prepared(
                &PanicRpc,
                Path::new("missing"),
                &fresh_status(Some("2")),
                draft(Some("2"), false, &recipient, "1"),
                now,
            )
            .unwrap_err();
        assert_eq!(e, QUOTE_STALE);
        assert!(!store.has_quote());
    }

    #[test]
    fn jarvis_zero_amount_is_quoted() {
        // Adapted: amount 0 is rejected before the quote, so this is no longer an observation.
        let q = build_quote(
            Address([1; 32]),
            &Address([3; 32]).to_string(),
            "0",
            4,
            0,
            1,
        );
        assert!(q.is_err(), "zero amount quote ok={}", q.is_ok());
    }

    #[test]
    fn jarvis_legacy_and_garbage_recipients() {
        let a = Address([3; 32]).to_string();
        assert!(build_quote(Address([1; 32]), &format!(" {a} "), "1", 4, 0, 1).is_ok());
        assert!(build_quote(Address([1; 32]), &a.to_uppercase(), "1", 4, 0, 1).is_err());
        assert!(build_quote(Address([1; 32]), &a[..a.len() - 1], "1", 4, 0, 1).is_err());
    }

    #[test]
    fn legacy_recipient_follows_the_chain_policy() {
        let sender = Address([1; 32]);
        let recipient = Address([3; 32]);
        let legacy = recipient.encode_legacy_hex();
        let bare = recipient.to_hex();
        let prefixed = format!("0x{bare}");
        let allowed = [chain_id::DEVNET, chain_id::TESTNET_V2, chain_id::LOCAL];
        let refused = [chain_id::MAINNET, chain_id::TESTNET, 0, 42];
        for chain in allowed {
            for form in [&legacy, &bare, &prefixed] {
                let quote = build_quote(sender, form, "1", chain, 0, 1).unwrap();
                assert_eq!(quote.recipient, recipient.to_string(), "{form} on {chain}");
            }
        }
        for chain in refused {
            for form in [&legacy, &bare, &prefixed] {
                let err = build_quote(sender, form, "1", chain, 0, 1).unwrap_err();
                assert_eq!(err, BAD_RECIPIENT, "{form} on {chain}");
                assert!(!err.contains(&bare));
            }
            let quote = build_quote(sender, &recipient.to_string(), "1", chain, 0, 1).unwrap();
            assert_eq!(quote.recipient, recipient.to_string());
        }

        let mut store = WalletStore::new();
        let now = Instant::now();
        store.open_for_test(sender.encode_legacy_hex(), now);
        let quote = store
            .quote_from_status(
                &ScriptRpc::account(4, 1),
                &fresh_status(Some("4")),
                draft(Some("4"), false, &legacy, "1"),
                now,
            )
            .unwrap();
        assert_eq!(quote.recipient, recipient.to_string());
        assert_eq!(quote.chain_id, "4");

        let mut refused_store = WalletStore::new();
        refused_store.open_for_test(sender.encode_legacy_hex(), now);
        let err = refused_store
            .quote_from_status(
                &ScriptRpc::account(4, 1),
                &fresh_status(Some("1")),
                draft(Some("1"), false, &recipient.to_string(), "1"),
                now,
            )
            .unwrap_err();
        assert_eq!(err, "A legacy address label is not accepted on chain 1.");
        assert!(!refused_store.has_quote());
    }

    #[test]
    fn legacy_keystore_label_is_refused_on_chain_1() {
        let label = Address([9; 32]).encode_legacy_hex();
        let err = wallet_address(&label, chain_id::MAINNET).unwrap_err();
        assert_eq!(err, "A legacy address label is not accepted on chain 1.");
        assert!(wallet_address(&label, chain_id::TESTNET_V2).is_ok());
        assert!(wallet_address(&label, chain_id::DEVNET).is_ok());
        assert!(wallet_address(&label, chain_id::LOCAL).is_ok());
        let canonical = Address([9; 32]).to_string();
        assert!(wallet_address(&canonical, chain_id::MAINNET).is_ok());
        assert_eq!(
            wallet_address("not-an-address", chain_id::MAINNET).unwrap_err(),
            "The wallet address could not be read."
        );
        assert_eq!(
            wallet_address(&label, chain_id::TESTNET).unwrap_err(),
            "A legacy address label is not accepted on chain 2."
        );
    }

    #[test]
    fn a_different_nonce_does_not_match_the_quote() {
        let sender = Address([1; 32]);
        let recipient = Address([3; 32]);
        let quote = build_quote(sender, &recipient.to_string(), "1", 4, 7, 3).unwrap();
        let amount: u64 = quote.amount_atoms.parse().unwrap();
        let mut tx = Transaction {
            sender,
            nonce: 7,
            kind: TransactionKind::Transfer {
                to: recipient,
                amount,
            },
            fee: 1,
            signature: Signature([0u8; 64]),
            hash: Hash::zero(),
        };
        assert!(transfer_matches(&tx, &quote));
        tx.nonce = 8;
        assert!(!transfer_matches(&tx, &quote));
    }
}
