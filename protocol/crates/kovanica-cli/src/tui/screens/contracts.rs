//! Contracts: HTLC (RFC-004), time-lock vault (RFC-005), and multisig
//! (RFC-001). HTLC/vault spends are built fully client-side with
//! `kovanica-state` templates and broadcast via `/api/submit_tx`; multisig
//! uses the node's build/combine endpoints but signs locally — the node never
//! sees a private key.

use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    text::{Line, Span, Text},
    Frame,
};
use serde_json::Value;

use kovanica_state::{Address, HtlcScript, OutPoint, Transaction, TxInput, TxOutput, VaultScript};

use crate::tui::{
    short_hex, theme, widgets, widgets::Field, widgets::Form, widgets::FormResult, widgets::Modal,
    widgets::ModalResult, ActionList, App, ScreenImpl, StatusMsg,
};

pub struct ContractsState {
    pub actions: ActionList,
    pub form: Option<Form>,
    pub modal: Option<Modal>,
    pub info: Option<Value>,
    pub result: Option<String>,
    pub error: Option<String>,
    /// Pending multisig build (tx blob + sighash) awaiting a local signature.
    pub multisig_pending: Option<MultisigPending>,
    /// The preimage of the last HTLC created, so the user can redeem later.
    pub last_preimage: Option<String>,
}

pub struct MultisigPending {
    pub tx_blob_hex: String,
    pub sighash_hex: String,
}

impl ContractsState {
    pub fn new() -> Self {
        Self {
            actions: ActionList::new(vec![
                "HTLC — create & fund".to_string(),
                "HTLC — redeem (recipient)".to_string(),
                "HTLC — refund (sender)".to_string(),
                "Vault — create & fund".to_string(),
                "Vault — release".to_string(),
                "Multisig — create address".to_string(),
                "Multisig — build & sign".to_string(),
                "Multisig — combine & submit".to_string(),
            ]),
            form: None,
            modal: None,
            info: None,
            result: None,
            error: None,
            multisig_pending: None,
            last_preimage: None,
        }
    }

    fn run_action(&mut self, app: &mut App, label: &str) {
        match label {
            "HTLC — create & fund" => {
                if app.wallet.is_none() {
                    app.status = StatusMsg::err("no wallet loaded").for_secs(4);
                    return;
                }
                self.form = Some(
                    Form::new(
                        "Create & fund HTLC",
                        vec![
                            Field::new("recipient public key (64-hex)").hint("Ed25519 pubkey"),
                            Field::new("preimage (hex or text)").hint("hashed with BLAKE3"),
                            Field::new("timeout (blocks)").hint("absolute block height"),
                            Field::new("amount (KVNC)").hint("e.g. 0.5 = 50000000 atoms"),
                        ],
                    )
                    .submit("Create"),
                );
            }
            "HTLC — redeem (recipient)" => {
                self.form = Some(
                    Form::new(
                        "Redeem HTLC",
                        vec![
                            Field::new("script hex (200 hex chars)").hint("from creation"),
                            Field::new("preimage (hex or text)").hint("revealed to redeem"),
                            Field::new("to (kvnc…dag or hex)").hint("recipient of the funds"),
                        ],
                    )
                    .submit("Redeem"),
                );
            }
            "HTLC — refund (sender)" => {
                self.form = Some(
                    Form::new(
                        "Refund HTLC",
                        vec![
                            Field::new("script hex (200 hex chars)").hint("from creation"),
                            Field::new("to (kvnc…dag or hex)").hint("sender refund address"),
                        ],
                    )
                    .submit("Refund"),
                );
            }
            "Vault — create & fund" => {
                if app.wallet.is_none() {
                    app.status = StatusMsg::err("no wallet loaded").for_secs(4);
                    return;
                }
                self.form = Some(
                    Form::new(
                        "Create & fund vault",
                        vec![
                            Field::new("unlock_height (blocks)").hint("0 = no absolute lock"),
                            Field::new("csv (blocks)").hint("0 = no relative lock"),
                            Field::new("owner public key (64-hex)").hint("empty = your key"),
                            Field::new("amount (KVNC)").hint("e.g. 2 = 200000000 atoms"),
                        ],
                    )
                    .submit("Create"),
                );
            }
            "Vault — release" => {
                self.form = Some(
                    Form::new(
                        "Release vault",
                        vec![
                            Field::new("script hex (80 hex chars)").hint("from creation"),
                            Field::new("to (kvnc…dag or hex)").hint("recipient of the funds"),
                        ],
                    )
                    .submit("Release"),
                );
            }
            "Multisig — create address" => {
                self.form = Some(
                    Form::new(
                        "Create multisig address",
                        vec![
                            Field::new("threshold m").hint("1..=16"),
                            Field::new("pubkeys (comma-separated 64-hex)").hint("n keys, n <= 16"),
                        ],
                    )
                    .submit("Create"),
                );
            }
            "Multisig — build & sign" => {
                if app.wallet.is_none() {
                    app.status = StatusMsg::err("no wallet loaded").for_secs(4);
                    return;
                }
                self.form = Some(
                    Form::new(
                        "Build & sign multisig spend",
                        vec![
                            Field::new("multisig address (kvnc…dag or hex)").hint("P2SH address"),
                            Field::new("to (kvnc…dag or hex)").hint("recipient of the funds"),
                            Field::new("amount (KVNC)").hint("e.g. 1 = 100000000 atoms"),
                        ],
                    )
                    .submit("Build"),
                );
            }
            "Multisig — combine & submit" => {
                let mut tx_blob_field = Field::new("tx_blob_hex").hint("from build");
                if let Some(p) = &self.multisig_pending {
                    tx_blob_field = tx_blob_field.with_value(p.tx_blob_hex.clone());
                }
                self.form = Some(
                    Form::new(
                        "Combine & submit multisig",
                        vec![
                            tx_blob_field,
                            Field::new("partial_sigs_hex (comma-separated)").hint("m signatures"),
                        ],
                    )
                    .submit("Combine"),
                );
            }
            _ => {}
        }
    }

    fn handle_form(&mut self, app: &mut App, result: FormResult) {
        match result {
            FormResult::Submit => {
                let Some(form) = self.form.take() else { return };
                let action = self.actions.selected_label().unwrap_or("").to_string();
                match action.as_str() {
                    "HTLC — create & fund" => {
                        let recipient_pk = match parse_pk(form.value(0).unwrap_or("")) {
                            Ok(pk) => pk,
                            Err(e) => {
                                app.status = StatusMsg::err(e).for_secs(5);
                                return;
                            }
                        };
                        let preimage = parse_preimage(form.value(1).unwrap_or(""));
                        let timeout: u32 = match form.value(2).unwrap_or("").trim().parse() {
                            Ok(t) => t,
                            Err(_) => {
                                app.status =
                                    StatusMsg::err("timeout must be a block height").for_secs(4);
                                return;
                            }
                        };
                        let amount = match parse_kvnc(form.value(3).unwrap_or("")) {
                            Ok(a) if a > 0 => a,
                            _ => {
                                app.status = StatusMsg::err("amount must be > 0").for_secs(4);
                                return;
                            }
                        };
                        let Some(wallet) = &app.wallet else { return };
                        let sender_pk = *wallet.address().payload();
                        let script = match HtlcScript::new(
                            *blake3::hash(&preimage).as_bytes(),
                            recipient_pk,
                            sender_pk,
                            timeout,
                        ) {
                            Ok(s) => s,
                            Err(e) => {
                                app.status =
                                    StatusMsg::err(format!("htlc: {}", e.as_str())).for_secs(5);
                                return;
                            }
                        };
                        let address = script.address();
                        let script_hex = hex::encode(script.bytes());
                        let preimage_hex = hex::encode(&preimage);
                        self.last_preimage = Some(preimage_hex.clone());
                        self.info = Some(serde_json::json!({
                            "kind": "htlc",
                            "address": address.to_kvnc(),
                            "address_hex": address.to_hex(),
                            "script_hex": script_hex,
                            "preimage_hex": preimage_hex,
                            "timeout": timeout,
                            "amount_atoms": amount,
                        }));
                        self.modal = Some(
                            Modal::new("HTLC created — save these")
                                .line(Line::from(vec![
                                    Span::styled("address  ", theme::label()),
                                    Span::styled(address.to_kvnc(), theme::value_hl()),
                                ]))
                                .line(Line::from(vec![
                                    Span::styled("script   ", theme::label()),
                                    Span::styled(short_hex(&script_hex, 16, 16), theme::hint()),
                                ]))
                                .line(Line::from(vec![
                                    Span::styled("preimage ", theme::label()),
                                    Span::styled(short_hex(&preimage_hex, 12, 12), theme::value()),
                                ]))
                                .line(Line::from(Span::styled(
                                    "Keep the preimage secret — it lets the recipient redeem.",
                                    theme::positive(),
                                )))
                                .line(Line::from(Span::styled(
                                    "Now fund the address with the next step.",
                                    theme::hint(),
                                )))
                                .confirm("Fund it")
                                .cancel("Later"),
                        );
                    }
                    "HTLC — redeem (recipient)" => {
                        let script = match parse_htlc_script(form.value(0).unwrap_or("")) {
                            Ok(s) => s,
                            Err(e) => {
                                app.status = StatusMsg::err(e).for_secs(5);
                                return;
                            }
                        };
                        let preimage = parse_preimage(form.value(1).unwrap_or(""));
                        let to = match crate::api::parse_address(form.value(2).unwrap_or("")) {
                            Ok(a) => a,
                            Err(e) => {
                                app.status =
                                    StatusMsg::err(format!("invalid address: {e}")).for_secs(5);
                                return;
                            }
                        };
                        let Some(wallet) = &app.wallet else { return };
                        let kp = wallet.keypair();
                        let addr_hex = script.address().to_hex();
                        let script_bytes = script.bytes().to_vec();
                        let preimage_bytes = preimage.clone();
                        let to_hex = to.to_hex();
                        app.spawn("htlc redeem", {
                            let client = app.client.clone();
                            move || {
                                let head = client.head().map_err(|e| e.to_string())?;
                                let min_fee =
                                    head.get("min_fee").and_then(|v| v.as_u64()).unwrap_or(1);
                                let utxos = client.utxos(&addr_hex).map_err(|e| e.to_string())?;
                                let outpoint = pick_outpoint(&utxos).ok_or_else(|| {
                                    format!("no spendable UTXO at HTLC address {addr_hex}")
                                })?;
                                let value = outpoint_value(&utxos, &outpoint).unwrap_or(0);
                                let out_value = value.checked_sub(min_fee).ok_or_else(|| {
                                    format!("locked value {value} below min fee {min_fee}")
                                })?;
                                let mut tx = Transaction::new(
                                    vec![TxInput::new(outpoint, Vec::new())],
                                    vec![TxOutput::native(
                                        out_value,
                                        Address::parse(&to_hex).map_err(|e| e.to_string())?,
                                    )],
                                    Vec::new(),
                                );
                                let sighash = tx.sighash();
                                let sig = kp.sign(&sighash);
                                let script = HtlcScript::parse(&script_bytes)
                                    .map_err(|e| e.as_str().to_string())?;
                                tx.inputs_mut()[0].witness =
                                    script.redeem_witness(&preimage_bytes, sig);
                                client
                                    .submit_tx(&hex::encode(tx.encode()))
                                    .map_err(|e| e.to_string())
                            }
                        });
                    }
                    "HTLC — refund (sender)" => {
                        let script = match parse_htlc_script(form.value(0).unwrap_or("")) {
                            Ok(s) => s,
                            Err(e) => {
                                app.status = StatusMsg::err(e).for_secs(5);
                                return;
                            }
                        };
                        let to = match crate::api::parse_address(form.value(1).unwrap_or("")) {
                            Ok(a) => a,
                            Err(e) => {
                                app.status =
                                    StatusMsg::err(format!("invalid address: {e}")).for_secs(5);
                                return;
                            }
                        };
                        let Some(wallet) = &app.wallet else { return };
                        let kp = wallet.keypair();
                        let addr_hex = script.address().to_hex();
                        let script_bytes = script.bytes().to_vec();
                        let to_hex = to.to_hex();
                        app.spawn("htlc refund", {
                            let client = app.client.clone();
                            move || {
                                let head = client.head().map_err(|e| e.to_string())?;
                                let min_fee =
                                    head.get("min_fee").and_then(|v| v.as_u64()).unwrap_or(1);
                                let utxos = client.utxos(&addr_hex).map_err(|e| e.to_string())?;
                                let outpoint = pick_outpoint(&utxos).ok_or_else(|| {
                                    format!("no spendable UTXO at HTLC address {addr_hex}")
                                })?;
                                let value = outpoint_value(&utxos, &outpoint).unwrap_or(0);
                                let out_value = value.checked_sub(min_fee).ok_or_else(|| {
                                    format!("locked value {value} below min fee {min_fee}")
                                })?;
                                let mut tx = Transaction::new(
                                    vec![TxInput::new(outpoint, Vec::new())],
                                    vec![TxOutput::native(
                                        out_value,
                                        Address::parse(&to_hex).map_err(|e| e.to_string())?,
                                    )],
                                    Vec::new(),
                                );
                                let sighash = tx.sighash();
                                let sig = kp.sign(&sighash);
                                let script = HtlcScript::parse(&script_bytes)
                                    .map_err(|e| e.as_str().to_string())?;
                                tx.inputs_mut()[0].witness = script.refund_witness(sig);
                                client
                                    .submit_tx(&hex::encode(tx.encode()))
                                    .map_err(|e| e.to_string())
                            }
                        });
                    }
                    "Vault — create & fund" => {
                        let unlock_height: u32 =
                            form.value(0).unwrap_or("0").trim().parse().unwrap_or(0);
                        let csv: u32 = form.value(1).unwrap_or("0").trim().parse().unwrap_or(0);
                        let owner_pk = match form.value(2).unwrap_or("").trim() {
                            "" => {
                                let Some(wallet) = &app.wallet else { return };
                                *wallet.address().payload()
                            }
                            s => match parse_pk(s) {
                                Ok(pk) => pk,
                                Err(e) => {
                                    app.status = StatusMsg::err(e).for_secs(5);
                                    return;
                                }
                            },
                        };
                        let amount = match parse_kvnc(form.value(3).unwrap_or("")) {
                            Ok(a) if a > 0 => a,
                            _ => {
                                app.status = StatusMsg::err("amount must be > 0").for_secs(4);
                                return;
                            }
                        };
                        let script = match VaultScript::new(unlock_height, csv, owner_pk) {
                            Ok(s) => s,
                            Err(e) => {
                                app.status =
                                    StatusMsg::err(format!("vault: {}", e.as_str())).for_secs(5);
                                return;
                            }
                        };
                        let address = script.address();
                        let script_hex = hex::encode(script.bytes());
                        self.info = Some(serde_json::json!({
                            "kind": "vault",
                            "address": address.to_kvnc(),
                            "address_hex": address.to_hex(),
                            "script_hex": script_hex,
                            "unlock_height": unlock_height,
                            "csv": csv,
                            "amount_atoms": amount,
                        }));
                        self.modal = Some(
                            Modal::new("Vault created — save these")
                                .line(Line::from(vec![
                                    Span::styled("address  ", theme::label()),
                                    Span::styled(address.to_kvnc(), theme::value_hl()),
                                ]))
                                .line(Line::from(vec![
                                    Span::styled("script   ", theme::label()),
                                    Span::styled(short_hex(&script_hex, 16, 16), theme::hint()),
                                ]))
                                .line(Line::from(vec![
                                    Span::styled("unlock   ", theme::label()),
                                    Span::styled(unlock_height.to_string(), theme::value()),
                                ]))
                                .line(Line::from(vec![
                                    Span::styled("csv      ", theme::label()),
                                    Span::styled(csv.to_string(), theme::value()),
                                ]))
                                .line(Line::from(Span::styled(
                                    "Fund the address with the next step.",
                                    theme::hint(),
                                )))
                                .confirm("Fund it")
                                .cancel("Later"),
                        );
                    }
                    "Vault — release" => {
                        let script = match parse_vault_script(form.value(0).unwrap_or("")) {
                            Ok(s) => s,
                            Err(e) => {
                                app.status = StatusMsg::err(e).for_secs(5);
                                return;
                            }
                        };
                        let to = match crate::api::parse_address(form.value(1).unwrap_or("")) {
                            Ok(a) => a,
                            Err(e) => {
                                app.status =
                                    StatusMsg::err(format!("invalid address: {e}")).for_secs(5);
                                return;
                            }
                        };
                        let Some(wallet) = &app.wallet else { return };
                        let kp = wallet.keypair();
                        let addr_hex = script.address().to_hex();
                        let script_bytes = script.bytes().to_vec();
                        let to_hex = to.to_hex();
                        app.spawn("vault release", {
                            let client = app.client.clone();
                            move || {
                                let head = client.head().map_err(|e| e.to_string())?;
                                let min_fee =
                                    head.get("min_fee").and_then(|v| v.as_u64()).unwrap_or(1);
                                let utxos = client.utxos(&addr_hex).map_err(|e| e.to_string())?;
                                let outpoint = pick_outpoint(&utxos).ok_or_else(|| {
                                    format!("no spendable UTXO at vault address {addr_hex}")
                                })?;
                                let value = outpoint_value(&utxos, &outpoint).unwrap_or(0);
                                let out_value = value.checked_sub(min_fee).ok_or_else(|| {
                                    format!("locked value {value} below min fee {min_fee}")
                                })?;
                                let mut tx = Transaction::new(
                                    vec![TxInput::new(outpoint, Vec::new())],
                                    vec![TxOutput::native(
                                        out_value,
                                        Address::parse(&to_hex).map_err(|e| e.to_string())?,
                                    )],
                                    Vec::new(),
                                );
                                let sighash = tx.sighash();
                                let sig = kp.sign(&sighash);
                                let script = VaultScript::parse(&script_bytes)
                                    .map_err(|e| e.as_str().to_string())?;
                                tx.inputs_mut()[0].witness = script.spend_witness(sig);
                                client
                                    .submit_tx(&hex::encode(tx.encode()))
                                    .map_err(|e| e.to_string())
                            }
                        });
                    }
                    "Multisig — create address" => {
                        let threshold: u8 = match form.value(0).unwrap_or("").trim().parse() {
                            Ok(t) if (1..=16).contains(&t) => t,
                            _ => {
                                app.status = StatusMsg::err("threshold must be 1..=16").for_secs(4);
                                return;
                            }
                        };
                        let pubkeys: Vec<String> = form
                            .value(1)
                            .unwrap_or("")
                            .split(',')
                            .map(|s| s.trim().to_string())
                            .filter(|s| !s.is_empty())
                            .collect();
                        if pubkeys.is_empty() || pubkeys.len() > 16 {
                            app.status = StatusMsg::err("need 1..=16 pubkeys").for_secs(4);
                            return;
                        }
                        app.spawn("multisig create", {
                            let client = app.client.clone();
                            move || {
                                client
                                    .multisig_create(threshold, &pubkeys)
                                    .map_err(|e| e.to_string())
                            }
                        });
                    }
                    "Multisig — build & sign" => {
                        let address = form.value(0).unwrap_or("").trim().to_string();
                        let to = match crate::api::parse_address(form.value(1).unwrap_or("")) {
                            Ok(a) => a,
                            Err(e) => {
                                app.status =
                                    StatusMsg::err(format!("invalid address: {e}")).for_secs(5);
                                return;
                            }
                        };
                        let amount = match parse_kvnc(form.value(2).unwrap_or("")) {
                            Ok(a) if a > 0 => a,
                            _ => {
                                app.status = StatusMsg::err("amount must be > 0").for_secs(4);
                                return;
                            }
                        };
                        let to_hex = to.to_hex();
                        app.spawn("multisig build", {
                            let client = app.client.clone();
                            move || {
                                client
                                    .multisig_build(&address, &[(to_hex, amount)])
                                    .map_err(|e| e.to_string())
                            }
                        });
                    }
                    "Multisig — combine & submit" => {
                        let tx_blob = form.value(0).unwrap_or("").trim().to_string();
                        let sigs: Vec<String> = form
                            .value(1)
                            .unwrap_or("")
                            .split(',')
                            .map(|s| s.trim().to_string())
                            .filter(|s| !s.is_empty())
                            .collect();
                        if tx_blob.is_empty() || sigs.is_empty() {
                            app.status =
                                StatusMsg::err("tx_blob and at least one sig required").for_secs(4);
                            return;
                        }
                        app.spawn("multisig combine", {
                            let client = app.client.clone();
                            move || {
                                let combined = client
                                    .multisig_combine(&tx_blob, &sigs)
                                    .map_err(|e| e.to_string())?;
                                let signed = combined
                                    .get("signed_tx_blob_hex")
                                    .and_then(|v| v.as_str())
                                    .ok_or("combine returned no signed_tx_blob_hex")?
                                    .to_string();
                                client.multisig_submit(&signed).map_err(|e| e.to_string())
                            }
                        });
                    }
                    _ => {}
                }
            }
            FormResult::Cancel => self.form = None,
            FormResult::Continue => {}
        }
    }

    fn handle_modal(&mut self, app: &mut App, result: ModalResult) {
        match result {
            ModalResult::Confirm => {
                // "Fund it" — prepare a transfer to the created contract address.
                let Some(info) = &self.info else { return };
                let Some(wallet) = &app.wallet else { return };
                let address = info
                    .get("address_hex")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let from = wallet.address().to_hex();
                let kind = info
                    .get("kind")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let amount = info
                    .get("amount_atoms")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(1_000_000_000u64);
                app.spawn("fund contract", {
                    let client = app.client.clone();
                    move || {
                        let head = client.head().map_err(|e| e.to_string())?;
                        let min_fee = head.get("min_fee").and_then(|v| v.as_u64()).unwrap_or(1);
                        let _ = (kind.clone(), min_fee);
                        client
                            .prepare(&from, &address, amount)
                            .map_err(|e| e.to_string())
                    }
                });
                self.modal = None;
            }
            ModalResult::Cancel => self.modal = None,
            ModalResult::Continue => {}
        }
    }
}

impl ScreenImpl for ContractsState {
    fn handle_key(&mut self, app: &mut App, key: crossterm::event::KeyEvent) {
        use crossterm::event::KeyCode;
        if let Some(modal) = &mut self.modal {
            let result = modal.handle_key(key);
            self.handle_modal(app, result);
            return;
        }
        if let Some(form) = &mut self.form {
            let result = form.handle_key(key);
            self.handle_form(app, result);
            return;
        }
        match key.code {
            KeyCode::Up | KeyCode::Char('k') => self.actions.previous(),
            KeyCode::Down | KeyCode::Char('j') => self.actions.next(),
            KeyCode::Enter => {
                if let Some(label) = self.actions.selected_label().map(str::to_string) {
                    self.run_action(app, &label);
                }
            }
            _ => {}
        }
    }

    fn render(&self, _app: &App, f: &mut Frame, area: Rect) {
        let (left, right) = widgets::split_action_area(area);
        let items: Vec<String> = self
            .actions
            .items
            .iter()
            .enumerate()
            .map(|(i, s)| {
                if i == self.actions.selected {
                    format!("▶ {s}")
                } else {
                    format!("  {s}")
                }
            })
            .collect();
        widgets::render_list_panel(f, "Contracts", &items, Some(self.actions.selected), left);

        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Percentage(55), Constraint::Percentage(45)])
            .split(right);

        let mut lines: Vec<Line> = Vec::new();
        if let Some(info) = &self.info {
            let kind = info.get("kind").and_then(|v| v.as_str()).unwrap_or("");
            lines.push(Line::from(vec![
                Span::styled("kind     ", theme::label()),
                Span::styled(kind.to_uppercase(), theme::value_hl()),
            ]));
            lines.push(Line::from(vec![
                Span::styled("address  ", theme::label()),
                Span::styled(
                    info.get("address").and_then(|v| v.as_str()).unwrap_or(""),
                    theme::value(),
                ),
            ]));
            lines.push(Line::from(vec![
                Span::styled("script   ", theme::label()),
                Span::styled(
                    short_hex(
                        info.get("script_hex")
                            .and_then(|v| v.as_str())
                            .unwrap_or(""),
                        16,
                        16,
                    ),
                    theme::hint(),
                ),
            ]));
            if let Some(p) = &self.last_preimage {
                lines.push(Line::from(vec![
                    Span::styled("preimage ", theme::label()),
                    Span::styled(short_hex(p, 12, 12), theme::value()),
                ]));
            }
            if let Some(ms) = &self.multisig_pending {
                lines.push(Line::from(vec![
                    Span::styled("sighash  ", theme::label()),
                    Span::styled(short_hex(&ms.sighash_hex, 16, 16), theme::value()),
                ]));
                lines.push(Line::from(Span::styled(
                    "Sign locally, then share the sig with the other signers.",
                    theme::positive(),
                )));
            }
        } else {
            lines.push(Line::from(Span::styled(
                "HTLC: lock funds behind a preimage + timeout (RFC-004).",
                theme::hint(),
            )));
            lines.push(Line::from(Span::styled(
                "Vault: time-locked escrow, absolute + relative locks (RFC-005).",
                theme::hint(),
            )));
            lines.push(Line::from(Span::styled(
                "Multisig: M-of-N P2SH — sign locally, node never sees keys.",
                theme::hint(),
            )));
        }
        widgets::render_panel(f, "Contract", &Text::from(lines), chunks[0]);

        let mut res_lines: Vec<Line> = Vec::new();
        if let Some(tx) = &self.result {
            res_lines.push(Line::from(vec![
                Span::styled("tx      ", theme::label()),
                Span::styled(tx.clone(), theme::value_hl()),
            ]));
        } else if let Some(err) = &self.error {
            res_lines.push(Line::from(Span::styled(err.clone(), theme::negative())));
        } else {
            res_lines.push(Line::from(Span::styled(
                "no contract transaction yet",
                theme::hint(),
            )));
        }
        widgets::render_panel(f, "Result", &Text::from(res_lines), chunks[1]);

        if let Some(form) = &self.form {
            widgets::render_form(f, form, area);
        }
        if let Some(modal) = &self.modal {
            widgets::render_modal(f, modal, area);
        }
    }

    fn on_result(&mut self, app: &mut App, label: &str, result: Result<Value, String>) {
        match (label, result) {
            ("htlc redeem", Ok(v)) | ("htlc refund", Ok(v)) | ("vault release", Ok(v)) => {
                let tx = v
                    .get("tx")
                    .and_then(|t| t.as_str())
                    .unwrap_or("")
                    .to_string();
                self.result = Some(tx.clone());
                app.status = StatusMsg::ok(format!(
                    "contract spend broadcast ✓ {}",
                    short_hex(&tx, 10, 10)
                ))
                .for_secs(6);
            }
            ("multisig create", Ok(v)) => {
                self.info = Some(v.clone());
                let addr = v.get("address").and_then(|a| a.as_str()).unwrap_or("");
                app.status = StatusMsg::ok(format!("multisig address {addr}")).for_secs(5);
            }
            ("multisig build", Ok(v)) => {
                let tx_blob = v
                    .get("tx_blob_hex")
                    .and_then(|x| x.as_str())
                    .unwrap_or("")
                    .to_string();
                let sighash = v
                    .get("sighash_hex")
                    .and_then(|x| x.as_str())
                    .unwrap_or("")
                    .to_string();
                let Some(wallet) = &app.wallet else { return };
                let sig = wallet
                    .keypair()
                    .sign(&hex::decode(&sighash).unwrap_or_default());
                let sig_hex = hex::encode(sig);
                self.multisig_pending = Some(MultisigPending {
                    tx_blob_hex: tx_blob,
                    sighash_hex: sighash,
                });
                self.modal = Some(
                    Modal::new("Your partial signature")
                        .line(Line::from(Span::styled(
                            "Signed locally — the node never saw your key.",
                            theme::positive(),
                        )))
                        .line(Line::from(""))
                        .line(Line::from(vec![
                            Span::styled("sig_hex  ", theme::label()),
                            Span::styled(sig_hex.clone(), theme::value()),
                        ]))
                        .line(Line::from(""))
                        .line(Line::from(Span::styled(
                            "Share this with the other signers, then use",
                            theme::hint(),
                        )))
                        .line(Line::from(Span::styled(
                            "“Multisig — combine & submit” with all m sigs.",
                            theme::hint(),
                        )))
                        .confirm("OK")
                        .cancel("Close"),
                );
            }
            ("multisig combine", Ok(v)) => {
                let tx = v
                    .get("tx_id_hex")
                    .and_then(|t| t.as_str())
                    .unwrap_or("")
                    .to_string();
                self.result = Some(tx.clone());
                app.status =
                    StatusMsg::ok(format!("multisig submitted ✓ {}", short_hex(&tx, 10, 10)))
                        .for_secs(6);
            }
            ("fund contract", Ok(v)) => {
                let sighash = v
                    .get("sighash")
                    .and_then(|s| s.as_str())
                    .unwrap_or("")
                    .to_string();
                let Some(wallet) = &app.wallet else { return };
                let sig = wallet
                    .keypair()
                    .sign(&hex::decode(&sighash).unwrap_or_default());
                let sig_hex = hex::encode(sig);
                let from = v
                    .get("from")
                    .and_then(|x| x.as_str())
                    .unwrap_or("")
                    .to_string();
                let to = v
                    .get("to")
                    .and_then(|x| x.as_str())
                    .unwrap_or("")
                    .to_string();
                let amount = v.get("amount").and_then(|x| x.as_u64()).unwrap_or(0);
                app.spawn("submit fund", {
                    let client = app.client.clone();
                    move || {
                        client
                            .submit(&from, &to, amount, &sig_hex)
                            .map_err(|e| e.to_string())
                    }
                });
            }
            ("submit fund", Ok(v)) => {
                let tx = v
                    .get("tx")
                    .and_then(|t| t.as_str())
                    .unwrap_or("")
                    .to_string();
                self.result = Some(tx.clone());
                app.status = StatusMsg::ok(format!("contract funded ✓ {}", short_hex(&tx, 10, 10)))
                    .for_secs(6);
            }
            (_, Err(e)) => {
                self.error = Some(e.clone());
                app.status = StatusMsg::err(format!("{label}: {e}")).for_secs(6);
            }
            _ => {}
        }
    }
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

fn parse_pk(s: &str) -> Result<[u8; 32], String> {
    let bytes = hex::decode(s.trim()).map_err(|_| "public key must be 64-hex".to_string())?;
    <[u8; 32]>::try_from(bytes.as_slice()).map_err(|_| "public key must be 32 bytes".to_string())
}

fn parse_preimage(s: &str) -> Vec<u8> {
    let t = s.trim();
    if let Ok(bytes) = hex::decode(t) {
        bytes
    } else {
        t.as_bytes().to_vec()
    }
}

fn parse_htlc_script(s: &str) -> Result<HtlcScript, String> {
    let bytes = hex::decode(s.trim()).map_err(|_| "script must be hex".to_string())?;
    HtlcScript::parse(&bytes).map_err(|e| e.as_str().to_string())
}

fn parse_vault_script(s: &str) -> Result<VaultScript, String> {
    let bytes = hex::decode(s.trim()).map_err(|_| "script must be hex".to_string())?;
    VaultScript::parse(&bytes).map_err(|e| e.as_str().to_string())
}

fn parse_kvnc(s: &str) -> Result<u64, String> {
    const ATOM: u64 = 100_000_000;
    let s = s.trim();
    if let Ok(atoms) = s.parse::<u64>() {
        return Ok(atoms);
    }
    let (whole, frac) = s
        .split_once('.')
        .ok_or_else(|| format!("cannot parse amount {s:?}"))?;
    let whole: u64 = whole
        .parse()
        .map_err(|_| format!("cannot parse amount {s:?}"))?;
    let frac = format!("{frac:<08}");
    let frac: u64 = frac[..8]
        .parse()
        .map_err(|_| format!("cannot parse amount {s:?}"))?;
    whole
        .checked_mul(ATOM)
        .and_then(|w| w.checked_add(frac))
        .ok_or_else(|| "amount overflows u64 atoms".to_string())
}

/// Pick the first spendable outpoint from a `/api/utxos` response.
fn pick_outpoint(utxos: &Value) -> Option<OutPoint> {
    let arr = utxos.as_array()?;
    for u in arr {
        let Some(tx) = u.get("tx").and_then(|v| v.as_str()) else {
            continue;
        };
        let index = u.get("index").and_then(|v| v.as_u64()).unwrap_or(0);
        let Ok(tx_bytes) = hex::decode(tx) else {
            continue;
        };
        let Ok(tx_id) = <[u8; 32]>::try_from(tx_bytes.as_slice()) else {
            continue;
        };
        return Some(OutPoint::new(
            kovanica_state::TxId::from_bytes(tx_id),
            index as u32,
        ));
    }
    None
}

fn outpoint_value(utxos: &Value, outpoint: &OutPoint) -> Option<u64> {
    let arr = utxos.as_array()?;
    for u in arr {
        let tx = u.get("tx").and_then(|v| v.as_str())?;
        let index = u.get("index").and_then(|v| v.as_u64()).unwrap_or(0);
        let tx_bytes = hex::decode(tx).ok()?;
        let tx_id = <[u8; 32]>::try_from(tx_bytes.as_slice()).ok()?;
        if kovanica_state::TxId::from_bytes(tx_id) == outpoint.tx && index as u32 == outpoint.index
        {
            return u.get("value").and_then(|v| v.as_u64());
        }
    }
    None
}

impl Default for ContractsState {
    fn default() -> Self {
        Self::new()
    }
}
