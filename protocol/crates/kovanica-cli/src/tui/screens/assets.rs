//! Assets (KVP-102): derive asset ids, issue/transfer assets, and inspect
//! per-asset balances.

use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    text::{Line, Span, Text},
    Frame,
};
use serde_json::Value;

use crate::tui::{
    short_hex, theme, widgets, widgets::Field, widgets::Form, widgets::FormResult, ActionList, App,
    ScreenImpl, StatusMsg,
};

pub struct AssetsState {
    pub actions: ActionList,
    pub form: Option<Form>,
    pub derived: Option<Value>,
    pub balance: Option<Value>,
    pub result: Option<String>,
    pub error: Option<String>,
}

impl AssetsState {
    pub fn new() -> Self {
        Self {
            actions: ActionList::new(vec![
                "Derive asset id".to_string(),
                "Issue / transfer asset".to_string(),
                "Asset balances".to_string(),
            ]),
            form: None,
            derived: None,
            balance: None,
            result: None,
            error: None,
        }
    }

    fn run_action(&mut self, app: &mut App, label: &str) {
        match label {
            "Derive asset id" => {
                self.form = Some(
                    Form::new(
                        "Derive asset id (KVP-106 RWA scheme)",
                        vec![
                            Field::new("issuer public key (64-hex)").hint("32-byte Ed25519 pubkey"),
                            Field::new("asset class").hint("e.g. RE, BOND, INVOICE, TOKEN"),
                            Field::new("unique id").hint("issuer-defined identifier"),
                            Field::new("version").with_value("1"),
                        ],
                    )
                    .submit("Derive"),
                );
            }
            "Issue / transfer asset" => {
                if app.wallet.is_none() {
                    app.status = StatusMsg::err("no wallet loaded").for_secs(4);
                    return;
                }
                self.form = Some(
                    Form::new(
                        "Issue / transfer asset",
                        vec![
                            Field::new("asset_id (64-hex)").hint("derived or existing asset"),
                            Field::new("amount (atoms)").hint("integer atom count"),
                            Field::new("to (kvnc…dag or hex)").hint("recipient address"),
                        ],
                    )
                    .submit("Prepare"),
                );
            }
            "Asset balances" => {
                let Some(addr) = app.address() else {
                    app.status = StatusMsg::err("no wallet loaded").for_secs(4);
                    return;
                };
                let hex = addr.hex.clone();
                app.spawn("asset balances", {
                    let client = app.client.clone();
                    move || client.utxos(&hex).map_err(|e| e.to_string())
                });
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
                    "Derive asset id" => {
                        let issuer = form.value(0).unwrap_or("").trim().to_string();
                        let class = form.value(1).unwrap_or("").trim().to_string();
                        let id = form.value(2).unwrap_or("").trim().to_string();
                        let version: u8 = form.value(3).unwrap_or("1").trim().parse().unwrap_or(1);
                        if issuer.is_empty() || class.is_empty() || id.is_empty() {
                            app.status =
                                StatusMsg::err("issuer, class and id are required").for_secs(4);
                            return;
                        }
                        let issuer_bytes = match hex::decode(&issuer) {
                            Ok(b) if b.len() == 32 => {
                                let mut arr = [0u8; 32];
                                arr.copy_from_slice(&b);
                                arr
                            }
                            _ => {
                                app.status =
                                    StatusMsg::err("issuer must be 32-byte hex").for_secs(5);
                                return;
                            }
                        };
                        let asset_id = kovanica_state::derive_rwa_asset_id(
                            &issuer_bytes,
                            &class,
                            &id,
                            version,
                        );
                        self.derived = Some(serde_json::json!({
                            "asset_id": asset_id.to_hex(),
                            "asset_id_kvnc": format!("kvnc{}dag", asset_id.to_hex()),
                        }));
                        app.status = StatusMsg::ok("asset id derived").for_secs(3);
                    }
                    "Issue / transfer asset" => {
                        let asset_id = form.value(0).unwrap_or("").trim().to_string();
                        let amount: u64 = match form.value(1).unwrap_or("").trim().parse() {
                            Ok(a) if a > 0 => a,
                            _ => {
                                app.status =
                                    StatusMsg::err("amount must be a positive integer").for_secs(4);
                                return;
                            }
                        };
                        let to = form.value(2).unwrap_or("").trim().to_string();
                        let to_hex = match crate::api::parse_address(&to) {
                            Ok(a) => a.to_hex(),
                            Err(e) => {
                                app.status =
                                    StatusMsg::err(format!("invalid address: {e}")).for_secs(5);
                                return;
                            }
                        };
                        let Some(wallet) = &app.wallet else { return };
                        let from = wallet.address().to_hex();
                        let asset = asset_id.clone();
                        app.spawn("prepare asset transfer", {
                            let client = app.client.clone();
                            move || {
                                let raw = hex::decode(&asset)
                                    .map_err(|e| format!("asset_id not hex: {e}"))?;
                                if raw.len() != 32 {
                                    return Err("asset_id must be 32 bytes".to_string());
                                }
                                let aid = kovanica_state::AssetId::from_bytes(
                                    <[u8; 32]>::try_from(raw.as_slice())
                                        .map_err(|_| "asset_id must be 32 bytes".to_string())?,
                                );
                                client
                                    .prepare_transfer_asset(&from, amount, &to_hex, Some(aid))
                                    .map_err(|e| e.to_string())
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
}

impl ScreenImpl for AssetsState {
    fn handle_key(&mut self, app: &mut App, key: crossterm::event::KeyEvent) {
        use crossterm::event::KeyCode;
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
        widgets::render_list_panel(f, "Assets", &items, Some(self.actions.selected), left);

        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
            .split(right);

        let mut lines: Vec<Line> = Vec::new();
        if let Some(d) = &self.derived {
            lines.push(Line::from(vec![
                Span::styled("asset_id  ", theme::label()),
                Span::styled(
                    d.get("asset_id").and_then(|v| v.as_str()).unwrap_or(""),
                    theme::value_hl(),
                ),
            ]));
            lines.push(Line::from(vec![
                Span::styled("kvnc form ", theme::label()),
                Span::styled(
                    d.get("asset_id_kvnc")
                        .and_then(|v| v.as_str())
                        .unwrap_or(""),
                    theme::hint(),
                ),
            ]));
            lines.push(Line::from(Span::styled(
                "Use this id to issue/transfer the asset.",
                theme::hint(),
            )));
        } else {
            lines.push(Line::from(Span::styled(
                "Derive a deterministic asset id from an issuer key + parameters,",
                theme::hint(),
            )));
            lines.push(Line::from(Span::styled(
                "or issue/transfer an existing asset to a recipient.",
                theme::hint(),
            )));
        }
        widgets::render_panel(f, "Asset", &Text::from(lines), chunks[0]);

        let mut bal_lines: Vec<Line> = Vec::new();
        if let Some(b) = &self.balance {
            if let Some(balances) = b.get("balances").and_then(|v| v.as_object()) {
                if balances.is_empty() {
                    bal_lines.push(Line::from(Span::styled("no assets held", theme::hint())));
                }
                for (asset, amount) in balances.iter() {
                    if asset == "KVNC" {
                        continue;
                    }
                    bal_lines.push(Line::from(vec![
                        Span::styled(short_hex(asset, 12, 10), theme::value()),
                        Span::styled(format!("  {amount}"), theme::value_hl()),
                    ]));
                }
            } else {
                bal_lines.push(Line::from(Span::styled("no balances", theme::hint())));
            }
        } else {
            bal_lines.push(Line::from(Span::styled(
                "press ⏎ on “Asset balances” to load",
                theme::hint(),
            )));
        }
        widgets::render_panel(f, "Balances", &Text::from(bal_lines), chunks[1]);

        if let Some(form) = &self.form {
            widgets::render_form(f, form, area);
        }
    }

    fn on_result(&mut self, app: &mut App, label: &str, result: Result<Value, String>) {
        match (label, result) {
            ("asset balances", Ok(v)) => {
                self.balance = Some(v);
                app.status = StatusMsg::ok("balances updated").for_secs(2);
            }
            ("prepare asset transfer", Ok(v)) => {
                let sighash = v.get("sighash").and_then(|s| s.as_str()).unwrap_or("");
                let Some(wallet) = &app.wallet else { return };
                let sig = wallet
                    .keypair()
                    .sign(&hex::decode(sighash).unwrap_or_default());
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
                let asset = v
                    .get("asset_id")
                    .and_then(|x| x.as_str())
                    .map(|s| s.to_string());
                app.spawn("submit asset transfer", {
                    let client = app.client.clone();
                    move || {
                        let aid = asset
                            .as_ref()
                            .and_then(|a| hex::decode(a).ok())
                            .and_then(|b| <[u8; 32]>::try_from(b.as_slice()).ok())
                            .map(kovanica_state::AssetId::from_bytes);
                        client
                            .submit_transfer_asset(&from, &to, amount, aid, &sig_hex)
                            .map_err(|e| e.to_string())
                    }
                });
            }
            ("submit asset transfer", Ok(v)) => {
                let tx = v
                    .get("tx")
                    .and_then(|t| t.as_str())
                    .unwrap_or("")
                    .to_string();
                self.result = Some(tx.clone());
                app.status = StatusMsg::ok(format!(
                    "asset transfer broadcast ✓ {}",
                    short_hex(&tx, 10, 10)
                ))
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

impl Default for AssetsState {
    fn default() -> Self {
        Self::new()
    }
}
