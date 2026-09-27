//! Send: KVNC and asset transfers with the prepare → offline-sign → submit
//! flow. The offline-sign boundary is explicit: a modal shows the sighash and
//! warns that signing happens locally before any signature is produced.

use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    text::{Line, Span, Text},
    Frame,
};
use serde_json::Value;

use crate::tui::{
    format_kvnc, short_hex, theme, widgets, widgets::Field, widgets::Form, widgets::FormResult,
    widgets::Modal, widgets::ModalResult, ActionList, App, ScreenImpl, StatusMsg,
};

pub struct SendState {
    pub actions: ActionList,
    pub form: Option<Form>,
    pub modal: Option<Modal>,
    pub prepared: Option<PreparedInfo>,
    pub result: Option<String>,
    pub error: Option<String>,
}

/// A prepared transfer awaiting the local signature.
pub struct PreparedInfo {
    pub from: String,
    pub to: String,
    pub amount: u64,
    pub asset_id: Option<String>,
    pub sighash: String,
    pub fee: u64,
    pub value: u64,
    pub change: u64,
}

impl SendState {
    pub fn new() -> Self {
        Self {
            actions: ActionList::new(vec![
                "Send KVNC".to_string(),
                "Send asset (KVP-102)".to_string(),
                "Request faucet (testnet)".to_string(),
            ]),
            form: None,
            modal: None,
            prepared: None,
            result: None,
            error: None,
        }
    }

    fn run_action(&mut self, app: &mut App, label: &str) {
        match label {
            "Send KVNC" => {
                if app.wallet.is_none() {
                    app.status = StatusMsg::err("no wallet loaded — create one in the Wallet tab")
                        .for_secs(5);
                    return;
                }
                self.form = Some(
                    Form::new(
                        "Send KVNC",
                        vec![
                            Field::new("to (kvnc…dag or hex)").hint("recipient address"),
                            Field::new("amount (KVNC)").hint("e.g. 1.5 = 150000000 atoms"),
                        ],
                    )
                    .submit("Prepare"),
                );
            }
            "Send asset (KVP-102)" => {
                if app.wallet.is_none() {
                    app.status = StatusMsg::err("no wallet loaded — create one in the Wallet tab")
                        .for_secs(5);
                    return;
                }
                self.form = Some(
                    Form::new(
                        "Send asset",
                        vec![
                            Field::new("to (kvnc…dag or hex)").hint("recipient address"),
                            Field::new("amount (atoms)").hint("integer atom count"),
                            Field::new("asset_id (64-hex)").hint("empty = native KVNC"),
                        ],
                    )
                    .submit("Prepare"),
                );
            }
            "Request faucet (testnet)" => {
                let Some(addr) = app.address() else {
                    app.status = StatusMsg::err("no wallet loaded").for_secs(4);
                    return;
                };
                let hex = addr.hex.clone();
                app.spawn("faucet", {
                    let client = app.client.clone();
                    move || client.faucet(&hex, 100_000_000).map_err(|e| e.to_string())
                });
            }
            _ => {}
        }
    }

    fn handle_form(&mut self, app: &mut App, result: FormResult) {
        match result {
            FormResult::Submit => {
                let Some(form) = self.form.take() else { return };
                let to = form.value(0).unwrap_or("").trim().to_string();
                let amount_str = form.value(1).unwrap_or("").trim().to_string();
                let asset_id = form
                    .value(2)
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty());

                if to.is_empty() {
                    app.status = StatusMsg::err("recipient address is required").for_secs(4);
                    return;
                }
                let amount = match parse_kvnc_input(&amount_str) {
                    Ok(a) => a,
                    Err(e) => {
                        app.status = StatusMsg::err(e).for_secs(5);
                        return;
                    }
                };
                if amount == 0 {
                    app.status = StatusMsg::err("amount must be greater than zero").for_secs(4);
                    return;
                }
                let Some(wallet) = &app.wallet else { return };
                let from = wallet.address().to_hex();
                let to_hex = match crate::api::parse_address(&to) {
                    Ok(a) => a.to_hex(),
                    Err(e) => {
                        app.status = StatusMsg::err(format!("invalid address: {e}")).for_secs(5);
                        return;
                    }
                };
                let asset = asset_id.clone();
                app.spawn("prepare send", {
                    let client = app.client.clone();
                    move || {
                        let prepared = match &asset {
                            Some(id) => client.prepare_transfer_asset(&from, amount, &to_hex, {
                                let raw = hex::decode(id)
                                    .map_err(|e| format!("asset_id not hex: {e}"))?;
                                if raw.len() != 32 {
                                    return Err("asset_id must be 32 bytes".to_string());
                                }
                                Some(kovanica_state::AssetId::from_bytes(
                                    <[u8; 32]>::try_from(raw.as_slice())
                                        .map_err(|_| "asset_id must be 32 bytes".to_string())?,
                                ))
                            }),
                            None => client.prepare(&from, &to_hex, amount),
                        };
                        prepared.map_err(|e| e.to_string())
                    }
                });
            }
            FormResult::Cancel => self.form = None,
            FormResult::Continue => {}
        }
    }

    fn handle_modal(&mut self, app: &mut App, result: ModalResult) {
        match result {
            ModalResult::Confirm => {
                let Some(prepared) = &self.prepared else {
                    return;
                };
                let Some(wallet) = &app.wallet else { return };
                let sighash = match hex::decode(prepared.sighash.trim()) {
                    Ok(s) => s,
                    Err(e) => {
                        app.status = StatusMsg::err(format!("sighash not hex: {e}")).for_secs(5);
                        return;
                    }
                };
                let sig = wallet.keypair().sign(&sighash);
                let sig_hex = hex::encode(sig);
                let from = prepared.from.clone();
                let to = prepared.to.clone();
                let amount = prepared.amount;
                let asset = prepared.asset_id.clone();
                app.spawn("submit send", {
                    let client = app.client.clone();
                    move || {
                        let result = match &asset {
                            Some(id) => client.submit_transfer_asset(
                                &from,
                                &to,
                                amount,
                                {
                                    let raw = hex::decode(id)
                                        .map_err(|e| format!("asset_id not hex: {e}"))?;
                                    Some(kovanica_state::AssetId::from_bytes(
                                        <[u8; 32]>::try_from(raw.as_slice())
                                            .map_err(|_| "asset_id must be 32 bytes".to_string())?,
                                    ))
                                },
                                &sig_hex,
                            ),
                            None => client.submit(&from, &to, amount, &sig_hex),
                        };
                        result.map_err(|e| e.to_string())
                    }
                });
                self.modal = None;
            }
            ModalResult::Cancel => {
                self.modal = None;
            }
            ModalResult::Continue => {}
        }
    }
}

impl ScreenImpl for SendState {
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
        widgets::render_list_panel(f, "Send", &items, Some(self.actions.selected), left);

        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
            .split(right);

        // Prepared transfer panel.
        let mut lines: Vec<Line> = Vec::new();
        if let Some(p) = &self.prepared {
            lines.push(Line::from(vec![
                Span::styled("from    ", theme::label()),
                Span::styled(short_hex(&p.from, 12, 10), theme::value()),
            ]));
            lines.push(Line::from(vec![
                Span::styled("to      ", theme::label()),
                Span::styled(short_hex(&p.to, 12, 10), theme::value()),
            ]));
            lines.push(Line::from(vec![
                Span::styled("amount  ", theme::label()),
                Span::styled(format_kvnc(p.amount), theme::value_hl()),
                Span::styled(
                    p.asset_id
                        .as_ref()
                        .map(|a| format!("  ({})", short_hex(a, 8, 6)))
                        .unwrap_or_else(|| " KVNC".to_string()),
                    theme::hint(),
                ),
            ]));
            lines.push(Line::from(vec![
                Span::styled("fee     ", theme::label()),
                Span::styled(p.fee.to_string(), theme::value()),
                Span::styled(" atoms", theme::hint()),
            ]));
            lines.push(Line::from(vec![
                Span::styled("value   ", theme::label()),
                Span::styled(format_kvnc(p.value), theme::value()),
            ]));
            lines.push(Line::from(vec![
                Span::styled("change  ", theme::label()),
                Span::styled(format_kvnc(p.change), theme::value()),
            ]));
            lines.push(Line::from(vec![
                Span::styled("sighash ", theme::label()),
                Span::styled(short_hex(&p.sighash, 16, 16), theme::hint()),
            ]));
            lines.push(Line::from(""));
            lines.push(Line::from(Span::styled(
                "Signed locally — your key never leaves this device.",
                theme::positive(),
            )));
        } else {
            lines.push(Line::from(Span::styled(
                "Fill the form to prepare a transfer. The node returns a sighash;",
                theme::hint(),
            )));
            lines.push(Line::from(Span::styled(
                "you sign it offline with your Ed25519 key, then submit.",
                theme::hint(),
            )));
        }
        widgets::render_panel(f, "Prepared transfer", &Text::from(lines), chunks[0]);

        // Result panel.
        let mut res_lines: Vec<Line> = Vec::new();
        if let Some(tx) = &self.result {
            res_lines.push(Line::from(vec![
                Span::styled("tx      ", theme::label()),
                Span::styled(tx.clone(), theme::value_hl()),
            ]));
            res_lines.push(Line::from(Span::styled(
                "Broadcast. Track it in the Explorer tab.",
                theme::hint(),
            )));
        } else if let Some(err) = &self.error {
            res_lines.push(Line::from(Span::styled(err.clone(), theme::negative())));
        } else {
            res_lines.push(Line::from(Span::styled(
                "no transaction submitted yet",
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
            ("prepare send", Ok(v)) => {
                let sighash = v
                    .get("sighash")
                    .and_then(|s| s.as_str())
                    .unwrap_or("")
                    .to_string();
                let fee = v.get("fee").and_then(|x| x.as_u64()).unwrap_or(0);
                let value = v.get("value").and_then(|x| x.as_u64()).unwrap_or(0);
                let change = v.get("change").and_then(|x| x.as_u64()).unwrap_or(0);
                let amount = v.get("amount").and_then(|x| x.as_u64()).unwrap_or(0);
                let to = v
                    .get("to")
                    .and_then(|x| x.as_str())
                    .unwrap_or("")
                    .to_string();
                let from = v
                    .get("from")
                    .and_then(|x| x.as_str())
                    .unwrap_or("")
                    .to_string();
                let asset_id = v
                    .get("asset_id")
                    .and_then(|x| x.as_str())
                    .filter(|s| !s.is_empty() && *s != "KVNC")
                    .map(|s| s.to_string());
                self.prepared = Some(PreparedInfo {
                    from,
                    to,
                    amount,
                    asset_id,
                    sighash,
                    fee,
                    value,
                    change,
                });
                self.modal = Some(
                    Modal::new("Offline sign")
                        .line(Line::from(Span::styled(
                            "Your key never leaves this device.",
                            theme::positive(),
                        )))
                        .line(Line::from(Span::styled(
                            "The node prepared the transaction and returned a sighash.",
                            theme::value(),
                        )))
                        .line(Line::from(Span::styled(
                            "Signing happens locally with your Ed25519 key.",
                            theme::value(),
                        )))
                        .line(Line::from(""))
                        .line(Line::from(vec![
                            Span::styled("sighash  ", theme::label()),
                            Span::styled(
                                short_hex(&self.prepared.as_ref().unwrap().sighash, 16, 16),
                                theme::hint(),
                            ),
                        ]))
                        .confirm("Sign & submit")
                        .cancel("Cancel"),
                );
            }
            ("submit send", Ok(v)) => {
                let tx = v
                    .get("tx")
                    .and_then(|t| t.as_str())
                    .unwrap_or("")
                    .to_string();
                self.result = Some(tx.clone());
                app.status =
                    StatusMsg::ok(format!("broadcast ✓ tx {}", short_hex(&tx, 10, 10))).for_secs(6);
            }
            ("faucet", Ok(v)) => {
                let block = v.get("block").and_then(|b| b.as_str()).unwrap_or("");
                app.status =
                    StatusMsg::ok(format!("faucet sent in block {}", short_hex(block, 10, 10)))
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

/// Parse a KVNC amount string ("1.5") into atoms, or a bare integer as atoms.
fn parse_kvnc_input(s: &str) -> Result<u64, String> {
    const ATOM: u64 = 100_000_000;
    let s = s.trim();
    if s.is_empty() {
        return Err("amount is required".to_string());
    }
    if let Ok(atoms) = s.parse::<u64>() {
        return Ok(atoms);
    }
    let (whole, frac) = match s.split_once('.') {
        Some((w, f)) => (w, f),
        None => return Err(format!("cannot parse amount {s:?}")),
    };
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

impl Default for SendState {
    fn default() -> Self {
        Self::new()
    }
}
