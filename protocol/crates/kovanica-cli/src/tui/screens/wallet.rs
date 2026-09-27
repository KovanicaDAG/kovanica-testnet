//! Wallet: key generation (BIP39), import, address display, balance, history.

use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Modifier, Style},
    text::{Line, Span, Text},
    Frame,
};
use serde_json::Value;

use crate::tui::{
    format_kvnc, short_hex, theme, widgets, widgets::Form, widgets::FormResult, widgets::Modal,
    widgets::ModalResult, ActionList, App, ScreenImpl, StatusMsg,
};
use crate::Wallet;

pub struct WalletState {
    pub actions: ActionList,
    pub form: Option<Form>,
    pub modal: Option<Modal>,
    pub generated: Option<GeneratedInfo>,
    pub balance: Option<Value>,
    pub history: Option<Value>,
    pub error: Option<String>,
}

/// A freshly generated wallet waiting for the user to save it.
pub struct GeneratedInfo {
    pub mnemonic: String,
    pub address_kvnc: String,
    pub address_hex: String,
    pub key_path: String,
}

impl WalletState {
    pub fn new() -> Self {
        Self {
            actions: ActionList::new(vec![
                "New wallet (BIP39)".to_string(),
                "Import wallet".to_string(),
                "Show address".to_string(),
                "Refresh balance".to_string(),
                "Transaction history".to_string(),
                "Backup mnemonic".to_string(),
                "Reload key file".to_string(),
            ]),
            form: None,
            modal: None,
            generated: None,
            balance: None,
            history: None,
            error: None,
        }
    }

    fn run_action(&mut self, app: &mut App, label: &str) {
        match label {
            "New wallet (BIP39)" => match Wallet::generate_with_mnemonic() {
                Ok(w) => {
                    let mnemonic = w.mnemonic().unwrap_or_default().to_string();
                    let info = GeneratedInfo {
                        mnemonic,
                        address_kvnc: w.address().to_kvnc(),
                        address_hex: w.address().to_hex(),
                        key_path: app.key_path.display().to_string(),
                    };
                    self.generated = Some(info);
                    let gen = self.generated.as_ref().unwrap();
                    self.modal = Some(
                        Modal::new("New wallet — write this down")
                            .text("Your 24-word recovery phrase is shown below.")
                            .text("Anyone with it controls the funds. It will not be shown again.")
                            .line(Line::from(vec![
                                Span::styled("address ", theme::label()),
                                Span::styled(gen.address_kvnc.clone(), theme::value_hl()),
                            ]))
                            .line(Line::from(vec![
                                Span::styled("hex     ", theme::label()),
                                Span::styled(short_hex(&gen.address_hex, 16, 16), theme::hint()),
                            ]))
                            .line(Line::from(Span::styled(
                                "⚠ keep it offline and secret",
                                Style::default().fg(theme::RED).add_modifier(Modifier::BOLD),
                            )))
                            .confirm("Save key file")
                            .cancel("Discard"),
                    );
                }
                Err(e) => {
                    app.status = StatusMsg::err(format!("keygen failed: {e}")).for_secs(6);
                }
            },
            "Import wallet" => {
                self.form = Some(
                    Form::new(
                        "Import wallet",
                        vec![widgets::Field::new("mnemonic or 64-hex seed")
                            .secret()
                            .hint("24 words, or the raw 32-byte seed as hex")
                            .max(1024)],
                    )
                    .submit("Import"),
                );
            }
            "Show address" => {
                let Some(addr) = app.address() else {
                    app.status = StatusMsg::err("no wallet loaded").for_secs(4);
                    return;
                };
                self.modal = Some(
                    Modal::new("Address")
                        .line(Line::from(vec![
                            Span::styled("kvnc  ", theme::label()),
                            Span::styled(addr.kvnc.clone(), theme::value()),
                        ]))
                        .line(Line::from(vec![
                            Span::styled("hex   ", theme::label()),
                            Span::styled(addr.hex.clone(), theme::value()),
                        ]))
                        .confirm("OK")
                        .cancel("Close"),
                );
            }
            "Refresh balance" => {
                let Some(addr) = app.address() else {
                    app.status = StatusMsg::err("no wallet loaded").for_secs(4);
                    return;
                };
                let hex = addr.hex.clone();
                app.spawn("wallet balance", {
                    let client = app.client.clone();
                    move || client.utxos(&hex).map_err(|e| e.to_string())
                });
            }
            "Transaction history" => {
                let Some(addr) = app.address() else {
                    app.status = StatusMsg::err("no wallet loaded").for_secs(4);
                    return;
                };
                let hex = addr.hex.clone();
                app.spawn("wallet history", {
                    let client = app.client.clone();
                    move || client.history(&hex, 50).map_err(|e| e.to_string())
                });
            }
            "Reload key file" => {
                app.load_wallet();
            }
            "Backup mnemonic" => {
                let Some(wallet) = &app.wallet else {
                    app.status = StatusMsg::err("no wallet loaded").for_secs(4);
                    return;
                };
                if wallet.mnemonic().is_none() {
                    app.status = StatusMsg::err("wallet has no mnemonic to back up").for_secs(5);
                    return;
                }
                let backup = app.key_path.with_extension("mnemonic");
                match wallet.save_mnemonic(&backup, false) {
                    Ok(()) => {
                        app.status = StatusMsg::ok(format!(
                            "mnemonic backed up to {} (0600)",
                            backup.display()
                        ))
                        .for_secs(5);
                    }
                    Err(_) => {
                        app.status = StatusMsg::err(format!(
                            "{} already exists — remove it first",
                            backup.display()
                        ))
                        .for_secs(6);
                    }
                }
            }
            _ => {}
        }
    }

    fn handle_form(&mut self, app: &mut App, result: FormResult) {
        match result {
            FormResult::Submit => {
                let Some(form) = &self.form else { return };
                let input = form.value(0).unwrap_or("").trim().to_string();
                self.form = None;
                if input.is_empty() {
                    app.status = StatusMsg::err("nothing to import").for_secs(4);
                    return;
                }
                let wallet = if input.split_whitespace().count() >= 12 {
                    Wallet::from_mnemonic(&input)
                } else {
                    match hex::decode(input.trim()) {
                        Ok(bytes) if bytes.len() == 32 => {
                            let mut seed = [0u8; 32];
                            seed.copy_from_slice(&bytes);
                            Ok(Wallet::from_seed(seed))
                        }
                        _ => Err(anyhow::anyhow!(
                            "expected a 24-word mnemonic or a 64-hex seed"
                        )),
                    }
                };
                match wallet {
                    Ok(w) => {
                        let addr = w.address();
                        let path = app.key_path.clone();
                        match w.save(&path, false) {
                            Ok(()) => {
                                app.wallet = Some(w);
                                app.status = StatusMsg::ok(format!(
                                    "imported {} → {}",
                                    addr.to_kvnc(),
                                    path.display()
                                ))
                                .for_secs(5);
                            }
                            Err(e) => {
                                app.status = StatusMsg::err(format!(
                                    "imported but could not save key file: {e}"
                                ))
                                .for_secs(6);
                            }
                        }
                    }
                    Err(e) => {
                        app.status = StatusMsg::err(format!("import failed: {e}")).for_secs(6);
                    }
                }
            }
            FormResult::Cancel => self.form = None,
            FormResult::Continue => {}
        }
    }

    fn handle_modal(&mut self, app: &mut App, result: ModalResult) {
        match result {
            ModalResult::Confirm => {
                if let Some(info) = &self.generated {
                    let path = std::path::PathBuf::from(&info.key_path);
                    match Wallet::from_mnemonic(&info.mnemonic) {
                        Ok(w) => match w.save(&path, false) {
                            Ok(()) => {
                                app.wallet = Some(w);
                                app.status = StatusMsg::ok(format!(
                                    "saved key file {} (0600)",
                                    path.display()
                                ))
                                .for_secs(5);
                            }
                            Err(_e) => {
                                app.status = StatusMsg::err(format!(
                                    "{} already exists — use the CLI with --force to overwrite",
                                    path.display()
                                ))
                                .for_secs(6);
                            }
                        },
                        Err(e) => {
                            app.status = StatusMsg::err(format!("keygen error: {e}")).for_secs(6);
                        }
                    }
                }
                self.modal = None;
            }
            ModalResult::Cancel => {
                self.modal = None;
            }
            ModalResult::Continue => {}
        }
    }
}

impl ScreenImpl for WalletState {
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

    fn render(&self, app: &App, f: &mut Frame, area: Rect) {
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
        widgets::render_list_panel(f, "Wallet", &items, Some(self.actions.selected), left);

        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Percentage(40), Constraint::Percentage(60)])
            .split(right);

        // Identity panel.
        let mut lines: Vec<Line> = Vec::new();
        match app.address() {
            Some(addr) => {
                lines.push(Line::from(vec![
                    Span::styled("address  ", theme::label()),
                    Span::styled(addr.kvnc.clone(), theme::value_hl()),
                ]));
                lines.push(Line::from(vec![
                    Span::styled("hex      ", theme::label()),
                    Span::styled(addr.hex.clone(), theme::hint()),
                ]));
                lines.push(Line::from(vec![
                    Span::styled("key file ", theme::label()),
                    Span::styled(app.key_path.display().to_string(), theme::hint()),
                ]));
                if let Some(bal) = &self.balance {
                    let native = bal.get("balance").and_then(|v| v.as_u64()).unwrap_or(0);
                    lines.push(Line::from(vec![
                        Span::styled("balance  ", theme::label()),
                        Span::styled(format_kvnc(native), theme::value_hl()),
                        Span::styled(" KVNC", theme::hint()),
                    ]));
                    if let Some(balances) = bal.get("balances").and_then(|v| v.as_object()) {
                        for (asset, amount) in balances.iter().take(6) {
                            if asset == "KVNC" {
                                continue;
                            }
                            lines.push(Line::from(vec![
                                Span::styled("asset    ", theme::label()),
                                Span::styled(short_hex(asset, 10, 8), theme::value()),
                                Span::styled(format!("  {amount}"), theme::value()),
                            ]));
                        }
                    }
                }
            }
            None => {
                lines.push(Line::from(Span::styled(
                    "No wallet loaded. Create a new one (BIP39) or import an existing key.",
                    theme::hint(),
                )));
            }
        }
        widgets::render_panel(f, "Identity", &Text::from(lines), chunks[0]);

        // History panel.
        let mut hist_lines: Vec<Line> = Vec::new();
        if let Some(h) = &self.history {
            if let Some(items) = h.as_array() {
                if items.is_empty() {
                    hist_lines.push(Line::from(Span::styled(
                        "no transactions yet",
                        theme::hint(),
                    )));
                }
                for item in items.iter().take(12) {
                    let kind = item.get("kind").and_then(|v| v.as_str()).unwrap_or("?");
                    let delta = item.get("delta").and_then(|v| v.as_i64()).unwrap_or(0);
                    let tx = item.get("tx").and_then(|v| v.as_str()).unwrap_or("");
                    let kind_style = match kind {
                        "coinbase" => theme::value_hl(),
                        "in" => theme::positive(),
                        "out" => theme::negative(),
                        _ => theme::hint(),
                    };
                    let delta_str = if delta > 0 {
                        format!("+{}", format_kvnc(delta as u64))
                    } else {
                        format!("-{}", format_kvnc(delta.unsigned_abs()))
                    };
                    hist_lines.push(Line::from(vec![
                        Span::styled(format!("{kind:<8}"), kind_style),
                        Span::styled(delta_str, kind_style),
                        Span::styled("  ", theme::hint()),
                        Span::styled(short_hex(tx, 8, 8), theme::hint()),
                    ]));
                }
            } else {
                hist_lines.push(Line::from(Span::styled(
                    "history unavailable",
                    theme::hint(),
                )));
            }
        } else {
            hist_lines.push(Line::from(Span::styled(
                "press ⏎ on “Transaction history” to load",
                theme::hint(),
            )));
        }
        widgets::render_panel(f, "History", &Text::from(hist_lines), chunks[1]);

        if let Some(form) = &self.form {
            widgets::render_form(f, form, area);
        }
        if let Some(modal) = &self.modal {
            widgets::render_modal(f, modal, area);
        }
    }

    fn on_result(&mut self, app: &mut App, label: &str, result: Result<Value, String>) {
        match (label, result) {
            ("wallet balance", Ok(v)) => {
                self.balance = Some(v);
                app.status = StatusMsg::ok("balance updated").for_secs(2);
            }
            ("wallet history", Ok(v)) => {
                self.history = Some(v);
                app.status = StatusMsg::ok("history updated").for_secs(2);
            }
            (_, Err(e)) => {
                self.error = Some(e.clone());
                app.status = StatusMsg::err(format!("{label}: {e}")).for_secs(6);
            }
            _ => {}
        }
    }
}

impl Default for WalletState {
    fn default() -> Self {
        Self::new()
    }
}
