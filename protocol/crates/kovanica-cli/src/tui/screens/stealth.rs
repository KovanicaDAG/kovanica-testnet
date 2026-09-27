//! Stealth (RFC-003): generate a stealth address from the wallet seed, send
//! unlinkable payments with a random ephemeral key, and scan received outputs.
//!
//! The stealth send is built fully client-side: the sender derives the
//! one-time output key (`StealthExt`) with a random `r`, signs locally, and
//! broadcasts via `/api/submit_tx` — the node never sees the ephemeral secret.

use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Modifier, Style},
    text::{Line, Span, Text},
    Frame,
};
use serde_json::Value;

use kovanica_state::{Address, OutPoint, StealthAddress, Transaction, TxOutput};

use crate::tui::{
    format_kvnc, short_hex, theme, widgets, widgets::Field, widgets::Form, widgets::FormResult,
    widgets::Modal, ActionList, App, ScreenImpl, StatusMsg,
};

pub struct StealthState {
    pub actions: ActionList,
    pub form: Option<Form>,
    pub modal: Option<Modal>,
    pub stealth: Option<StealthInfo>,
    pub scan: Option<Value>,
    pub result: Option<String>,
    pub error: Option<String>,
}

pub struct StealthInfo {
    pub published_hex: String,
    pub published_kvnc: String,
    pub owner_kvnc: String,
    pub owner_hex: String,
}

impl StealthState {
    pub fn new() -> Self {
        Self {
            actions: ActionList::new(vec![
                "Generate stealth address".to_string(),
                "Send to stealth".to_string(),
                "Scan stealth outputs".to_string(),
            ]),
            form: None,
            modal: None,
            stealth: None,
            scan: None,
            result: None,
            error: None,
        }
    }

    /// Derive scan/spend keypairs from the wallet seed (BLAKE3 domain-separated).
    fn derive_stealth(wallet: &crate::Wallet) -> StealthAddress {
        let seed = wallet.seed();
        let scan_seed: [u8; 32] =
            *blake3::hash(&[seed.as_slice(), b"kovanica-scan"].concat()).as_bytes();
        let spend_seed: [u8; 32] =
            *blake3::hash(&[seed.as_slice(), b"kovanica-spend"].concat()).as_bytes();
        let scan_kp = kovanica_state::KeyPair::from_seed(scan_seed);
        let spend_kp = kovanica_state::KeyPair::from_seed(spend_seed);
        StealthAddress::new(*scan_kp.address().payload(), *spend_kp.address().payload())
    }

    fn run_action(&mut self, app: &mut App, label: &str) {
        match label {
            "Generate stealth address" => {
                let Some(wallet) = &app.wallet else {
                    app.status = StatusMsg::err("no wallet loaded").for_secs(4);
                    return;
                };
                let stealth = Self::derive_stealth(wallet);
                let info = StealthInfo {
                    published_hex: stealth.to_hex(),
                    published_kvnc: stealth.to_kvnc(),
                    owner_kvnc: stealth.address().to_kvnc(),
                    owner_hex: stealth.address().to_hex(),
                };
                self.stealth = Some(info);
                app.status = StatusMsg::ok("stealth address generated").for_secs(3);
            }
            "Send to stealth" => {
                if app.wallet.is_none() {
                    app.status = StatusMsg::err("no wallet loaded").for_secs(4);
                    return;
                }
                self.form = Some(
                    Form::new(
                        "Send to stealth",
                        vec![
                            Field::new("stealth address (130-hex or kvnc…dag)")
                                .hint("recipient's published address"),
                            Field::new("amount (KVNC)").hint("e.g. 0.25 = 25000000 atoms"),
                        ],
                    )
                    .submit("Prepare"),
                );
            }
            "Scan stealth outputs" => {
                let Some(info) = &self.stealth else {
                    app.status = StatusMsg::err("generate a stealth address first").for_secs(4);
                    return;
                };
                let owner_hex = info.owner_hex.clone();
                app.spawn("stealth scan", {
                    let client = app.client.clone();
                    move || client.utxos(&owner_hex).map_err(|e| e.to_string())
                });
            }
            _ => {}
        }
    }

    fn handle_form(&mut self, app: &mut App, result: FormResult) {
        match result {
            FormResult::Submit => {
                let Some(form) = self.form.take() else { return };
                let stealth = match StealthAddress::parse(form.value(0).unwrap_or("")) {
                    Ok(s) => s,
                    Err(e) => {
                        app.status =
                            StatusMsg::err(format!("invalid stealth address: {e}")).for_secs(5);
                        return;
                    }
                };
                let amount = match parse_kvnc(form.value(1).unwrap_or("")) {
                    Ok(a) if a > 0 => a,
                    _ => {
                        app.status = StatusMsg::err("amount must be > 0").for_secs(4);
                        return;
                    }
                };
                let Some(wallet) = &app.wallet else { return };
                let kp = wallet.keypair();
                let from_hex = kp.address().to_hex();
                let owner = stealth.address();
                let owner_hex = owner.to_hex();
                let stealth_bytes = stealth.to_bytes();
                app.spawn("stealth send", {
                    let client = app.client.clone();
                    move || {
                        let head = client.head().map_err(|e| e.to_string())?;
                        let fee = head.get("min_fee").and_then(|v| v.as_u64()).unwrap_or(1);
                        let need = amount.checked_add(fee).ok_or("amount + fee overflow")?;
                        let utxos = client.utxos(&from_hex).map_err(|e| e.to_string())?;
                        let mut owned: Vec<(OutPoint, u64)> = Vec::new();
                        if let Some(arr) = utxos.as_array() {
                            for u in arr {
                                let tx = u.get("tx").and_then(|v| v.as_str()).unwrap_or("");
                                let index = u.get("index").and_then(|v| v.as_u64()).unwrap_or(0);
                                let value = u.get("value").and_then(|v| v.as_u64()).unwrap_or(0);
                                let asset =
                                    u.get("asset_id").and_then(|v| v.as_str()).unwrap_or("KVNC");
                                if asset != "KVNC" {
                                    continue;
                                }
                                let tx_bytes =
                                    hex::decode(tx).map_err(|e| format!("bad utxo tx hex: {e}"))?;
                                let tx_id = <[u8; 32]>::try_from(tx_bytes.as_slice())
                                    .map_err(|_| "utxo tx id must be 32 bytes")?;
                                owned.push((
                                    OutPoint::new(
                                        kovanica_state::TxId::from_bytes(tx_id),
                                        index as u32,
                                    ),
                                    value,
                                ));
                            }
                        }
                        owned.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
                        let mut selected: Vec<(OutPoint, u64)> = Vec::new();
                        let mut total: u64 = 0;
                        for (op, value) in owned {
                            selected.push((op, value));
                            total = total.saturating_add(value);
                            if total >= need {
                                break;
                            }
                        }
                        if total < need {
                            return Err(format!(
                                "insufficient funds: have {}, need {}",
                                format_kvnc(total),
                                format_kvnc(need)
                            ));
                        }
                        // Random ephemeral secret for unlinkability.
                        let mut r_secret = [0u8; 32];
                        getrandom::getrandom(&mut r_secret)
                            .map_err(|e| format!("rng failure: {e}"))?;
                        let stealth = StealthAddress::from_slice(&stealth_bytes)
                            .map_err(|e| e.to_string())?;
                        let ext = stealth
                            .derive_output(&r_secret)
                            .map_err(|e| e.to_string())?;
                        let owner = Address::parse(&owner_hex).map_err(|e| e.to_string())?;
                        let mut outputs = vec![TxOutput::stealth(amount, owner, ext)];
                        let change = total - need;
                        if change > 0 {
                            let from = Address::parse(&from_hex).map_err(|e| e.to_string())?;
                            outputs.push(TxOutput::native(change, from));
                        }
                        let outpoints: Vec<OutPoint> = selected.iter().map(|(op, _)| *op).collect();
                        let mut tx = Transaction::unsigned(&outpoints, outputs, Vec::new());
                        let sighash = tx.sighash();
                        let sig = kp.sign(&sighash);
                        for i in 0..tx.inputs().len() {
                            tx.attach_signature(i, kovanica_state::Sig::from_bytes(sig));
                        }
                        client
                            .submit_tx(&hex::encode(tx.encode()))
                            .map_err(|e| e.to_string())
                    }
                });
            }
            FormResult::Cancel => self.form = None,
            FormResult::Continue => {}
        }
    }
}

impl ScreenImpl for StealthState {
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
        widgets::render_list_panel(f, "Stealth", &items, Some(self.actions.selected), left);

        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Percentage(55), Constraint::Percentage(45)])
            .split(right);

        let mut lines: Vec<Line> = Vec::new();
        if let Some(info) = &self.stealth {
            lines.push(Line::from(vec![
                Span::styled("published ", theme::label()),
                Span::styled(
                    short_hex(&info.published_hex, 20, 20),
                    Style::default()
                        .fg(theme::TEAL)
                        .add_modifier(Modifier::BOLD),
                ),
            ]));
            lines.push(Line::from(vec![
                Span::styled("          ", theme::label()),
                Span::styled(&info.published_kvnc, theme::hint()),
            ]));
            lines.push(Line::from(vec![
                Span::styled("on-chain  ", theme::label()),
                Span::styled(
                    &info.owner_kvnc,
                    Style::default()
                        .fg(theme::TEAL_DARK)
                        .add_modifier(Modifier::BOLD),
                ),
            ]));
            lines.push(Line::from(vec![
                Span::styled("          ", theme::label()),
                Span::styled(&info.owner_hex, theme::hint()),
            ]));
            lines.push(Line::from(""));
            lines.push(Line::from(Span::styled(
                "Share the published address. Senders derive a fresh one-time",
                theme::hint(),
            )));
            lines.push(Line::from(Span::styled(
                "key per payment — outputs are unlinkable on-chain.",
                theme::hint(),
            )));
        } else {
            lines.push(Line::from(Span::styled(
                "Generate a stealth address from your wallet seed (RFC-003).",
                theme::hint(),
            )));
            lines.push(Line::from(Span::styled(
                "scan/spend keys are BLAKE3-derived from your seed — no extra",
                theme::hint(),
            )));
            lines.push(Line::from(Span::styled(
                "key file needed. The on-chain owner is a 33-byte hash.",
                theme::hint(),
            )));
        }
        widgets::render_panel(f, "Stealth address", &Text::from(lines), chunks[0]);

        let mut scan_lines: Vec<Line> = Vec::new();
        if let Some(s) = &self.scan {
            if let Some(arr) = s.as_array() {
                if arr.is_empty() {
                    scan_lines.push(Line::from(Span::styled(
                        "no outputs received yet",
                        theme::hint(),
                    )));
                }
                for u in arr.iter().take(10) {
                    let tx = u.get("tx").and_then(|v| v.as_str()).unwrap_or("");
                    let value = u.get("value").and_then(|v| v.as_u64()).unwrap_or(0);
                    let view_tag = u.get("view_tag").and_then(|v| v.as_u64()).unwrap_or(0);
                    scan_lines.push(Line::from(vec![
                        Span::styled(format_kvnc(value), theme::value_hl()),
                        Span::styled("  ", theme::hint()),
                        Span::styled(short_hex(tx, 8, 8), theme::hint()),
                        Span::styled(format!("  vt={view_tag:02x}"), theme::hint()),
                    ]));
                }
            } else {
                scan_lines.push(Line::from(Span::styled("no scan data", theme::hint())));
            }
        } else {
            scan_lines.push(Line::from(Span::styled(
                "press ⏎ on “Scan stealth outputs” to list received payments",
                theme::hint(),
            )));
        }
        widgets::render_panel(f, "Received outputs", &Text::from(scan_lines), chunks[1]);

        if let Some(form) = &self.form {
            widgets::render_form(f, form, area);
        }
        if let Some(modal) = &self.modal {
            widgets::render_modal(f, modal, area);
        }
    }

    fn on_result(&mut self, app: &mut App, label: &str, result: Result<Value, String>) {
        match (label, result) {
            ("stealth send", Ok(v)) => {
                let tx = v
                    .get("tx")
                    .and_then(|t| t.as_str())
                    .unwrap_or("")
                    .to_string();
                self.result = Some(tx.clone());
                app.status = StatusMsg::ok(format!(
                    "stealth payment broadcast ✓ {}",
                    short_hex(&tx, 10, 10)
                ))
                .for_secs(6);
            }
            ("stealth scan", Ok(v)) => {
                self.scan = Some(v);
                app.status = StatusMsg::ok("scan updated").for_secs(2);
            }
            (_, Err(e)) => {
                self.error = Some(e.clone());
                app.status = StatusMsg::err(format!("{label}: {e}")).for_secs(6);
            }
            _ => {}
        }
    }
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

impl Default for StealthState {
    fn default() -> Self {
        Self::new()
    }
}
