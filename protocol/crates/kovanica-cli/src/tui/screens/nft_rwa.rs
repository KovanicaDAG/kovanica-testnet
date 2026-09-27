//! NFT (KVP-106 / RFC-007 draft) and RWA (KVP-106): inspect registry entries,
//! derive RWA asset ids, and transfer assets.

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

pub struct NftRwaState {
    pub actions: ActionList,
    pub form: Option<Form>,
    pub detail: Option<Value>,
    pub result: Option<String>,
    pub error: Option<String>,
}

impl NftRwaState {
    pub fn new() -> Self {
        Self {
            actions: ActionList::new(vec![
                "NFT detail".to_string(),
                "Collection detail".to_string(),
                "RWA — derive asset id".to_string(),
                "RWA detail".to_string(),
                "Issue / transfer RWA".to_string(),
            ]),
            form: None,
            detail: None,
            result: None,
            error: None,
        }
    }

    fn run_action(&mut self, app: &mut App, label: &str) {
        match label {
            "NFT detail" => {
                self.form = Some(
                    Form::new(
                        "NFT detail",
                        vec![Field::new("asset_id (64-hex)").hint("NFT asset id")],
                    )
                    .submit("Fetch"),
                );
            }
            "Collection detail" => {
                self.form = Some(
                    Form::new(
                        "Collection detail",
                        vec![Field::new("collection_id (64-hex)").hint("collection id")],
                    )
                    .submit("Fetch"),
                );
            }
            "RWA — derive asset id" => {
                self.form = Some(
                    Form::new(
                        "Derive RWA asset id",
                        vec![
                            Field::new("issuer public key (64-hex)").hint("32-byte Ed25519 pubkey"),
                            Field::new("asset class").hint("e.g. RE, BOND, INVOICE"),
                            Field::new("unique id").hint("issuer-defined identifier"),
                            Field::new("version").with_value("1"),
                        ],
                    )
                    .submit("Derive"),
                );
            }
            "RWA detail" => {
                self.form = Some(
                    Form::new(
                        "RWA detail",
                        vec![Field::new("asset_id (64-hex)").hint("RWA asset id")],
                    )
                    .submit("Fetch"),
                );
            }
            "Issue / transfer RWA" => {
                if app.wallet.is_none() {
                    app.status = StatusMsg::err("no wallet loaded").for_secs(4);
                    return;
                }
                self.form = Some(
                    Form::new(
                        "Issue / transfer RWA",
                        vec![
                            Field::new("asset_id (64-hex)").hint("derived RWA asset id"),
                            Field::new("amount (atoms)").hint("integer atom count"),
                            Field::new("to (kvnc…dag or hex)").hint("recipient address"),
                        ],
                    )
                    .submit("Prepare"),
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
                    "NFT detail" => {
                        let id = form.value(0).unwrap_or("").trim().to_string();
                        app.spawn("nft detail", {
                            let client = app.client.clone();
                            move || client.nft_detail(&id).map_err(|e| e.to_string())
                        });
                    }
                    "Collection detail" => {
                        let id = form.value(0).unwrap_or("").trim().to_string();
                        app.spawn("collection detail", {
                            let client = app.client.clone();
                            move || client.collection_detail(&id).map_err(|e| e.to_string())
                        });
                    }
                    "RWA — derive asset id" => {
                        let issuer = form.value(0).unwrap_or("").trim().to_string();
                        let class = form.value(1).unwrap_or("").trim().to_string();
                        let id = form.value(2).unwrap_or("").trim().to_string();
                        let version: u8 = form.value(3).unwrap_or("1").trim().parse().unwrap_or(1);
                        app.spawn("rwa derive", {
                            let client = app.client.clone();
                            move || {
                                client
                                    .rwa_derive(&issuer, &class, &id, version)
                                    .map_err(|e| e.to_string())
                            }
                        });
                    }
                    "RWA detail" => {
                        let id = form.value(0).unwrap_or("").trim().to_string();
                        app.spawn("rwa detail", {
                            let client = app.client.clone();
                            move || client.rwa_detail(&id).map_err(|e| e.to_string())
                        });
                    }
                    "Issue / transfer RWA" => {
                        let asset_id = form.value(0).unwrap_or("").trim().to_string();
                        let amount: u64 = match form.value(1).unwrap_or("").trim().parse() {
                            Ok(a) if a > 0 => a,
                            _ => {
                                app.status =
                                    StatusMsg::err("amount must be a positive integer").for_secs(4);
                                return;
                            }
                        };
                        let to = match crate::api::parse_address(form.value(2).unwrap_or("")) {
                            Ok(a) => a,
                            Err(e) => {
                                app.status =
                                    StatusMsg::err(format!("invalid address: {e}")).for_secs(5);
                                return;
                            }
                        };
                        let Some(wallet) = &app.wallet else { return };
                        let from = wallet.address().to_hex();
                        let to_hex = to.to_hex();
                        let asset = asset_id.clone();
                        app.spawn("prepare rwa transfer", {
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

impl ScreenImpl for NftRwaState {
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
        widgets::render_list_panel(f, "NFT / RWA", &items, Some(self.actions.selected), left);

        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Percentage(60), Constraint::Percentage(40)])
            .split(right);

        let mut lines: Vec<Line> = Vec::new();
        if let Some(d) = &self.detail {
            let kind = d.get("kind").and_then(|v| v.as_str()).unwrap_or("?");
            lines.push(Line::from(vec![
                Span::styled("kind       ", theme::label()),
                Span::styled(kind.to_uppercase(), theme::value_hl()),
            ]));
            lines.push(Line::from(vec![
                Span::styled("asset_id   ", theme::label()),
                Span::styled(
                    d.get("asset_id").and_then(|v| v.as_str()).unwrap_or(""),
                    theme::value(),
                ),
            ]));
            if let Some(v) = d.get("max_supply") {
                lines.push(Line::from(vec![
                    Span::styled("max_supply ", theme::label()),
                    Span::styled(v.to_string(), theme::value()),
                ]));
            }
            if let Some(v) = d.get("minted") {
                lines.push(Line::from(vec![
                    Span::styled("minted     ", theme::label()),
                    Span::styled(v.to_string(), theme::value()),
                ]));
            }
            if let Some(v) = d.get("owner").and_then(|v| v.as_str()) {
                lines.push(Line::from(vec![
                    Span::styled("owner      ", theme::label()),
                    Span::styled(v, theme::value_hl()),
                ]));
            }
            if let Some(v) = d.get("metadata_hash").and_then(|v| v.as_str()) {
                lines.push(Line::from(vec![
                    Span::styled("metadata   ", theme::label()),
                    Span::styled(short_hex(v, 12, 12), theme::hint()),
                ]));
            }
            if let Some(v) = d.get("collection_id").and_then(|v| v.as_str()) {
                lines.push(Line::from(vec![
                    Span::styled("collection ", theme::label()),
                    Span::styled(short_hex(v, 12, 12), theme::hint()),
                ]));
            }
            if let Some(v) = d.get("creator").and_then(|v| v.as_str()) {
                lines.push(Line::from(vec![
                    Span::styled("creator    ", theme::label()),
                    Span::styled(short_hex(v, 12, 12), theme::hint()),
                ]));
            }
            if let Some(v) = d.get("name").and_then(|v| v.as_str()) {
                lines.push(Line::from(vec![
                    Span::styled("name       ", theme::label()),
                    Span::styled(v, theme::value()),
                ]));
            }
        } else {
            lines.push(Line::from(Span::styled(
                "KVP-106: NFTs are non-fungible (amount = 1, no splits);",
                theme::hint(),
            )));
            lines.push(Line::from(Span::styled(
                "RWAs are fungible assets with a registry entry (issuer, class,",
                theme::hint(),
            )));
            lines.push(Line::from(Span::styled(
                "metadata hash, collection). Derive RWA ids deterministically.",
                theme::hint(),
            )));
        }
        widgets::render_panel(f, "Detail", &Text::from(lines), chunks[0]);

        let mut res_lines: Vec<Line> = Vec::new();
        if let Some(tx) = &self.result {
            res_lines.push(Line::from(vec![
                Span::styled("tx      ", theme::label()),
                Span::styled(tx.clone(), theme::value_hl()),
            ]));
        } else if let Some(err) = &self.error {
            res_lines.push(Line::from(Span::styled(err.clone(), theme::negative())));
        } else {
            res_lines.push(Line::from(Span::styled("no transfer yet", theme::hint())));
        }
        widgets::render_panel(f, "Result", &Text::from(res_lines), chunks[1]);

        if let Some(form) = &self.form {
            widgets::render_form(f, form, area);
        }
    }

    fn on_result(&mut self, app: &mut App, label: &str, result: Result<Value, String>) {
        match (label, result) {
            ("nft detail", Ok(v)) | ("collection detail", Ok(v)) | ("rwa detail", Ok(v)) => {
                self.detail = Some(v);
                app.status = StatusMsg::ok("detail loaded").for_secs(2);
            }
            ("rwa derive", Ok(v)) => {
                self.detail = Some(v.clone());
                let id = v.get("asset_id").and_then(|x| x.as_str()).unwrap_or("");
                app.status = StatusMsg::ok(format!("derived asset id {}", short_hex(id, 12, 12)))
                    .for_secs(5);
            }
            ("prepare rwa transfer", Ok(v)) => {
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
                app.spawn("submit rwa transfer", {
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
            ("submit rwa transfer", Ok(v)) => {
                let tx = v
                    .get("tx")
                    .and_then(|t| t.as_str())
                    .unwrap_or("")
                    .to_string();
                self.result = Some(tx.clone());
                app.status = StatusMsg::ok(format!(
                    "RWA transfer broadcast ✓ {}",
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

impl Default for NftRwaState {
    fn default() -> Self {
        Self::new()
    }
}
