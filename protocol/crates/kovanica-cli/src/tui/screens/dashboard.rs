//! Dashboard: chain head, network parameters, supply, and wallet summary.

use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Modifier, Style},
    text::{Line, Span, Text},
    Frame,
};
use serde_json::Value;

use crate::tui::{format_kvnc, short_hex, theme, widgets, ActionList, App, ScreenImpl, StatusMsg};

pub struct DashboardState {
    pub actions: ActionList,
    pub head: Option<Value>,
    pub bootstrap: Option<Value>,
    pub fee: Option<Value>,
    pub balance: Option<Value>,
    pub error: Option<String>,
}

impl DashboardState {
    pub fn new() -> Self {
        Self {
            actions: ActionList::new(vec![
                "Refresh".to_string(),
                "Fetch bootstrap".to_string(),
                "Fee estimate".to_string(),
                "Wallet balance".to_string(),
            ]),
            head: None,
            bootstrap: None,
            fee: None,
            balance: None,
            error: None,
        }
    }

    fn run_action(&mut self, app: &mut App, label: &str) {
        match label {
            "Refresh" => {
                app.spawn("fetch head", {
                    let client = app.client.clone();
                    move || client.head().map_err(|e| e.to_string())
                });
            }
            "Fetch bootstrap" => {
                app.spawn("fetch bootstrap", {
                    let client = app.client.clone();
                    move || client.bootstrap().map_err(|e| e.to_string())
                });
            }
            "Fee estimate" => {
                app.spawn("fee estimate", {
                    let client = app.client.clone();
                    move || client.fee_estimate(0).map_err(|e| e.to_string())
                });
            }
            "Wallet balance" => {
                let Some(addr) = app.address() else {
                    app.status = StatusMsg::err("no wallet loaded — create one in the Wallet tab")
                        .for_secs(5);
                    return;
                };
                let hex = addr.hex.clone();
                app.spawn("wallet balance", {
                    let client = app.client.clone();
                    move || client.utxos(&hex).map_err(|e| e.to_string())
                });
            }
            _ => {}
        }
    }
}

impl ScreenImpl for DashboardState {
    fn handle_key(&mut self, app: &mut App, key: crossterm::event::KeyEvent) {
        use crossterm::event::{KeyCode, KeyModifiers};
        match key.code {
            KeyCode::Up | KeyCode::Char('k') => self.actions.previous(),
            KeyCode::Down | KeyCode::Char('j') => self.actions.next(),
            KeyCode::Enter => {
                if let Some(label) = self.actions.selected_label().map(str::to_string) {
                    self.run_action(app, &label);
                }
            }
            KeyCode::Char('r') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                self.run_action(app, "Refresh");
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
        widgets::render_list_panel(f, "Dashboard", &items, Some(self.actions.selected), left);

        // Right side: two stacked panels (network + wallet).
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Percentage(55), Constraint::Percentage(45)])
            .split(right);

        let mut net_lines: Vec<Line> = Vec::new();
        if let Some(head) = &self.head {
            net_lines.push(Line::from(vec![
                Span::styled("network  ", theme::label()),
                Span::styled(
                    head.get("network").and_then(|v| v.as_str()).unwrap_or("?"),
                    theme::value_hl(),
                ),
            ]));
            net_lines.push(Line::from(vec![
                Span::styled("blocks   ", theme::label()),
                Span::styled(
                    head.get("blocks")
                        .and_then(|v| v.as_u64())
                        .unwrap_or(0)
                        .to_string(),
                    theme::value(),
                ),
            ]));
            net_lines.push(Line::from(vec![
                Span::styled("tip      ", theme::label()),
                Span::styled(
                    short_hex(
                        head.get("tip").and_then(|v| v.as_str()).unwrap_or(""),
                        10,
                        10,
                    ),
                    theme::value(),
                ),
            ]));
            net_lines.push(Line::from(vec![
                Span::styled("genesis  ", theme::label()),
                Span::styled(
                    short_hex(
                        head.get("genesis").and_then(|v| v.as_str()).unwrap_or(""),
                        10,
                        10,
                    ),
                    theme::hint(),
                ),
            ]));
            net_lines.push(Line::from(vec![
                Span::styled("min fee  ", theme::label()),
                Span::styled(
                    head.get("min_fee")
                        .and_then(|v| v.as_u64())
                        .unwrap_or(0)
                        .to_string(),
                    theme::value(),
                ),
                Span::styled(" atoms", theme::hint()),
            ]));
        } else if let Some(err) = &self.error {
            net_lines.push(Line::from(Span::styled(err.clone(), theme::negative())));
        } else {
            net_lines.push(Line::from(Span::styled("fetching head…", theme::hint())));
        }

        if let Some(b) = &self.bootstrap {
            net_lines.push(Line::from(""));
            net_lines.push(Line::from(vec![
                Span::styled("supply    ", theme::label()),
                Span::styled(
                    format_kvnc(b.get("circulating").and_then(|v| v.as_u64()).unwrap_or(0)),
                    theme::value_hl(),
                ),
                Span::styled(" circulating", theme::hint()),
            ]));
            net_lines.push(Line::from(vec![
                Span::styled("           ", theme::label()),
                Span::styled(
                    format_kvnc(b.get("total").and_then(|v| v.as_u64()).unwrap_or(0)),
                    theme::value(),
                ),
                Span::styled(" minted", theme::hint()),
            ]));
            net_lines.push(Line::from(vec![
                Span::styled("           ", theme::label()),
                Span::styled(
                    format_kvnc(b.get("burned").and_then(|v| v.as_u64()).unwrap_or(0)),
                    theme::negative(),
                ),
                Span::styled(" burned", theme::hint()),
            ]));
            net_lines.push(Line::from(vec![
                Span::styled("           ", theme::label()),
                Span::styled(
                    format_kvnc(b.get("max_supply").and_then(|v| v.as_u64()).unwrap_or(0)),
                    theme::value(),
                ),
                Span::styled(" max (RFC-006)", theme::hint()),
            ]));
            net_lines.push(Line::from(vec![
                Span::styled("k          ", theme::label()),
                Span::styled(
                    b.get("k").and_then(|v| v.as_u64()).unwrap_or(0).to_string(),
                    theme::value(),
                ),
                Span::styled("  subsidy ", theme::hint()),
                Span::styled(
                    format_kvnc(b.get("subsidy").and_then(|v| v.as_u64()).unwrap_or(0)),
                    Style::default()
                        .fg(theme::GOLD_DARK)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled("/block", theme::hint()),
            ]));
        }

        if let Some(fee) = &self.fee {
            net_lines.push(Line::from(""));
            net_lines.push(Line::from(vec![
                Span::styled("fee est   ", theme::label()),
                Span::styled("slow ", theme::hint()),
                Span::styled(
                    fee.get("slow")
                        .and_then(|v| v.as_u64())
                        .unwrap_or(0)
                        .to_string(),
                    theme::value(),
                ),
                Span::styled("  normal ", theme::hint()),
                Span::styled(
                    fee.get("normal")
                        .and_then(|v| v.as_u64())
                        .unwrap_or(0)
                        .to_string(),
                    theme::value_hl(),
                ),
                Span::styled("  fast ", theme::hint()),
                Span::styled(
                    fee.get("fast")
                        .and_then(|v| v.as_u64())
                        .unwrap_or(0)
                        .to_string(),
                    theme::value(),
                ),
            ]));
        }

        widgets::render_panel(f, "Network", &Text::from(net_lines), chunks[0]);

        // Wallet summary panel.
        let mut wallet_lines: Vec<Line> = Vec::new();
        match app.address() {
            Some(addr) => {
                wallet_lines.push(Line::from(vec![
                    Span::styled("address  ", theme::label()),
                    Span::styled(short_hex(&addr.kvnc, 14, 8), theme::value()),
                ]));
                if let Some(bal) = &self.balance {
                    let native = bal.get("balance").and_then(|v| v.as_u64()).unwrap_or(0);
                    wallet_lines.push(Line::from(vec![
                        Span::styled("balance  ", theme::label()),
                        Span::styled(format_kvnc(native), theme::value_hl()),
                        Span::styled(" KVNC", theme::hint()),
                    ]));
                    if let Some(balances) = bal.get("balances").and_then(|v| v.as_object()) {
                        for (asset, amount) in balances.iter().take(4) {
                            if asset == "KVNC" {
                                continue;
                            }
                            wallet_lines.push(Line::from(vec![
                                Span::styled("asset    ", theme::label()),
                                Span::styled(short_hex(asset, 8, 6), theme::value()),
                                Span::styled(format!("  {amount}"), theme::value()),
                            ]));
                        }
                    }
                } else {
                    wallet_lines.push(Line::from(Span::styled(
                        "press ⏎ on “Wallet balance” to load",
                        theme::hint(),
                    )));
                }
            }
            None => {
                wallet_lines.push(Line::from(Span::styled(
                    "no wallet loaded — create or import one in the Wallet tab",
                    theme::hint(),
                )));
            }
        }
        widgets::render_panel(f, "Wallet", &Text::from(wallet_lines), chunks[1]);
    }

    fn on_result(&mut self, app: &mut App, label: &str, result: Result<Value, String>) {
        match (label, result) {
            ("fetch head", Ok(v)) => {
                self.head = Some(v.clone());
                if let Some(net) = v.get("network").and_then(|n| n.as_str()) {
                    app.network = net.to_string();
                }
                app.status = StatusMsg::ok("head updated").for_secs(2);
            }
            ("fetch bootstrap", Ok(v)) => {
                self.bootstrap = Some(v);
                app.status = StatusMsg::ok("bootstrap updated").for_secs(2);
            }
            ("fee estimate", Ok(v)) => {
                self.fee = Some(v);
                app.status = StatusMsg::ok("fee estimate updated").for_secs(2);
            }
            ("wallet balance", Ok(v)) => {
                self.balance = Some(v);
                app.status = StatusMsg::ok("balance updated").for_secs(2);
            }
            (_, Err(e)) => {
                self.error = Some(e.clone());
                app.status = StatusMsg::err(format!("{label}: {e}")).for_secs(6);
            }
            _ => {}
        }
    }
}

impl Default for DashboardState {
    fn default() -> Self {
        Self::new()
    }
}
