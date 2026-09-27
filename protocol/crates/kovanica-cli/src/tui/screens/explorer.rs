//! Explorer: network head, bootstrap info, P2P peers, and block/tx/address
//! detail lookups against the connected node.

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

pub struct ExplorerState {
    pub actions: ActionList,
    pub form: Option<Form>,
    pub detail: Option<Value>,
    pub error: Option<String>,
}

impl ExplorerState {
    pub fn new() -> Self {
        Self {
            actions: ActionList::new(vec![
                "Network head".to_string(),
                "Bootstrap info".to_string(),
                "P2P peers".to_string(),
                "Block detail".to_string(),
                "Tx detail".to_string(),
                "Address detail".to_string(),
            ]),
            form: None,
            detail: None,
            error: None,
        }
    }

    fn run_action(&mut self, app: &mut App, label: &str) {
        match label {
            "Network head" => {
                app.spawn("head", {
                    let client = app.client.clone();
                    move || client.head().map_err(|e| e.to_string())
                });
            }
            "Bootstrap info" => {
                app.spawn("bootstrap", {
                    let client = app.client.clone();
                    move || client.bootstrap().map_err(|e| e.to_string())
                });
            }
            "P2P peers" => {
                app.spawn("p2p", {
                    let client = app.client.clone();
                    move || client.p2p().map_err(|e| e.to_string())
                });
            }
            "Block detail" => {
                self.form = Some(
                    Form::new(
                        "Block detail",
                        vec![Field::new("block id (64-hex)").hint("or 'tip' for the selected tip")],
                    )
                    .submit("Fetch"),
                );
            }
            "Tx detail" => {
                self.form = Some(
                    Form::new(
                        "Tx detail",
                        vec![Field::new("tx id (64-hex)").hint("transaction id")],
                    )
                    .submit("Fetch"),
                );
            }
            "Address detail" => {
                self.form = Some(
                    Form::new(
                        "Address detail",
                        vec![Field::new("address (kvnc…dag or hex)").hint("any address")],
                    )
                    .submit("Fetch"),
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
                let input = form.value(0).unwrap_or("").trim().to_string();
                match action.as_str() {
                    "Block detail" => {
                        app.spawn("block detail", {
                            let client = app.client.clone();
                            move || client.block_detail(&input).map_err(|e| e.to_string())
                        });
                    }
                    "Tx detail" => {
                        app.spawn("tx detail", {
                            let client = app.client.clone();
                            move || client.tx_detail(&input).map_err(|e| e.to_string())
                        });
                    }
                    "Address detail" => {
                        app.spawn("address detail", {
                            let client = app.client.clone();
                            move || client.address_detail(&input).map_err(|e| e.to_string())
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

impl ScreenImpl for ExplorerState {
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
        widgets::render_list_panel(f, "Explorer", &items, Some(self.actions.selected), left);

        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Percentage(60), Constraint::Percentage(40)])
            .split(right);

        let mut lines: Vec<Line> = Vec::new();
        if let Some(d) = &self.detail {
            render_value(&mut lines, d, 0);
        } else {
            lines.push(Line::from(Span::styled(
                "Query the connected node: head, bootstrap, peers, blocks,",
                theme::hint(),
            )));
            lines.push(Line::from(Span::styled(
                "transactions and addresses. All read-only.",
                theme::hint(),
            )));
        }
        widgets::render_panel(f, "Detail", &Text::from(lines), chunks[0]);

        let mut net_lines: Vec<Line> = Vec::new();
        let net = self
            .detail
            .as_ref()
            .filter(|d| d.get("tip").is_some() && d.get("blocks").is_some());
        if let Some(net) = net {
            net_lines.push(Line::from(vec![
                Span::styled("network ", theme::label()),
                Span::styled(
                    net.get("network").and_then(|v| v.as_str()).unwrap_or("?"),
                    theme::value_hl(),
                ),
            ]));
            net_lines.push(Line::from(vec![
                Span::styled("tip     ", theme::label()),
                Span::styled(
                    short_hex(
                        net.get("tip").and_then(|v| v.as_str()).unwrap_or(""),
                        12,
                        12,
                    ),
                    theme::value(),
                ),
            ]));
            net_lines.push(Line::from(vec![
                Span::styled("blocks  ", theme::label()),
                Span::styled(
                    net.get("blocks").map(|v| v.to_string()).unwrap_or_default(),
                    theme::value(),
                ),
            ]));
            net_lines.push(Line::from(vec![
                Span::styled("min_fee ", theme::label()),
                Span::styled(
                    net.get("min_fee")
                        .map(|v| v.to_string())
                        .unwrap_or_default(),
                    theme::value(),
                ),
                Span::styled(" atoms/byte", theme::hint()),
            ]));
        } else {
            net_lines.push(Line::from(Span::styled(
                "press ⏎ on “Network head” to load",
                theme::hint(),
            )));
        }
        widgets::render_panel(f, "Network", &Text::from(net_lines), chunks[1]);

        if let Some(form) = &self.form {
            widgets::render_form(f, form, area);
        }
    }

    fn on_result(&mut self, app: &mut App, label: &str, result: Result<Value, String>) {
        match (label, result) {
            ("head", Ok(v)) => {
                app.network = v
                    .get("network")
                    .and_then(|x| x.as_str())
                    .unwrap_or("")
                    .to_string();
                self.detail = Some(v);
                app.status = StatusMsg::ok("head updated").for_secs(2);
            }
            ("bootstrap", Ok(v))
            | ("p2p", Ok(v))
            | ("block detail", Ok(v))
            | ("tx detail", Ok(v))
            | ("address detail", Ok(v)) => {
                self.detail = Some(v);
                app.status = StatusMsg::ok("loaded").for_secs(2);
            }
            (_, Err(e)) => {
                self.error = Some(e.clone());
                app.status = StatusMsg::err(format!("{label}: {e}")).for_secs(6);
            }
            _ => {}
        }
    }
}

/// Render a JSON value as key/value lines (2-level nesting max).
fn render_value(lines: &mut Vec<Line>, v: &Value, depth: usize) {
    match v {
        Value::Object(map) => {
            for (k, val) in map {
                match val {
                    Value::Object(_) | Value::Array(_) => {
                        lines.push(Line::from(vec![Span::styled(
                            format!("{}{}  ", " ".repeat(depth * 2), k),
                            theme::label(),
                        )]));
                        render_value(lines, val, depth + 1);
                    }
                    Value::String(s) => {
                        let style = if k == "tx" || k == "tx_id" || k == "block" || k == "id" {
                            theme::value_hl()
                        } else {
                            theme::value()
                        };
                        lines.push(Line::from(vec![
                            Span::styled(
                                format!("{}{:<14}", " ".repeat(depth * 2), k),
                                theme::label(),
                            ),
                            Span::styled(short_hex(s, 20, 20), style),
                        ]));
                    }
                    other => {
                        lines.push(Line::from(vec![
                            Span::styled(
                                format!("{}{:<14}", " ".repeat(depth * 2), k),
                                theme::label(),
                            ),
                            Span::styled(other.to_string(), theme::value()),
                        ]));
                    }
                }
            }
        }
        Value::Array(arr) => {
            for (i, item) in arr.iter().enumerate().take(20) {
                lines.push(Line::from(vec![Span::styled(
                    format!("{}[{i}]", " ".repeat(depth * 2)),
                    theme::label(),
                )]));
                render_value(lines, item, depth + 1);
            }
            if arr.len() > 20 {
                lines.push(Line::from(Span::styled(
                    format!("… {} more", arr.len() - 20),
                    theme::hint(),
                )));
            }
        }
        other => {
            lines.push(Line::from(Span::styled(other.to_string(), theme::value())));
        }
    }
}

impl Default for ExplorerState {
    fn default() -> Self {
        Self::new()
    }
}
