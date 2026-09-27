//! Settings: API endpoint, key file path, network identity, and about.

use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    text::{Line, Span, Text},
    Frame,
};
use serde_json::Value;

use crate::tui::{
    theme, widgets, widgets::Field, widgets::Form, widgets::FormResult, ActionList, App,
    ScreenImpl, StatusMsg,
};

pub struct SettingsState {
    pub actions: ActionList,
    pub form: Option<Form>,
    pub about: bool,
}

impl SettingsState {
    pub fn new() -> Self {
        Self {
            actions: ActionList::new(vec![
                "Set API URL".to_string(),
                "Set key file path".to_string(),
                "Refresh network info".to_string(),
                "About".to_string(),
            ]),
            form: None,
            about: false,
        }
    }

    fn run_action(&mut self, app: &mut App, label: &str) {
        match label {
            "Set API URL" => {
                self.form = Some(
                    Form::new(
                        "Set API URL",
                        vec![Field::new("base URL")
                            .with_value(&app.api_url)
                            .hint("e.g. https://explorer.kovanica.online")],
                    )
                    .submit("Save"),
                );
            }
            "Set key file path" => {
                self.form = Some(
                    Form::new(
                        "Set key file path",
                        vec![Field::new("path")
                            .with_value(app.key_path.display().to_string())
                            .hint("absolute or relative path")],
                    )
                    .submit("Save"),
                );
            }
            "Refresh network info" => {
                app.spawn("head", {
                    let client = app.client.clone();
                    move || client.head().map_err(|e| e.to_string())
                });
            }
            "About" => {
                self.about = !self.about;
            }
            _ => {}
        }
    }

    fn handle_form(&mut self, app: &mut App, result: FormResult) {
        match result {
            FormResult::Submit => {
                let Some(form) = self.form.take() else { return };
                let action = self.actions.selected_label().unwrap_or("").to_string();
                let value = form.value(0).unwrap_or("").trim().to_string();
                match action.as_str() {
                    "Set API URL" => {
                        if value.is_empty() {
                            app.status = StatusMsg::err("URL cannot be empty").for_secs(4);
                            return;
                        }
                        app.api_url = value.clone();
                        app.client = crate::api::Client::new(&value);
                        app.status = StatusMsg::ok(format!("api → {value}")).for_secs(4);
                    }
                    "Set key file path" => {
                        if value.is_empty() {
                            app.status = StatusMsg::err("path cannot be empty").for_secs(4);
                            return;
                        }
                        app.key_path = std::path::PathBuf::from(&value);
                        app.load_wallet();
                        app.status = StatusMsg::ok(format!("key file → {value}")).for_secs(4);
                    }
                    _ => {}
                }
            }
            FormResult::Cancel => self.form = None,
            FormResult::Continue => {}
        }
    }
}

impl ScreenImpl for SettingsState {
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
            KeyCode::Esc => self.about = false,
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
        widgets::render_list_panel(f, "Settings", &items, Some(self.actions.selected), left);

        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
            .split(right);

        let mut lines: Vec<Line> = Vec::new();
        lines.push(Line::from(vec![
            Span::styled("api url   ", theme::label()),
            Span::styled(app.api_url.clone(), theme::link()),
        ]));
        lines.push(Line::from(vec![
            Span::styled("key file  ", theme::label()),
            Span::styled(app.key_path.display().to_string(), theme::value()),
        ]));
        lines.push(Line::from(vec![
            Span::styled("wallet    ", theme::label()),
            match app.address() {
                Some(a) => Span::styled(a.kvnc.clone(), theme::value_hl()),
                None => Span::styled("not loaded", theme::hint()),
            },
        ]));
        if !app.network.is_empty() {
            lines.push(Line::from(vec![
                Span::styled("network   ", theme::label()),
                Span::styled(app.network.clone(), theme::value_hl()),
            ]));
        }
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            "Keys stay client-side. The node only ever sees signatures.",
            theme::positive(),
        )));
        lines.push(Line::from(Span::styled(
            "Never run KOVANICA_ALLOW_RESET=1 on a public-facing node.",
            theme::negative(),
        )));
        widgets::render_panel(f, "Configuration", &Text::from(lines), chunks[0]);

        let mut about_lines: Vec<Line> = Vec::new();
        if self.about {
            about_lines.push(Line::from(Span::styled(
                "kovanica — interactive ecosystem wallet",
                theme::value_hl(),
            )));
            about_lines.push(Line::from(""));
            about_lines.push(Line::from(Span::styled(
                "KVNC · GHOSTDAG k=3 · UTXO · Ed25519",
                theme::value(),
            )));
            about_lines.push(Line::from(Span::styled(
                "RFC-001 multisig · RFC-002 assets · RFC-003 stealth",
                theme::hint(),
            )));
            about_lines.push(Line::from(Span::styled(
                "RFC-004 HTLC · RFC-005 vault · RFC-006 tokenomics",
                theme::hint(),
            )));
            about_lines.push(Line::from(Span::styled(
                "KVP-106 NFT / RWA (draft)",
                theme::hint(),
            )));
            about_lines.push(Line::from(""));
            about_lines.push(Line::from(Span::styled(
                "1 KVNC = 100_000_000 atoms · max supply 90.2M",
                theme::hint(),
            )));
            about_lines.push(Line::from(Span::styled(
                "coinbase maturity 100 blocks · 75% of fees burned",
                theme::hint(),
            )));
        } else {
            about_lines.push(Line::from(Span::styled(
                "press ⏎ on “About” for the protocol summary",
                theme::hint(),
            )));
        }
        widgets::render_panel(f, "About", &Text::from(about_lines), chunks[1]);

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
                app.status = StatusMsg::ok("network info refreshed").for_secs(2);
            }
            (_, Err(e)) => {
                app.status = StatusMsg::err(format!("{label}: {e}")).for_secs(6);
            }
            _ => {}
        }
    }
}

impl Default for SettingsState {
    fn default() -> Self {
        Self::new()
    }
}
