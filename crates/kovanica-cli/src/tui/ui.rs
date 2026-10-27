//! Terminal layout for the Kovanica wallet.
//!
//! The view model is built by [`crate::tui::app::App::view`]. This module does
//! not read passphrases or signing keys.

use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph, Wrap};
use ratatui::Frame;

use crate::amount::format_kuna;
use crate::tui::app::{chain_title, FormFocus, FormKind, GateFocus, View, ViewScreen};
use crate::tui::net::{Snapshot, ValidatorRow};
use kovanica_types::signing::chain_id;

pub(crate) fn draw(frame: &mut Frame, view_source: &crate::tui::app::App) {
    let view = view_source.view();
    let area = frame.area();
    let block = Block::default()
        .borders(Borders::ALL)
        .title(title_line(&view));
    let inner = block.inner(area);
    frame.render_widget(block, area);
    let pieces = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(1), Constraint::Length(4)])
        .split(inner);
    let body_area = pieces[0];
    frame.render_widget(body(&view, body_area), body_area);
    frame.render_widget(footer(&view), pieces[1]);
}

fn title_line(view: &View) -> Line<'static> {
    let mut spans = vec![
        Span::styled(
            " Kovanica ",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(view.chain_label.clone(), chain_style(view.chain_id)),
    ];
    if let Some(activity) = view.activity {
        spans.push(Span::styled(
            format!(" {activity}"),
            Style::default().fg(Color::DarkGray),
        ));
    }
    spans.push(Span::raw(" "));
    Line::from(spans)
}

fn chain_style(chain_id: Option<u64>) -> Style {
    match chain_id {
        Some(chain_id::MAINNET) => Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
        Some(chain_id::TESTNET) | Some(chain_id::TESTNET_V2) => Style::default().fg(Color::Yellow),
        Some(_) => Style::default().fg(Color::Cyan),
        None => Style::default().fg(Color::DarkGray),
    }
}

fn body(view: &View, area: Rect) -> Paragraph<'static> {
    let lines = match &view.screen {
        ViewScreen::Gate { focus } => gate_lines(view, *focus),
        ViewScreen::Secret { title, hint, input } => secret_lines(title, hint, input),
        ViewScreen::Home { address, snapshot } => home_lines(view, address, *snapshot),
        ViewScreen::Validators {
            rows,
            selected,
            loaded,
        } => validator_lines(rows, *selected, *loaded, area.height as usize),
        ViewScreen::Form {
            kind,
            focus,
            to,
            amount,
            fee,
            validator,
        } => form_lines(*kind, *focus, to, amount, fee, validator),
        ViewScreen::Confirm {
            action,
            lines,
            warning,
        } => confirm_lines(action, lines, *warning),
        ViewScreen::Backup { address, words } => backup_lines(address, words),
    };
    Paragraph::new(lines).wrap(Wrap { trim: false })
}

fn gate_lines(view: &View, focus: GateFocus) -> Vec<Line<'static>> {
    vec![
        Line::from("Kovanica wallet. The node never sees the seed."),
        Line::from(""),
        field_label("keystore", focus == GateFocus::Keystore),
        field_value(&view.keystore_path, focus == GateFocus::Keystore),
        field_label("rpc", focus == GateFocus::Rpc),
        field_value(&view.rpc_url, focus == GateFocus::Rpc),
        field_label("chain", focus == GateFocus::Chain),
        chain_value(view, focus == GateFocus::Chain),
        Line::from(""),
        button("Unlock", focus == GateFocus::Unlock),
        button("Create a new keystore", focus == GateFocus::Create),
        button("Import a 24-word phrase", focus == GateFocus::Import),
    ]
}

fn secret_lines(title: &str, hint: &str, input: &str) -> Vec<Line<'static>> {
    let shown = if input.is_empty() {
        "_".to_string()
    } else {
        input.to_string()
    };
    vec![
        Line::styled(
            title.to_string(),
            Style::default().add_modifier(Modifier::BOLD),
        ),
        Line::from(""),
        Line::from(hint.to_string()),
        Line::from(""),
        Line::styled(shown, Style::default().fg(Color::Cyan)),
    ]
}

fn home_lines(view: &View, address: &str, snapshot: Option<Snapshot>) -> Vec<Line<'static>> {
    let mut lines = vec![
        labeled("keystore", &view.keystore_path),
        labeled("rpc", &view.rpc_url),
        labeled("network", &chain_title(view.chain_id)),
        Line::from(""),
        labeled("address", address),
    ];
    match snapshot {
        Some(snapshot) => {
            lines.push(labeled("balance", &format_kuna(snapshot.balance)));
            lines.push(labeled("stake", &format_kuna(snapshot.stake)));
            lines.push(labeled("rewards", &format_kuna(snapshot.rewards)));
            lines.push(labeled("nonce", &snapshot.nonce.to_string()));
            lines.push(Line::from(""));
            lines.push(labeled("block", &snapshot.height.to_string()));
            lines.push(labeled("committee", &snapshot.committee_size.to_string()));
            lines.push(labeled(
                "peers",
                &snapshot
                    .peers
                    .map(|count| count.to_string())
                    .unwrap_or_else(|| "unknown".to_string()),
            ));
        }
        None => {
            let placeholder = if view.sync_error.is_some() {
                "unavailable"
            } else {
                "..."
            };
            lines.push(labeled("balance", placeholder));
            lines.push(labeled("stake", placeholder));
            lines.push(labeled("rewards", placeholder));
            lines.push(labeled("nonce", placeholder));
        }
    }
    lines
}

fn validator_lines(
    rows: &[ValidatorRow],
    selected: usize,
    loaded: bool,
    height: usize,
) -> Vec<Line<'static>> {
    let mut lines = vec![Line::styled(
        "Validators",
        Style::default().add_modifier(Modifier::BOLD),
    )];
    if !loaded {
        lines.push(Line::from("Loading validators..."));
        return lines;
    }
    if rows.is_empty() {
        lines.push(Line::from("The node reported no validators."));
        return lines;
    }
    let budget = height.saturating_sub(1).max(1);
    let start = window_start(selected, rows.len(), budget);
    for (index, row) in rows.iter().enumerate().skip(start).take(budget) {
        let marker = if index == selected { ">" } else { " " };
        let state = if row.active { "active" } else { "inactive" };
        let style = if index == selected {
            Style::default().fg(Color::Cyan)
        } else {
            Style::default()
        };
        lines.push(Line::styled(
            format!(
                "{marker} {}  {}  {} bps  {state}",
                row.address,
                format_kuna(row.stake),
                row.commission_bps
            ),
            style,
        ));
    }
    lines
}

fn form_lines(
    kind: FormKind,
    focus: FormFocus,
    to: &str,
    amount: &str,
    fee: &str,
    validator: &str,
) -> Vec<Line<'static>> {
    let mut lines = vec![
        Line::styled(
            form_title(kind).to_string(),
            Style::default().add_modifier(Modifier::BOLD),
        ),
        Line::from(""),
    ];
    if kind == FormKind::Transfer {
        lines.push(field_label("to", focus == FormFocus::To));
        lines.push(field_value(to, focus == FormFocus::To));
    }
    if matches!(kind, FormKind::Delegate | FormKind::Claim) {
        let label = if kind == FormKind::Claim {
            "validator (empty claims all)"
        } else {
            "validator"
        };
        lines.push(field_label(label, focus == FormFocus::Validator));
        lines.push(field_value(validator, focus == FormFocus::Validator));
    }
    if kind != FormKind::Claim {
        lines.push(field_label("amount (KUNA)", focus == FormFocus::Amount));
        lines.push(field_value(amount, focus == FormFocus::Amount));
    }
    lines.push(field_label("fee (atoms)", focus == FormFocus::Fee));
    lines.push(field_value(fee, focus == FormFocus::Fee));
    lines
}

fn confirm_lines(
    action: &str,
    rows: &[(String, String)],
    warning: Option<&str>,
) -> Vec<Line<'static>> {
    let mut lines = vec![Line::styled(
        format!("Sign {action}?"),
        Style::default().add_modifier(Modifier::BOLD),
    )];
    if let Some(warning) = warning {
        lines.push(Line::styled(
            warning.to_string(),
            Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
        ));
    }
    lines.push(Line::from(""));
    for (label, value) in rows {
        lines.push(labeled(label, value));
    }
    lines.push(Line::from(""));
    lines.push(Line::from("Nothing is signed until you press y."));
    lines
}

fn backup_lines(address: &str, words: &[String]) -> Vec<Line<'static>> {
    let mut lines = vec![
        Line::styled(
            "Recovery phrase",
            Style::default().add_modifier(Modifier::BOLD),
        ),
        Line::from(""),
        Line::from("Write these words down. Anyone who can see this screen can take the account."),
        Line::from("The phrase is shown only once."),
        Line::from(""),
        labeled("address", address),
        Line::from(""),
    ];
    for (row, chunk) in words.chunks(4).enumerate() {
        let text = chunk
            .iter()
            .enumerate()
            .map(|(offset, word)| format!("{:>2} {:<12}", row * 4 + offset + 1, word))
            .collect::<Vec<_>>()
            .join(" ");
        lines.push(Line::from(text));
    }
    lines
}

fn footer(view: &View) -> Paragraph<'static> {
    let mut lines = Vec::new();
    if let Some(notice) = &view.notice {
        let style = if notice.is_error {
            Style::default().fg(Color::Red)
        } else {
            Style::default().fg(Color::Green)
        };
        lines.push(Line::styled(notice.text.clone(), style));
    }
    if let Some(sync_error) = &view.sync_error {
        let duplicate = view
            .notice
            .as_ref()
            .is_some_and(|notice| notice.text == *sync_error);
        if !duplicate {
            lines.push(Line::styled(
                sync_error.clone(),
                Style::default().fg(Color::Red),
            ));
        }
    }
    lines.push(Line::styled(
        hints(&view.screen).to_string(),
        Style::default().fg(Color::DarkGray),
    ));
    Paragraph::new(lines).wrap(Wrap { trim: false })
}

fn hints(screen: &ViewScreen) -> &'static str {
    match screen {
        ViewScreen::Gate { .. } => {
            "tab moves   enter activates   left and right change the chain   ctrl-c quits"
        }
        ViewScreen::Secret { .. } => "enter continues   esc cancels   ctrl-u clears the field",
        ViewScreen::Home { .. } => {
            "t transfer  s stake  u unstake  d delegate  c claim  v validators  r refresh  l lock  q quit"
        }
        ViewScreen::Validators { .. } => "up and down move   enter delegates   r reloads   esc returns",
        ViewScreen::Form { .. } => "tab moves   enter reviews   esc returns   ctrl-u clears the field",
        ViewScreen::Confirm { .. } => "y signs and submits   n returns   nothing is sent before y",
        ViewScreen::Backup { .. } => "enter hides the phrase after you have written it down",
    }
}

fn form_title(kind: FormKind) -> &'static str {
    match kind {
        FormKind::Transfer => "Send KUNA",
        FormKind::Stake => "Stake KUNA",
        FormKind::Unstake => "Unstake KUNA",
        FormKind::Delegate => "Delegate KUNA",
        FormKind::Claim => "Claim rewards",
    }
}

fn field_label(label: &str, focused: bool) -> Line<'static> {
    Line::styled(
        format!("{} {label}", marker(focused)),
        if focused {
            Style::default().fg(Color::Cyan)
        } else {
            Style::default().fg(Color::DarkGray)
        },
    )
}

fn field_value(value: &str, focused: bool) -> Line<'static> {
    let shown = if value.is_empty() && focused {
        "_"
    } else {
        value
    };
    Line::from(format!("  {shown}"))
}

fn chain_value(view: &View, focused: bool) -> Line<'static> {
    let label = if focused {
        format!("< {} >", view.chain_label)
    } else {
        view.chain_label.clone()
    };
    Line::from(format!("  {label}"))
}

fn button(label: &str, focused: bool) -> Line<'static> {
    Line::styled(
        format!("{} {label}", marker(focused)),
        if focused {
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default()
        },
    )
}

fn labeled(label: &str, value: &str) -> Line<'static> {
    Line::from(vec![
        Span::styled(format!("{label:<12}"), Style::default().fg(Color::DarkGray)),
        Span::raw(value.to_string()),
    ])
}

fn marker(focused: bool) -> &'static str {
    if focused {
        ">"
    } else {
        " "
    }
}

pub(crate) fn window_start(selected: usize, len: usize, rows: usize) -> usize {
    if rows == 0 || len <= rows {
        return 0;
    }
    let max_start = len - rows;
    selected.saturating_sub(rows / 2).min(max_start)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;

    use crate::tui::app::{App, Input, TuiConfig, ViewScreen};
    use kovanica_types::signing::chain_id;

    fn test_app() -> App {
        App::new(TuiConfig {
            rpc_url: "http://127.0.0.1:8545".to_string(),
            chain_id: Some(chain_id::LOCAL),
            keystore: std::path::PathBuf::from("/no/such/kovanica-keystore.json"),
        })
    }

    fn rendered(app: &App, width: u16, height: u16) -> String {
        let backend = TestBackend::new(width, height);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|frame| draw(frame, app)).unwrap();
        let buffer = terminal.backend().buffer().clone();
        let mut text = String::new();
        for y in 0..buffer.area.height {
            for x in 0..buffer.area.width {
                text.push_str(buffer[(x, y)].symbol());
            }
            text.push('\n');
        }
        text
    }

    #[test]
    fn passphrase_is_masked_on_screen() {
        let mut app = test_app();
        app.show_unlock_passphrase("hunter2");
        let text = rendered(&app, 100, 30);
        assert!(text.contains("*******"));
        assert!(!text.contains("hunter2"));
        rendered(&app, 40, 12);
    }

    #[test]
    fn mainnet_review_is_labeled_in_the_frame() {
        let mut app = test_app();
        app.show_mainnet_transfer_review();
        let text = rendered(&app, 100, 36);
        assert!(text.contains("MAINNET"));
        assert!(text.contains("2.5 KUNA"));
        assert!(text.contains("This signs a mainnet transaction."));
        assert!(text.contains("Nothing is signed until you press y."));
    }

    #[test]
    fn backup_phrase_is_visible_until_it_is_acknowledged() {
        let mut app = test_app();
        app.show_backup("alpha bravo charlie delta");
        let shown = rendered(&app, 100, 36);
        assert!(shown.contains("alpha"));
        assert!(shown.contains("1 alpha"));
        app.handle(Input::Enter);
        let hidden = rendered(&app, 100, 36);
        assert!(!hidden.contains("alpha"));
        assert!(matches!(app.view().screen, ViewScreen::Home { .. }));
    }

    #[test]
    fn every_screen_draws_in_a_narrow_terminal() {
        let mut app = test_app();
        rendered(&app, 40, 12);
        app.handle(Input::Up);
        rendered(&app, 40, 12);
        app.show_home();
        rendered(&app, 40, 12);
        app.show_stake_form();
        rendered(&app, 40, 12);
        app.show_validators();
        rendered(&app, 40, 12);
    }

    #[test]
    fn validator_window_keeps_the_selection_visible() {
        assert_eq!(window_start(0, 10, 3), 0);
        assert_eq!(window_start(5, 10, 3), 4);
        assert_eq!(window_start(9, 10, 3), 7);
        assert_eq!(window_start(2, 3, 10), 0);
        assert_eq!(window_start(0, 0, 3), 0);
    }
}
