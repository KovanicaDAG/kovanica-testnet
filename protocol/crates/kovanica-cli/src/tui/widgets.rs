//! Reusable TUI widgets: input forms, modals, tables, and panel helpers.
//!
//! Everything here is brand-styled via [`crate::tui::theme`] and deliberately
//! small — the screens compose these primitives rather than re-implementing
//! key handling.

use ratatui::{
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Modifier, Style},
    text::{Line, Span, Text},
    widgets::{Block, Borders, Clear, List, ListItem, ListState, Paragraph, Wrap},
    Frame,
};

use crate::tui::theme;

/// A single labelled input field inside a [`Form`].
#[derive(Clone)]
pub struct Field {
    pub label: String,
    pub value: String,
    /// Mask the value while typing (secrets).
    pub secret: bool,
    pub hint: String,
    /// Maximum number of characters accepted.
    pub max: usize,
}

impl Field {
    pub fn new(label: impl Into<String>) -> Self {
        Self {
            label: label.into(),
            value: String::new(),
            secret: false,
            hint: String::new(),
            max: 512,
        }
    }

    pub fn secret(mut self) -> Self {
        self.secret = true;
        self
    }

    pub fn hint(mut self, hint: impl Into<String>) -> Self {
        self.hint = hint.into();
        self
    }

    pub fn max(mut self, max: usize) -> Self {
        self.max = max;
        self
    }

    pub fn with_value(mut self, value: impl Into<String>) -> Self {
        self.value = value.into();
        self
    }

    /// The display form of the value (masked for secrets).
    pub fn display(&self) -> String {
        if self.secret && !self.value.is_empty() {
            "•".repeat(self.value.len().min(24))
        } else {
            self.value.clone()
        }
    }
}

/// A labelled form with a submit action. `Enter` on the last field submits;
/// `Esc` cancels.
pub struct Form {
    pub title: String,
    pub fields: Vec<Field>,
    pub submit_label: String,
    pub focused: usize,
}

impl Form {
    pub fn new(title: impl Into<String>, fields: Vec<Field>) -> Self {
        Self {
            title: title.into(),
            fields,
            submit_label: "Submit".to_string(),
            focused: 0,
        }
    }

    pub fn submit(mut self, label: impl Into<String>) -> Self {
        self.submit_label = label.into();
        self
    }

    pub fn value(&self, idx: usize) -> Option<&str> {
        self.fields.get(idx).map(|f| f.value.as_str())
    }

    /// Handle a key press. Returns `FormResult::Submit` when the user confirms.
    pub fn handle_key(&mut self, key: crossterm::event::KeyEvent) -> FormResult {
        use crossterm::event::{KeyCode, KeyModifiers};
        if self.fields.is_empty() {
            return FormResult::Continue;
        }
        match key.code {
            KeyCode::Tab | KeyCode::Down | KeyCode::Char('j') => {
                self.focused = (self.focused + 1) % self.fields.len();
                FormResult::Continue
            }
            KeyCode::BackTab | KeyCode::Up | KeyCode::Char('k') => {
                self.focused = if self.focused == 0 {
                    self.fields.len() - 1
                } else {
                    self.focused - 1
                };
                FormResult::Continue
            }
            KeyCode::Enter => {
                if self.focused + 1 < self.fields.len() {
                    self.focused += 1;
                    FormResult::Continue
                } else {
                    FormResult::Submit
                }
            }
            KeyCode::Esc => FormResult::Cancel,
            KeyCode::Char(c) => {
                let field = &mut self.fields[self.focused];
                if field.value.len() < field.max {
                    field.value.push(c);
                }
                FormResult::Continue
            }
            KeyCode::Backspace => {
                let field = &mut self.fields[self.focused];
                field.value.pop();
                FormResult::Continue
            }
            KeyCode::Delete => {
                let field = &mut self.fields[self.focused];
                field.value.clear();
                FormResult::Continue
            }
            KeyCode::Left => {
                let field = &mut self.fields[self.focused];
                if key.modifiers.contains(KeyModifiers::CONTROL) {
                    field.value.clear();
                }
                FormResult::Continue
            }
            KeyCode::Right => FormResult::Continue,
            _ => FormResult::Continue,
        }
    }
}

/// Result of a form key press.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FormResult {
    Continue,
    Submit,
    Cancel,
}

/// Render a form into `area`.
pub fn render_form(f: &mut Frame, form: &Form, area: Rect) {
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(theme::modal_border())
        .title(Span::styled(
            format!(" {} ", form.title),
            theme::panel_title(),
        ));
    let inner = block.inner(area);
    f.render_widget(block, area);

    let rows = form.fields.len() + 1; // fields + submit row
    let row_h = 3u16;
    let _needed = rows as u16 * row_h;
    let top = inner.y.saturating_add(1);
    let mut y = top;

    for (idx, field) in form.fields.iter().enumerate() {
        if y + 2 > inner.bottom() {
            break;
        }
        let label = Paragraph::new(Line::from(vec![
            Span::styled(format!("{} ", field.label), theme::label()),
            Span::styled(
                field.display(),
                if idx == form.focused {
                    theme::input_focused()
                } else {
                    theme::input_idle()
                },
            ),
        ]))
        .block(Block::default().borders(Borders::BOTTOM).border_style(
            if idx == form.focused {
                Style::default().fg(theme::GOLD)
            } else {
                Style::default().fg(theme::BORDER)
            },
        ));
        f.render_widget(
            label,
            Rect::new(inner.x + 1, y, inner.width.saturating_sub(2), 1),
        );
        if !field.hint.is_empty() {
            let hint = Paragraph::new(Span::styled(&field.hint, theme::hint()));
            f.render_widget(
                hint,
                Rect::new(inner.x + 2, y + 1, inner.width.saturating_sub(4), 1),
            );
        }
        y += row_h;
    }

    if y < inner.bottom() {
        let submit = Paragraph::new(Line::from(vec![
            Span::styled("⏎ ", theme::value_hl()),
            Span::styled(&form.submit_label, theme::value_hl()),
            Span::styled("   esc ", theme::hint()),
            Span::styled("cancel", theme::hint()),
        ]))
        .alignment(Alignment::Left);
        f.render_widget(
            submit,
            Rect::new(inner.x + 1, y, inner.width.saturating_sub(2), 1),
        );
    }
}

/// A confirmation modal (used for the offline-sign boundary and destructive
/// actions). Renders a centered box with a message and two choices.
pub struct Modal {
    pub title: String,
    pub lines: Vec<Line<'static>>,
    pub confirm_label: String,
    pub cancel_label: String,
    pub selected: bool, // true = confirm highlighted
}

impl Modal {
    pub fn new(title: impl Into<String>) -> Self {
        Self {
            title: title.into(),
            lines: Vec::new(),
            confirm_label: "Confirm".to_string(),
            cancel_label: "Cancel".to_string(),
            selected: false,
        }
    }

    pub fn line(mut self, line: Line<'static>) -> Self {
        self.lines.push(line);
        self
    }

    pub fn text(mut self, text: impl Into<String>) -> Self {
        self.lines
            .push(Line::from(Span::styled(text.into(), theme::value())));
        self
    }

    pub fn confirm(mut self, label: impl Into<String>) -> Self {
        self.confirm_label = label.into();
        self
    }

    pub fn cancel(mut self, label: impl Into<String>) -> Self {
        self.cancel_label = label.into();
        self
    }

    pub fn handle_key(&mut self, key: crossterm::event::KeyEvent) -> ModalResult {
        use crossterm::event::{KeyCode, KeyModifiers};
        match key.code {
            KeyCode::Tab | KeyCode::Left | KeyCode::Right => {
                self.selected = !self.selected;
                ModalResult::Continue
            }
            KeyCode::Enter => {
                if self.selected {
                    ModalResult::Confirm
                } else {
                    ModalResult::Cancel
                }
            }
            KeyCode::Esc => ModalResult::Cancel,
            KeyCode::Char('y') | KeyCode::Char('Y') => ModalResult::Confirm,
            KeyCode::Char('n') | KeyCode::Char('N') => ModalResult::Cancel,
            KeyCode::Char(_c) if key.modifiers.contains(KeyModifiers::CONTROL) => {
                ModalResult::Continue
            }
            _ => ModalResult::Continue,
        }
    }
}

/// Result of a modal key press.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModalResult {
    Continue,
    Confirm,
    Cancel,
}

/// Render a modal centered over the current frame.
pub fn render_modal(f: &mut Frame, modal: &Modal, area: Rect) {
    let width = area.width.min(76).saturating_sub(8);
    let height = (modal.lines.len() as u16 + 5).min(area.height.saturating_sub(4));
    let x = area.x + (area.width.saturating_sub(width)) / 2;
    let y = area.y + (area.height.saturating_sub(height)) / 2;
    let rect = Rect::new(x, y, width, height);

    f.render_widget(Clear, rect);
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(theme::modal_border())
        .title(Span::styled(
            format!(" {} ", modal.title),
            theme::value_hl(),
        ));
    let inner = block.inner(rect);
    f.render_widget(block, rect);

    for (y_cursor, line) in (inner.y + 1..).zip(modal.lines.iter()) {
        if y_cursor + 1 > inner.bottom() {
            break;
        }
        let p = Paragraph::new(line.clone()).wrap(Wrap { trim: true });
        f.render_widget(
            p,
            Rect::new(inner.x + 1, y_cursor, inner.width.saturating_sub(2), 1),
        );
    }

    // Buttons row.
    let btn_y = inner.bottom().saturating_sub(2);
    let confirm_style = if modal.selected {
        theme::item_selected()
    } else {
        Style::default()
            .fg(theme::GOLD)
            .add_modifier(Modifier::BOLD)
    };
    let cancel_style = if !modal.selected {
        theme::item_selected()
    } else {
        theme::hint()
    };
    let buttons = Paragraph::new(Line::from(vec![
        Span::styled(format!(" [ {} ] ", modal.confirm_label), confirm_style),
        Span::styled("   ", theme::hint()),
        Span::styled(format!(" [ {} ] ", modal.cancel_label), cancel_style),
    ]))
    .alignment(Alignment::Center);
    f.render_widget(buttons, Rect::new(inner.x, btn_y, inner.width, 1));
}

/// Render a titled panel with a body paragraph.
pub fn render_panel(f: &mut Frame, title: &str, body: &Text, area: Rect) {
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(theme::BORDER))
        .style(Style::default().bg(theme::SURFACE))
        .title(Span::styled(format!(" {title} "), theme::panel_title()));
    let inner = block.inner(area);
    f.render_widget(block, area);
    let p = Paragraph::new(body.clone())
        .wrap(Wrap { trim: true })
        .style(theme::base());
    f.render_widget(
        p,
        Rect::new(
            inner.x + 1,
            inner.y + 1,
            inner.width.saturating_sub(2),
            inner.height.saturating_sub(2),
        ),
    );
}

/// Render a titled panel with a list of items (with selection state).
pub fn render_list_panel(
    f: &mut Frame,
    title: &str,
    items: &[String],
    selected: Option<usize>,
    area: Rect,
) {
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(theme::BORDER))
        .style(Style::default().bg(theme::SURFACE))
        .title(Span::styled(format!(" {title} "), theme::panel_title()));
    let list_items: Vec<ListItem> = items
        .iter()
        .enumerate()
        .map(|(idx, item)| {
            let style = if Some(idx) == selected {
                theme::item_selected()
            } else {
                theme::item_idle()
            };
            ListItem::new(Line::from(Span::styled(item.clone(), style)))
        })
        .collect();
    let mut state = ListState::default();
    state.select(selected);
    let list = List::new(list_items)
        .block(block)
        .highlight_style(theme::item_selected())
        .highlight_symbol("▶ ");
    f.render_stateful_widget(list, area, &mut state);
}

/// Split an area into a left action list and a right content pane.
pub fn split_action_area(area: Rect) -> (Rect, Rect) {
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(28), Constraint::Percentage(72)])
        .split(area);
    (chunks[0], chunks[1])
}

/// A spinner frame for pending operations.
pub fn spinner(tick: u64) -> &'static str {
    const FRAMES: [&str; 10] = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];
    FRAMES[(tick as usize) % FRAMES.len()]
}
