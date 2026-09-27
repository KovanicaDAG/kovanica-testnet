//! Kovanica brand palette.
//!
//! Mirrors the web surface (`web/site/src/styles.css`) so the terminal wallet
//! renders in the same tones as explorer.kovanica.online: a near-black canvas,
//! warm off-white foreground, muted slate text, and the signature gold/teal
//! accents.

use ratatui::style::{Color, Modifier, Style};

/// Canvas background — `#09090b`.
pub const BG: Color = Color::Rgb(9, 9, 11);
/// Raised surface — `#121214`.
pub const SURFACE: Color = Color::Rgb(18, 18, 20);
/// Elevated surface — `#1a1a1e`.
pub const ELEVATED: Color = Color::Rgb(26, 26, 30);
/// Primary foreground — `#f2f1ee`.
pub const FG: Color = Color::Rgb(242, 241, 238);
/// Muted text — `#9a9aa3`.
pub const MUTED: Color = Color::Rgb(154, 154, 163);
/// Subtle text — `#6b6b74`.
pub const SUBTLE: Color = Color::Rgb(107, 107, 116);
/// Hairline borders — `#2a2a30`.
pub const BORDER: Color = Color::Rgb(42, 42, 48);
/// Accent (buttons, highlights) — `#d8d4cc`.
pub const ACCENT: Color = Color::Rgb(216, 212, 204);
/// Accent foreground — `#0a0a0b`.
pub const ACCENT_FG: Color = Color::Rgb(10, 10, 11);
/// Cool blue (links, info) — `#8aa0b4`.
pub const BLUE: Color = Color::Rgb(138, 160, 180);
/// Warm red (warnings) — `#b08980`.
pub const RED: Color = Color::Rgb(176, 137, 128);
/// Success green — `#7d9a7a`.
pub const OK: Color = Color::Rgb(125, 154, 122);
/// Danger red — `#c45c4a`.
pub const DANGER: Color = Color::Rgb(196, 92, 74);
/// Signature gold — `#F2A900`.
pub const GOLD: Color = Color::Rgb(242, 169, 0);
/// Gold (dark) — `#c48a00`.
pub const GOLD_DARK: Color = Color::Rgb(196, 138, 0);
/// Signature teal — `#2fbaa4`.
pub const TEAL: Color = Color::Rgb(47, 186, 164);
/// Teal (dark) — `#1c7c72`.
pub const TEAL_DARK: Color = Color::Rgb(28, 124, 114);
/// Testnet amber — `#f59e0b`.
pub const TESTNET: Color = Color::Rgb(245, 158, 11);
/// Mainnet green — `#16a765`.
pub const MAINNET: Color = Color::Rgb(22, 167, 101);

/// Base style for the whole app.
pub fn base() -> Style {
    Style::default().fg(FG).bg(BG)
}

/// Style for a panel title.
pub fn panel_title() -> Style {
    Style::default().fg(SUBTLE).add_modifier(Modifier::BOLD)
}

/// Style for a section label (uppercase micro-label look).
pub fn label() -> Style {
    Style::default().fg(SUBTLE).add_modifier(Modifier::BOLD)
}

/// Style for a value (mono-ish emphasis).
pub fn value() -> Style {
    Style::default().fg(FG)
}

/// Style for a highlighted value.
pub fn value_hl() -> Style {
    Style::default().fg(GOLD).add_modifier(Modifier::BOLD)
}

/// Style for a positive delta.
pub fn positive() -> Style {
    Style::default().fg(OK)
}

/// Style for a negative delta / error.
pub fn negative() -> Style {
    Style::default().fg(DANGER)
}

/// Style for a muted hint.
pub fn hint() -> Style {
    Style::default().fg(SUBTLE)
}

/// Style for a link / interactive element.
pub fn link() -> Style {
    Style::default().fg(BLUE).add_modifier(Modifier::UNDERLINED)
}

/// Style for the selected tab.
pub fn tab_active() -> Style {
    Style::default()
        .fg(ACCENT_FG)
        .bg(ACCENT)
        .add_modifier(Modifier::BOLD)
}

/// Style for an inactive tab.
pub fn tab_idle() -> Style {
    Style::default().fg(MUTED)
}

/// Style for a selected list item.
pub fn item_selected() -> Style {
    Style::default()
        .fg(BG)
        .bg(GOLD)
        .add_modifier(Modifier::BOLD)
}

/// Style for an unselected list item.
pub fn item_idle() -> Style {
    Style::default().fg(FG)
}

/// Style for a focused input field.
pub fn input_focused() -> Style {
    Style::default()
        .fg(FG)
        .bg(ELEVATED)
        .add_modifier(Modifier::BOLD)
}

/// Style for an unfocused input field.
pub fn input_idle() -> Style {
    Style::default().fg(MUTED).bg(ELEVATED)
}

/// Style for a modal border.
pub fn modal_border() -> Style {
    Style::default().fg(GOLD)
}

/// Style for a status-bar message.
pub fn status_ok() -> Style {
    Style::default().fg(OK)
}

/// Style for a status-bar error.
pub fn status_err() -> Style {
    Style::default().fg(DANGER).add_modifier(Modifier::BOLD)
}

/// Style for a status-bar info message.
pub fn status_info() -> Style {
    Style::default().fg(MUTED)
}
