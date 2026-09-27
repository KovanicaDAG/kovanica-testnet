//! Interactive TUI wallet for the Kovanica ecosystem.
//!
//! A tabbed, brand-styled terminal wallet covering the full protocol surface:
//! dashboard, key management, sends, assets (KVP-102), HTLC + vault + multisig
//! contracts (KVP-101/104/105), stealth (KVP-103), NFT/RWA (KVP-106), and the
//! explorer API.
//!
//! Security model: **private keys never enter the node.** Every signing step
//! happens locally with the loaded Ed25519 keypair, and the UI shows an
//! explicit "offline sign" boundary modal before any signature is produced.

pub mod screens;
pub mod theme;
pub mod widgets;

use std::io;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use anyhow::Result;
use crossterm::{
    event::{
        self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyEvent, KeyEventKind,
    },
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::{Backend, CrosstermBackend},
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph},
    Frame, Terminal,
};
use serde_json::Value;

use crate::api::Client;
use crate::Wallet;

use self::screens::{DashboardState, Screen};
use self::widgets::{spinner, Modal, ModalResult};

/// A pending background API call (spawned on a blocking thread).
pub struct Pending {
    pub label: String,
    pub rx: std::sync::mpsc::Receiver<Result<Value, String>>,
}

/// Status-bar message kinds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StatusKind {
    Ok,
    Err,
    Info,
}

/// A status-bar message with an optional expiry.
pub struct StatusMsg {
    pub text: String,
    pub kind: StatusKind,
    pub until: Option<Instant>,
}

impl StatusMsg {
    pub fn new(text: impl Into<String>, kind: StatusKind) -> Self {
        Self {
            text: text.into(),
            kind,
            until: None,
        }
    }

    pub fn ok(text: impl Into<String>) -> Self {
        Self::new(text, StatusKind::Ok)
    }

    pub fn err(text: impl Into<String>) -> Self {
        Self::new(text, StatusKind::Err)
    }

    pub fn info(text: impl Into<String>) -> Self {
        Self::new(text, StatusKind::Info)
    }

    pub fn for_secs(mut self, secs: u64) -> Self {
        self.until = Some(Instant::now() + Duration::from_secs(secs));
        self
    }
}

/// The application state shared by every screen.
pub struct App {
    pub client: Client,
    pub wallet: Option<Wallet>,
    pub key_path: PathBuf,
    pub screen: Screen,
    pub status: StatusMsg,
    pub pending: Option<Pending>,
    pub tick: u64,
    pub quit: bool,
    pub confirm_quit: Option<Modal>,
    pub api_url: String,
    pub network: String,
}

impl App {
    pub fn new(client: Client, api_url: String) -> Self {
        let key_path = std::env::var("KOVANICA_KEY")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("kovanica.key"));
        let wallet = Wallet::load(&key_path).ok();
        Self {
            client,
            wallet,
            key_path,
            screen: Screen::Dashboard(DashboardState::new()),
            status: StatusMsg::info("loading…"),
            pending: None,
            tick: 0,
            quit: false,
            confirm_quit: None,
            api_url,
            network: String::new(),
        }
    }

    /// Spawn a blocking API call; the result is routed to the current screen
    /// via [`ScreenImpl::on_result`] once it completes.
    pub fn spawn<F>(&mut self, label: &str, f: F)
    where
        F: FnOnce() -> Result<Value, String> + Send + 'static,
    {
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = tx.send(f());
        });
        self.pending = Some(Pending {
            label: label.to_string(),
            rx,
        });
    }

    /// Poll the pending action and route completed results.
    pub fn poll_pending(&mut self) {
        let Some(p) = &mut self.pending else {
            return;
        };
        let outcome = match p.rx.try_recv() {
            Ok(outcome) => outcome,
            Err(std::sync::mpsc::TryRecvError::Empty) => return,
            Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                Err("background task ended without a result".to_string())
            }
        };
        let label = p.label.clone();
        self.pending = None;
        // Take the screen out of `self` so the screen state and `App` can be
        // borrowed independently, then put it back.
        let mut screen =
            std::mem::replace(&mut self.screen, Screen::Dashboard(DashboardState::new()));
        match &mut screen {
            Screen::Dashboard(s) => s.on_result(self, &label, outcome),
            Screen::Wallet(s) => s.on_result(self, &label, outcome),
            Screen::Send(s) => s.on_result(self, &label, outcome),
            Screen::Assets(s) => s.on_result(self, &label, outcome),
            Screen::Contracts(s) => s.on_result(self, &label, outcome),
            Screen::Stealth(s) => s.on_result(self, &label, outcome),
            Screen::NftRwa(s) => s.on_result(self, &label, outcome),
            Screen::Explorer(s) => s.on_result(self, &label, outcome),
            Screen::Settings(s) => s.on_result(self, &label, outcome),
        }
        self.screen = screen;
    }

    /// Load (or reload) the wallet from the configured key path.
    pub fn load_wallet(&mut self) {
        match Wallet::load(&self.key_path) {
            Ok(w) => {
                self.wallet = Some(w);
                self.status =
                    StatusMsg::ok(format!("wallet loaded from {}", self.key_path.display()))
                        .for_secs(4);
            }
            Err(e) => {
                self.wallet = None;
                self.status = StatusMsg::err(format!("no wallet: {e}")).for_secs(6);
            }
        }
    }

    /// The wallet's address, if a wallet is loaded.
    pub fn address(&self) -> Option<WalletAddress> {
        self.wallet.as_ref().map(|w| WalletAddress {
            kvnc: w.address().to_kvnc(),
            hex: w.address().to_hex(),
        })
    }

    /// Handle a global key (tabs, quit) or route to the active screen.
    pub fn handle_key(&mut self, key: KeyEvent) {
        if let Some(modal) = &mut self.confirm_quit {
            match modal.handle_key(key) {
                ModalResult::Confirm => self.quit = true,
                ModalResult::Cancel => self.confirm_quit = None,
                ModalResult::Continue => {}
            }
            return;
        }
        match key.code {
            KeyCode::Char('q') | KeyCode::Char('Q') => {
                self.confirm_quit = Some(
                    Modal::new("Quit Kovanica wallet")
                        .text("Exit the interactive wallet?")
                        .confirm("Quit")
                        .cancel("Stay"),
                );
            }
            KeyCode::Char(c) if c.is_ascii_digit() && c != '0' => {
                let idx = (c.to_digit(10).unwrap() - 1) as usize;
                if let Some(screen) = Screen::from_index(idx) {
                    self.screen = screen;
                }
            }
            _ => {
                let mut screen =
                    std::mem::replace(&mut self.screen, Screen::Dashboard(DashboardState::new()));
                match &mut screen {
                    Screen::Dashboard(s) => s.handle_key(self, key),
                    Screen::Wallet(s) => s.handle_key(self, key),
                    Screen::Send(s) => s.handle_key(self, key),
                    Screen::Assets(s) => s.handle_key(self, key),
                    Screen::Contracts(s) => s.handle_key(self, key),
                    Screen::Stealth(s) => s.handle_key(self, key),
                    Screen::NftRwa(s) => s.handle_key(self, key),
                    Screen::Explorer(s) => s.handle_key(self, key),
                    Screen::Settings(s) => s.handle_key(self, key),
                }
                self.screen = screen;
            }
        }
    }

    /// Render the full frame: header, tabs, screen content, status bar, modals.
    pub fn render(&mut self, f: &mut Frame) {
        let area = f.area();
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(2), // header
                Constraint::Length(1), // tabs
                Constraint::Min(3),    // content
                Constraint::Length(1), // status
            ])
            .split(area);

        self.render_header(f, chunks[0]);
        self.render_tabs(f, chunks[1]);
        self.render_status(f, chunks[3]);

        match &self.screen {
            Screen::Dashboard(s) => s.render(self, f, chunks[2]),
            Screen::Wallet(s) => s.render(self, f, chunks[2]),
            Screen::Send(s) => s.render(self, f, chunks[2]),
            Screen::Assets(s) => s.render(self, f, chunks[2]),
            Screen::Contracts(s) => s.render(self, f, chunks[2]),
            Screen::Stealth(s) => s.render(self, f, chunks[2]),
            Screen::NftRwa(s) => s.render(self, f, chunks[2]),
            Screen::Explorer(s) => s.render(self, f, chunks[2]),
            Screen::Settings(s) => s.render(self, f, chunks[2]),
        }

        if let Some(modal) = &self.confirm_quit {
            widgets::render_modal(f, modal, area);
        }
    }

    fn render_header(&self, f: &mut Frame, area: Rect) {
        let block = Block::default()
            .borders(Borders::BOTTOM)
            .border_style(Style::default().fg(theme::BORDER));
        let inner = block.inner(area);
        f.render_widget(block, area);

        let net_color = if self.network.contains("mainnet") {
            theme::MAINNET
        } else {
            theme::TESTNET
        };
        let net_badge = if self.network.is_empty() {
            "connecting…".to_string()
        } else {
            self.network.clone()
        };

        let line = Line::from(vec![
            Span::styled("◆ ", theme::value_hl()),
            Span::styled(
                "KOVANICA",
                Style::default().fg(theme::FG).add_modifier(Modifier::BOLD),
            ),
            Span::styled("  wallet", theme::hint()),
            Span::styled(format!("  v{}", env!("CARGO_PKG_VERSION")), theme::hint()),
            Span::styled("   ", theme::hint()),
            Span::styled(
                format!("[{net_badge}]"),
                Style::default().fg(net_color).add_modifier(Modifier::BOLD),
            ),
            Span::styled("   ", theme::hint()),
            Span::styled(&self.api_url, theme::hint()),
        ]);
        f.render_widget(
            Paragraph::new(line).alignment(Alignment::Left),
            Rect::new(inner.x + 1, inner.y, inner.width.saturating_sub(2), 1),
        );
    }

    fn render_tabs(&self, f: &mut Frame, area: Rect) {
        let tabs = [
            ("1", "Dashboard"),
            ("2", "Wallet"),
            ("3", "Send"),
            ("4", "Assets"),
            ("5", "Contracts"),
            ("6", "Stealth"),
            ("7", "NFT/RWA"),
            ("8", "Explorer"),
            ("9", "Settings"),
        ];
        let current = self.screen.index();
        let mut spans: Vec<Span> = Vec::new();
        for (i, (num, name)) in tabs.iter().enumerate() {
            let style = if i == current {
                theme::tab_active()
            } else {
                theme::tab_idle()
            };
            spans.push(Span::styled(format!(" {num} {name} "), style));
            spans.push(Span::styled("│", theme::hint()));
        }
        f.render_widget(
            Paragraph::new(Line::from(spans)).alignment(Alignment::Left),
            area,
        );
    }

    fn render_status(&self, f: &mut Frame, area: Rect) {
        let style = match self.status.kind {
            StatusKind::Ok => theme::status_ok(),
            StatusKind::Err => theme::status_err(),
            StatusKind::Info => theme::status_info(),
        };
        let mut text = self.status.text.clone();
        if let Some(p) = &self.pending {
            text = format!("{} {}…", spinner(self.tick), p.label);
        }
        let left = Paragraph::new(Line::from(vec![Span::styled(text, style)]));
        let right = Paragraph::new(Line::from(vec![Span::styled(
            "↑↓/jk move · ⏎ select · esc back · 1-9 tabs · q quit",
            theme::hint(),
        )]))
        .alignment(Alignment::Right);
        let chunks = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(60), Constraint::Percentage(40)])
            .split(area);
        f.render_widget(left, chunks[0]);
        f.render_widget(right, chunks[1]);
    }
}

/// The per-screen behaviour contract.
pub trait ScreenImpl {
    /// Handle a key press. `app` is available for spawning actions and
    /// updating shared state.
    fn handle_key(&mut self, app: &mut App, key: KeyEvent);

    /// Render the screen body into `area`.
    fn render(&self, app: &App, f: &mut Frame, area: Rect);

    /// Route a completed background action to this screen. The default ignores
    /// unknown labels.
    fn on_result(&mut self, _app: &mut App, _label: &str, _result: Result<Value, String>) {}
}

/// A small helper for the common "action list on the left" pattern.
pub struct ActionList {
    pub items: Vec<String>,
    pub selected: usize,
}

impl ActionList {
    pub fn new(items: Vec<String>) -> Self {
        Self { items, selected: 0 }
    }

    pub fn next(&mut self) {
        if !self.items.is_empty() {
            self.selected = (self.selected + 1) % self.items.len();
        }
    }

    pub fn previous(&mut self) {
        if !self.items.is_empty() {
            self.selected = if self.selected == 0 {
                self.items.len() - 1
            } else {
                self.selected - 1
            };
        }
    }

    pub fn selected_label(&self) -> Option<&str> {
        self.items.get(self.selected).map(|s| s.as_str())
    }
}

/// Format an atom amount as a fixed-point KVNC string (8 decimals).
pub fn format_kvnc(atoms: u64) -> String {
    const ATOM: u64 = 100_000_000;
    format!("{}.{:08}", atoms / ATOM, atoms % ATOM)
}

/// Shorten a hex string for display: `0xab12…cd34`.
pub fn short_hex(s: &str, head: usize, tail: usize) -> String {
    if s.len() <= head + tail + 1 {
        return s.to_string();
    }
    format!("{}…{}", &s[..head], &s[s.len() - tail..])
}

/// The main TUI entry point.
pub fn run(client: Client, api_url: String) -> Result<()> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut app = App::new(client, api_url);
    // Kick off the initial dashboard load.
    app.spawn("fetch head", {
        let client = app.client.clone();
        move || client.head().map_err(|e| e.to_string())
    });
    let result = run_app(&mut terminal, &mut app);

    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )?;
    terminal.show_cursor()?;
    result
}

fn run_app<B: Backend>(terminal: &mut Terminal<B>, app: &mut App) -> Result<()> {
    loop {
        terminal.draw(|f| app.render(f))?;

        if event::poll(Duration::from_millis(80))? {
            if let Event::Key(key) = event::read()? {
                if key.kind == KeyEventKind::Press {
                    app.handle_key(key);
                }
            }
        }
        app.tick = app.tick.wrapping_add(1);
        app.poll_pending();
        // Expire transient status messages.
        if let Some(until) = app.status.until {
            if Instant::now() >= until {
                app.status = StatusMsg::info("");
            }
        }
        if app.quit {
            return Ok(());
        }
    }
}

/// A wallet address in both renderings.
pub struct WalletAddress {
    pub kvnc: String,
    pub hex: String,
}
