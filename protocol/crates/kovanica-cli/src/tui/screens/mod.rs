//! TUI screens. Each screen owns its state and implements [`ScreenImpl`].

pub mod assets;
pub mod contracts;
pub mod dashboard;
pub mod explorer;
pub mod nft_rwa;
pub mod send;
pub mod settings;
pub mod stealth;
pub mod wallet;

use crate::tui::ScreenImpl;

pub use assets::AssetsState;
pub use contracts::ContractsState;
pub use dashboard::DashboardState;
pub use explorer::ExplorerState;
pub use nft_rwa::NftRwaState;
pub use send::SendState;
pub use settings::SettingsState;
pub use stealth::StealthState;
pub use wallet::WalletState;

/// The active screen. Tab order matches the tab bar (1-9).
pub enum Screen {
    Dashboard(DashboardState),
    Wallet(WalletState),
    Send(SendState),
    Assets(AssetsState),
    Contracts(ContractsState),
    Stealth(StealthState),
    NftRwa(NftRwaState),
    Explorer(ExplorerState),
    Settings(SettingsState),
}

impl Screen {
    pub fn index(&self) -> usize {
        match self {
            Screen::Dashboard(_) => 0,
            Screen::Wallet(_) => 1,
            Screen::Send(_) => 2,
            Screen::Assets(_) => 3,
            Screen::Contracts(_) => 4,
            Screen::Stealth(_) => 5,
            Screen::NftRwa(_) => 6,
            Screen::Explorer(_) => 7,
            Screen::Settings(_) => 8,
        }
    }

    pub fn from_index(idx: usize) -> Option<Self> {
        match idx {
            0 => Some(Screen::Dashboard(DashboardState::new())),
            1 => Some(Screen::Wallet(WalletState::new())),
            2 => Some(Screen::Send(SendState::new())),
            3 => Some(Screen::Assets(AssetsState::new())),
            4 => Some(Screen::Contracts(ContractsState::new())),
            5 => Some(Screen::Stealth(StealthState::new())),
            6 => Some(Screen::NftRwa(NftRwaState::new())),
            7 => Some(Screen::Explorer(ExplorerState::new())),
            8 => Some(Screen::Settings(SettingsState::new())),
            _ => None,
        }
    }
}

impl ScreenImpl for Screen {
    fn handle_key(&mut self, app: &mut crate::tui::App, key: crossterm::event::KeyEvent) {
        match self {
            Screen::Dashboard(s) => s.handle_key(app, key),
            Screen::Wallet(s) => s.handle_key(app, key),
            Screen::Send(s) => s.handle_key(app, key),
            Screen::Assets(s) => s.handle_key(app, key),
            Screen::Contracts(s) => s.handle_key(app, key),
            Screen::Stealth(s) => s.handle_key(app, key),
            Screen::NftRwa(s) => s.handle_key(app, key),
            Screen::Explorer(s) => s.handle_key(app, key),
            Screen::Settings(s) => s.handle_key(app, key),
        }
    }

    fn render(&self, app: &crate::tui::App, f: &mut ratatui::Frame, area: ratatui::layout::Rect) {
        match self {
            Screen::Dashboard(s) => s.render(app, f, area),
            Screen::Wallet(s) => s.render(app, f, area),
            Screen::Send(s) => s.render(app, f, area),
            Screen::Assets(s) => s.render(app, f, area),
            Screen::Contracts(s) => s.render(app, f, area),
            Screen::Stealth(s) => s.render(app, f, area),
            Screen::NftRwa(s) => s.render(app, f, area),
            Screen::Explorer(s) => s.render(app, f, area),
            Screen::Settings(s) => s.render(app, f, area),
        }
    }

    fn on_result(
        &mut self,
        app: &mut crate::tui::App,
        label: &str,
        result: Result<serde_json::Value, String>,
    ) {
        match self {
            Screen::Dashboard(s) => s.on_result(app, label, result),
            Screen::Wallet(s) => s.on_result(app, label, result),
            Screen::Send(s) => s.on_result(app, label, result),
            Screen::Assets(s) => s.on_result(app, label, result),
            Screen::Contracts(s) => s.on_result(app, label, result),
            Screen::Stealth(s) => s.on_result(app, label, result),
            Screen::NftRwa(s) => s.on_result(app, label, result),
            Screen::Explorer(s) => s.on_result(app, label, result),
            Screen::Settings(s) => s.on_result(app, label, result),
        }
    }
}
