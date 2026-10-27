//! Interactive Kovanica wallet.
//!
//! `kovanica tui` unlocks a local keystore and talks to a node over JSON-RPC.
//! Seeds are decrypted in this process only. Signing uses [`crate::tx::build_signed`]
//! and submission uses `kovanica_sendRawTransaction`, the same path as the one-shot
//! commands. Contracts stay on the `kovanica htlc`, `vault`, `multisig`, and `token`
//! commands.

mod app;
mod net;
mod ui;

use std::io::{self, stdout, Write};
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use ratatui::crossterm::event::{
    self, DisableBracketedPaste, EnableBracketedPaste, Event, KeyCode, KeyEvent, KeyEventKind,
    KeyModifiers,
};
use ratatui::crossterm::execute;
use ratatui::crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use ratatui::prelude::{CrosstermBackend, Terminal};

use crate::rpc::RpcClient;

pub use app::TuiConfig;

use app::{ensure_chain, App, Input, Job};

/// Open the wallet until the operator quits.
pub async fn run(config: TuiConfig) -> Result<()> {
    let mut app = App::new(config);
    enable_raw_mode().context("enabling raw mode")?;
    if let Err(err) = execute!(stdout(), EnterAlternateScreen, EnableBracketedPaste) {
        let _ = disable_raw_mode();
        return Err(err).context("entering the alternate screen");
    }
    let _guard = RawGuard;
    let mut terminal =
        Terminal::new(CrosstermBackend::new(stdout())).context("starting the terminal")?;
    let mut runtime = Runtime::new(app.rpc_url());
    event_loop(&mut terminal, &mut app, &mut runtime).await
}

async fn event_loop(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    app: &mut App,
    runtime: &mut Runtime,
) -> Result<()> {
    loop {
        terminal.draw(|frame| ui::draw(frame, app))?;
        if app.quit() {
            break;
        }
        if let Some(job) = app.take_job() {
            let quiet = app.job_quiet();
            run_job(app, runtime, job, quiet).await;
            continue;
        }
        if app.wants_auto_refresh() {
            app.queue_refresh(true);
            continue;
        }
        if event::poll(Duration::from_millis(200))? {
            match event::read()? {
                Event::Key(key) => {
                    if let Some(input) = map_key(key) {
                        app.handle(input);
                    }
                }
                Event::Paste(text) => app.handle(Input::Paste(text)),
                _ => {}
            }
        }
    }
    Ok(())
}

async fn run_job(app: &mut App, runtime: &mut Runtime, job: Job, quiet: bool) {
    match job {
        Job::Unlock { path, passphrase } => match net::unlock(path, passphrase).await {
            Ok(unlocked) => app.on_unlocked(unlocked),
            Err(err) => app.on_unlock_failed(err),
        },
        Job::Create { path, passphrase } => match net::create_keystore(path, passphrase).await {
            Ok(created) => app.on_created(created),
            Err(err) => app.on_create_failed(err),
        },
        Job::Import {
            path,
            mnemonic,
            passphrase,
        } => match net::import_mnemonic(path, mnemonic, passphrase).await {
            Ok(unlocked) => app.on_unlocked(unlocked),
            Err(err) => app.on_import_failed(err),
        },
        Job::Refresh => refresh(app, runtime, quiet).await,
        Job::Validators => load_validators(app, runtime).await,
        Job::Prepare(draft) => prepare(app, runtime, draft).await,
        Job::Submit => submit(app, runtime).await,
    }
}

async fn refresh(app: &mut App, runtime: &mut Runtime, quiet: bool) {
    let Some(address) = app.signer().map(|(address, _)| address) else {
        app.finish_job();
        return;
    };
    if app.rpc_url().is_empty() {
        app.on_refresh_failed(anyhow!("RPC URL is required."), quiet);
        return;
    }
    match net::fetch_snapshot(runtime.client(app.rpc_url()), &address).await {
        Ok(snapshot) => app.on_snapshot(snapshot),
        Err(err) => app.on_refresh_failed(err, quiet),
    }
}

async fn load_validators(app: &mut App, runtime: &mut Runtime) {
    if app.rpc_url().is_empty() {
        app.on_validators_failed(anyhow!("RPC URL is required."));
        return;
    }
    match net::fetch_validators(runtime.client(app.rpc_url())).await {
        Ok(rows) => app.on_validators(rows),
        Err(err) => app.on_validators_failed(err),
    }
}

async fn prepare(app: &mut App, runtime: &mut Runtime, draft: app::TxDraft) {
    let Some(address) = app.signer().map(|(address, _)| address) else {
        app.on_prepare_failed(anyhow!("Unlock a keystore first."));
        return;
    };
    let chain_id = app.chain_id();
    let client = runtime.client(app.rpc_url());
    if let Err(err) = crate::node::ensure_node_chain_matches(client, chain_id).await {
        app.on_prepare_failed(err);
        return;
    }
    match net::fetch_nonce(client, &address).await {
        Ok(nonce) => app.on_review_ready(draft, nonce),
        Err(err) => app.on_prepare_failed(err),
    }
}

async fn submit(app: &mut App, runtime: &mut Runtime) {
    let Some(review) = app.review() else {
        app.on_submit_failed(anyhow!("Nothing to sign."));
        return;
    };
    let chain_id = match ensure_chain(app.chain_id()) {
        Ok(id) => id,
        Err(message) => {
            app.on_submit_failed(anyhow!(message));
            return;
        }
    };
    let Some(address) = app.signer().map(|(address, _)| address) else {
        app.on_submit_failed(anyhow!("Unlock a keystore first."));
        return;
    };
    let nonce = match net::fetch_nonce(runtime.client(app.rpc_url()), &address).await {
        Ok(nonce) => nonce,
        Err(err) => {
            app.on_submit_failed(err);
            return;
        }
    };
    if nonce != review.nonce {
        app.on_nonce_changed(nonce);
        return;
    }
    let submitted = {
        let Some((sender, signing_key)) = app.signer() else {
            app.on_submit_failed(anyhow!("Unlock a keystore first."));
            return;
        };
        net::submit(
            runtime.client(app.rpc_url()),
            chain_id,
            sender,
            signing_key,
            review,
        )
        .await
    };
    match submitted {
        Ok(hash) => app.on_submitted(hash),
        Err(err) => app.on_submit_failed(err),
    }
}

struct Runtime {
    client: RpcClient,
    bound_url: String,
}

impl Runtime {
    fn new(url: &str) -> Self {
        let url = url.trim().to_string();
        let client = RpcClient::new(url.clone());
        Self {
            client,
            bound_url: url,
        }
    }

    fn client(&mut self, url: &str) -> &RpcClient {
        let url = url.trim();
        if self.bound_url != url {
            self.client = RpcClient::new(url);
            self.bound_url = url.to_string();
        }
        &self.client
    }
}

struct RawGuard;

impl Drop for RawGuard {
    fn drop(&mut self) {
        let _ = disable_raw_mode();
        let _ = execute!(stdout(), DisableBracketedPaste, LeaveAlternateScreen);
        let _ = stdout().flush();
    }
}

fn map_key(key: KeyEvent) -> Option<Input> {
    if key.kind == KeyEventKind::Release {
        return None;
    }
    let control = key.modifiers.contains(KeyModifiers::CONTROL);
    let alt = key.modifiers.contains(KeyModifiers::ALT);
    match key.code {
        KeyCode::Char('c') if control => Some(Input::Quit),
        KeyCode::Char('u') if control => Some(Input::ClearField),
        KeyCode::Char(ch) if !control && !alt => Some(Input::Char(ch)),
        KeyCode::Backspace => Some(Input::Backspace),
        KeyCode::Delete => Some(Input::ClearField),
        KeyCode::Enter => Some(Input::Enter),
        KeyCode::Esc => Some(Input::Esc),
        KeyCode::Tab => Some(Input::Tab),
        KeyCode::BackTab => Some(Input::BackTab),
        KeyCode::Up => Some(Input::Up),
        KeyCode::Down => Some(Input::Down),
        KeyCode::Left => Some(Input::Left),
        KeyCode::Right => Some(Input::Right),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn control_c_quits_and_release_events_are_ignored() {
        let quit = KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL);
        assert_eq!(map_key(quit), Some(Input::Quit));

        let typed = KeyEvent::new(KeyCode::Char('t'), KeyModifiers::NONE);
        assert_eq!(map_key(typed), Some(Input::Char('t')));

        let mut release = KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE);
        release.kind = KeyEventKind::Release;
        assert_eq!(map_key(release), None);
    }
}
