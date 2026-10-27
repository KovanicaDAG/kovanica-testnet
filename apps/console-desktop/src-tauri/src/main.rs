//! Kovanica Console desktop shell.
//!
//! The webview only displays what this process returns. RPC calls, chain-id
//! checks, and key handling stay on this side of the bridge.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod amount;
mod connection;
mod history;
mod transfer;
mod wallet;

use amount::{format_kuna_atoms, parse_kuna_atoms};

use std::env;
use std::path::PathBuf;
use std::sync::Arc;

use connection::{
    endpoint_label, fetch_status, read_saved_url, resolve_rpc_url, write_saved_url, HttpRpc,
    NodeStatus, RPC_URL_ENV,
};
use serde::Serialize;
use std::time::Instant;
use tauri::Emitter;
use tauri::Manager;
use tauri::State;
use zeroize::Zeroizing;

/// Process-local wallet session. The keystore file lives in the app data directory.
///
/// `idle` is read so the lock thread stays alive for the process. Drop joins it.
struct WalletApp {
    idle: wallet::IdleLockThread,
    shared: Arc<wallet::WalletShared>,
    notify: Arc<dyn wallet::SessionNotify>,
}

/// Endpoint the screen should show and edit.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ConnectionConfig {
    rpc_url: String,
    endpoint_label: String,
}

fn endpoint_path(app: &tauri::AppHandle) -> Result<PathBuf, String> {
    let dir = app
        .path()
        .app_config_dir()
        .map_err(|_| "Could not open the app data directory.".to_string())?;
    std::fs::create_dir_all(&dir)
        .map_err(|_| "Could not open the app data directory.".to_string())?;
    Ok(dir.join("rpc-endpoint.json"))
}

fn current_url(app: &tauri::AppHandle) -> Result<String, String> {
    let saved = read_saved_url(&endpoint_path(app)?).map_err(|err| err.to_string())?;
    let env_value = env::var(RPC_URL_ENV).ok();
    Ok(resolve_rpc_url(saved.as_deref(), env_value.as_deref()))
}

fn config_for(rpc_url: String) -> ConnectionConfig {
    let endpoint_label = endpoint_label(&rpc_url);
    ConnectionConfig {
        rpc_url,
        endpoint_label,
    }
}

/// Saved endpoint, or the environment, or the public testnet DNS name.
#[tauri::command]
fn connection_config(app: tauri::AppHandle) -> Result<ConnectionConfig, String> {
    current_url(&app).map(config_for)
}

/// Store an endpoint in the app data directory and use it from now on.
#[tauri::command]
fn save_connection(app: tauri::AppHandle, rpc_url: String) -> Result<ConnectionConfig, String> {
    let saved = write_saved_url(&endpoint_path(&app)?, &rpc_url).map_err(|err| err.to_string())?;
    Ok(config_for(saved))
}

/// Forget the saved endpoint and return to the environment or the DNS default.
#[tauri::command]
fn reset_connection(app: tauri::AppHandle) -> Result<ConnectionConfig, String> {
    let path = endpoint_path(&app)?;
    if path.exists() {
        std::fs::remove_file(&path).map_err(|_| "Could not reset the RPC setting.".to_string())?;
    }
    current_url(&app).map(config_for)
}

/// Parse a KUNA amount. The result is a decimal atom string.
#[tauri::command]
fn parse_kuna(amount: String) -> Result<String, String> {
    parse_kuna_atoms(&amount).map(|atoms| atoms.to_string())
}

/// Format an atom string as KUNA. The input is decimal, never a float.
#[tauri::command]
fn format_kuna(atoms: String) -> Result<String, String> {
    let atoms = parse_atom_string(&atoms)?;
    Ok(format_kuna_atoms(atoms))
}

fn wallet_file<R: tauri::Runtime>(app: &tauri::AppHandle<R>) -> Result<PathBuf, String> {
    let dir = app
        .path()
        .app_config_dir()
        .map_err(|_| "Could not open the app data directory.".to_string())?;
    std::fs::create_dir_all(&dir)
        .map_err(|_| "Could not open the app data directory.".to_string())?;
    Ok(dir.join(wallet::KEYSTORE_FILE))
}

fn with_wallet<T>(
    state: &State<'_, WalletApp>,
    body: impl FnOnce(&mut wallet::WalletStore) -> Result<T, String>,
) -> Result<T, String> {
    let _idle = &state.idle;
    wallet::with_store(&state.shared, state.notify.as_ref(), body)
}

/// Whether a wallet file exists, and whether the session is open.
#[tauri::command]
fn wallet_status(
    app: tauri::AppHandle,
    state: State<'_, WalletApp>,
) -> Result<wallet::WalletStatus, String> {
    let path = wallet_file(&app)?;
    with_wallet(&state, |store| store.status(&path, Instant::now()))
}

/// Create a key. The phrase is returned once.
#[tauri::command]
fn wallet_create(
    app: tauri::AppHandle,
    state: State<'_, WalletApp>,
    passphrase: String,
) -> Result<wallet::NewWallet, String> {
    let path = wallet_file(&app)?;
    let passphrase = Zeroizing::new(passphrase);
    with_wallet(&state, |store| {
        store.create(&path, passphrase.as_str(), Instant::now())
    })
}

/// Import a 24-word seed. The phrase is not returned.
#[tauri::command]
fn wallet_import(
    app: tauri::AppHandle,
    state: State<'_, WalletApp>,
    mnemonic: String,
    passphrase: String,
) -> Result<wallet::WalletStatus, String> {
    let path = wallet_file(&app)?;
    let mnemonic = Zeroizing::new(mnemonic);
    let passphrase = Zeroizing::new(passphrase);
    with_wallet(&state, |store| {
        store.import(
            &path,
            mnemonic.as_str(),
            passphrase.as_str(),
            Instant::now(),
        )
    })
}

/// Open an existing wallet. A wrong password does not reveal the phrase.
#[tauri::command]
fn wallet_unlock(
    app: tauri::AppHandle,
    state: State<'_, WalletApp>,
    passphrase: String,
) -> Result<wallet::WalletStatus, String> {
    let path = wallet_file(&app)?;
    let passphrase = Zeroizing::new(passphrase);
    with_wallet(&state, |store| {
        store.unlock(&path, passphrase.as_str(), Instant::now())
    })
}

/// Show the recovery phrase again. The password is required. A wrong password
/// returns no phrase.
#[tauri::command]
fn wallet_reveal(
    app: tauri::AppHandle,
    state: State<'_, WalletApp>,
    passphrase: String,
) -> Result<wallet::NewWallet, String> {
    let path = wallet_file(&app)?;
    let passphrase = Zeroizing::new(passphrase);
    with_wallet(&state, |store| {
        store.reveal(&path, passphrase.as_str(), Instant::now())
    })
}

/// Drop the session and tell the webview. [`wallet_lock`] calls this.
fn lock_and_emit(
    path: &std::path::Path,
    shared: &wallet::WalletShared,
    notify: &dyn wallet::SessionNotify,
    now: Instant,
) -> Result<wallet::WalletStatus, String> {
    let outcome = wallet::with_store(shared, notify, |store| store.manual_lock(path, now))?;
    wallet::notify_manual_lock(&outcome, notify);
    Ok(outcome.status)
}

/// Drop the session. The webview hears [`wallet::WALLET_LOCKED_EVENT`] at once.
///
/// `R` is generic so the mock runtime can invoke this same command.
#[tauri::command]
fn wallet_lock<R: tauri::Runtime>(
    app: tauri::AppHandle<R>,
    state: State<'_, WalletApp>,
) -> Result<wallet::WalletStatus, String> {
    let path = wallet_file(&app)?;
    lock_and_emit(&path, &state.shared, state.notify.as_ref(), Instant::now())
}

/// Note that the user is still at the keyboard.
///
/// This is the only IPC that moves the idle deadline of an open session.
#[tauri::command]
fn wallet_touch(state: State<'_, WalletApp>) -> Result<(), String> {
    with_wallet(&state, |store| {
        store.touch(Instant::now());
        Ok(())
    })
}

/// Quote a transfer. The keystore is not decrypted.
#[tauri::command]
async fn wallet_quote(
    app: tauri::AppHandle,
    shown_chain_id: Option<String>,
    recipient: String,
    amount: String,
) -> Result<transfer::TransferQuote, String> {
    let url = current_url(&app)?;
    tauri::async_runtime::spawn_blocking(move || {
        let rpc = HttpRpc::new(url.clone()).map_err(|err| err.to_string())?;
        let wallet = app.state::<WalletApp>();
        with_wallet(&wallet, |store| {
            store.quote_on(
                &rpc,
                &url,
                transfer::TransferDraft {
                    shown_chain_id: shown_chain_id.as_deref(),
                    confirm_mainnet: false,
                    recipient: &recipient,
                    amount: &amount,
                },
                Instant::now(),
            )
        })
    })
    .await
    .map_err(|_| "The quote was interrupted.".to_string())?
}

/// Balance the node reported. It is not a light-client proof.
#[tauri::command]
async fn wallet_balance(app: tauri::AppHandle) -> Result<history::ReportedBalance, String> {
    let url = current_url(&app)?;
    let path = wallet_file(&app)?;
    tauri::async_runtime::spawn_blocking(move || {
        let rpc = HttpRpc::new(url.clone()).map_err(|err| err.to_string())?;
        let wallet = app.state::<WalletApp>();
        let address = with_wallet(&wallet, |store| {
            store
                .status(&path, Instant::now())?
                .address
                .ok_or_else(|| "Create or import a wallet first.".to_string())
        })?;
        history::reported_balance(&rpc, &address)
    })
    .await
    .map_err(|_| "The balance request was interrupted.".to_string())?
}

/// Transfers the node reported for this wallet. They are not proven.
#[tauri::command]
async fn wallet_history(app: tauri::AppHandle) -> Result<history::HistoryPage, String> {
    let url = current_url(&app)?;
    let path = wallet_file(&app)?;
    tauri::async_runtime::spawn_blocking(move || {
        let rpc = HttpRpc::new(url.clone()).map_err(|err| err.to_string())?;
        let wallet = app.state::<WalletApp>();
        let address = with_wallet(&wallet, |store| {
            store
                .status(&path, Instant::now())?
                .address
                .ok_or_else(|| "Create or import a wallet first.".to_string())
        })?;
        let chain_id = fetch_status(&rpc, &url)
            .ok()
            .and_then(|status| history::proven_chain_id(status.chain_id.as_deref()));
        history::reported_history(&rpc, &address, chain_id)
    })
    .await
    .map_err(|_| "The history request was interrupted.".to_string())?
}

/// Sign a quoted transfer. Chain 1 is refused until `confirm_mainnet` is set.
#[tauri::command]
async fn wallet_send(
    app: tauri::AppHandle,
    shown_chain_id: Option<String>,
    confirm_mainnet: bool,
    recipient: String,
    amount: String,
) -> Result<transfer::SendReceipt, String> {
    let url = current_url(&app)?;
    let path = wallet_file(&app)?;
    tauri::async_runtime::spawn_blocking(move || {
        let rpc = HttpRpc::new(url.clone()).map_err(|err| err.to_string())?;
        let status = fetch_status(&rpc, &url).map_err(|err| err.to_string())?;
        let wallet = app.state::<WalletApp>();
        with_wallet(&wallet, |store| {
            store.send_prepared(
                &rpc,
                &path,
                &status,
                transfer::TransferDraft {
                    shown_chain_id: shown_chain_id.as_deref(),
                    confirm_mainnet,
                    recipient: &recipient,
                    amount: &amount,
                },
                Instant::now(),
            )
        })
    })
    .await
    .map_err(|_| "The transfer was interrupted.".to_string())?
}

fn parse_atom_string(text: &str) -> Result<u64, String> {
    let text = text.trim();
    if text.is_empty() || !text.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err("Enter an atom amount.".to_string());
    }
    text.parse::<u64>()
        .map_err(|_| "That amount is larger than KUNA can send.".to_string())
}

/// Chain id, height, leader round, epoch, and peers. Fails with a clear error
/// when the node cannot be reached.
#[tauri::command]
async fn node_status(app: tauri::AppHandle) -> Result<NodeStatus, String> {
    let url = current_url(&app)?;
    tauri::async_runtime::spawn_blocking(move || {
        let rpc = HttpRpc::new(url.clone())?;
        fetch_status(&rpc, &url)
    })
    .await
    .map_err(|_| "The status request was interrupted.".to_string())?
    .map_err(|err| err.to_string())
}

/// Forwards a session lock to the webview. The idle thread calls this.
struct EmitSession<R: tauri::Runtime> {
    app: tauri::AppHandle<R>,
}

impl<R: tauri::Runtime> wallet::SessionNotify for EmitSession<R> {
    fn wallet_locked(&self) {
        let _ = self.app.emit(wallet::WALLET_LOCKED_EVENT, ());
    }

    fn wallet_lock_warning(&self) {
        let _ = self.app.emit(wallet::WALLET_LOCK_WARNING_EVENT, ());
    }
}

/// Session, idle thread, and the notifier that emits `wallet-locked`.
fn install_wallet<R: tauri::Runtime>(app: &tauri::AppHandle<R>) -> WalletApp {
    let shared = Arc::new(wallet::WalletShared::new());
    let notify: Arc<dyn wallet::SessionNotify> = Arc::new(EmitSession { app: app.clone() });
    let idle = wallet::IdleLockThread::spawn_with(Arc::clone(&shared), Arc::clone(&notify));
    WalletApp {
        idle,
        shared,
        notify,
    }
}

fn main() {
    tauri::Builder::default()
        .setup(|app| {
            app.manage(install_wallet(app.handle()));
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            connection_config,
            save_connection,
            reset_connection,
            node_status,
            parse_kuna,
            format_kuna,
            wallet_status,
            wallet_create,
            wallet_import,
            wallet_unlock,
            wallet_reveal,
            wallet_lock,
            wallet_touch,
            wallet_quote,
            wallet_send,
            wallet_balance,
            wallet_history
        ])
        .run(tauri::generate_context!())
        .expect("error while running Kovanica Console");
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::{install_wallet, lock_and_emit};
    use tauri::Listener;
    use tauri::Manager;

    /// The lock command's emitter is the app bus, not a string in `main.rs`.
    #[test]
    fn wallet_lock_emits_wallet_locked_on_the_app() {
        let app = tauri::test::mock_builder()
            .build(tauri::test::mock_context(tauri::test::noop_assets()))
            .expect("test app");
        let wallet = install_wallet(app.handle());
        let now = std::time::Instant::now();
        wallet
            .shared
            .lock_store()
            .open_for_test("kvnc-emit".into(), now);
        assert!(wallet.shared.lock_store().is_open_for_test());

        let hits = Arc::new(AtomicUsize::new(0));
        let seen = Arc::clone(&hits);
        app.listen(crate::wallet::WALLET_LOCKED_EVENT, move |_| {
            seen.fetch_add(1, Ordering::SeqCst);
        });

        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "kovanica-console-missing-wallet-{}-{}",
            std::process::id(),
            nanos
        ));
        assert!(!path.exists());

        let status =
            lock_and_emit(&path, &wallet.shared, wallet.notify.as_ref(), now).expect("lock");
        assert_eq!(status.phase, "absent");
        assert!(!wallet.shared.lock_store().is_open_for_test());
        assert_eq!(hits.load(Ordering::SeqCst), 1);

        let again =
            lock_and_emit(&path, &wallet.shared, wallet.notify.as_ref(), now).expect("second lock");
        assert_eq!(again.phase, "absent");
        assert_eq!(hits.load(Ordering::SeqCst), 1);
        drop(wallet);
    }

    /// The `wallet_lock` command itself emits `wallet-locked`, and a second
    /// call with no session does not emit it again.
    #[test]
    fn wallet_lock_command_emits_wallet_locked_once() {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "kovanica-console-lock-ipc-{}-{}",
            std::process::id(),
            nanos
        ));
        let _ = std::fs::remove_dir_all(&root);
        let _cleanup = RemoveDir(root.clone());

        let mut context = tauri::test::mock_context(tauri::test::noop_assets());
        context.config_mut().app.app_directories_override = Some(
            tauri::utils::config::AppDirectoriesOverride::Root(root.clone()),
        );

        let app = tauri::test::mock_builder()
            .invoke_handler(tauri::generate_handler![super::wallet_lock])
            .build(context)
            .expect("test app");
        app.manage(install_wallet(app.handle()));

        let now = std::time::Instant::now();
        {
            let wallet = app.state::<super::WalletApp>();
            wallet
                .shared
                .lock_store()
                .open_for_test("kvnc-lock-cmd".into(), now);
            assert!(wallet.shared.lock_store().is_open_for_test());
        }

        let hits = Arc::new(AtomicUsize::new(0));
        let seen = Arc::clone(&hits);
        app.listen(crate::wallet::WALLET_LOCKED_EVENT, move |_| {
            seen.fetch_add(1, Ordering::SeqCst);
        });

        let webview = tauri::WebviewWindowBuilder::new(&app, "main", Default::default())
            .build()
            .expect("webview");

        let first = tauri::test::get_ipc_response(&webview, wallet_lock_request())
            .unwrap_or_else(|err| panic!("wallet_lock failed: {err}"));
        let first = response_json(first);
        assert_eq!(first["phase"], "absent");
        assert!(first["address"].is_null());
        assert!(root.is_dir());
        assert!(!app
            .state::<super::WalletApp>()
            .shared
            .lock_store()
            .is_open_for_test());
        assert_eq!(hits.load(Ordering::SeqCst), 1);

        let second = tauri::test::get_ipc_response(&webview, wallet_lock_request())
            .unwrap_or_else(|err| panic!("second wallet_lock failed: {err}"));
        let second = response_json(second);
        assert_eq!(second["phase"], "absent");
        assert_eq!(hits.load(Ordering::SeqCst), 1);
    }

    fn wallet_lock_request() -> tauri::webview::InvokeRequest {
        tauri::webview::InvokeRequest {
            cmd: "wallet_lock".into(),
            callback: tauri::ipc::CallbackFn(0),
            error: tauri::ipc::CallbackFn(1),
            url: "tauri://localhost".parse().expect("local url"),
            body: tauri::ipc::InvokeBody::Json(serde_json::json!({})),
            headers: Default::default(),
            invoke_key: tauri::test::INVOKE_KEY.to_string(),
        }
    }

    fn response_json(body: tauri::ipc::InvokeResponseBody) -> serde_json::Value {
        match body {
            tauri::ipc::InvokeResponseBody::Json(text) => {
                serde_json::from_str(&text).expect("wallet_lock json")
            }
            tauri::ipc::InvokeResponseBody::Raw(_) => panic!("wallet_lock returned bytes"),
        }
    }

    /// Deletes a test directory when the test ends, including on failure.
    struct RemoveDir(std::path::PathBuf);

    impl Drop for RemoveDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
}
