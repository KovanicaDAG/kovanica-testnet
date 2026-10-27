//! Local wallet file for Kovanica Console.
//!
//! The file is the v2 keystore JSON produced by `kovanica-light-ffi`, the same
//! document the Android wallet stores. `kovanica_keystore::parse` checks the
//! parameters. This module does not derive keys itself.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use serde::Serialize;
use zeroize::{Zeroize, Zeroizing};

/// File name inside the app data directory.
pub const KEYSTORE_FILE: &str = "wallet.keystore.json";

/// Lock the session after this long with no activity.
pub const LOCK_AFTER: Duration = Duration::from_secs(5 * 60);

/// Tauri event the webview listens for. The payload is empty.
pub const WALLET_LOCKED_EVENT: &str = "wallet-locked";

/// Tauri event sent while the session is still open, before the idle lock.
pub const WALLET_LOCK_WARNING_EVENT: &str = "wallet-lock-warning";

/// How long before the idle lock the webview is warned.
///
/// The warning does not move the deadline. Pausing the lock while a recovery
/// phrase is on screen would leave the seed and an open session unattended.
pub const LOCK_WARNING_BEFORE: Duration = Duration::from_secs(30);

/// Wait after the first wrong unlock or reveal password. Later failures double it.
const PASSPHRASE_BACKOFF_BASE: Duration = Duration::from_secs(1);

/// Longest unlock or reveal lockout. The wait stops doubling here.
const PASSPHRASE_BACKOFF_MAX: Duration = Duration::from_secs(32);

/// Largest shift that still fits in [`PASSPHRASE_BACKOFF_MAX`].
const PASSPHRASE_BACKOFF_SHIFT_CAP: u32 = 5;

/// Returned when unlock or reveal is refused because earlier passwords were wrong.
const PASSPHRASE_BACKOFF_MESSAGE: &str = "Wait a moment before trying the password again.";

/// How long a password guess stays refused after `failures` wrong passwords.
///
/// `failures` is the count after the latest real decrypt failure, shared by
/// [`WalletStore::unlock`] and [`WalletStore::reveal`]. Zero failures wait
/// nothing. The first failure waits [`PASSPHRASE_BACKOFF_BASE`]. Each further
/// failure doubles that wait, up to [`PASSPHRASE_BACKOFF_MAX`].
fn passphrase_backoff_after(failures: u32) -> Duration {
    if failures == 0 {
        return Duration::ZERO;
    }
    let shift = failures.saturating_sub(1).min(PASSPHRASE_BACKOFF_SHIFT_CAP);
    PASSPHRASE_BACKOFF_BASE
        .saturating_mul(1_u32 << shift)
        .min(PASSPHRASE_BACKOFF_MAX)
}

/// How long the idle thread sleeps when no session is open.
const IDLE_PARK: Duration = Duration::from_secs(60);

/// Tells the webview that the open session was dropped, or is about to be.
pub trait SessionNotify: Send + Sync {
    fn wallet_locked(&self);
    fn wallet_lock_warning(&self);
}

/// No UI. Tests that do not care about the event use this.
#[cfg(test)]
struct SilentSession;

#[cfg(test)]
impl SessionNotify for SilentSession {
    fn wallet_locked(&self) {}
    fn wallet_lock_warning(&self) {}
}

const PHASE_ABSENT: &str = "absent";
const PHASE_LOCKED: &str = "locked";
const PHASE_OPEN: &str = "open";

const MAX_KEYSTORE_BYTES: u64 = 64 * 1024;

/// Outcome of the lock command. The webview event is separate from the status.
pub struct ManualLock {
    /// Phase after the session was dropped.
    pub status: WalletStatus,
    /// True when this call closed an open session.
    pub session_closed: bool,
}

/// Tell the webview that a manual lock closed the session.
///
/// `SessionNotify::wallet_locked` is the `wallet-locked` event. A lock that
/// finds the session already closed does not emit it again.
pub fn notify_manual_lock(lock: &ManualLock, notify: &dyn SessionNotify) {
    if lock.session_closed {
        notify.wallet_locked();
    }
}

/// What the screen should show. The passphrase is never included.
#[derive(Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WalletStatus {
    /// `absent`, `locked`, or `open`.
    pub phase: String,
    /// Canonical address from Rust, when a wallet file exists.
    pub address: Option<String>,
}

/// A wallet whose phrase the screen may show.
///
/// `create` returns the phrase for a new key. `reveal` returns that same
/// phrase again after the password checks out. The screen holds it until the
/// user dismisses it or the session locks.
#[derive(Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NewWallet {
    /// Canonical address from `kovanica-light-ffi`.
    pub address: String,
    /// 24-word seed. Drop overwrites the buffer with zeroes.
    pub mnemonic: Zeroizing<String>,
}

pub(crate) struct OpenWallet {
    pub(crate) passphrase: Zeroizing<String>,
    pub(crate) address: String,
    pub(crate) last_active: Instant,
    pub(crate) quote: Option<crate::transfer::TransferQuote>,
}

impl Drop for OpenWallet {
    fn drop(&mut self) {
        self.passphrase.zeroize();
    }
}

/// In-memory session. The keystore file is the only copy on disk.
pub struct WalletStore {
    open: Option<OpenWallet>,
    /// Idle limit for this store. Production uses [`LOCK_AFTER`].
    lock_after: Duration,
    /// An idle lock has not yet been reported as `wallet-locked`.
    idle_lock_pending: bool,
    /// Consecutive wrong unlock or reveal passwords since the last success.
    passphrase_failures: u32,
    /// Instant before which another unlock or reveal is refused.
    passphrase_blocked_until: Option<Instant>,
}

/// Session plus the condvar the idle thread waits on.
///
/// The condvar is paired with [`WalletShared::store`]. Notify it after every
/// change to the session so the idle thread recomputes its deadline.
pub struct WalletShared {
    pub store: Mutex<WalletStore>,
    pub wake: Condvar,
}

impl WalletShared {
    /// Empty session. The idle thread is started separately.
    pub fn new() -> Self {
        Self {
            store: Mutex::new(WalletStore::new()),
            wake: Condvar::new(),
        }
    }

    /// Lock the session. A poisoned mutex still yields the store.
    pub fn lock_store(&self) -> MutexGuard<'_, WalletStore> {
        self.store.lock().unwrap_or_else(|err| err.into_inner())
    }
}

/// Run one IPC call against the session.
///
/// `session` and `status` apply the idle limit. When that call is the one
/// that locks, this emits `wallet-locked` after the mutex is released so the
/// screen can clear passphrase fields.
pub fn with_store<T>(
    shared: &WalletShared,
    notify: &dyn SessionNotify,
    body: impl FnOnce(&mut WalletStore) -> Result<T, String>,
) -> Result<T, String> {
    let mut store = shared.lock_store();
    let result = body(&mut store);
    let emit_lock = store.take_idle_lock_event();
    drop(store);
    shared.wake.notify_one();
    if emit_lock {
        notify.wallet_locked();
    }
    result
}

/// Background lock. The session is cleared after [`LOCK_AFTER`] even when the
/// webview never calls status again. A lock notifies the webview immediately.
pub struct IdleLockThread {
    shared: Arc<WalletShared>,
    stop: Arc<AtomicBool>,
    join: Mutex<Option<JoinHandle<()>>>,
}

impl IdleLockThread {
    /// Start the idle thread. Drop joins it.
    #[cfg(test)]
    pub fn spawn(shared: Arc<WalletShared>) -> Self {
        Self::spawn_with(shared, Arc::new(SilentSession))
    }

    /// Start the idle thread and report each lock to `notify`.
    pub fn spawn_with(shared: Arc<WalletShared>, notify: Arc<dyn SessionNotify>) -> Self {
        let stop = Arc::new(AtomicBool::new(false));
        let thread_shared = Arc::clone(&shared);
        let thread_stop = Arc::clone(&stop);
        let join = std::thread::Builder::new()
            .name("kovanica-wallet-idle".into())
            .spawn(move || idle_lock_loop(&thread_shared, &thread_stop, notify.as_ref()))
            .expect("wallet idle lock thread");
        Self {
            shared,
            stop,
            join: Mutex::new(Some(join)),
        }
    }
}

impl Drop for IdleLockThread {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        self.shared.wake.notify_one();
        if let Some(join) = self
            .join
            .lock()
            .unwrap_or_else(|err| err.into_inner())
            .take()
        {
            let _ = join.join();
        }
    }
}

/// How long the idle thread should sleep.
///
/// A warning does not add time. The wait until the warning plus the wait
/// after it equals the time left on the idle deadline.
fn next_idle_wait(remaining: Option<Duration>, already_warned: bool) -> Duration {
    match remaining {
        Some(left) if left.is_zero() => Duration::from_millis(1),
        Some(left) if !already_warned && left > LOCK_WARNING_BEFORE => left - LOCK_WARNING_BEFORE,
        Some(left) => left,
        None => IDLE_PARK,
    }
}

/// Sleep until the open session is idle, then clear it. A notify recomputes the wait.
fn idle_lock_loop(shared: &WalletShared, stop: &AtomicBool, notify: &dyn SessionNotify) {
    let mut store = shared.lock_store();
    let mut warned_for: Option<Instant> = None;
    while !stop.load(Ordering::SeqCst) {
        let now = Instant::now();
        if store.lock_if_idle(now) {
            // This thread emits the event. Clear the mark first so the next
            // IPC call does not emit a second one.
            let emit = store.take_idle_lock_event();
            drop(store);
            if emit {
                notify.wallet_locked();
            }
            warned_for = None;
            store = shared.lock_store();
        } else {
            let active = store.open.as_ref().map(|open| open.last_active);
            let remaining = store.idle_remaining(now);
            let should_warn = matches!(
                (active, remaining),
                (Some(active), Some(left))
                    if left <= LOCK_WARNING_BEFORE && warned_for != Some(active)
            );
            if should_warn {
                drop(store);
                notify.wallet_lock_warning();
                warned_for = active;
                store = shared.lock_store();
            } else if active.is_none() || warned_for != active {
                warned_for = None;
            }
        }
        let now = Instant::now();
        let active = store.open.as_ref().map(|open| open.last_active);
        let already_warned = active.is_some() && warned_for == active;
        let wait = next_idle_wait(store.idle_remaining(now), already_warned);
        let waited = shared.wake.wait_timeout(store, wait);
        store = match waited {
            Ok((guard, _)) => guard,
            Err(poisoned) => poisoned.into_inner().0,
        };
    }
}

impl WalletStore {
    /// No session and no file handle.
    pub fn new() -> Self {
        Self {
            open: None,
            lock_after: LOCK_AFTER,
            idle_lock_pending: false,
            passphrase_failures: 0,
            passphrase_blocked_until: None,
        }
    }

    /// Create a key. Refuses to replace or follow a file that is already there.
    pub fn create(
        &mut self,
        path: &Path,
        passphrase: &str,
        now: Instant,
    ) -> Result<NewWallet, String> {
        if passphrase.is_empty() {
            return Err("Enter a password.".to_string());
        }
        refuse_existing(path)?;
        let mut created = kovanica_light_ffi::create_wallet(passphrase.to_string())
            .map_err(|err| map_ffi_error(&err))?;
        let saved = (|| {
            let address = accept_keystore_json(&created.keystore_json)?;
            if address != created.address {
                return Err("The wallet could not be opened.".to_string());
            }
            write_new_keystore(path, created.keystore_json.as_bytes())?;
            Ok(address)
        })();
        let address = match saved {
            Ok(address) => address,
            Err(err) => {
                created.mnemonic.zeroize();
                created.keystore_json.zeroize();
                return Err(err);
            }
        };
        self.open = Some(OpenWallet {
            passphrase: Zeroizing::new(passphrase.to_string()),
            address: address.clone(),
            last_active: now,
            quote: None,
        });
        let mnemonic = Zeroizing::new(std::mem::take(&mut created.mnemonic));
        created.keystore_json.zeroize();
        Ok(NewWallet { address, mnemonic })
    }

    /// Import a 24-word seed. The phrase is not returned.
    pub fn import(
        &mut self,
        path: &Path,
        mnemonic: &str,
        passphrase: &str,
        now: Instant,
    ) -> Result<WalletStatus, String> {
        if passphrase.is_empty() {
            return Err("Enter a password.".to_string());
        }
        if mnemonic.trim().is_empty() {
            return Err("That recovery phrase is not a 24-word Kovanica seed.".to_string());
        }
        refuse_existing(path)?;
        let mut imported =
            kovanica_light_ffi::import_wallet(mnemonic.to_string(), passphrase.to_string())
                .map_err(|err| map_ffi_error(&err))?;
        let saved = (|| {
            let address = accept_keystore_json(&imported.keystore_json)?;
            if address != imported.address {
                return Err("The wallet could not be opened.".to_string());
            }
            write_new_keystore(path, imported.keystore_json.as_bytes())?;
            Ok(address)
        })();
        let address = match saved {
            Ok(address) => address,
            Err(err) => {
                imported.keystore_json.zeroize();
                return Err(err);
            }
        };
        self.open = Some(OpenWallet {
            passphrase: Zeroizing::new(passphrase.to_string()),
            address: address.clone(),
            last_active: now,
            quote: None,
        });
        imported.keystore_json.zeroize();
        Ok(WalletStatus {
            phase: PHASE_OPEN.to_string(),
            address: Some(address),
        })
    }

    /// Check the password, then keep the session open. The phrase is wiped.
    ///
    /// A wrong password is counted with [`reveal`]. Guessing here does not
    /// skip the backoff.
    pub fn unlock(
        &mut self,
        path: &Path,
        passphrase: &str,
        now: Instant,
    ) -> Result<WalletStatus, String> {
        if passphrase.is_empty() {
            return Err("Enter a password.".to_string());
        }
        let json = read_keystore(path)?;
        let mut phrase = self.decrypt_with_shared_backoff(&json, passphrase, now)?;
        phrase.zeroize();
        let address = kovanica_light_ffi::wallet_address(json)
            .map_err(|_| "Could not read the wallet.".to_string())?;
        self.open = Some(OpenWallet {
            passphrase: Zeroizing::new(passphrase.to_string()),
            address: address.clone(),
            last_active: now,
            quote: None,
        });
        Ok(WalletStatus {
            phase: PHASE_OPEN.to_string(),
            address: Some(address),
        })
    }

    /// Show the recovery phrase again. The password is checked by
    /// `kovanica_light_ffi::reveal_mnemonic_raw`.
    ///
    /// A lock drops the on-screen copy and the open session. The keystore file
    /// still holds the encrypted phrase, so this opens a new session and
    /// returns the same words. A wrong password returns no phrase. It does not
    /// open a session, and it does not close one that is already open.
    ///
    /// Wrong passwords share one counter with [`unlock`]. The next unlock or
    /// reveal is refused until [`passphrase_backoff_after`] has passed.
    /// Attempts inside that window do not decrypt and do not extend the window.
    /// A correct password after the window clears the count.
    pub fn reveal(
        &mut self,
        path: &Path,
        passphrase: &str,
        now: Instant,
    ) -> Result<NewWallet, String> {
        if passphrase.is_empty() {
            return Err("Enter a password.".to_string());
        }
        let json = read_keystore(path)?;
        let mut phrase = self.decrypt_with_shared_backoff(&json, passphrase, now)?;
        let address = match kovanica_light_ffi::wallet_address(json) {
            Ok(address) => address,
            Err(_) => {
                phrase.zeroize();
                return Err("Could not read the wallet.".to_string());
            }
        };
        self.open = Some(OpenWallet {
            passphrase: Zeroizing::new(passphrase.to_string()),
            address: address.clone(),
            last_active: now,
            quote: None,
        });
        Ok(NewWallet {
            address,
            mnemonic: Zeroizing::new(std::mem::take(&mut phrase)),
        })
    }

    /// Decrypt `json` for [`unlock`] and [`reveal`].
    ///
    /// Both calls share [`WalletStore::passphrase_failures`]. A wrong password
    /// starts the lockout. A guess inside that window is refused before
    /// decrypt. A correct password clears the count.
    fn decrypt_with_shared_backoff(
        &mut self,
        json: &str,
        passphrase: &str,
        now: Instant,
    ) -> Result<String, String> {
        if self.passphrase_is_blocked(now) {
            return Err(PASSPHRASE_BACKOFF_MESSAGE.to_string());
        }
        match kovanica_light_ffi::reveal_mnemonic_raw(json.to_owned(), passphrase.to_owned()) {
            Ok(phrase) => {
                self.clear_passphrase_backoff();
                Ok(phrase)
            }
            Err(err) => {
                self.note_passphrase_failure(now);
                Err(map_ffi_error(&err))
            }
        }
    }

    /// True when `now` is still inside the shared passphrase lockout.
    fn passphrase_is_blocked(&self, now: Instant) -> bool {
        self.passphrase_blocked_until
            .is_some_and(|until| now < until)
    }

    /// Record one wrong unlock or reveal password and start its lockout window.
    fn note_passphrase_failure(&mut self, now: Instant) {
        self.passphrase_failures = self.passphrase_failures.saturating_add(1);
        let delay = passphrase_backoff_after(self.passphrase_failures);
        self.passphrase_blocked_until = now.checked_add(delay);
    }

    /// A correct unlock or reveal password may be tried again immediately.
    fn clear_passphrase_backoff(&mut self) {
        self.passphrase_failures = 0;
        self.passphrase_blocked_until = None;
    }

    /// The open session, after an idle lock.
    pub(crate) fn session(&mut self, now: Instant) -> Result<&mut OpenWallet, String> {
        self.lock_if_idle(now);
        self.open
            .as_mut()
            .ok_or_else(|| "The wallet is locked.".to_string())
    }

    /// Drop the session. The file stays on disk.
    ///
    /// Returns whether a session was open.
    pub fn lock(&mut self) -> bool {
        self.open.take().is_some()
    }

    /// Drop the session for the lock command and read the phase afterwards.
    ///
    /// `session_closed` is true only when this call closed an open session.
    /// The caller emits `wallet-locked` in that case.
    pub fn manual_lock(&mut self, path: &Path, now: Instant) -> Result<ManualLock, String> {
        let session_closed = self.lock();
        let status = self.status(path, now)?;
        Ok(ManualLock {
            status,
            session_closed,
        })
    }

    /// Move the idle deadline of an open session.
    ///
    /// This is the only extension. Create, import, and unlock start a new
    /// deadline. Status, quote, and send leave it where it is.
    pub fn touch(&mut self, now: Instant) {
        if let Some(open) = self.open.as_mut() {
            open.last_active = now;
        }
    }

    /// Lock when `now` is at least [`LOCK_AFTER`] after the last activity.
    ///
    /// Returns whether this call cleared an open session.
    pub fn lock_if_idle(&mut self, now: Instant) -> bool {
        let limit = self.lock_after;
        let idle = self
            .open
            .as_ref()
            .is_some_and(|open| now.saturating_duration_since(open.last_active) >= limit);
        if idle {
            self.open.take();
            self.idle_lock_pending = true;
            true
        } else {
            false
        }
    }

    /// Whether an idle lock still needs a `wallet-locked` event. Clears the mark.
    #[must_use]
    pub fn take_idle_lock_event(&mut self) -> bool {
        let pending = self.idle_lock_pending;
        self.idle_lock_pending = false;
        pending
    }

    /// Time left before [`lock_if_idle`] clears the session.
    pub fn idle_remaining(&self, now: Instant) -> Option<Duration> {
        let open = self.open.as_ref()?;
        let elapsed = now.saturating_duration_since(open.last_active);
        Some(self.lock_after.saturating_sub(elapsed))
    }

    /// Phase and address. An idle session is locked first.
    pub fn status(&mut self, path: &Path, now: Instant) -> Result<WalletStatus, String> {
        self.lock_if_idle(now);
        if let Some(open) = &self.open {
            return Ok(WalletStatus {
                phase: PHASE_OPEN.to_string(),
                address: Some(open.address.clone()),
            });
        }
        if !path_exists(path)? {
            return Ok(WalletStatus {
                phase: PHASE_ABSENT.to_string(),
                address: None,
            });
        }
        let json = read_keystore(path)?;
        let address = kovanica_light_ffi::wallet_address(json)
            .map_err(|_| "Could not read the wallet.".to_string())?;
        Ok(WalletStatus {
            phase: PHASE_LOCKED.to_string(),
            address: Some(address),
        })
    }

    /// Open a session without a keystore. Tests use this for quotes that must not decrypt.
    #[cfg(test)]
    pub(crate) fn open_for_test(&mut self, address: String, now: Instant) {
        self.open = Some(OpenWallet {
            passphrase: Zeroizing::new("unused-passphrase".into()),
            address,
            last_active: now,
            quote: None,
        });
    }

    /// Whether the open session is holding a quote.
    #[cfg(test)]
    pub(crate) fn has_quote(&self) -> bool {
        self.open.as_ref().is_some_and(|open| open.quote.is_some())
    }

    /// Shorten the idle limit. Production keeps [`LOCK_AFTER`].
    #[cfg(test)]
    pub(crate) fn set_lock_after_for_test(&mut self, lock_after: Duration) {
        self.lock_after = lock_after;
    }

    /// True when a session is open. Does not apply the idle limit.
    #[cfg(test)]
    pub(crate) fn is_open_for_test(&self) -> bool {
        self.open.is_some()
    }

    /// Deadline anchor, when a session is open.
    #[cfg(test)]
    pub(crate) fn last_active_for_test(&self) -> Option<Instant> {
        self.open.as_ref().map(|open| open.last_active)
    }

    /// Wrong unlock or reveal passwords since the last success.
    #[cfg(test)]
    fn passphrase_failures_for_test(&self) -> u32 {
        self.passphrase_failures
    }

    /// When the shared passphrase lockout ends, if one is active.
    #[cfg(test)]
    fn passphrase_block_for_test(&self) -> Option<Instant> {
        self.passphrase_blocked_until
    }
}

impl Default for WalletStore {
    fn default() -> Self {
        Self::new()
    }
}

/// Map a light-ffi failure onto a fixed sentence. The raw text is never returned.
pub(crate) fn map_ffi_error(err: &kovanica_light_ffi::LightFfiError) -> String {
    let lower = err.to_string().to_ascii_lowercase();
    if lower.contains("passphrase is empty") {
        "Enter a password.".to_string()
    } else if lower.contains("mnemonic") || lower.contains("bip-39") || lower.contains("bip39") {
        "That recovery phrase is not a 24-word Kovanica seed.".to_string()
    } else if lower.contains("authentication")
        || lower.contains("decrypt")
        || lower.contains("passphrase")
    {
        "That password does not open this wallet.".to_string()
    } else {
        "The wallet could not be opened.".to_string()
    }
}

fn refuse_existing(path: &Path) -> Result<(), String> {
    match fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_symlink() => {
            Err("Refusing to write the wallet through a symlink.".to_string())
        }
        Ok(_) => Err("A wallet already exists on this device.".to_string()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err("Could not save the wallet.".to_string()),
    }
}

fn path_exists(path: &Path) -> Result<bool, String> {
    match fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_symlink() => {
            Err("Refusing to read the wallet through a symlink.".to_string())
        }
        Ok(_) => Ok(true),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(_) => Err("Could not read the wallet.".to_string()),
    }
}

/// Accept a keystore only when `kovanica_keystore::parse` does.
fn accept_keystore_json(json: &str) -> Result<String, String> {
    let parsed = kovanica_keystore::parse(json.as_bytes())
        .map_err(|_| "Could not save the wallet.".to_string())?;
    kovanica_keystore::address(&parsed)
        .map(|address| address.to_string())
        .map_err(|_| "Could not save the wallet.".to_string())
}

fn write_new_keystore(path: &Path, bytes: &[u8]) -> Result<(), String> {
    if bytes.len() as u64 > MAX_KEYSTORE_BYTES {
        return Err("Could not save the wallet.".to_string());
    }
    refuse_existing(path)?;
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    fs::create_dir_all(parent).map_err(|_| "Could not open the app data directory.".to_string())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(parent, fs::Permissions::from_mode(0o700))
            .map_err(|_| "Could not save the wallet.".to_string())?;
    }
    let tmp_name = format!(
        ".{}.tmp",
        path.file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("wallet")
    );
    let tmp = parent.join(tmp_name);
    if fs::symlink_metadata(&tmp).is_ok() {
        return Err("Could not save the wallet.".to_string());
    }
    {
        let mut options = OpenOptions::new();
        options.create_new(true).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options
            .open(&tmp)
            .map_err(|_| "Could not save the wallet.".to_string())?;
        file.write_all(bytes)
            .map_err(|_| "Could not save the wallet.".to_string())?;
        file.sync_all()
            .map_err(|_| "Could not save the wallet.".to_string())?;
    }
    fs::rename(&tmp, path).map_err(|_| {
        let _ = fs::remove_file(&tmp);
        "Could not save the wallet.".to_string()
    })?;
    Ok(())
}

pub(crate) fn read_keystore(path: &Path) -> Result<String, String> {
    path_exists(path)?;
    let file = fs::File::open(path).map_err(|_| "Could not read the wallet.".to_string())?;
    let mut bytes = Vec::new();
    use std::io::Read;
    file.take(MAX_KEYSTORE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "Could not read the wallet.".to_string())?;
    if bytes.len() as u64 > MAX_KEYSTORE_BYTES {
        return Err("Could not read the wallet.".to_string());
    }
    String::from_utf8(bytes).map_err(|_| "Could not read the wallet.".to_string())
}

#[cfg(test)]
struct WarningOrder {
    events: Mutex<Vec<&'static str>>,
    shared: Arc<WalletShared>,
}

#[cfg(test)]
impl SessionNotify for WarningOrder {
    fn wallet_locked(&self) {
        assert!(!self.shared.lock_store().is_open_for_test());
        self.events.lock().expect("events").push("locked");
    }

    fn wallet_lock_warning(&self) {
        assert!(self.shared.lock_store().is_open_for_test());
        self.events.lock().expect("events").push("warning");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;
    use std::sync::atomic::{AtomicBool, Ordering};

    struct RecordedLock {
        locked: AtomicBool,
    }

    struct NamedLock {
        events: Mutex<Vec<&'static str>>,
    }

    impl SessionNotify for NamedLock {
        fn wallet_locked(&self) {
            self.events
                .lock()
                .expect("events")
                .push(WALLET_LOCKED_EVENT);
        }

        fn wallet_lock_warning(&self) {}
    }

    impl SessionNotify for RecordedLock {
        fn wallet_locked(&self) {
            self.locked.store(true, Ordering::SeqCst);
        }

        fn wallet_lock_warning(&self) {}
    }

    fn temp_dir(name: &str) -> std::path::PathBuf {
        let dir =
            std::env::temp_dir().join(format!("kovanica-console-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn keystore_in(dir: &Path) -> std::path::PathBuf {
        dir.join(KEYSTORE_FILE)
    }

    fn must<T>(result: Result<T, String>) -> T {
        match result {
            Ok(value) => value,
            Err(err) => panic!("{err}"),
        }
    }

    fn must_err<T>(result: Result<T, String>) -> String {
        match result {
            Ok(_) => panic!("expected the wallet call to fail"),
            Err(err) => err,
        }
    }

    #[test]
    fn new_wallet_mnemonic_is_wiped_on_drop() {
        use zeroize::{Zeroize, ZeroizeOnDrop};

        fn assert_wiped_on_drop(mnemonic: &Zeroizing<String>) {
            fn bound<T: Zeroize + ZeroizeOnDrop>(_: &T) {}
            bound(mnemonic);
        }

        let words = "alpha beta gamma delta";
        let mut wallet = NewWallet {
            address: "kvnc".to_string(),
            mnemonic: Zeroizing::new(words.to_string()),
        };
        assert_wiped_on_drop(&wallet.mnemonic);
        assert_eq!(wallet.mnemonic.as_str(), words);
        let json = serde_json::to_value(&wallet).unwrap();
        assert_eq!(json["mnemonic"].as_str(), Some(words));

        wallet.mnemonic.zeroize();
        assert_eq!(wallet.mnemonic.as_str(), "");
        let cleared = serde_json::to_string(&wallet).unwrap();
        assert!(!cleared.contains(words));
        assert!(!cleared.contains("alpha"));

        let held = NewWallet {
            address: "kvnc".to_string(),
            mnemonic: Zeroizing::new(words.to_string()),
        };
        assert_eq!(held.mnemonic.as_str(), words);
        drop(held);
    }

    #[test]
    fn wallet_source_does_not_log_secrets() {
        let src = include_str!("wallet.rs");
        let body = src.split("mod tests").next().unwrap_or(src);
        assert!(!body.contains("print"));
        assert!(!body.contains("dbg!"));
        assert!(!body.contains("tracing"));
        assert!(!body.contains("log::"));
    }

    #[test]
    fn ffi_errors_do_not_echo_the_secret() {
        let word = "zznotawordzz";
        let err = kovanica_light_ffi::LightFfiError::Failed {
            reason: format!("invalid mnemonic word {word}"),
        };
        let mapped = map_ffi_error(&err);
        assert_eq!(
            mapped,
            "That recovery phrase is not a 24-word Kovanica seed."
        );
        assert!(!mapped.contains(word));

        let password = "wrong-horse-marker";
        let err = kovanica_light_ffi::LightFfiError::Failed {
            reason: format!("keystore authentication failed for {password}"),
        };
        let mapped = map_ffi_error(&err);
        assert_eq!(mapped, "That password does not open this wallet.");
        assert!(!mapped.contains(password));
    }

    #[test]
    fn a_bad_phrase_is_rejected_before_the_file_is_written() {
        let dir = temp_dir("bad-phrase");
        let path = keystore_in(&dir);
        let mut store = WalletStore::new();
        let marker = "zznotawordzz";
        let err = must_err(store.import(&path, marker, "import-password", Instant::now()));
        assert_eq!(err, "That recovery phrase is not a 24-word Kovanica seed.");
        assert!(!err.contains(marker));
        assert!(!path.exists());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_empty_password_is_rejected() {
        let dir = temp_dir("empty-password");
        let path = keystore_in(&dir);
        let mut store = WalletStore::new();
        let err = must_err(store.create(&path, "", Instant::now()));
        assert_eq!(err, "Enter a password.");
        assert!(!path.exists());
        let _ = fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn a_symlink_is_not_a_wallet_file() {
        use std::os::unix::fs::symlink;
        let dir = temp_dir("symlink");
        let target = dir.join("elsewhere");
        fs::write(&target, b"keep").unwrap();
        let path = keystore_in(&dir);
        symlink(&target, &path).unwrap();
        let mut store = WalletStore::new();
        let err = must_err(store.create(&path, "symlink-password", Instant::now()));
        assert_eq!(err, "Refusing to write the wallet through a symlink.");
        assert_eq!(fs::read(&target).unwrap(), b"keep");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn create_writes_an_android_v2_keystore_and_locks_when_idle() {
        let dir = temp_dir("create");
        let path = keystore_in(&dir);
        let mut store = WalletStore::new();
        let now = Instant::now();
        let created = must(store.create(&path, "create-password", now));
        assert_eq!(created.mnemonic.split_whitespace().count(), 24);

        let bytes = fs::read(&path).unwrap();
        let text = String::from_utf8(bytes.clone()).unwrap();
        assert!(!text.contains(created.mnemonic.as_str()));
        let value: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(value["version"], 2);
        assert_eq!(value["encrypted"], true);
        assert_eq!(value["cipher"], "xchacha20poly1305");
        assert_eq!(value["kdf"], "argon2id");
        assert_eq!(value["kdf_memory_kib"], 65_536);
        assert_eq!(value["kdf_iterations"], 3);
        assert_eq!(value["kdf_parallelism"], 4);
        assert_eq!(value["secret_key"].as_str().unwrap().len(), (32 + 16) * 2);
        let parsed = kovanica_keystore::parse(&bytes).unwrap();
        assert_eq!(
            kovanica_keystore::address(&parsed).unwrap().to_string(),
            created.address
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }

        let status = must(store.status(&path, now));
        assert_eq!(status.phase, PHASE_OPEN);
        let status_json = serde_json::to_string(&status).unwrap();
        assert!(!status_json.contains(created.mnemonic.as_str()));

        let err = must_err(store.create(&path, "create-password", now));
        assert_eq!(err, "A wallet already exists on this device.");

        let err = must_err(store.unlock(&path, "wrong-horse-marker", now));
        assert_eq!(err, "That password does not open this wallet.");
        assert!(!err.contains("wrong-horse-marker"));

        store.touch(now + Duration::from_secs(200));
        let still_open = must(store.status(
            &path,
            now + Duration::from_secs(200) + LOCK_AFTER - Duration::from_secs(1),
        ));
        assert_eq!(still_open.phase, PHASE_OPEN);

        let locked = must(store.status(&path, now + Duration::from_secs(200) + LOCK_AFTER));
        assert_eq!(locked.phase, PHASE_LOCKED);
        assert_eq!(locked.address.as_deref(), Some(created.address.as_str()));

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn status_does_not_extend_idle_and_only_touch_does() {
        let path = Path::new("missing-idle-wallet");
        let mut store = WalletStore::new();
        let now = Instant::now();
        store.open_for_test("kvnc-idle".into(), now);
        let later = now + Duration::from_secs(30);
        let status = must(store.status(path, later));
        assert_eq!(status.phase, PHASE_OPEN);
        assert_eq!(store.last_active_for_test(), Some(now));
        store.touch(later);
        assert_eq!(store.last_active_for_test(), Some(later));
        let still = must(store.status(path, later + LOCK_AFTER - Duration::from_secs(1)));
        assert_eq!(still.phase, PHASE_OPEN);
        assert!(store.session(later + LOCK_AFTER).is_err());
        assert!(!store.is_open_for_test());
        store.touch(later + LOCK_AFTER + Duration::from_secs(1));
        assert!(store.last_active_for_test().is_none());
        assert!(!store.is_open_for_test());
    }

    #[test]
    fn idle_thread_clears_the_session_without_a_status_poll() {
        let shared = Arc::new(WalletShared::new());
        {
            let mut store = shared.lock_store();
            store.set_lock_after_for_test(Duration::from_millis(40));
            store.open_for_test("kvnc-timer".into(), Instant::now());
        }
        let idle = IdleLockThread::spawn(Arc::clone(&shared));
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut cleared = false;
        while Instant::now() < deadline {
            if !shared.lock_store().is_open_for_test() {
                cleared = true;
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        drop(idle);
        assert!(cleared, "idle thread left the session open");
        shared.lock_store().touch(Instant::now());
        assert!(!shared.lock_store().is_open_for_test());
    }

    #[test]
    fn import_round_trips_the_same_keystore_parser() {
        let phrase = kovanica_keystore::seed_to_mnemonic(&[0x11; 32]).unwrap();
        let dir = temp_dir("import");
        let path = keystore_in(&dir);
        let mut store = WalletStore::new();
        let now = Instant::now();
        let status = must(store.import(&path, &phrase, "import-password", now));
        assert_eq!(status.phase, PHASE_OPEN);
        let bytes = fs::read(&path).unwrap();
        let text = String::from_utf8(bytes.clone()).unwrap();
        assert!(!text.contains(&phrase));
        let parsed = kovanica_keystore::parse(&bytes).unwrap();
        assert_eq!(
            kovanica_keystore::address(&parsed).unwrap().to_string(),
            status.address.unwrap()
        );
        assert_eq!(parsed.kdf.as_deref(), Some("argon2id"));
        assert_eq!(parsed.cipher.as_deref(), Some("xchacha20poly1305"));
        store.lock();
        let locked = must(store.status(&path, now));
        assert_eq!(locked.phase, PHASE_LOCKED);
        let _ = fs::remove_dir_all(&dir);
    }

    /// Encrypted keystore from `kovanica_keystore::from_seed(&[0x5A; 32], "cross-check")`.
    ///
    /// The ciphertext lives in `tests/fixtures`, not in this source file.
    fn cross_keystore_json() -> String {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/cross-keystore.json");
        fs::read_to_string(&path)
            .expect("encrypted test vector fixture")
            .trim()
            .to_string()
    }

    #[test]
    fn reveal_shows_the_phrase_again_after_the_session_is_gone() {
        let phrase = kovanica_keystore::seed_to_mnemonic(&[0x5A; 32]).unwrap();
        let dir = temp_dir("reveal");
        let path = keystore_in(&dir);
        fs::write(&path, cross_keystore_json()).unwrap();
        let mut store = WalletStore::new();
        let now = Instant::now();

        let err = must_err(store.reveal(&path, "", now));
        assert_eq!(err, "Enter a password.");
        assert!(!store.is_open_for_test());

        let err = must_err(store.reveal(&path, "wrong-horse-marker", now));
        assert_eq!(err, "That password does not open this wallet.");
        assert!(!err.contains("wrong-horse-marker"));
        assert!(!err.contains(&phrase));
        assert!(!store.is_open_for_test());
        assert_eq!(fs::read(&path).unwrap(), cross_keystore_json().as_bytes());

        let revealed = must(store.reveal(&path, "cross-check", now + passphrase_backoff_after(1)));
        assert_eq!(revealed.mnemonic.as_str(), phrase.as_str());
        assert_eq!(revealed.mnemonic.split_whitespace().count(), 24);
        assert_eq!(
            revealed.address,
            "kvncp464qa2wpqq2t53ham6cycp4we4ek0j6zkrg49q2k2yetpuguwc8hj0hadag"
        );
        let status = must(store.status(&path, now));
        assert_eq!(status.phase, PHASE_OPEN);
        let status_json = serde_json::to_string(&status).unwrap();
        assert!(!status_json.contains(&phrase));
        assert!(!fs::read_to_string(&path).unwrap().contains(&phrase));

        assert!(store.lock());
        let locked = must(store.status(&path, now));
        assert_eq!(locked.phase, PHASE_LOCKED);
        assert!(!store.is_open_for_test());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn wrong_reveal_passwords_are_throttled_until_the_window_ends() {
        assert_eq!(passphrase_backoff_after(0), Duration::ZERO);
        assert_eq!(passphrase_backoff_after(1), Duration::from_secs(1));
        assert_eq!(passphrase_backoff_after(2), Duration::from_secs(2));
        assert_eq!(passphrase_backoff_after(3), Duration::from_secs(4));
        assert_eq!(passphrase_backoff_after(6), PASSPHRASE_BACKOFF_MAX);
        assert_eq!(passphrase_backoff_after(100), PASSPHRASE_BACKOFF_MAX);

        let phrase = kovanica_keystore::seed_to_mnemonic(&[0x5A; 32]).unwrap();
        let dir = temp_dir("reveal-backoff");
        let path = keystore_in(&dir);
        fs::write(&path, cross_keystore_json()).unwrap();
        let mut store = WalletStore::new();
        let now = Instant::now();

        let err = must_err(store.reveal(&path, "", now));
        assert_eq!(err, "Enter a password.");
        assert_eq!(store.passphrase_failures_for_test(), 0);
        assert!(store.passphrase_block_for_test().is_none());

        let err = must_err(store.reveal(&path, "wrong-horse-marker", now));
        assert_eq!(err, "That password does not open this wallet.");
        assert!(!err.contains("wrong-horse-marker"));
        assert!(!err.contains(&phrase));
        assert!(!store.is_open_for_test());
        assert_eq!(store.passphrase_failures_for_test(), 1);
        let first_wait = passphrase_backoff_after(1);
        assert_eq!(
            store.passphrase_block_for_test(),
            now.checked_add(first_wait)
        );

        let err = must_err(store.reveal(&path, "cross-check", now));
        assert_eq!(err, PASSPHRASE_BACKOFF_MESSAGE);
        assert!(!err.contains(&phrase));
        assert!(!store.is_open_for_test());
        assert_eq!(store.passphrase_failures_for_test(), 1);
        assert_eq!(fs::read(&path).unwrap(), cross_keystore_json().as_bytes());

        let err = must_err(store.reveal(
            &path,
            "wrong-horse-marker",
            now + first_wait - Duration::from_millis(1),
        ));
        assert_eq!(err, PASSPHRASE_BACKOFF_MESSAGE);
        assert_eq!(store.passphrase_failures_for_test(), 1);

        let second = now + first_wait;
        let err = must_err(store.reveal(&path, "wrong-horse-marker", second));
        assert_eq!(err, "That password does not open this wallet.");
        assert_eq!(store.passphrase_failures_for_test(), 2);
        let second_wait = passphrase_backoff_after(2);
        assert!(second_wait > first_wait);
        assert_eq!(
            store.passphrase_block_for_test(),
            second.checked_add(second_wait)
        );

        let err = must_err(store.reveal(&path, "cross-check", second));
        assert_eq!(err, PASSPHRASE_BACKOFF_MESSAGE);
        assert!(!store.is_open_for_test());

        let revealed = must(store.reveal(&path, "cross-check", second + second_wait));
        assert_eq!(revealed.mnemonic.as_str(), phrase.as_str());
        assert!(store.is_open_for_test());
        assert_eq!(store.passphrase_failures_for_test(), 0);
        assert!(store.passphrase_block_for_test().is_none());
        let _ = fs::remove_dir_all(&dir);
    }

    /// Unlock and reveal share one counter. A wrong unlock must throttle a
    /// later reveal, and a wrong reveal must throttle a later unlock.
    #[test]
    fn unlock_and_reveal_share_one_backoff() {
        assert_eq!(passphrase_backoff_after(0), Duration::ZERO);
        assert_eq!(passphrase_backoff_after(1), Duration::from_secs(1));
        assert_eq!(passphrase_backoff_after(2), Duration::from_secs(2));
        assert_eq!(passphrase_backoff_after(3), Duration::from_secs(4));
        assert_eq!(passphrase_backoff_after(4), Duration::from_secs(8));
        assert_eq!(passphrase_backoff_after(5), Duration::from_secs(16));
        assert_eq!(passphrase_backoff_after(6), Duration::from_secs(32));
        assert_eq!(passphrase_backoff_after(7), PASSPHRASE_BACKOFF_MAX);
        assert_eq!(passphrase_backoff_after(100), PASSPHRASE_BACKOFF_MAX);
        assert_eq!(PASSPHRASE_BACKOFF_MAX, Duration::from_secs(32));

        let phrase = kovanica_keystore::seed_to_mnemonic(&[0x5A; 32]).unwrap();
        let dir = temp_dir("shared-backoff");
        let path = keystore_in(&dir);
        fs::write(&path, cross_keystore_json()).unwrap();
        let mut store = WalletStore::new();
        let now = Instant::now();

        let err = must_err(store.unlock(&path, "", now));
        assert_eq!(err, "Enter a password.");
        assert_eq!(store.passphrase_failures_for_test(), 0);
        assert!(store.passphrase_block_for_test().is_none());

        let err = must_err(store.unlock(&path, "wrong-horse-marker", now));
        assert_eq!(err, "That password does not open this wallet.");
        assert!(!err.contains("wrong-horse-marker"));
        assert!(!err.contains(&phrase));
        assert!(!store.is_open_for_test());
        assert_eq!(store.passphrase_failures_for_test(), 1);
        let first_wait = Duration::from_secs(1);
        assert_eq!(
            store.passphrase_block_for_test(),
            now.checked_add(first_wait)
        );

        let err = must_err(store.reveal(&path, "cross-check", now));
        assert_eq!(err, PASSPHRASE_BACKOFF_MESSAGE);
        assert!(!err.contains(&phrase));
        assert!(!store.is_open_for_test());
        assert_eq!(store.passphrase_failures_for_test(), 1);

        let err = must_err(store.unlock(
            &path,
            "cross-check",
            now + first_wait - Duration::from_millis(1),
        ));
        assert_eq!(err, PASSPHRASE_BACKOFF_MESSAGE);
        assert!(!store.is_open_for_test());
        assert_eq!(store.passphrase_failures_for_test(), 1);

        let second = now + first_wait;
        let err = must_err(store.reveal(&path, "wrong-horse-marker", second));
        assert_eq!(err, "That password does not open this wallet.");
        assert!(!err.contains(&phrase));
        assert_eq!(store.passphrase_failures_for_test(), 2);
        let second_wait = Duration::from_secs(2);
        assert!(second_wait > first_wait);
        assert_eq!(
            store.passphrase_block_for_test(),
            second.checked_add(second_wait)
        );

        let err = must_err(store.unlock(&path, "cross-check", second));
        assert_eq!(err, PASSPHRASE_BACKOFF_MESSAGE);
        assert!(!err.contains(&phrase));
        assert!(!store.is_open_for_test());
        assert_eq!(store.passphrase_failures_for_test(), 2);

        let mut cursor = second + second_wait;
        let mut previous = second_wait;
        let mut use_unlock = true;
        while previous < PASSPHRASE_BACKOFF_MAX {
            let err = if use_unlock {
                must_err(store.unlock(&path, "wrong-horse-marker", cursor))
            } else {
                must_err(store.reveal(&path, "wrong-horse-marker", cursor))
            };
            assert_eq!(err, "That password does not open this wallet.");
            assert!(!err.contains(&phrase));
            let wait = passphrase_backoff_after(store.passphrase_failures_for_test());
            assert!(wait > previous);
            assert!(wait <= PASSPHRASE_BACKOFF_MAX);
            assert_eq!(store.passphrase_block_for_test(), cursor.checked_add(wait));
            previous = wait;
            cursor += wait;
            use_unlock = !use_unlock;
        }
        assert_eq!(previous, Duration::from_secs(32));
        assert_eq!(store.passphrase_failures_for_test(), 6);

        let err = must_err(store.unlock(&path, "wrong-horse-marker", cursor));
        assert_eq!(err, "That password does not open this wallet.");
        let capped = passphrase_backoff_after(store.passphrase_failures_for_test());
        assert_eq!(capped, Duration::from_secs(32));
        assert_eq!(store.passphrase_failures_for_test(), 7);
        assert_eq!(
            store.passphrase_block_for_test(),
            cursor.checked_add(capped)
        );

        let err = must_err(store.reveal(&path, "cross-check", cursor));
        assert_eq!(err, PASSPHRASE_BACKOFF_MESSAGE);
        assert!(!err.contains(&phrase));
        assert!(!store.is_open_for_test());
        assert_eq!(store.passphrase_failures_for_test(), 7);

        let opened = must(store.unlock(&path, "cross-check", cursor + capped));
        assert_eq!(opened.phase, PHASE_OPEN);
        assert!(store.is_open_for_test());
        assert_eq!(store.passphrase_failures_for_test(), 0);
        assert!(store.passphrase_block_for_test().is_none());
        let status_json = serde_json::to_string(&opened).unwrap();
        assert!(!status_json.contains(&phrase));

        let revealed = must(store.reveal(&path, "cross-check", cursor + capped));
        assert_eq!(revealed.mnemonic.as_str(), phrase.as_str());
        assert_eq!(store.passphrase_failures_for_test(), 0);
        assert!(store.passphrase_block_for_test().is_none());
        assert_eq!(fs::read(&path).unwrap(), cross_keystore_json().as_bytes());
        let _ = fs::remove_dir_all(&dir);
    }

    /// The unlocked screen uses the same reveal path. A wrong password returns
    /// no phrase, counts toward the shared backoff, and leaves the session open.
    #[test]
    fn reveal_from_an_open_session_checks_the_passphrase() {
        let phrase = kovanica_keystore::seed_to_mnemonic(&[0x5A; 32]).unwrap();
        let dir = temp_dir("reveal-open");
        let path = keystore_in(&dir);
        fs::write(&path, cross_keystore_json()).unwrap();
        let mut store = WalletStore::new();
        let now = Instant::now();

        let status = must(store.unlock(&path, "cross-check", now));
        assert_eq!(status.phase, PHASE_OPEN);
        assert!(store.is_open_for_test());
        assert_eq!(store.passphrase_failures_for_test(), 0);

        let err = must_err(store.reveal(&path, "wrong-horse-marker", now));
        assert_eq!(err, "That password does not open this wallet.");
        assert!(!err.contains("wrong-horse-marker"));
        assert!(!err.contains(&phrase));
        assert!(store.is_open_for_test());
        assert_eq!(store.passphrase_failures_for_test(), 1);
        let wait = passphrase_backoff_after(1);
        assert_eq!(store.passphrase_block_for_test(), now.checked_add(wait));

        let err = must_err(store.reveal(&path, "cross-check", now));
        assert_eq!(err, PASSPHRASE_BACKOFF_MESSAGE);
        assert!(!err.contains(&phrase));
        assert!(store.is_open_for_test());
        assert_eq!(store.passphrase_failures_for_test(), 1);

        let revealed = must(store.reveal(&path, "cross-check", now + wait));
        assert_eq!(revealed.mnemonic.as_str(), phrase.as_str());
        assert_eq!(revealed.mnemonic.split_whitespace().count(), 24);
        assert_eq!(
            revealed.address,
            "kvncp464qa2wpqq2t53ham6cycp4we4ek0j6zkrg49q2k2yetpuguwc8hj0hadag"
        );
        assert!(store.is_open_for_test());
        assert_eq!(store.passphrase_failures_for_test(), 0);
        assert!(store.passphrase_block_for_test().is_none());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_fixed_keystore_vector_uses_keystore_validation() {
        let body = include_str!("wallet.rs").split("mod tests").next().unwrap();
        assert!(!body.contains("kdf_memory_kib"));
        assert!(!body.contains("65_536"));
        assert!(!body.contains("kdf_iterations"));

        let address = must(accept_keystore_json(&cross_keystore_json()));
        let parsed = kovanica_keystore::parse(cross_keystore_json().as_bytes()).unwrap();
        assert_eq!(
            kovanica_keystore::address(&parsed).unwrap().to_string(),
            address
        );
        assert_eq!(
            kovanica_keystore::secret_seed(&parsed, Some("cross-check"))
                .unwrap()
                .as_ref(),
            &[0x5A; 32]
        );

        let mut tampered: Value = serde_json::from_str(&cross_keystore_json()).unwrap();
        tampered["kdf_iterations"] = Value::from(1);
        let bad = serde_json::to_string(&tampered).unwrap();
        assert!(accept_keystore_json(&bad).is_err());
        assert!(kovanica_keystore::parse(bad.as_bytes()).is_err());
    }

    #[test]
    fn jarvis_cross_keystore_core_to_desktop_and_back() {
        let dir = temp_dir("jarvis-cross");
        let path = keystore_in(&dir);
        let ks = kovanica_keystore::from_seed(&[0x22; 32], "core-password").unwrap();
        let addr = kovanica_keystore::address(&ks).unwrap().to_string();
        let json = serde_json::to_string(&ks).unwrap();
        fs::write(&path, json).unwrap();
        let mut store = WalletStore::new();
        let st = must(store.unlock(&path, "core-password", Instant::now()));
        assert_eq!(st.address.as_deref(), Some(addr.as_str()));
        assert!(store.unlock(&path, "nope", Instant::now()).is_err());
        let _ = fs::remove_dir_all(&dir);

        let dir = temp_dir("jarvis-cross2");
        let path = keystore_in(&dir);
        let mut store = WalletStore::new();
        let created = must(store.create(&path, "desk-password", Instant::now()));
        let parsed = kovanica_keystore::parse(&fs::read(&path).unwrap()).unwrap();
        let sk = kovanica_keystore::signing_key(&parsed, Some("desk-password")).unwrap();
        let seed = kovanica_keystore::seed_from_mnemonic(created.mnemonic.as_str()).unwrap();
        assert_eq!(sk.to_bytes(), *seed);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn jarvis_idle_lock_drops_session_and_quote_path() {
        let mut store = WalletStore::new();
        let now = Instant::now();
        store.open_for_test("x".into(), now);
        assert!(store
            .session(now + LOCK_AFTER - Duration::from_millis(1))
            .is_ok());
        assert!(store.session(now + LOCK_AFTER).is_err());
        assert!(store.open.is_none());
        // touching after lock must not reopen
        store.touch(now + LOCK_AFTER + Duration::from_secs(1));
        assert!(store.open.is_none());
    }

    #[test]
    fn lock_if_idle_reports_only_the_transition() {
        let mut store = WalletStore::new();
        let now = Instant::now();
        assert!(!store.lock_if_idle(now));
        assert!(!store.lock());
        store.open_for_test("kvnc-event".into(), now);
        assert!(store.lock());
        store.open_for_test("kvnc-event".into(), now);
        assert!(!store.lock_if_idle(now + LOCK_AFTER - Duration::from_millis(1)));
        assert!(store.lock_if_idle(now + LOCK_AFTER));
        assert!(!store.lock_if_idle(now + LOCK_AFTER));
        assert!(!store.is_open_for_test());
    }

    #[test]
    fn idle_thread_emits_a_lock_without_a_status_poll() {
        let shared = Arc::new(WalletShared::new());
        let recorded = Arc::new(RecordedLock {
            locked: AtomicBool::new(false),
        });
        {
            let mut store = shared.lock_store();
            store.set_lock_after_for_test(Duration::from_millis(40));
            store.open_for_test("kvnc-event".into(), Instant::now());
        }
        let idle = IdleLockThread::spawn_with(Arc::clone(&shared), recorded.clone());
        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline && !recorded.locked.load(Ordering::SeqCst) {
            std::thread::sleep(Duration::from_millis(10));
        }
        drop(idle);
        assert!(
            recorded.locked.load(Ordering::SeqCst),
            "idle thread did not emit a lock"
        );
        assert!(!shared.lock_store().is_open_for_test());
    }

    #[test]
    fn manual_lock_emits_wallet_locked_when_a_session_closes() {
        let dir = temp_dir("manual-lock");
        let path = keystore_in(&dir);
        fs::write(&path, cross_keystore_json()).unwrap();
        let mut store = WalletStore::new();
        let now = Instant::now();
        let address = "kvncp464qa2wpqq2t53ham6cycp4we4ek0j6zkrg49q2k2yetpuguwc8hj0hadag";
        store.open_for_test(address.to_string(), now);
        let notify = NamedLock {
            events: Mutex::new(Vec::new()),
        };

        let outcome = must(store.manual_lock(&path, now));
        assert!(outcome.session_closed);
        assert_eq!(outcome.status.phase, PHASE_LOCKED);
        assert_eq!(outcome.status.address.as_deref(), Some(address));
        notify_manual_lock(&outcome, &notify);
        assert_eq!(
            notify.events.lock().expect("events").as_slice(),
            [WALLET_LOCKED_EVENT]
        );
        assert!(!store.is_open_for_test());

        let again = must(store.manual_lock(&path, now));
        assert!(!again.session_closed);
        assert_eq!(again.status.phase, PHASE_LOCKED);
        notify_manual_lock(&again, &notify);
        assert_eq!(
            notify.events.lock().expect("events").as_slice(),
            [WALLET_LOCKED_EVENT]
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn ipc_session_lock_emits_wallet_locked_once() {
        let shared = Arc::new(WalletShared::new());
        let notify = NamedLock {
            events: Mutex::new(Vec::new()),
        };
        let now = Instant::now();
        shared.lock_store().open_for_test("kvnc-ipc".into(), now);

        let open = must(with_store(&shared, &notify, |store| {
            store.session(now).map(|open| open.address.clone())
        }));
        assert_eq!(open, "kvnc-ipc");
        assert!(notify.events.lock().expect("events").is_empty());

        let err = with_store(&shared, &notify, |store| {
            store
                .session(now + LOCK_AFTER)
                .map(|open| open.address.clone())
        });
        assert!(err.is_err());
        assert!(!shared.lock_store().is_open_for_test());
        assert_eq!(
            notify.events.lock().expect("events").as_slice(),
            [WALLET_LOCKED_EVENT]
        );

        let err = with_store(&shared, &notify, |store| {
            store
                .session(now + LOCK_AFTER)
                .map(|open| open.address.clone())
        });
        assert!(err.is_err());
        assert_eq!(
            notify.events.lock().expect("events").as_slice(),
            [WALLET_LOCKED_EVENT]
        );
    }

    #[test]
    fn the_encrypted_test_vector_fixture_loads_and_is_ignored() {
        let loaded = cross_keystore_json();
        let value: Value = serde_json::from_str(&loaded).expect("fixture json");
        assert_eq!(value["version"], 2);
        assert_eq!(value["encrypted"], true);
        assert_eq!(value["cipher"], "xchacha20poly1305");
        assert_eq!(value["kdf"], "argon2id");
        assert_eq!(value["secret_key"].as_str().map(str::len), Some(96));
        let body = include_str!("wallet.rs").split("mod tests").next().unwrap();
        assert!(!body.contains("CROSS_KEYSTORE_JSON"));

        let ignore = include_str!("../../../../.gitleaksignore");
        let historical = "62f487532da42ada4cd656ea3de1d89db0bb8ea0:apps/console-desktop/src-tauri/src/wallet.rs:generic-api-key:735";
        assert!(
            ignore.lines().any(|line| line.trim() == historical),
            "gitleaks fingerprint for the old encrypted test vector is missing"
        );
        let fixture = "apps/console-desktop/src-tauri/tests/fixtures/cross-keystore.json";
        let line_no = loaded.lines().count();
        assert_eq!(line_no, 1);
        let dir_fingerprint = format!("{fixture}:generic-api-key:{line_no}");
        assert!(
            ignore.lines().any(|line| line.trim() == dir_fingerprint),
            "gitleaks directory fingerprint for the encrypted test vector is missing"
        );
    }

    #[test]
    fn a_lock_warning_does_not_extend_the_idle_deadline() {
        let left = Duration::from_secs(5 * 60);
        let until_warning = next_idle_wait(Some(left), false);
        assert_eq!(until_warning, left - LOCK_WARNING_BEFORE);
        let after_warning = next_idle_wait(Some(LOCK_WARNING_BEFORE), true);
        assert_eq!(after_warning, LOCK_WARNING_BEFORE);
        assert_eq!(until_warning + after_warning, left);
        let short = Duration::from_secs(10);
        assert_eq!(next_idle_wait(Some(short), false), short);
        assert_eq!(WALLET_LOCK_WARNING_EVENT, "wallet-lock-warning");
        let main = include_str!("main.rs");
        assert!(main.contains("emit(wallet::WALLET_LOCK_WARNING_EVENT"));
    }

    #[test]
    fn idle_thread_warns_while_the_session_is_still_open() {
        let shared = Arc::new(WalletShared::new());
        let order = Arc::new(WarningOrder {
            events: Mutex::new(Vec::new()),
            shared: Arc::clone(&shared),
        });
        {
            let mut store = shared.lock_store();
            store.set_lock_after_for_test(Duration::from_millis(300));
            store.open_for_test("kvnc-warn".into(), Instant::now());
        }
        let started = Instant::now();
        let idle = IdleLockThread::spawn_with(Arc::clone(&shared), order.clone());
        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline && order.events.lock().expect("events").len() < 2 {
            std::thread::sleep(Duration::from_millis(10));
        }
        drop(idle);
        assert_eq!(
            order.events.lock().expect("events").as_slice(),
            ["warning", "locked"]
        );
        assert!(started.elapsed() < Duration::from_secs(3));
        assert!(!shared.lock_store().is_open_for_test());
    }
}
