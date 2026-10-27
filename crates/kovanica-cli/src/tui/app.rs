//! Screen state for the interactive wallet.
//!
//! Key handling is synchronous and tested without a terminal. Secret fields are
//! wiped with [`zeroize`] when they are discarded. The signing key stays inside
//! [`Session`] and is dropped on lock or quit.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use kovanica_types::signing::chain_id;
use kovanica_types::transaction::TransactionKind;
use kovanica_types::{Address, SigningKey};
use zeroize::{Zeroize, Zeroizing};

use crate::amount::{self, format_atoms_pair, format_fee};
use crate::tui::net::{Snapshot, ValidatorRow};
use crate::tx;
use crate::wallet;

const REFRESH_EVERY: Duration = Duration::from_secs(4);
const PATH_LIMIT: usize = 2048;
const SECRET_LIMIT: usize = 1024;
const MNEMONIC_LIMIT: usize = 512;
const ADDRESS_LIMIT: usize = 160;
const AMOUNT_LIMIT: usize = 40;
const FEE_LIMIT: usize = 24;

const TRANSFER_FIELDS: [FormFocus; 3] = [FormFocus::To, FormFocus::Amount, FormFocus::Fee];
const AMOUNT_FIELDS: [FormFocus; 2] = [FormFocus::Amount, FormFocus::Fee];
const DELEGATE_FIELDS: [FormFocus; 3] = [FormFocus::Validator, FormFocus::Amount, FormFocus::Fee];
const CLAIM_FIELDS: [FormFocus; 2] = [FormFocus::Validator, FormFocus::Fee];
const GATE_ORDER: [GateFocus; 6] = [
    GateFocus::Keystore,
    GateFocus::Rpc,
    GateFocus::Chain,
    GateFocus::Unlock,
    GateFocus::Create,
    GateFocus::Import,
];

/// Arguments for [`super::run`].
pub struct TuiConfig {
    /// JSON-RPC endpoint. `/rpc` is appended when it is missing.
    pub rpc_url: String,
    /// Registered chain id. `None` means the operator still has to choose one.
    pub chain_id: Option<u64>,
    /// Encrypted keystore path.
    pub keystore: PathBuf,
}

/// A key or paste event, detached from the terminal crate so navigation tests
/// do not need a tty.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Input {
    /// A typed character.
    Char(char),
    /// Bracketed paste.
    Paste(String),
    /// Delete the previous character.
    Backspace,
    /// Wipe the focused field.
    ClearField,
    /// Activate the focused control.
    Enter,
    /// Leave the current screen.
    Esc,
    /// Next field.
    Tab,
    /// Previous field.
    BackTab,
    /// Previous item.
    Up,
    /// Next item.
    Down,
    /// Previous chain, when the chain control is focused.
    Left,
    /// Next chain, when the chain control is focused.
    Right,
    /// Leave the wallet.
    Quit,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum GateFocus {
    Keystore,
    Rpc,
    Chain,
    Unlock,
    Create,
    Import,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum FormKind {
    Transfer,
    Stake,
    Unstake,
    Delegate,
    Claim,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum FormFocus {
    To,
    Validator,
    Amount,
    Fee,
}

/// Reviewed transaction. Pressing `y` is what signs it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Review {
    /// Native action to sign.
    pub action: TxAction,
    /// Fee in atoms. Never zero.
    pub fee: u64,
    /// Nonce that will be signed. It is read again immediately before submit.
    pub nonce: u64,
}

/// Form contents after they parse, before the nonce is known.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct TxDraft {
    /// Native action to sign.
    pub action: TxAction,
    /// Fee in atoms.
    pub fee: u64,
}

/// Native transaction the wallet knows how to sign.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TxAction {
    /// `TransactionKind::Transfer`.
    Transfer { to: Address, amount: u64 },
    /// `TransactionKind::Stake`.
    Stake { amount: u64 },
    /// `TransactionKind::Unstake`.
    Unstake { amount: u64 },
    /// `TransactionKind::Delegate`.
    Delegate { validator: Address, amount: u64 },
    /// `TransactionKind::ClaimRewards`. `None` claims every delegation.
    Claim { validator: Option<Address> },
}

impl TxAction {
    /// Short name used on the review screen.
    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::Transfer { .. } => "transfer",
            Self::Stake { .. } => "stake",
            Self::Unstake { .. } => "unstake",
            Self::Delegate { .. } => "delegate",
            Self::Claim { .. } => "claim rewards",
        }
    }

    /// The consensus transaction kind corresponding to this action.
    pub(crate) fn kind(self) -> TransactionKind {
        match self {
            Self::Transfer { to, amount } => TransactionKind::Transfer { to, amount },
            Self::Stake { amount } => TransactionKind::Stake { amount },
            Self::Unstake { amount } => TransactionKind::Unstake { amount },
            Self::Delegate { validator, amount } => TransactionKind::Delegate { validator, amount },
            Self::Claim { validator } => TransactionKind::ClaimRewards { validator },
        }
    }
}

enum SecretStep {
    Unlock,
    CreateFirst,
    CreateConfirm {
        first: Zeroizing<String>,
    },
    ImportPhrase,
    ImportPassFirst {
        mnemonic: Zeroizing<String>,
    },
    ImportPassConfirm {
        mnemonic: Zeroizing<String>,
        first: Zeroizing<String>,
    },
}

enum SecretKind {
    Unlock,
    CreateFirst,
    CreateConfirm,
    ImportPhrase,
    ImportPassFirst,
    ImportPassConfirm,
}

enum Screen {
    Gate { focus: GateFocus },
    Secret { step: SecretStep },
    Home,
    Validators { selected: usize },
    Form { kind: FormKind, focus: FormFocus },
    Confirm { review: Review },
    Backup { phrase: Zeroizing<String> },
}

enum ScreenKind {
    Gate,
    Secret,
    Home,
    Validators,
    Form,
    Confirm,
    Backup,
}

#[derive(Clone, Copy)]
enum Slot {
    Keystore,
    Rpc,
    Secret,
    To,
    Amount,
    Fee,
    Validator,
}

/// Background work the terminal loop runs between frames.
pub(crate) enum Job {
    /// Decrypt an existing keystore.
    Unlock {
        path: PathBuf,
        passphrase: Zeroizing<String>,
    },
    /// Generate a keystore and its one-time recovery phrase.
    Create {
        path: PathBuf,
        passphrase: Zeroizing<String>,
    },
    /// Encrypt an imported 24-word phrase.
    Import {
        path: PathBuf,
        mnemonic: Zeroizing<String>,
        passphrase: Zeroizing<String>,
    },
    /// Reload the home-screen account figures.
    Refresh,
    /// Reload `kovanica_getValidators`.
    Validators,
    /// Read the nonce, then open the review screen.
    Prepare(TxDraft),
    /// Re-read the nonce, sign, and submit.
    Submit,
}

struct Session {
    address: Address,
    signing_key: SigningKey,
}

/// Status line. Transient notes are cleared when a background job finishes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Notice {
    /// Text shown in the footer.
    pub text: String,
    /// Render the text as a failure.
    pub is_error: bool,
    /// Clear this note when the current job finishes successfully.
    pub transient: bool,
}

/// What the terminal is allowed to draw. Passphrases are already masked.
pub(crate) struct View {
    /// Selected chain, if any.
    pub chain_id: Option<u64>,
    /// Human-readable chain label, including `MAINNET` when relevant.
    pub chain_label: String,
    /// RPC endpoint currently in the editor.
    pub rpc_url: String,
    /// Keystore path currently in the editor.
    pub keystore_path: String,
    /// Active screen.
    pub screen: ViewScreen,
    /// Footer note.
    pub notice: Option<Notice>,
    /// Last quiet refresh failure. It does not replace a review or a hash.
    pub sync_error: Option<String>,
    /// Short description of background work, shown in the title.
    pub activity: Option<&'static str>,
}

/// Drawable screen contents.
pub(crate) enum ViewScreen {
    /// Locked wallet.
    Gate { focus: GateFocus },
    /// Passphrase or recovery phrase.
    Secret {
        title: &'static str,
        hint: &'static str,
        input: String,
    },
    /// Balances and staking totals.
    Home {
        address: String,
        snapshot: Option<Snapshot>,
    },
    /// `kovanica_getValidators`.
    Validators {
        rows: Vec<ValidatorRow>,
        selected: usize,
        loaded: bool,
    },
    /// Transfer, stake, unstake, delegate, or claim.
    Form {
        kind: FormKind,
        focus: FormFocus,
        to: String,
        amount: String,
        fee: String,
        validator: String,
    },
    /// Last screen before a signature is produced.
    Confirm {
        action: &'static str,
        lines: Vec<(String, String)>,
        warning: Option<&'static str>,
    },
    /// One-time recovery phrase.
    Backup { address: String, words: Vec<String> },
}

/// Interactive wallet state.
pub(crate) struct App {
    screen: Screen,
    rpc_url: String,
    chain_id: Option<u64>,
    keystore_path: String,
    secret_input: String,
    to: String,
    amount: String,
    fee: String,
    validator: String,
    notice: Option<Notice>,
    sync_error: Option<String>,
    snapshot: Option<Snapshot>,
    validators: Vec<ValidatorRow>,
    validators_loaded: bool,
    session: Option<Session>,
    job: Option<Job>,
    job_quiet: bool,
    quit: bool,
    last_refresh: Option<Instant>,
}

impl App {
    pub(crate) fn new(config: TuiConfig) -> Self {
        Self {
            screen: Screen::Gate {
                focus: GateFocus::Unlock,
            },
            rpc_url: config.rpc_url,
            chain_id: config.chain_id,
            keystore_path: config.keystore.display().to_string(),
            secret_input: String::new(),
            to: String::new(),
            amount: String::new(),
            fee: "1".to_string(),
            validator: String::new(),
            notice: None,
            sync_error: None,
            snapshot: None,
            validators: Vec::new(),
            validators_loaded: false,
            session: None,
            job: None,
            job_quiet: false,
            quit: false,
            last_refresh: None,
        }
    }

    pub(crate) fn handle(&mut self, input: Input) {
        if matches!(input, Input::Quit) {
            self.request_quit();
            return;
        }
        if self.job.is_some() {
            return;
        }
        match self.screen_kind() {
            ScreenKind::Gate => self.handle_gate(input),
            ScreenKind::Secret => self.handle_secret(input),
            ScreenKind::Home => self.handle_home(input),
            ScreenKind::Validators => self.handle_validators(input),
            ScreenKind::Form => self.handle_form(input),
            ScreenKind::Confirm => self.handle_confirm(input),
            ScreenKind::Backup => self.handle_backup(input),
        }
    }

    pub(crate) fn quit(&self) -> bool {
        self.quit
    }

    pub(crate) fn job_quiet(&self) -> bool {
        self.job_quiet
    }

    pub(crate) fn take_job(&mut self) -> Option<Job> {
        self.job.take()
    }

    pub(crate) fn rpc_url(&self) -> &str {
        self.rpc_url.trim()
    }

    pub(crate) fn chain_id(&self) -> Option<u64> {
        self.chain_id
    }

    pub(crate) fn wants_auto_refresh(&self) -> bool {
        if self.job.is_some() || self.session.is_none() || !matches!(self.screen, Screen::Home) {
            return false;
        }
        match self.last_refresh {
            None => true,
            Some(then) => then.elapsed() >= REFRESH_EVERY,
        }
    }

    pub(crate) fn queue_refresh(&mut self, quiet: bool) {
        if self.session.is_none() || self.job.is_some() {
            return;
        }
        self.job = Some(Job::Refresh);
        self.job_quiet = quiet;
        if !quiet {
            self.progress("Refreshing…");
        }
    }

    pub(crate) fn signer(&self) -> Option<(Address, &SigningKey)> {
        self.session
            .as_ref()
            .map(|session| (session.address, &session.signing_key))
    }

    pub(crate) fn review(&self) -> Option<Review> {
        match &self.screen {
            Screen::Confirm { review } => Some(*review),
            _ => None,
        }
    }

    pub(crate) fn on_unlocked(&mut self, unlocked: crate::tui::net::Unlocked) {
        self.session = Some(Session {
            address: unlocked.address,
            signing_key: unlocked.signing_key,
        });
        self.snapshot = None;
        self.validators.clear();
        self.validators_loaded = false;
        self.last_refresh = None;
        self.sync_error = None;
        self.finish_job();
        wipe(&mut self.secret_input);
        self.screen = Screen::Home;
        if ensure_chain(self.chain_id).is_err() {
            self.error(
                "No registered signing network is selected. Lock, then use left and right, before sending KUNA.",
            );
        }
        self.queue_refresh(true);
    }

    pub(crate) fn on_created(&mut self, created: crate::tui::net::Created) {
        self.session = Some(Session {
            address: created.unlocked.address,
            signing_key: created.unlocked.signing_key,
        });
        self.finish_job();
        wipe(&mut self.secret_input);
        self.screen = Screen::Backup {
            phrase: created.phrase,
        };
        self.info("Write the phrase down. Enter hides it. It is shown only this once.");
    }

    pub(crate) fn on_unlock_failed(&mut self, err: anyhow::Error) {
        self.finish_job();
        wipe(&mut self.secret_input);
        self.error(explain_unlock(&err));
    }

    pub(crate) fn on_create_failed(&mut self, err: anyhow::Error) {
        self.finish_job();
        wipe(&mut self.secret_input);
        self.screen = Screen::Secret {
            step: SecretStep::CreateFirst,
        };
        self.error(format!(
            "Could not create the keystore: {}",
            user_message(&err)
        ));
    }

    pub(crate) fn on_import_failed(&mut self, err: anyhow::Error) {
        let mnemonic = self.clone_import_mnemonic();
        self.finish_job();
        wipe(&mut self.secret_input);
        if let Some(mnemonic) = mnemonic {
            self.screen = Screen::Secret {
                step: SecretStep::ImportPassFirst { mnemonic },
            };
        }
        self.error(format!(
            "Could not import the keystore: {}",
            user_message(&err)
        ));
    }

    pub(crate) fn on_snapshot(&mut self, snapshot: Snapshot) {
        self.snapshot = Some(snapshot);
        self.sync_error = None;
        self.last_refresh = Some(Instant::now());
        self.finish_job();
    }

    pub(crate) fn on_refresh_failed(&mut self, err: anyhow::Error, quiet: bool) {
        self.last_refresh = Some(Instant::now());
        let message = format!("Refresh failed: {}", user_message(&err));
        self.sync_error = Some(message.clone());
        self.finish_job();
        if !quiet {
            self.error(message);
        }
    }

    pub(crate) fn on_validators(&mut self, rows: Vec<ValidatorRow>) {
        self.validators = rows;
        self.validators_loaded = true;
        if let Screen::Validators { selected } = &mut self.screen {
            *selected = clamp_index(*selected, self.validators.len());
        }
        self.finish_job();
    }

    pub(crate) fn on_validators_failed(&mut self, err: anyhow::Error) {
        self.finish_job();
        self.error(format!("Could not load validators: {}", user_message(&err)));
    }

    pub(crate) fn on_review_ready(&mut self, draft: TxDraft, nonce: u64) {
        self.finish_job();
        self.screen = Screen::Confirm {
            review: Review {
                action: draft.action,
                fee: draft.fee,
                nonce,
            },
        };
        self.info("Review the transaction. y signs it on this machine. n goes back.");
    }

    pub(crate) fn on_prepare_failed(&mut self, err: anyhow::Error) {
        self.finish_job();
        self.error(format!(
            "Could not read the account nonce: {}",
            user_message(&err)
        ));
    }

    pub(crate) fn on_nonce_changed(&mut self, nonce: u64) {
        if let Screen::Confirm { review } = &mut self.screen {
            review.nonce = nonce;
        }
        self.finish_job();
        self.error(format!(
            "The account nonce changed to {nonce}. Review the transaction again, then press y."
        ));
    }

    pub(crate) fn on_submitted(&mut self, hash: String) {
        let network = chain_title(self.chain_id);
        wipe(&mut self.to);
        wipe(&mut self.amount);
        wipe(&mut self.validator);
        self.screen = Screen::Home;
        self.finish_job();
        if hash.is_empty() {
            self.info(format!(
                "The node accepted the transaction on {network} but returned no hash."
            ));
        } else {
            self.info(format!("Submitted {hash} on {network}."));
        }
        self.queue_refresh(true);
    }

    pub(crate) fn on_submit_failed(&mut self, err: anyhow::Error) {
        self.finish_job();
        self.error(format!(
            "Transaction was not submitted: {}",
            user_message(&err)
        ));
    }

    pub(crate) fn finish_job(&mut self) {
        self.job = None;
        self.job_quiet = false;
        if self.notice.as_ref().is_some_and(|notice| notice.transient) {
            self.notice = None;
        }
    }

    pub(crate) fn view(&self) -> View {
        View {
            chain_id: self.chain_id,
            chain_label: chain_title(self.chain_id),
            rpc_url: self.rpc_url.trim().to_string(),
            keystore_path: self.keystore_path.clone(),
            screen: self.view_screen(),
            notice: self.notice.clone(),
            sync_error: self.sync_error.clone(),
            activity: self.activity(),
        }
    }

    fn view_screen(&self) -> ViewScreen {
        match &self.screen {
            Screen::Gate { focus } => ViewScreen::Gate { focus: *focus },
            Screen::Secret { step } => {
                let (title, hint, masked) = secret_copy(step);
                ViewScreen::Secret {
                    title,
                    hint,
                    input: self.secret_display(masked),
                }
            }
            Screen::Home => ViewScreen::Home {
                address: self
                    .address_text()
                    .unwrap_or_else(|| "No keystore is unlocked.".to_string()),
                snapshot: self.snapshot,
            },
            Screen::Validators { selected } => ViewScreen::Validators {
                rows: self.validators.clone(),
                selected: *selected,
                loaded: self.validators_loaded,
            },
            Screen::Form { kind, focus } => ViewScreen::Form {
                kind: *kind,
                focus: *focus,
                to: self.to.clone(),
                amount: self.amount.clone(),
                fee: self.fee.clone(),
                validator: self.validator.clone(),
            },
            Screen::Confirm { review } => ViewScreen::Confirm {
                action: review.action.label(),
                lines: self.confirm_lines(*review),
                warning: confirm_warning(self.chain_id),
            },
            Screen::Backup { phrase } => ViewScreen::Backup {
                address: self
                    .address_text()
                    .unwrap_or_else(|| "address unavailable".to_string()),
                words: phrase.split_whitespace().map(str::to_string).collect(),
            },
        }
    }

    fn confirm_lines(&self, review: Review) -> Vec<(String, String)> {
        let mut lines = vec![
            ("network".to_string(), chain_title(self.chain_id)),
            (
                "from".to_string(),
                self.address_text().unwrap_or_else(|| "locked".to_string()),
            ),
        ];
        match review.action {
            TxAction::Transfer { to, amount } => {
                lines.push(("to".to_string(), to.to_string()));
                lines.push(("amount".to_string(), format_atoms_pair(amount)));
            }
            TxAction::Stake { amount } => {
                lines.push(("action".to_string(), "stake".to_string()));
                lines.push(("amount".to_string(), format_atoms_pair(amount)));
            }
            TxAction::Unstake { amount } => {
                lines.push(("action".to_string(), "unstake".to_string()));
                lines.push(("amount".to_string(), format_atoms_pair(amount)));
            }
            TxAction::Delegate { validator, amount } => {
                lines.push(("validator".to_string(), validator.to_string()));
                lines.push(("amount".to_string(), format_atoms_pair(amount)));
            }
            TxAction::Claim { validator } => {
                lines.push((
                    "validator".to_string(),
                    validator
                        .map(|address| address.to_string())
                        .unwrap_or_else(|| "all delegations".to_string()),
                ));
            }
        }
        lines.push(("fee".to_string(), format_fee(review.fee)));
        lines.push(("nonce".to_string(), review.nonce.to_string()));
        lines
    }

    fn secret_display(&self, masked: bool) -> String {
        if masked {
            "*".repeat(self.secret_input.chars().count())
        } else {
            self.secret_input.clone()
        }
    }

    fn activity(&self) -> Option<&'static str> {
        match self.job {
            Some(Job::Refresh) => Some("syncing"),
            Some(Job::Unlock { .. }) => Some("decrypting"),
            Some(Job::Create { .. } | Job::Import { .. }) => Some("encrypting"),
            Some(Job::Prepare(_)) => Some("reading nonce"),
            Some(Job::Submit) => Some("signing"),
            Some(Job::Validators) => Some("loading validators"),
            None => None,
        }
    }

    fn handle_gate(&mut self, input: Input) {
        let focus = match &self.screen {
            Screen::Gate { focus } => *focus,
            _ => return,
        };
        match input {
            Input::Tab | Input::Down => {
                self.screen = Screen::Gate {
                    focus: cycle_gate(focus, true),
                };
            }
            Input::BackTab | Input::Up => {
                self.screen = Screen::Gate {
                    focus: cycle_gate(focus, false),
                };
            }
            Input::Right if focus == GateFocus::Chain => self.step_signing_chain(true),
            Input::Left if focus == GateFocus::Chain => self.step_signing_chain(false),
            Input::Enter => self.activate_gate(focus),
            Input::Esc => self.request_quit(),
            other @ (Input::Char(_) | Input::Paste(_) | Input::Backspace | Input::ClearField) => {
                self.edit_focused(other);
            }
            Input::Left | Input::Right | Input::Quit => {}
        }
    }

    fn handle_secret(&mut self, input: Input) {
        match input {
            Input::Enter => self.accept_secret(),
            Input::Esc => {
                wipe(&mut self.secret_input);
                self.screen = Screen::Gate {
                    focus: GateFocus::Unlock,
                };
                self.info("Cancelled.");
            }
            other @ (Input::Char(_) | Input::Paste(_) | Input::Backspace | Input::ClearField) => {
                self.edit_focused(other);
            }
            _ => {}
        }
    }

    fn handle_home(&mut self, input: Input) {
        match input {
            Input::Char('t' | 'T') => self.open_form(FormKind::Transfer),
            Input::Char('s' | 'S') => self.open_form(FormKind::Stake),
            Input::Char('u' | 'U') => self.open_form(FormKind::Unstake),
            Input::Char('d' | 'D') => self.open_form(FormKind::Delegate),
            Input::Char('c' | 'C') => self.open_form(FormKind::Claim),
            Input::Char('v' | 'V') => self.open_validators(),
            Input::Char('r' | 'R') => self.queue_refresh(false),
            Input::Char('l' | 'L') | Input::Esc => self.lock(),
            Input::Char('q' | 'Q') => self.request_quit(),
            _ => {}
        }
    }

    fn handle_validators(&mut self, input: Input) {
        match input {
            Input::Up | Input::Char('k' | 'K') => self.move_validator(-1),
            Input::Down | Input::Char('j' | 'J') => self.move_validator(1),
            Input::Enter | Input::Char('d' | 'D') => self.delegate_selected(),
            Input::Char('r' | 'R') => {
                if self.job.is_none() {
                    self.job = Some(Job::Validators);
                    self.job_quiet = false;
                    self.progress("Loading validators…");
                }
            }
            Input::Esc => {
                self.screen = Screen::Home;
                self.notice = None;
            }
            Input::Char('q' | 'Q') => self.request_quit(),
            _ => {}
        }
    }

    fn handle_form(&mut self, input: Input) {
        let Some((kind, focus)) = self.form_state() else {
            return;
        };
        match input {
            Input::Tab | Input::Down => {
                self.screen = Screen::Form {
                    kind,
                    focus: cycle_field(kind, focus, true),
                };
            }
            Input::BackTab | Input::Up => {
                self.screen = Screen::Form {
                    kind,
                    focus: cycle_field(kind, focus, false),
                };
            }
            Input::Enter => {
                let fields = fields(kind);
                let index = fields.iter().position(|item| *item == focus).unwrap_or(0);
                if index + 1 == fields.len() {
                    self.begin_review();
                } else {
                    self.screen = Screen::Form {
                        kind,
                        focus: fields[index + 1],
                    };
                }
            }
            Input::Esc => {
                self.screen = Screen::Home;
                self.notice = None;
            }
            other @ (Input::Char(_) | Input::Paste(_) | Input::Backspace | Input::ClearField) => {
                self.edit_focused(other);
            }
            _ => {}
        }
    }

    fn handle_confirm(&mut self, input: Input) {
        match input {
            Input::Char('y' | 'Y') => self.confirm_sign(),
            Input::Char('n' | 'N') | Input::Esc => self.cancel_review(),
            Input::Char('q' | 'Q') => self.request_quit(),
            _ => {}
        }
    }

    fn handle_backup(&mut self, input: Input) {
        match input {
            Input::Enter => self.acknowledge_backup(true),
            Input::Esc => self.acknowledge_backup(false),
            _ => self.info(
                "Press enter after you have written the phrase down. Esc hides it. The keystore is already saved.",
            ),
        }
    }

    fn activate_gate(&mut self, focus: GateFocus) {
        match focus {
            GateFocus::Keystore => {
                self.screen = Screen::Gate {
                    focus: GateFocus::Rpc,
                };
            }
            GateFocus::Rpc => {
                self.screen = Screen::Gate {
                    focus: GateFocus::Chain,
                };
            }
            GateFocus::Chain => {
                self.screen = Screen::Gate {
                    focus: GateFocus::Unlock,
                };
            }
            GateFocus::Unlock => self.begin_unlock(),
            GateFocus::Create => self.begin_create(),
            GateFocus::Import => self.begin_import(),
        }
    }

    fn begin_unlock(&mut self) {
        let path = self.keystore_path_buf();
        if let Err(message) = ensure_readable_keystore(&path) {
            self.error(message);
            return;
        }
        if self.rpc_url.trim().is_empty() {
            self.error("RPC URL is required.");
            return;
        }
        wipe(&mut self.secret_input);
        self.screen = Screen::Secret {
            step: SecretStep::Unlock,
        };
        self.progress("Keystore passphrase. It stays on this machine.");
    }

    fn begin_create(&mut self) {
        if let Err(message) = ensure_creatable(&self.keystore_path_buf()) {
            self.error(message);
            return;
        }
        wipe(&mut self.secret_input);
        self.screen = Screen::Secret {
            step: SecretStep::CreateFirst,
        };
        self.progress("Choose a passphrase. It encrypts the keystore on this machine.");
    }

    fn begin_import(&mut self) {
        if let Err(message) = ensure_creatable(&self.keystore_path_buf()) {
            self.error(message);
            return;
        }
        wipe(&mut self.secret_input);
        self.screen = Screen::Secret {
            step: SecretStep::ImportPhrase,
        };
        self.progress("Enter the 24-word recovery phrase. It stays on this machine.");
    }

    fn accept_secret(&mut self) {
        let kind = match &self.screen {
            Screen::Secret { step } => secret_kind(step),
            _ => return,
        };
        match kind {
            SecretKind::Unlock => self.submit_unlock(),
            SecretKind::CreateFirst => self.advance_create(),
            SecretKind::CreateConfirm => self.finish_create_passphrase(),
            SecretKind::ImportPhrase => self.advance_import_phrase(),
            SecretKind::ImportPassFirst => self.advance_import_pass(),
            SecretKind::ImportPassConfirm => self.finish_import_passphrase(),
        }
    }

    fn submit_unlock(&mut self) {
        if self.secret_input.is_empty() {
            self.error("Passphrase is required.");
            return;
        }
        let passphrase = take_string(&mut self.secret_input);
        self.job = Some(Job::Unlock {
            path: self.keystore_path_buf(),
            passphrase,
        });
        self.job_quiet = false;
        self.progress("Decrypting keystore…");
    }

    fn advance_create(&mut self) {
        if self.secret_input.is_empty() {
            self.error("Passphrase is required.");
            return;
        }
        let first = take_string(&mut self.secret_input);
        self.screen = Screen::Secret {
            step: SecretStep::CreateConfirm { first },
        };
        self.progress("Type the passphrase again.");
    }

    fn finish_create_passphrase(&mut self) {
        if self.secret_input.is_empty() {
            self.error("Passphrase is required.");
            return;
        }
        let matches_first = match &self.screen {
            Screen::Secret {
                step: SecretStep::CreateConfirm { first },
            } => first.as_str() == self.secret_input,
            _ => return,
        };
        if !matches_first {
            wipe(&mut self.secret_input);
            self.screen = Screen::Secret {
                step: SecretStep::CreateFirst,
            };
            self.error("Passphrases do not match.");
            return;
        }
        let passphrase = take_string(&mut self.secret_input);
        self.job = Some(Job::Create {
            path: self.keystore_path_buf(),
            passphrase,
        });
        self.job_quiet = false;
        self.progress("Encrypting a new keystore…");
    }

    fn advance_import_phrase(&mut self) {
        let normalized = normalize_mnemonic(&self.secret_input);
        if wallet::seed_from_mnemonic(&normalized).is_err() {
            self.error(
                "Enter exactly 24 English words. This phrase is the raw seed, not an HD wallet.",
            );
            return;
        }
        wipe(&mut self.secret_input);
        self.screen = Screen::Secret {
            step: SecretStep::ImportPassFirst {
                mnemonic: Zeroizing::new(normalized),
            },
        };
        self.progress("Choose a passphrase for the new keystore.");
    }

    fn advance_import_pass(&mut self) {
        if self.secret_input.is_empty() {
            self.error("Passphrase is required.");
            return;
        }
        let Some(mnemonic) = self.clone_import_mnemonic() else {
            return;
        };
        let first = take_string(&mut self.secret_input);
        self.screen = Screen::Secret {
            step: SecretStep::ImportPassConfirm { mnemonic, first },
        };
        self.progress("Type the passphrase again.");
    }

    fn finish_import_passphrase(&mut self) {
        if self.secret_input.is_empty() {
            self.error("Passphrase is required.");
            return;
        }
        let matches_first = match &self.screen {
            Screen::Secret {
                step: SecretStep::ImportPassConfirm { first, .. },
            } => first.as_str() == self.secret_input,
            _ => return,
        };
        let Some(mnemonic) = self.clone_import_mnemonic() else {
            return;
        };
        if !matches_first {
            wipe(&mut self.secret_input);
            self.screen = Screen::Secret {
                step: SecretStep::ImportPassFirst { mnemonic },
            };
            self.error("Passphrases do not match.");
            return;
        }
        let passphrase = take_string(&mut self.secret_input);
        self.job = Some(Job::Import {
            path: self.keystore_path_buf(),
            mnemonic,
            passphrase,
        });
        self.job_quiet = false;
        self.progress("Encrypting the keystore…");
    }

    fn open_form(&mut self, kind: FormKind) {
        if self.session.is_none() {
            self.error("Unlock a keystore first.");
            return;
        }
        wipe(&mut self.to);
        wipe(&mut self.amount);
        wipe(&mut self.validator);
        if amount::parse_fee_atoms(&self.fee).is_err() {
            self.fee = "1".to_string();
        }
        self.screen = Screen::Form {
            kind,
            focus: first_field(kind),
        };
        self.progress(form_hint(kind));
    }

    fn open_validators(&mut self) {
        if self.session.is_none() {
            self.error("Unlock a keystore first.");
            return;
        }
        self.screen = Screen::Validators { selected: 0 };
        self.job = Some(Job::Validators);
        self.job_quiet = false;
        self.progress("Loading validators…");
    }

    fn delegate_selected(&mut self) {
        let Some(selected) = self.validator_selected() else {
            return;
        };
        let Some(address) = self.validators.get(selected).map(|row| row.address.clone()) else {
            self.error("No validator is selected.");
            return;
        };
        self.open_form(FormKind::Delegate);
        if self.session.is_none() {
            return;
        }
        self.validator = address;
        self.screen = Screen::Form {
            kind: FormKind::Delegate,
            focus: FormFocus::Amount,
        };
    }

    fn move_validator(&mut self, delta: isize) {
        let Some(selected) = self.validator_selected() else {
            return;
        };
        let len = self.validators.len();
        if len == 0 {
            return;
        }
        let next = (selected as isize + delta).clamp(0, len as isize - 1) as usize;
        self.screen = Screen::Validators { selected: next };
    }

    fn begin_review(&mut self) {
        let Some((kind, _)) = self.form_state() else {
            return;
        };
        if self.session.is_none() {
            self.error("Unlock a keystore first.");
            return;
        }
        if let Err(message) = ensure_chain(self.chain_id) {
            self.error(message);
            return;
        }
        let draft = match self.draft(kind) {
            Ok(draft) => draft,
            Err(message) => {
                self.error(message);
                return;
            }
        };
        self.job = Some(Job::Prepare(draft));
        self.progress("Reading the account nonce…");
    }

    fn draft(&self, kind: FormKind) -> Result<TxDraft, String> {
        let chain = ensure_chain(self.chain_id)?;
        let fee = amount::parse_fee_atoms(&self.fee).map_err(|err| err.to_string())?;
        let action = match kind {
            FormKind::Transfer => TxAction::Transfer {
                to: wallet::parse_address(self.to.trim(), "recipient", chain)
                    .map_err(|err| err.to_string())?,
                amount: amount::parse_positive_kuna(&self.amount).map_err(|err| err.to_string())?,
            },
            FormKind::Stake => TxAction::Stake {
                amount: amount::parse_positive_kuna(&self.amount).map_err(|err| err.to_string())?,
            },
            FormKind::Unstake => TxAction::Unstake {
                amount: amount::parse_positive_kuna(&self.amount).map_err(|err| err.to_string())?,
            },
            FormKind::Delegate => TxAction::Delegate {
                validator: wallet::parse_address(self.validator.trim(), "validator", chain)
                    .map_err(|err| err.to_string())?,
                amount: amount::parse_positive_kuna(&self.amount).map_err(|err| err.to_string())?,
            },
            FormKind::Claim => TxAction::Claim {
                validator: if self.validator.trim().is_empty() {
                    None
                } else {
                    Some(
                        wallet::parse_address(self.validator.trim(), "validator", chain)
                            .map_err(|err| err.to_string())?,
                    )
                },
            },
        };
        Ok(TxDraft { action, fee })
    }

    fn confirm_sign(&mut self) {
        if self.review().is_none() {
            return;
        }
        if self.session.is_none() {
            self.error("Unlock a keystore first.");
            return;
        }
        if let Err(message) = ensure_chain(self.chain_id) {
            self.error(message);
            return;
        }
        self.job = Some(Job::Submit);
        self.progress("Signing and submitting…");
    }

    fn cancel_review(&mut self) {
        let Some(review) = self.review() else {
            return;
        };
        self.screen = Screen::Form {
            kind: kind_of(review.action),
            focus: FormFocus::Fee,
        };
        self.info("Review cancelled. Nothing was signed.");
    }

    fn acknowledge_backup(&mut self, stored: bool) {
        if !matches!(self.screen, Screen::Backup { .. }) {
            return;
        }
        self.screen = Screen::Home;
        wipe(&mut self.secret_input);
        if stored {
            self.info(
                "Keystore saved. The recovery phrase will not be shown again. `kovanica export --format mnemonic` can print it later if you still have the passphrase.",
            );
        } else {
            self.info(
                "Phrase hidden. The keystore is already saved. It will not be shown again. Use `kovanica export --format mnemonic` while you still have the passphrase if you still need the words.",
            );
        }
        self.queue_refresh(true);
    }

    fn lock(&mut self) {
        self.session = None;
        self.snapshot = None;
        self.validators.clear();
        self.validators_loaded = false;
        self.sync_error = None;
        wipe(&mut self.secret_input);
        wipe(&mut self.to);
        wipe(&mut self.amount);
        wipe(&mut self.validator);
        self.fee = "1".to_string();
        self.screen = Screen::Gate {
            focus: GateFocus::Unlock,
        };
        self.info("Locked.");
    }

    fn request_quit(&mut self) {
        self.quit = true;
        self.job = None;
        self.session = None;
        wipe(&mut self.secret_input);
        wipe(&mut self.to);
        wipe(&mut self.amount);
        wipe(&mut self.validator);
        self.screen = Screen::Gate {
            focus: GateFocus::Unlock,
        };
    }

    fn step_signing_chain(&mut self, right: bool) {
        self.chain_id = step_chain(self.chain_id, right);
        self.info(format!(
            "Signing network is now {}.",
            chain_title(self.chain_id)
        ));
    }

    fn edit_focused(&mut self, input: Input) {
        let Some(slot) = self.text_slot() else {
            return;
        };
        let limit = self.slot_limit(slot);
        let newlines = matches!(slot, Slot::Secret)
            && matches!(
                self.screen,
                Screen::Secret {
                    step: SecretStep::ImportPhrase
                }
            );
        let buffer = self.buffer_mut(slot);
        match input {
            Input::Char(ch) => push_text(buffer, ch, limit),
            Input::Paste(text) => push_paste(buffer, &text, limit, newlines),
            Input::Backspace => backspace(buffer),
            Input::ClearField => wipe(buffer),
            _ => {}
        }
    }

    fn text_slot(&self) -> Option<Slot> {
        match &self.screen {
            Screen::Gate {
                focus: GateFocus::Keystore,
            } => Some(Slot::Keystore),
            Screen::Gate {
                focus: GateFocus::Rpc,
            } => Some(Slot::Rpc),
            Screen::Secret { .. } => Some(Slot::Secret),
            Screen::Form { focus, kind } => match focus {
                FormFocus::To if *kind == FormKind::Transfer => Some(Slot::To),
                FormFocus::Amount if *kind != FormKind::Claim => Some(Slot::Amount),
                FormFocus::Fee => Some(Slot::Fee),
                FormFocus::Validator if matches!(kind, FormKind::Delegate | FormKind::Claim) => {
                    Some(Slot::Validator)
                }
                _ => None,
            },
            _ => None,
        }
    }

    fn slot_limit(&self, slot: Slot) -> usize {
        match slot {
            Slot::Keystore | Slot::Rpc => PATH_LIMIT,
            Slot::Secret => self.secret_limit(),
            Slot::To | Slot::Validator => ADDRESS_LIMIT,
            Slot::Amount => AMOUNT_LIMIT,
            Slot::Fee => FEE_LIMIT,
        }
    }

    fn secret_limit(&self) -> usize {
        if matches!(
            self.screen,
            Screen::Secret {
                step: SecretStep::ImportPhrase
            }
        ) {
            MNEMONIC_LIMIT
        } else {
            SECRET_LIMIT
        }
    }

    fn buffer_mut(&mut self, slot: Slot) -> &mut String {
        match slot {
            Slot::Keystore => &mut self.keystore_path,
            Slot::Rpc => &mut self.rpc_url,
            Slot::Secret => &mut self.secret_input,
            Slot::To => &mut self.to,
            Slot::Amount => &mut self.amount,
            Slot::Fee => &mut self.fee,
            Slot::Validator => &mut self.validator,
        }
    }

    fn screen_kind(&self) -> ScreenKind {
        match &self.screen {
            Screen::Gate { .. } => ScreenKind::Gate,
            Screen::Secret { .. } => ScreenKind::Secret,
            Screen::Home => ScreenKind::Home,
            Screen::Validators { .. } => ScreenKind::Validators,
            Screen::Form { .. } => ScreenKind::Form,
            Screen::Confirm { .. } => ScreenKind::Confirm,
            Screen::Backup { .. } => ScreenKind::Backup,
        }
    }

    fn form_state(&self) -> Option<(FormKind, FormFocus)> {
        match &self.screen {
            Screen::Form { kind, focus } => Some((*kind, *focus)),
            _ => None,
        }
    }

    fn validator_selected(&self) -> Option<usize> {
        match &self.screen {
            Screen::Validators { selected } => Some(*selected),
            _ => None,
        }
    }

    fn keystore_path_buf(&self) -> PathBuf {
        PathBuf::from(self.keystore_path.trim())
    }

    fn address_text(&self) -> Option<String> {
        self.session
            .as_ref()
            .map(|session| session.address.to_string())
    }

    fn clone_import_mnemonic(&self) -> Option<Zeroizing<String>> {
        match &self.screen {
            Screen::Secret {
                step: SecretStep::ImportPassFirst { mnemonic },
            }
            | Screen::Secret {
                step: SecretStep::ImportPassConfirm { mnemonic, .. },
            } => Some(mnemonic.clone()),
            _ => None,
        }
    }

    #[cfg(test)]
    fn screen_name(&self) -> &'static str {
        match &self.screen {
            Screen::Gate { .. } => "gate",
            Screen::Secret {
                step: SecretStep::Unlock,
            } => "unlock",
            Screen::Secret {
                step: SecretStep::CreateFirst,
            } => "create",
            Screen::Secret {
                step: SecretStep::CreateConfirm { .. },
            } => "create-confirm",
            Screen::Secret {
                step: SecretStep::ImportPhrase,
            } => "import-phrase",
            Screen::Secret {
                step: SecretStep::ImportPassFirst { .. },
            } => "import-pass",
            Screen::Secret {
                step: SecretStep::ImportPassConfirm { .. },
            } => "import-confirm",
            Screen::Home => "home",
            Screen::Validators { .. } => "validators",
            Screen::Form {
                kind: FormKind::Transfer,
                ..
            } => "transfer",
            Screen::Form {
                kind: FormKind::Stake,
                ..
            } => "stake",
            Screen::Form {
                kind: FormKind::Unstake,
                ..
            } => "unstake",
            Screen::Form {
                kind: FormKind::Delegate,
                ..
            } => "delegate",
            Screen::Form {
                kind: FormKind::Claim,
                ..
            } => "claim",
            Screen::Confirm { .. } => "confirm",
            Screen::Backup { .. } => "backup",
        }
    }

    fn error(&mut self, text: impl Into<String>) {
        self.notice = Some(Notice {
            text: text.into(),
            is_error: true,
            transient: false,
        });
    }

    fn info(&mut self, text: impl Into<String>) {
        self.notice = Some(Notice {
            text: text.into(),
            is_error: false,
            transient: false,
        });
    }

    fn progress(&mut self, text: impl Into<String>) {
        self.notice = Some(Notice {
            text: text.into(),
            is_error: false,
            transient: true,
        });
    }
}

#[cfg(test)]
impl App {
    pub(crate) fn show_unlock_passphrase(&mut self, passphrase: &str) {
        self.screen = Screen::Secret {
            step: SecretStep::Unlock,
        };
        self.secret_input = passphrase.to_string();
    }

    pub(crate) fn show_mainnet_transfer_review(&mut self) {
        self.chain_id = Some(chain_id::MAINNET);
        self.screen = Screen::Confirm {
            review: Review {
                action: TxAction::Transfer {
                    to: Address([9u8; 32]),
                    amount: 2_500_000_000,
                },
                fee: 1,
                nonce: 4,
            },
        };
    }

    pub(crate) fn show_backup(&mut self, phrase: &str) {
        self.screen = Screen::Backup {
            phrase: Zeroizing::new(phrase.to_string()),
        };
    }

    pub(crate) fn show_home(&mut self) {
        self.screen = Screen::Home;
    }

    pub(crate) fn show_stake_form(&mut self) {
        self.screen = Screen::Form {
            kind: FormKind::Stake,
            focus: FormFocus::Amount,
        };
        self.amount = "2.5".to_string();
    }

    pub(crate) fn show_validators(&mut self) {
        self.screen = Screen::Validators { selected: 0 };
    }
}

/// Move through local, devnet, testnet, and mainnet.
///
/// From an unset chain, either arrow selects local. The list does not wrap, so
/// mainnet is reached only by moving right from testnet.
pub(crate) fn step_chain(current: Option<u64>, right: bool) -> Option<u64> {
    const ORDER: [u64; 4] = [
        chain_id::LOCAL,
        chain_id::DEVNET,
        chain_id::TESTNET,
        chain_id::MAINNET,
    ];
    let Some(id) = current else {
        return Some(ORDER[0]);
    };
    let Some(index) = ORDER.iter().position(|chain| *chain == id) else {
        return Some(ORDER[0]);
    };
    let next = if right {
        (index + 1).min(ORDER.len() - 1)
    } else {
        index.saturating_sub(1)
    };
    Some(ORDER[next])
}

pub(crate) fn chain_name(id: u64) -> &'static str {
    match id {
        chain_id::LOCAL => "local",
        chain_id::DEVNET => "devnet",
        chain_id::TESTNET => "testnet",
        chain_id::TESTNET_V2 => "testnet v2",
        chain_id::MAINNET => "mainnet",
        _ => "unregistered",
    }
}

pub(crate) fn chain_title(chain_id_value: Option<u64>) -> String {
    match chain_id_value {
        Some(chain_id::MAINNET) => "MAINNET (chain 1)".to_string(),
        Some(id) => format!("{} (chain {id})", chain_name(id)),
        None => "not selected".to_string(),
    }
}

pub(crate) fn ensure_chain(id: Option<u64>) -> Result<u64, String> {
    match tx::signing_context(id) {
        Ok(context) => Ok(context.chain_id),
        Err(_) => match id {
            None => Err(
                "Choose a chain with left and right before signing. Signing has no default network."
                    .to_string(),
            ),
            Some(id) => Err(format!(
                "Chain {id} is not registered. Choose local (1337), devnet (3), testnet (2), testnet v2 (4), or mainnet (1)."
            )),
        },
    }
}

pub(crate) fn user_message(err: &anyhow::Error) -> String {
    err.to_string().replace(['\n', '\r'], " ")
}

fn explain_unlock(err: &anyhow::Error) -> String {
    let raw = user_message(err);
    if raw.contains("authentication failed") {
        "Wrong passphrase, or the keystore was modified.".to_string()
    } else {
        format!("Could not open the keystore: {raw}")
    }
}

fn confirm_warning(id: Option<u64>) -> Option<&'static str> {
    match id {
        Some(chain_id::MAINNET) => Some("This signs a mainnet transaction."),
        None => Some("No network is selected. Go back and choose one."),
        Some(id) if !chain_id::is_registered(id) => Some("This chain id is not registered."),
        _ => None,
    }
}

fn secret_copy(step: &SecretStep) -> (&'static str, &'static str, bool) {
    match step {
        SecretStep::Unlock => (
            "Unlock keystore",
            "The passphrase decrypts the keystore on this machine. It is not sent to the node.",
            true,
        ),
        SecretStep::CreateFirst => (
            "New keystore passphrase",
            "This passphrase encrypts the new keystore. It is not sent to the node.",
            true,
        ),
        SecretStep::CreateConfirm { .. } => (
            "Confirm passphrase",
            "Type the same passphrase again.",
            true,
        ),
        SecretStep::ImportPhrase => (
            "Recovery phrase",
            "24 English words. This is the raw seed, not an HD wallet. The words are visible while you type.",
            false,
        ),
        SecretStep::ImportPassFirst { .. } => (
            "Keystore passphrase",
            "Choose a passphrase for the new keystore file.",
            true,
        ),
        SecretStep::ImportPassConfirm { .. } => (
            "Confirm passphrase",
            "Type the same passphrase again.",
            true,
        ),
    }
}

fn secret_kind(step: &SecretStep) -> SecretKind {
    match step {
        SecretStep::Unlock => SecretKind::Unlock,
        SecretStep::CreateFirst => SecretKind::CreateFirst,
        SecretStep::CreateConfirm { .. } => SecretKind::CreateConfirm,
        SecretStep::ImportPhrase => SecretKind::ImportPhrase,
        SecretStep::ImportPassFirst { .. } => SecretKind::ImportPassFirst,
        SecretStep::ImportPassConfirm { .. } => SecretKind::ImportPassConfirm,
    }
}

fn fields(kind: FormKind) -> &'static [FormFocus] {
    match kind {
        FormKind::Transfer => &TRANSFER_FIELDS,
        FormKind::Stake | FormKind::Unstake => &AMOUNT_FIELDS,
        FormKind::Delegate => &DELEGATE_FIELDS,
        FormKind::Claim => &CLAIM_FIELDS,
    }
}

fn first_field(kind: FormKind) -> FormFocus {
    fields(kind)[0]
}

fn cycle_field(kind: FormKind, focus: FormFocus, forward: bool) -> FormFocus {
    let fields = fields(kind);
    let index = fields.iter().position(|item| *item == focus).unwrap_or(0);
    let next = if forward {
        (index + 1) % fields.len()
    } else {
        (index + fields.len() - 1) % fields.len()
    };
    fields[next]
}

fn cycle_gate(focus: GateFocus, forward: bool) -> GateFocus {
    let index = GATE_ORDER
        .iter()
        .position(|item| *item == focus)
        .unwrap_or(0);
    let next = if forward {
        (index + 1) % GATE_ORDER.len()
    } else {
        (index + GATE_ORDER.len() - 1) % GATE_ORDER.len()
    };
    GATE_ORDER[next]
}

fn kind_of(action: TxAction) -> FormKind {
    match action {
        TxAction::Transfer { .. } => FormKind::Transfer,
        TxAction::Stake { .. } => FormKind::Stake,
        TxAction::Unstake { .. } => FormKind::Unstake,
        TxAction::Delegate { .. } => FormKind::Delegate,
        TxAction::Claim { .. } => FormKind::Claim,
    }
}

fn form_hint(kind: FormKind) -> &'static str {
    match kind {
        FormKind::Transfer => "Send KUNA. Amounts use 9 decimal places. The fee is in atoms.",
        FormKind::Stake => "Self-stake KUNA. Amounts use 9 decimal places. The fee is in atoms.",
        FormKind::Unstake => "Begin unbonding staked KUNA. The fee is in atoms.",
        FormKind::Delegate => "Delegate KUNA to a validator. The fee is in atoms.",
        FormKind::Claim => {
            "Claim rewards. Leave the validator empty to claim every delegation. The fee is in atoms."
        }
    }
}

fn ensure_readable_keystore(path: &Path) -> Result<(), String> {
    ensure_path_present(path)?;
    match fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_symlink() => {
            Err("Refusing to open a symlink. Choose the real keystore file.".to_string())
        }
        Ok(meta) if meta.is_file() => Ok(()),
        Ok(_) => Err("Keystore path is not a file.".to_string()),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Err(format!(
            "No keystore at {}. Create one, or import a 24-word phrase.",
            path.display()
        )),
        Err(err) => Err(format!("Cannot read {}: {err}", path.display())),
    }
}

fn ensure_creatable(path: &Path) -> Result<(), String> {
    ensure_path_present(path)?;
    match fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_symlink() => {
            Err("Refusing to write through a symlink.".to_string())
        }
        Ok(_) => Err(format!(
            "A keystore already exists at {}. This wallet will not overwrite it.",
            path.display()
        )),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(format!("Cannot use {}: {err}", path.display())),
    }
}

fn ensure_path_present(path: &Path) -> Result<(), String> {
    if path.as_os_str().is_empty() || path.file_name().is_none() {
        Err("Keystore path is required.".to_string())
    } else {
        Ok(())
    }
}

fn clamp_index(selected: usize, len: usize) -> usize {
    if len == 0 {
        0
    } else {
        selected.min(len - 1)
    }
}

fn normalize_mnemonic(input: &str) -> String {
    input.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn take_string(value: &mut String) -> Zeroizing<String> {
    let mut owned = String::new();
    std::mem::swap(&mut owned, value);
    Zeroizing::new(owned)
}

fn wipe(value: &mut String) {
    value.zeroize();
    value.clear();
}

fn backspace(value: &mut String) {
    if value.is_empty() {
        return;
    }
    let mut chars = value.chars();
    chars.next_back();
    let rebuilt: String = chars.collect();
    wipe(value);
    *value = rebuilt;
}

fn push_text(buffer: &mut String, ch: char, limit: usize) {
    if ch.is_control() || buffer.chars().count() >= limit {
        return;
    }
    buffer.push(ch);
}

fn push_paste(buffer: &mut String, text: &str, limit: usize, newlines_as_spaces: bool) {
    for ch in text.chars() {
        let ch = if newlines_as_spaces && matches!(ch, '\n' | '\r' | '\t') {
            ' '
        } else {
            ch
        };
        push_text(buffer, ch, limit);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tui::net::ValidatorRow;

    fn test_app() -> App {
        App::new(TuiConfig {
            rpc_url: "http://127.0.0.1:8545".to_string(),
            chain_id: None,
            keystore: PathBuf::from("/no/such/kovanica-keystore.json"),
        })
    }

    fn unlock_session(app: &mut App) {
        let (signing_key, public_key) = kovanica_crypto::generate_keypair();
        app.session = Some(Session {
            address: Address::from_public_key(&public_key),
            signing_key,
        });
        app.screen = Screen::Home;
    }

    #[test]
    fn arrows_from_an_unset_chain_select_local_not_mainnet() {
        assert_eq!(step_chain(None, true), Some(chain_id::LOCAL));
        assert_eq!(step_chain(None, false), Some(chain_id::LOCAL));
        assert_eq!(
            step_chain(Some(chain_id::LOCAL), false),
            Some(chain_id::LOCAL)
        );
        assert_eq!(
            step_chain(Some(chain_id::LOCAL), true),
            Some(chain_id::DEVNET)
        );
        assert_eq!(
            step_chain(Some(chain_id::TESTNET), true),
            Some(chain_id::MAINNET)
        );
        assert_eq!(
            step_chain(Some(chain_id::MAINNET), true),
            Some(chain_id::MAINNET)
        );
        assert_eq!(
            step_chain(Some(chain_id::MAINNET), false),
            Some(chain_id::TESTNET)
        );
        assert_eq!(step_chain(Some(99), true), Some(chain_id::LOCAL));
        assert!(ensure_chain(None).unwrap_err().contains("no default"));
        assert_eq!(ensure_chain(Some(4)).unwrap(), 4);
        assert_eq!(ensure_chain(Some(chain_id::LOCAL)).unwrap(), 1337);
        assert_eq!(chain_title(Some(chain_id::MAINNET)), "MAINNET (chain 1)");
    }

    #[test]
    fn typing_in_the_keystore_field_does_not_run_a_command() {
        let mut app = test_app();
        app.handle(Input::Up);
        app.handle(Input::Up);
        app.handle(Input::Up);
        app.handle(Input::Char('n'));
        assert!(app.keystore_path.ends_with("jsonn"));
        assert_eq!(app.screen_name(), "gate");
        assert!(app.job.is_none());
    }

    #[test]
    fn missing_keystore_stays_on_the_gate() {
        let mut app = test_app();
        app.handle(Input::Enter);
        assert_eq!(app.screen_name(), "gate");
        assert!(app.notice.unwrap().text.contains("No keystore"));
    }

    #[test]
    fn create_refuses_to_overwrite_an_existing_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("keystore.json");
        std::fs::write(&path, b"{}").unwrap();
        let mut app = test_app();
        app.keystore_path = path.display().to_string();
        app.handle(Input::Tab);
        app.handle(Input::Enter);
        assert_eq!(app.screen_name(), "gate");
        assert!(app.notice.unwrap().text.contains("already exists"));
    }

    #[test]
    fn passphrase_mismatch_restarts_creation_and_wipes_the_field() {
        let dir = tempfile::tempdir().unwrap();
        let mut app = test_app();
        app.keystore_path = dir.path().join("fresh.json").display().to_string();
        app.handle(Input::Tab);
        app.handle(Input::Enter);
        assert_eq!(app.screen_name(), "create");
        app.secret_input = "alpha".to_string();
        app.handle(Input::Enter);
        assert_eq!(app.screen_name(), "create-confirm");
        app.secret_input = "beta".to_string();
        app.handle(Input::Enter);
        assert_eq!(app.screen_name(), "create");
        assert!(app.secret_input.is_empty());
        assert!(app.notice.unwrap().text.contains("do not match"));
    }

    #[test]
    fn short_import_phrase_is_rejected_without_a_job() {
        let dir = tempfile::tempdir().unwrap();
        let mut app = test_app();
        app.keystore_path = dir.path().join("fresh.json").display().to_string();
        app.handle(Input::Tab);
        app.handle(Input::Tab);
        app.handle(Input::Enter);
        assert_eq!(app.screen_name(), "import-phrase");
        app.secret_input = "one two three".to_string();
        app.handle(Input::Enter);
        assert_eq!(app.screen_name(), "import-phrase");
        assert!(app.job.is_none());
        assert!(app.notice.unwrap().text.contains("24"));
    }

    #[test]
    fn masked_view_does_not_contain_the_passphrase() {
        let mut app = test_app();
        app.screen = Screen::Secret {
            step: SecretStep::Unlock,
        };
        app.secret_input = "hunter2".to_string();
        let view = app.view();
        match view.screen {
            ViewScreen::Secret { input, .. } => {
                assert_eq!(input, "*******");
                assert!(!input.contains("hunter2"));
            }
            _ => panic!("expected the unlock screen"),
        }
    }

    #[test]
    fn quit_and_lock_drop_the_session_and_wipe_secrets() {
        let mut app = test_app();
        unlock_session(&mut app);
        app.secret_input = "hunter2".to_string();
        app.handle(Input::Char('l'));
        assert!(app.session.is_none());
        assert!(app.secret_input.is_empty());
        assert_eq!(app.screen_name(), "gate");

        unlock_session(&mut app);
        app.screen = Screen::Secret {
            step: SecretStep::Unlock,
        };
        app.secret_input = "hunter2".to_string();
        app.handle(Input::Quit);
        assert!(app.quit());
        assert!(app.session.is_none());
        assert!(app.secret_input.is_empty());
        assert_eq!(app.screen_name(), "gate");
    }

    #[test]
    fn transfer_review_uses_kuna_decimals_and_rejects_a_zero_fee() {
        let mut app = test_app();
        unlock_session(&mut app);
        app.chain_id = Some(chain_id::LOCAL);
        app.screen = Screen::Form {
            kind: FormKind::Transfer,
            focus: FormFocus::Fee,
        };
        app.to = Address([9u8; 32]).to_hex();
        app.amount = "2.5".to_string();
        app.fee = "0".to_string();
        app.handle(Input::Enter);
        assert!(app.job.is_none());
        assert!(app.notice.as_ref().unwrap().text.contains("at least 1"));

        app.fee = "1".to_string();
        app.handle(Input::Enter);
        match app.take_job() {
            Some(Job::Prepare(draft)) => match draft.action {
                TxAction::Transfer { to, amount } => {
                    assert_eq!(to, Address([9u8; 32]));
                    assert_eq!(amount, 2_500_000_000);
                    assert_eq!(draft.fee, 1);
                }
                other => panic!("unexpected {other:?}"),
            },
            _ => panic!("expected a prepared transfer"),
        }
    }

    #[test]
    fn claim_with_an_empty_validator_claims_all_delegations() {
        let mut app = test_app();
        unlock_session(&mut app);
        app.chain_id = Some(chain_id::TESTNET);
        app.screen = Screen::Form {
            kind: FormKind::Claim,
            focus: FormFocus::Fee,
        };
        app.fee = "2".to_string();
        app.handle(Input::Enter);
        match app.take_job() {
            Some(Job::Prepare(draft)) => {
                assert!(matches!(draft.action, TxAction::Claim { validator: None }));
                assert_eq!(draft.fee, 2);
            }
            _ => panic!("expected a prepared claim"),
        }
    }

    #[test]
    fn signing_requires_a_registered_chain() {
        let mut app = test_app();
        unlock_session(&mut app);
        app.chain_id = None;
        app.screen = Screen::Confirm {
            review: Review {
                action: TxAction::Stake { amount: 1 },
                fee: 1,
                nonce: 3,
            },
        };
        app.handle(Input::Char('y'));
        assert!(app.job.is_none());
        assert!(app.notice.as_ref().unwrap().text.contains("no default"));

        app.chain_id = Some(chain_id::LOCAL);
        app.handle(Input::Char('y'));
        assert!(matches!(app.job, Some(Job::Submit)));
    }

    #[test]
    fn nonce_change_stays_on_the_review_screen() {
        let mut app = test_app();
        app.screen = Screen::Confirm {
            review: Review {
                action: TxAction::Stake { amount: 1 },
                fee: 1,
                nonce: 3,
            },
        };
        app.on_nonce_changed(9);
        assert_eq!(app.screen_name(), "confirm");
        assert_eq!(app.review().unwrap().nonce, 9);
        assert!(app.notice.unwrap().text.contains("changed to 9"));
    }

    #[test]
    fn selecting_a_validator_fills_the_delegate_form() {
        let mut app = test_app();
        unlock_session(&mut app);
        app.validators = vec![ValidatorRow {
            address: "validator-a".to_string(),
            stake: 1,
            commission_bps: 500,
            active: true,
        }];
        app.validators_loaded = true;
        app.screen = Screen::Validators { selected: 0 };
        app.handle(Input::Enter);
        assert_eq!(app.screen_name(), "delegate");
        assert_eq!(app.validator, "validator-a");
    }

    #[test]
    fn acknowledging_the_backup_drops_the_phrase_from_the_view() {
        let mut app = test_app();
        app.screen = Screen::Backup {
            phrase: Zeroizing::new("alpha bravo charlie".to_string()),
        };
        let shown = app.view();
        match shown.screen {
            ViewScreen::Backup { words, .. } => assert_eq!(words[0], "alpha"),
            _ => panic!("expected the backup screen"),
        }
        app.handle(Input::Enter);
        assert_eq!(app.screen_name(), "home");
        let hidden = app.view();
        match hidden.screen {
            ViewScreen::Home { .. } => {}
            _ => panic!("expected the home screen"),
        }
    }

    #[test]
    fn home_transfer_requires_an_unlocked_session() {
        let mut app = test_app();
        app.screen = Screen::Home;
        app.handle(Input::Char('t'));
        assert_eq!(app.screen_name(), "home");
        assert!(app.notice.as_ref().unwrap().text.contains("Unlock"));

        unlock_session(&mut app);
        app.handle(Input::Char('t'));
        assert_eq!(app.screen_name(), "transfer");
    }
}
