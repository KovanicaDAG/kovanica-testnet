use anyhow::{Context, Result};
use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyEventKind},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span, Text},
    widgets::{Block, Borders, List, ListItem, ListState, Paragraph, Wrap},
    Frame, Terminal,
};
use std::io;
use std::path::PathBuf;

use kovanica_cli::api::Client;
use kovanica_state::Address;
use tokio::runtime::Runtime;

#[derive(Debug, Clone, Copy, PartialEq)]
enum MenuItem {
    Head,
    P2p,
    Bootstrap,
    State,
    Blocks,
    Balance,
    Keygen,
    Address,
    Send,
    Htlc,
    Offer,
    Rwa,
    Nft,
    Quit,
}

impl MenuItem {
    fn label(&self) -> &'static str {
        match self {
            MenuItem::Head => "1. Chain Head",
            MenuItem::P2p => "2. P2P Info",
            MenuItem::Bootstrap => "3. Bootstrap",
            MenuItem::State => "4. Node State",
            MenuItem::Blocks => "5. Blocks",
            MenuItem::Balance => "6. Balance",
            MenuItem::Keygen => "7. Keygen",
            MenuItem::Address => "8. Address",
            MenuItem::Send => "9. Send",
            MenuItem::Htlc => "10. HTLC",
            MenuItem::Offer => "11. Offer",
            MenuItem::Rwa => "12. RWA",
            MenuItem::Nft => "13. NFT",
            MenuItem::Quit => "Q. Quit",
        }
    }

    fn all() -> &'static [MenuItem] {
        &[
            MenuItem::Head,
            MenuItem::P2p,
            MenuItem::Bootstrap,
            MenuItem::State,
            MenuItem::Blocks,
            MenuItem::Balance,
            MenuItem::Keygen,
            MenuItem::Address,
            MenuItem::Send,
            MenuItem::Htlc,
            MenuItem::Offer,
            MenuItem::Rwa,
            MenuItem::Nft,
            MenuItem::Quit,
        ]
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum SendStep {
    KeyPath,
    ToAddress,
    Amount,
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum HtlcStep {
    SubCommand,
    KeyPath,
    Amount,
    RecipientPk,
    PreimageHash,
    Timeout,
    AssetId,
    OutpointTx,
    OutpointIndex,
    Script,
    Preimage,
    ToAddress,
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum OfferStep {
    SubCommand,
    Maker,
    GiveAsset,
    GiveAmount,
    TakeAsset,
    TakeAmount,
    PreimageHash,
    Timeout,
    ExpiresAt,
    /// Terminal step: the expiry has been collected, run the subcommand.
    Submit,
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum RwaStep {
    SubCommand,
    Issuer,
    Class,
    Id,
    Version,
    KeyPath,
    Amount,
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum NftStep {
    SubCommand,
    AssetId,
    CollectionId,
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum InputMode {
    Normal,
    BalanceAddress,
    AddressKeyPath,
    Send(SendStep),
    Htlc(HtlcStep),
    Offer(OfferStep),
    Rwa(RwaStep),
    Nft(NftStep),
}

#[derive(Default)]
struct SendState {
    key_path: Option<String>,
    to_address: Option<String>,
    amount: Option<u64>,
}

#[derive(Default)]
struct HtlcState {
    sub_command: Option<String>,
    key_path: Option<String>,
    amount: Option<u64>,
    recipient_pk: Option<String>,
    preimage_hash: Option<String>,
    timeout: Option<u32>,
    asset_id: Option<String>,
    outpoint_tx: Option<String>,
    outpoint_index: Option<u32>,
    script: Option<String>,
    preimage: Option<[u8; 32]>,
    to_address: Option<String>,
}

#[derive(Default)]
struct OfferState {
    sub_command: Option<String>,
    key_path: Option<String>,
    maker: Option<String>,
    give_asset: Option<String>,
    give_amount: Option<u64>,
    take_asset: Option<String>,
    take_amount: Option<u64>,
    preimage_hash: Option<String>,
    timeout: Option<u32>,
    expires_at: Option<String>,
}

#[derive(Default)]
struct RwaState {
    sub_command: Option<String>,
    issuer: Option<String>,
    class: Option<String>,
    id: Option<String>,
    version: Option<u8>,
    key_path: Option<String>,
    amount: Option<u64>,
}

#[derive(Default)]
struct NftState {
    sub_command: Option<String>,
    asset_id: Option<String>,
    collection_id: Option<String>,
}

struct App {
    menu_state: ListState,
    client: Client,
    output: String,
    show_output: bool,
    input_buffer: String,
    input_prompt: Option<String>,
    input_mode: InputMode,
    send_state: SendState,
    htlc_state: HtlcState,
    offer_state: OfferState,
    rwa_state: RwaState,
    nft_state: NftState,
}

impl App {
    fn new(client: Client) -> Self {
        let mut menu_state = ListState::default();
        menu_state.select(Some(0));
        Self {
            menu_state,
            client,
            output: String::new(),
            show_output: false,
            input_buffer: String::new(),
            input_prompt: None,
            input_mode: InputMode::Normal,
            send_state: SendState::default(),
            htlc_state: HtlcState::default(),
            offer_state: OfferState::default(),
            rwa_state: RwaState::default(),
            nft_state: NftState::default(),
        }
    }

    fn next(&mut self) {
        if self.input_prompt.is_none() {
            let i = self.menu_state.selected().unwrap_or(0);
            if i < MenuItem::all().len() - 1 {
                self.menu_state.select(Some(i + 1));
            }
        }
    }

    fn previous(&mut self) {
        if self.input_prompt.is_none() {
            let i = self.menu_state.selected().unwrap_or(0);
            if i > 0 {
                self.menu_state.select(Some(i - 1));
            }
        }
    }

    fn start_input(&mut self, prompt: String, mode: InputMode) {
        self.input_prompt = Some(prompt);
        self.input_buffer.clear();
        self.input_mode = mode;
    }

    async fn submit_input(&mut self) -> Result<()> {
        let input = std::mem::take(&mut self.input_buffer);
        let mode = std::mem::replace(&mut self.input_mode, InputMode::Normal);
        self.input_prompt = None;

        match mode {
            InputMode::BalanceAddress => {
                let addr = Address::parse(&self.input_buffer)
                    .map_err(|e| anyhow::anyhow!("invalid address: {e}"))?;
                let result = self.client.utxos(&addr.to_hex())?;
                self.output = serde_json::to_string_pretty(&result)?;
                self.show_output = true;
            }
            InputMode::AddressKeyPath => {
                let path = if self.input_buffer.trim().is_empty() {
                    "kovanica.key".to_string()
                } else {
                    self.input_buffer.clone()
                };
                let wallet = crate::Wallet::load(&PathBuf::from(&path))?;
                let addr = wallet.address();
                self.output = format!(
                    "address (kvnc): {}\naddress (hex):  {}",
                    addr.to_kvnc(),
                    addr.to_hex()
                );
                self.show_output = true;
            }
            InputMode::Send(step) => match step {
                SendStep::KeyPath => {
                    self.send_state.key_path = Some(if self.input_buffer.trim().is_empty() {
                        "kovanica.key".to_string()
                    } else {
                        self.input_buffer.clone()
                    });
                    self.start_input(
                        "Enter recipient address (kvnc...dag or hex): ".to_string(),
                        InputMode::Send(SendStep::ToAddress),
                    );
                }
                SendStep::ToAddress => {
                    self.send_state.to_address = Some(self.input_buffer.clone());
                    self.start_input(
                        "Enter amount in atoms (1 KVNC = 100000000): ".to_string(),
                        InputMode::Send(SendStep::Amount),
                    );
                }
                SendStep::Amount => {
                    let amount = self
                        .input_buffer
                        .parse::<u64>()
                        .map_err(|_| anyhow::anyhow!("invalid amount"))?;
                    self.send_state.amount = Some(amount);
                    self.execute_send().await?;
                }
            },
            InputMode::Htlc(step) => {
                self.handle_htlc_input(step, &input).await?;
            }
            InputMode::Offer(step) => {
                self.handle_offer_input(step, &input).await?;
            }
            InputMode::Rwa(step) => {
                self.handle_rwa_input(step, &input).await?;
            }
            InputMode::Nft(step) => {
                self.handle_nft_input(step, &input).await?;
            }
            InputMode::Normal => {}
        }
        Ok(())
    }

    async fn execute_send(&mut self) -> Result<()> {
        let key_path = self
            .send_state
            .key_path
            .clone()
            .unwrap_or_else(|| "kovanica.key".to_string());
        let to_address = self.send_state.to_address.clone().unwrap();
        let amount = self.send_state.amount.unwrap();

        let wallet = crate::Wallet::load(&PathBuf::from(&key_path))?;
        let from = wallet.address().to_hex();
        let to_addr = Address::parse(&to_address)
            .map_err(|e| anyhow::anyhow!("invalid address: {e}"))?
            .to_hex();

        let prepared = self.client.prepare(&from, &to_addr, amount)?;
        let sighash_hex = prepared
            .get("sighash")
            .and_then(|v| v.as_str())
            .context("missing sighash")?;
        let sighash = hex::decode(sighash_hex.trim()).context("sighash not hex")?;

        let wallet = crate::Wallet::load(&PathBuf::from(&key_path))?;
        let sig = wallet.keypair().sign(&sighash);
        let sig_hex = hex::encode(sig);

        self.client.submit(&from, &to_addr, amount, &sig_hex)?;
        self.output = format!(
            "Sent {} atoms ({} KVNC) to {}",
            amount,
            amount / 100_000_000,
            to_address
        );
        self.show_output = true;
        Ok(())
    }

    async fn execute_htlc_create(&mut self) -> Result<()> {
        let key_path = self
            .htlc_state
            .key_path
            .clone()
            .unwrap_or_else(|| "kovanica.key".to_string());
        let amount = self.htlc_state.amount.unwrap();
        let recipient_pk_hex = self.htlc_state.recipient_pk.clone().unwrap();
        let preimage_hash_hex = self.htlc_state.preimage_hash.clone().unwrap();
        let timeout = self.htlc_state.timeout.unwrap();
        let asset_id = self.htlc_state.asset_id.clone();

        let mut recipient_pk = [0u8; 32];
        hex::decode_to_slice(&recipient_pk_hex, &mut recipient_pk)
            .map_err(|_| anyhow::anyhow!("invalid hex"))?;
        let mut preimage_hash = [0u8; 32];
        hex::decode_to_slice(&preimage_hash_hex, &mut preimage_hash)
            .map_err(|_| anyhow::anyhow!("invalid hex"))?;

        let asset_id_opt = if let Some(asset) = asset_id {
            Some(kovanica_state::AssetId::from_bytes(
                <[u8; 32]>::try_from(asset.as_bytes())
                    .map_err(|_| anyhow::anyhow!("asset_id must be 32 bytes"))?,
            ))
        } else {
            None
        };

        // Load wallet to get the from address
        let wallet = crate::Wallet::load(&PathBuf::from(&key_path))?;
        let from_addr = wallet.address().to_hex();

        let prepared = self.client.prepare_htlc(
            &from_addr,
            amount,
            &recipient_pk,
            &preimage_hash,
            timeout,
            asset_id_opt,
        )?;

        let sighash_hex = prepared
            .get("sighash")
            .and_then(|v| v.as_str())
            .context("missing sighash")?;
        let sighash = hex::decode(sighash_hex.trim()).context("sighash not hex")?;

        let wallet = crate::Wallet::load(&PathBuf::from(&key_path))?;
        let sig = wallet.keypair().sign(&sighash);
        let sig_hex = hex::encode(sig);

        let result = self.client.submit_htlc(&from_addr, sighash_hex, &sig_hex)?;
        self.output = format!(
            "HTLC created: tx={}",
            result
                .get("tx")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown")
        );
        self.show_output = true;
        Ok(())
    }

    // Handler methods for HTLC multi-step input
    async fn handle_htlc_input(&mut self, step: HtlcStep, input: &str) -> Result<()> {
        match step {
            HtlcStep::SubCommand => {
                let cmd = input.trim().to_lowercase();
                match cmd.as_str() {
                    "create" | "redeem" | "refund" | "balance" => {
                        self.htlc_state.sub_command = Some(cmd);
                        self.start_input(
                            "Enter key file path (default: kovanica.key): ".to_string(),
                            InputMode::Htlc(HtlcStep::KeyPath),
                        );
                    }
                    _ => {
                        self.output = "Invalid subcommand. Use: create, redeem, refund, or balance"
                            .to_string();
                        self.show_output = true;
                    }
                }
            }
            HtlcStep::KeyPath => {
                self.htlc_state.key_path = Some(if input.trim().is_empty() {
                    "kovanica.key".to_string()
                } else {
                    input.to_string()
                });
                match self.htlc_state.sub_command.as_deref() {
                    Some("create") => {
                        self.start_input(
                            "Enter amount in atoms (1 KVNC = 100000000): ".to_string(),
                            InputMode::Htlc(HtlcStep::Amount),
                        );
                    }
                    Some("redeem") | Some("refund") => {
                        self.start_input(
                            "Enter outpoint transaction ID (64-hex): ".to_string(),
                            InputMode::Htlc(HtlcStep::OutpointTx),
                        );
                    }
                    Some("balance") => {
                        self.start_input(
                            "Enter HTLC script (100-byte hex): ".to_string(),
                            InputMode::Htlc(HtlcStep::Script),
                        );
                    }
                    _ => {}
                }
            }
            HtlcStep::Amount => {
                let amount = input
                    .parse::<u64>()
                    .map_err(|_| anyhow::anyhow!("invalid amount"))?;
                self.htlc_state.amount = Some(amount);
                self.start_input(
                    "Enter recipient public key (64-hex): ".to_string(),
                    InputMode::Htlc(HtlcStep::RecipientPk),
                );
            }
            HtlcStep::RecipientPk => {
                let pk = input.trim();
                if pk.len() != 64 {
                    self.output = "Public key must be 64 hex chars (32 bytes)".to_string();
                    self.show_output = true;
                    return Ok(());
                }
                self.htlc_state.recipient_pk = Some(pk.to_string());
                self.start_input(
                    "Enter preimage hash (64-hex): ".to_string(),
                    InputMode::Htlc(HtlcStep::PreimageHash),
                );
            }
            HtlcStep::PreimageHash => {
                let hash = input.trim();
                if hash.len() != 64 {
                    self.output = "Preimage hash must be 64 hex chars (32 bytes)".to_string();
                    self.show_output = true;
                    return Ok(());
                }
                self.htlc_state.preimage_hash = Some(hash.to_string());
                self.start_input(
                    "Enter timeout (block height): ".to_string(),
                    InputMode::Htlc(HtlcStep::Timeout),
                );
            }
            HtlcStep::Timeout => {
                let timeout = input
                    .parse::<u32>()
                    .map_err(|_| anyhow::anyhow!("invalid timeout"))?;
                self.htlc_state.timeout = Some(timeout);
                self.start_input(
                    "Enter asset ID (64-hex, or leave empty for native KVNC): ".to_string(),
                    InputMode::Htlc(HtlcStep::AssetId),
                );
            }
            HtlcStep::AssetId => {
                let asset = input.trim();
                if !asset.is_empty() {
                    if asset.len() != 64 {
                        self.output = "Asset ID must be 64 hex chars (32 bytes)".to_string();
                        self.show_output = true;
                        return Ok(());
                    }
                    self.htlc_state.asset_id = Some(asset.to_string());
                }
                // Execute HTLC create
                self.execute_htlc_create().await?;
            }
            HtlcStep::OutpointTx => {
                let tx = input.trim();
                if tx.len() != 64 {
                    self.output = "Outpoint TX must be 64 hex chars (32 bytes)".to_string();
                    self.show_output = true;
                    return Ok(());
                }
                self.htlc_state.outpoint_tx = Some(tx.to_string());
                self.start_input(
                    "Enter outpoint index: ".to_string(),
                    InputMode::Htlc(HtlcStep::OutpointIndex),
                );
            }
            HtlcStep::OutpointIndex => {
                let index = input
                    .parse::<u32>()
                    .map_err(|_| anyhow::anyhow!("invalid index"))?;
                self.htlc_state.outpoint_index = Some(index);
                self.start_input(
                    "Enter HTLC script (100-byte hex): ".to_string(),
                    InputMode::Htlc(HtlcStep::Script),
                );
            }
            HtlcStep::Script => {
                let script = input.trim();
                if script.len() != 200 {
                    self.output = "HTLC script must be 200 hex chars (100 bytes)".to_string();
                    self.show_output = true;
                    return Ok(());
                }
                let script_bytes =
                    hex::decode(script).map_err(|_| anyhow::anyhow!("invalid hex"))?;
                if script_bytes.len() != 100 {
                    self.output = "HTLC script must be 100 bytes".to_string();
                    self.show_output = true;
                    return Ok(());
                }
                self.htlc_state.script = Some(script.to_string());
                match self.htlc_state.sub_command.as_deref() {
                    Some("redeem") => {
                        self.start_input(
                            "Enter preimage (64-hex): ".to_string(),
                            InputMode::Htlc(HtlcStep::Preimage),
                        );
                    }
                    Some("refund") => {
                        self.start_input(
                            "Enter destination address (kvnc...dag or hex): ".to_string(),
                            InputMode::Htlc(HtlcStep::ToAddress),
                        );
                    }
                    Some("balance") => {
                        self.execute_htlc_balance().await?;
                    }
                    _ => {}
                }
            }
            HtlcStep::Preimage => {
                let preimage = input.trim();
                if preimage.len() != 64 {
                    self.output = "Preimage must be 64 hex chars (32 bytes)".to_string();
                    self.show_output = true;
                    return Ok(());
                }
                let mut preimage_bytes = [0u8; 32];
                hex::decode_to_slice(preimage, &mut preimage_bytes)
                    .map_err(|_| anyhow::anyhow!("invalid hex"))?;
                self.htlc_state.preimage = Some(preimage_bytes);
                self.start_input(
                    "Enter destination address (kvnc...dag or hex): ".to_string(),
                    InputMode::Htlc(HtlcStep::ToAddress),
                );
            }
            HtlcStep::ToAddress => {
                let to_addr = input.trim();
                let _ =
                    Address::parse(to_addr).map_err(|e| anyhow::anyhow!("invalid address: {e}"))?;
                self.htlc_state.to_address = Some(to_addr.to_string());
                // Execute redeem or refund
                if self.htlc_state.sub_command.as_deref() == Some("redeem") {
                    self.execute_htlc_redeem().await?;
                } else {
                    self.execute_htlc_refund().await?;
                }
            }
        }
        Ok(())
    }

    // Handler methods for Offer multi-step input
    async fn handle_offer_input(&mut self, step: OfferStep, input: &str) -> Result<()> {
        match step {
            OfferStep::SubCommand => {
                let cmd = input.trim().to_lowercase();
                match cmd.as_str() {
                    "create" | "verify" => {
                        self.offer_state.sub_command = Some(cmd);
                        self.start_input(
                            "Enter key file path (default: kovanica.key): ".to_string(),
                            InputMode::Offer(OfferStep::Maker),
                        );
                    }
                    _ => {
                        self.output = "Invalid subcommand. Use: create or verify".to_string();
                        self.show_output = true;
                    }
                }
            }
            OfferStep::Maker => {
                self.offer_state.key_path = Some(if input.trim().is_empty() {
                    "kovanica.key".to_string()
                } else {
                    input.to_string()
                });
                self.start_input(
                    "Enter maker address (64-hex): ".to_string(),
                    InputMode::Offer(OfferStep::GiveAsset),
                );
            }
            OfferStep::GiveAsset => {
                let maker = input.trim();
                if maker.len() != 64 {
                    self.output = "Maker address must be 64 hex chars (32 bytes)".to_string();
                    self.show_output = true;
                    return Ok(());
                }
                self.offer_state.maker = Some(maker.to_string());
                self.start_input(
                    "Enter give asset ID (64-hex, or leave empty for native KVNC): ".to_string(),
                    InputMode::Offer(OfferStep::GiveAmount),
                );
            }
            OfferStep::GiveAmount => {
                let give_asset = input.trim();
                if !give_asset.is_empty() {
                    if give_asset.len() != 64 {
                        self.output = "Give asset must be 64 hex chars (32 bytes)".to_string();
                        self.show_output = true;
                        return Ok(());
                    }
                    self.offer_state.give_asset = Some(give_asset.to_string());
                }
                self.start_input(
                    "Enter give amount in atoms: ".to_string(),
                    InputMode::Offer(OfferStep::TakeAsset),
                );
            }
            OfferStep::TakeAsset => {
                let amount = input
                    .parse::<u64>()
                    .map_err(|_| anyhow::anyhow!("invalid amount"))?;
                self.offer_state.give_amount = Some(amount);
                self.start_input(
                    "Enter take asset ID (64-hex, or leave empty for native KVNC): ".to_string(),
                    InputMode::Offer(OfferStep::TakeAmount),
                );
            }
            OfferStep::TakeAmount => {
                let take_asset = input.trim();
                if !take_asset.is_empty() {
                    if take_asset.len() != 64 {
                        self.output = "Take asset must be 64 hex chars (32 bytes)".to_string();
                        self.show_output = true;
                        return Ok(());
                    }
                    self.offer_state.take_asset = Some(take_asset.to_string());
                }
                self.start_input(
                    "Enter take amount in atoms: ".to_string(),
                    InputMode::Offer(OfferStep::PreimageHash),
                );
            }
            OfferStep::PreimageHash => {
                let amount = input
                    .parse::<u64>()
                    .map_err(|_| anyhow::anyhow!("invalid amount"))?;
                self.offer_state.take_amount = Some(amount);
                self.start_input(
                    "Enter preimage hash (64-hex): ".to_string(),
                    InputMode::Offer(OfferStep::Timeout),
                );
            }
            OfferStep::Timeout => {
                let hash = input.trim();
                if hash.len() != 64 {
                    self.output = "Preimage hash must be 64 hex chars (32 bytes)".to_string();
                    self.show_output = true;
                    return Ok(());
                }
                self.offer_state.preimage_hash = Some(hash.to_string());
                self.start_input(
                    "Enter timeout (block height): ".to_string(),
                    InputMode::Offer(OfferStep::ExpiresAt),
                );
            }
            OfferStep::ExpiresAt => {
                let timeout = input
                    .parse::<u32>()
                    .map_err(|_| anyhow::anyhow!("invalid timeout"))?;
                self.offer_state.timeout = Some(timeout);
                self.start_input(
                    "Enter expiration timestamp (ISO 8601 or Unix timestamp): ".to_string(),
                    InputMode::Offer(OfferStep::Submit),
                );
            }
            OfferStep::Submit => {
                let expires_at = input.trim();
                if expires_at.is_empty() {
                    self.output = "Expiration is required (ISO 8601 or Unix timestamp)".to_string();
                    self.show_output = true;
                    return Ok(());
                }
                self.offer_state.expires_at = Some(expires_at.to_string());
                match self.offer_state.sub_command.as_deref() {
                    Some("verify") => self.execute_offer_verify(),
                    _ => self.execute_offer_create(),
                }
            }
        }
        Ok(())
    }

    // Handler methods for RWA multi-step input
    async fn handle_rwa_input(&mut self, step: RwaStep, input: &str) -> Result<()> {
        match step {
            RwaStep::SubCommand => {
                let cmd = input.trim().to_lowercase();
                match cmd.as_str() {
                    "derive" | "issue" | "burn" | "info" => {
                        self.rwa_state.sub_command = Some(cmd);
                        self.start_input(
                            "Enter key file path (default: kovanica.key): ".to_string(),
                            InputMode::Rwa(RwaStep::KeyPath),
                        );
                    }
                    _ => {
                        self.output =
                            "Invalid subcommand. Use: derive, issue, burn, or info".to_string();
                        self.show_output = true;
                    }
                }
            }
            RwaStep::KeyPath => {
                self.rwa_state.key_path = Some(if input.trim().is_empty() {
                    "kovanica.key".to_string()
                } else {
                    input.to_string()
                });
                match self.rwa_state.sub_command.as_deref() {
                    Some("derive") => {
                        self.start_input(
                            "Enter issuer address (64-hex): ".to_string(),
                            InputMode::Rwa(RwaStep::Issuer),
                        );
                    }
                    Some("issue") | Some("burn") => {
                        self.start_input(
                            "Enter issuer address (64-hex): ".to_string(),
                            InputMode::Rwa(RwaStep::Issuer),
                        );
                    }
                    Some("info") => {
                        self.start_input(
                            "Enter asset class: ".to_string(),
                            InputMode::Rwa(RwaStep::Class),
                        );
                    }
                    _ => {}
                }
            }
            RwaStep::Issuer => {
                let issuer = input.trim();
                if issuer.len() != 64 {
                    self.output = "Issuer must be 64 hex chars (32 bytes)".to_string();
                    self.show_output = true;
                    return Ok(());
                }
                self.rwa_state.issuer = Some(issuer.to_string());
                self.start_input(
                    "Enter asset class: ".to_string(),
                    InputMode::Rwa(RwaStep::Class),
                );
            }
            RwaStep::Class => {
                self.rwa_state.class = Some(input.to_string());
                self.start_input("Enter asset ID: ".to_string(), InputMode::Rwa(RwaStep::Id));
            }
            RwaStep::Id => {
                self.rwa_state.id = Some(input.to_string());
                match self.rwa_state.sub_command.as_deref() {
                    Some("derive") => {
                        self.start_input(
                            "Enter version (default 1): ".to_string(),
                            InputMode::Rwa(RwaStep::Version),
                        );
                    }
                    Some("issue") => {
                        self.start_input(
                            "Enter amount in atoms: ".to_string(),
                            InputMode::Rwa(RwaStep::Amount),
                        );
                    }
                    Some("burn") | Some("info") => {
                        // Execute directly
                        match self.rwa_state.sub_command.as_deref() {
                            Some("burn") => self.execute_rwa_burn().await?,
                            Some("info") => self.execute_rwa_info().await?,
                            _ => {}
                        }
                    }
                    _ => {}
                }
            }
            RwaStep::Version => {
                let version = input.parse::<u8>().unwrap_or(1);
                self.rwa_state.version = Some(version);
                self.execute_rwa_derive().await?;
            }
            RwaStep::Amount => {
                let amount = input
                    .parse::<u64>()
                    .map_err(|_| anyhow::anyhow!("invalid amount"))?;
                self.rwa_state.amount = Some(amount);
                self.execute_rwa_issue().await?;
            }
        }
        Ok(())
    }

    // Handler methods for NFT multi-step input
    async fn handle_nft_input(&mut self, step: NftStep, input: &str) -> Result<()> {
        match step {
            NftStep::SubCommand => {
                let cmd = input.trim().to_lowercase();
                let cmd_clone = cmd.clone();
                match cmd.as_str() {
                    "info" | "collection" => {
                        self.nft_state.sub_command = Some(cmd);
                        match cmd_clone.as_str() {
                            "info" => {
                                self.start_input(
                                    "Enter asset ID (64-hex): ".to_string(),
                                    InputMode::Nft(NftStep::AssetId),
                                );
                            }
                            "collection" => {
                                self.start_input(
                                    "Enter collection ID (64-hex): ".to_string(),
                                    InputMode::Nft(NftStep::CollectionId),
                                );
                            }
                            _ => {}
                        }
                    }
                    _ => {
                        self.output = "Invalid subcommand. Use: info or collection".to_string();
                        self.show_output = true;
                    }
                }
            }
            NftStep::AssetId => {
                let asset_id = input.trim();
                if asset_id.len() != 64 {
                    self.output = "Asset ID must be 64 hex chars (32 bytes)".to_string();
                    self.show_output = true;
                    return Ok(());
                }
                self.nft_state.asset_id = Some(asset_id.to_string());
                self.execute_nft_info().await?;
            }
            NftStep::CollectionId => {
                let collection_id = input.trim();
                if collection_id.len() != 64 {
                    self.output = "Collection ID must be 64 hex chars (32 bytes)".to_string();
                    self.show_output = true;
                    return Ok(());
                }
                self.nft_state.collection_id = Some(collection_id.to_string());
                self.execute_nft_collection().await?;
            }
        }
        Ok(())
    }

    async fn execute_htlc_redeem(&mut self) -> Result<()> {
        let key_path = self
            .htlc_state
            .key_path
            .clone()
            .unwrap_or_else(|| "kovanica.key".to_string());
        let outpoint_tx_hex = self.htlc_state.outpoint_tx.clone().unwrap();
        let outpoint_index = self.htlc_state.outpoint_index.unwrap();
        let script_hex = self.htlc_state.script.clone().unwrap();
        let preimage = self.htlc_state.preimage.unwrap();
        let to_address = self.htlc_state.to_address.clone().unwrap();

        let mut outpoint_tx = [0u8; 32];
        hex::decode_to_slice(&outpoint_tx_hex, &mut outpoint_tx)
            .map_err(|_| anyhow::anyhow!("invalid hex"))?;
        let outpoint = kovanica_state::OutPoint::new(
            kovanica_state::TxId::from_bytes(outpoint_tx),
            outpoint_index,
        );

        let script_bytes = hex::decode(&script_hex).map_err(|_| anyhow::anyhow!("invalid hex"))?;
        if script_bytes.len() != 100 {
            return Err(anyhow::anyhow!("script must be 100 bytes"));
        }
        let script = kovanica_state::htlc::HtlcScript::parse(&script_bytes)
            .map_err(|e| anyhow::anyhow!("invalid script: {e:?}"))?;

        let to_addr = kovanica_state::Address::parse(&to_address)
            .map_err(|e| anyhow::anyhow!("invalid address: {e}"))?;

        let wallet = crate::Wallet::load(&PathBuf::from(&key_path))?;
        let from = wallet.address().to_hex();

        let result =
            self.client
                .redeem_htlc(&from, outpoint, script, preimage, &to_addr.to_hex())?;
        self.output = format!(
            "HTLC redeemed: tx={}",
            result
                .get("tx")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown")
        );
        self.show_output = true;
        Ok(())
    }

    async fn execute_htlc_refund(&mut self) -> Result<()> {
        let key_path = self
            .htlc_state
            .key_path
            .clone()
            .unwrap_or_else(|| "kovanica.key".to_string());
        let outpoint_tx_hex = self.htlc_state.outpoint_tx.clone().unwrap();
        let outpoint_index = self.htlc_state.outpoint_index.unwrap();
        let script_hex = self.htlc_state.script.clone().unwrap();
        let to_address = self.htlc_state.to_address.clone().unwrap();

        let mut outpoint_tx = [0u8; 32];
        hex::decode_to_slice(&outpoint_tx_hex, &mut outpoint_tx)
            .map_err(|_| anyhow::anyhow!("invalid hex"))?;
        let outpoint = kovanica_state::OutPoint::new(
            kovanica_state::TxId::from_bytes(outpoint_tx),
            outpoint_index,
        );

        let script_bytes = hex::decode(&script_hex).map_err(|_| anyhow::anyhow!("invalid hex"))?;
        if script_bytes.len() != 100 {
            return Err(anyhow::anyhow!("script must be 100 bytes"));
        }
        let script = kovanica_state::htlc::HtlcScript::parse(&script_bytes)
            .map_err(|e| anyhow::anyhow!("invalid script: {e:?}"))?;

        let to_addr = kovanica_state::Address::parse(&to_address)
            .map_err(|e| anyhow::anyhow!("invalid address: {e}"))?;

        let wallet = crate::Wallet::load(&PathBuf::from(&key_path))?;
        let from = wallet.address().to_hex();

        let result = self
            .client
            .refund_htlc(&from, outpoint, script, &to_addr.to_hex())?;
        self.output = format!(
            "HTLC refunded: tx={}",
            result
                .get("tx")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown")
        );
        self.show_output = true;
        Ok(())
    }

    async fn execute_htlc_balance(&mut self) -> Result<()> {
        let script_hex = self.htlc_state.script.clone().unwrap();
        let script_bytes = hex::decode(&script_hex).map_err(|_| anyhow::anyhow!("invalid hex"))?;
        if script_bytes.len() != 100 {
            return Err(anyhow::anyhow!("script must be 100 bytes"));
        }
        let script = kovanica_state::htlc::HtlcScript::parse(&script_bytes)
            .map_err(|e| anyhow::anyhow!("invalid script: {e:?}"))?;

        let balance = self.client.htlc_balance(&script)?;
        self.output = format!("{} atoms ({} KVNC)", balance, balance / 100_000_000);
        self.show_output = true;
        Ok(())
    }

    /// Render the collected offer as a local summary.
    ///
    /// The node exposes no `/api/offer/*` endpoint, so an offer is never
    /// broadcast and nothing is signed here — this reports exactly what would
    /// be submitted and says so, rather than implying an offer was created.
    fn execute_offer_create(&mut self) {
        let s = &self.offer_state;
        let asset = |a: &Option<String>| match a {
            Some(v) if !v.is_empty() => v.clone(),
            _ => "KVNC (native)".to_string(),
        };
        self.output = format!(
            "Offer prepared (local only — no /api/offer endpoint exists, nothing was broadcast or signed):\n  \
             Subcommand: {}\n  \
             Key:       {}\n  \
             Maker:     {}\n  \
             Give:      {} atoms of {}\n  \
             Take:      {} atoms of {}\n  \
             Preimage:  {}\n  \
             Timeout:   {} blocks\n  \
             Expires:   {}",
            s.sub_command.as_deref().unwrap_or("create"),
            s.key_path.as_deref().unwrap_or("kovanica.key"),
            s.maker.as_deref().unwrap_or("(unset)"),
            s.give_amount.unwrap_or(0),
            asset(&s.give_asset),
            s.take_amount.unwrap_or(0),
            asset(&s.take_asset),
            s.preimage_hash.as_deref().unwrap_or("(unset)"),
            s.timeout.unwrap_or(0),
            s.expires_at.as_deref().unwrap_or("(unset)"),
        );
        self.show_output = true;
    }

    /// Check the collected offer for internal consistency.
    ///
    /// There is no on-chain offer to verify against (no `/api/offer/*`
    /// endpoint), so this validates the parameters themselves and reports each
    /// field, instead of claiming a verification that never happened.
    fn execute_offer_verify(&mut self) {
        let s = &self.offer_state;
        let is_hex = |v: &Option<String>, n: usize| v.as_ref().is_some_and(|x| x.len() == n);
        let mut checks: Vec<(&str, bool)> = vec![
            ("maker is 32 bytes of hex", is_hex(&s.maker, 64)),
            (
                "give asset is 32 bytes of hex (or native)",
                s.give_asset
                    .as_ref()
                    .map_or(true, |v| v.is_empty() || v.len() == 64),
            ),
            (
                "take asset is 32 bytes of hex (or native)",
                s.take_asset
                    .as_ref()
                    .map_or(true, |v| v.is_empty() || v.len() == 64),
            ),
            (
                "give amount is non-zero",
                s.give_amount.is_some_and(|a| a > 0),
            ),
            (
                "take amount is non-zero",
                s.take_amount.is_some_and(|a| a > 0),
            ),
            (
                "preimage hash is 32 bytes of hex",
                is_hex(&s.preimage_hash, 64),
            ),
            ("timeout is set", s.timeout.is_some()),
            (
                "expiry is set",
                s.expires_at.as_ref().is_some_and(|v| !v.is_empty()),
            ),
        ];
        let failed = checks.iter().filter(|(_, ok)| !ok).count();
        let body = checks
            .iter()
            .map(|(label, ok)| format!("  [{}] {label}", if *ok { "ok" } else { "FAIL" }))
            .collect::<Vec<_>>()
            .join("\n");
        self.output = format!(
            "Offer parameter check (local only — no /api/offer endpoint exists, so there is no \
             on-chain offer to verify):\n{body}\n{}",
            if failed == 0 {
                "All parameters are well-formed."
            } else {
                "Some parameters are not usable as an offer."
            }
        );
        self.show_output = true;
        checks.clear();
    }

    /// The RWA parameters the wizard gathered.
    fn rwa_params(&self) -> (String, String, String, u8) {
        let s = &self.rwa_state;
        (
            s.issuer.clone().unwrap_or_default(),
            s.class.clone().unwrap_or_default(),
            s.id.clone().unwrap_or_default(),
            s.version.unwrap_or(1),
        )
    }

    /// Resolve the RWA asset id the node derives for the current parameters.
    fn rwa_asset_id(&self) -> Result<String> {
        let (issuer, class, id, version) = self.rwa_params();
        let derived = self.client.rwa_derive(&issuer, &class, &id, version)?;
        derived
            .get("asset_id")
            .and_then(|v| v.as_str())
            .map(str::to_string)
            .ok_or_else(|| anyhow::anyhow!("node returned no asset_id for this RWA derive"))
    }

    async fn execute_rwa_derive(&mut self) -> Result<()> {
        let (issuer, class, id, version) = self.rwa_params();
        let derived = self.client.rwa_derive(&issuer, &class, &id, version)?;
        let hex = derived
            .get("asset_id")
            .and_then(|v| v.as_str())
            .unwrap_or("(none)");
        let kvnc = derived
            .get("asset_id_kvnc")
            .and_then(|v| v.as_str())
            .unwrap_or("(none)");
        self.output = format!(
            "RWA asset id derived by the node (POST /api/rwa/derive):\n  Issuer:  {issuer}\n  Class:   {class}\n  ID:      {id}\n  Version: {version}\n  Asset:   {hex}\n  KVNC:    {kvnc}"
        );
        self.show_output = true;
        Ok(())
    }

    /// RWA issuance is not implementable client-side yet.
    ///
    /// The node exposes only the read-only `/api/rwa/derive` and
    /// `/api/rwa/{asset_id}` routes — there is no endpoint to issue against, so
    /// this reports that plainly instead of printing a success line for an
    /// asset that was never created.
    async fn execute_rwa_issue(&mut self) -> Result<()> {
        let s = &self.rwa_state;
        Err(anyhow::anyhow!(
            "RWA issue is NOT implemented. The node exposes only the read-only \
             /api/rwa/derive and /api/rwa/{{asset_id}} routes — there is no issue endpoint, \
             so nothing was signed or broadcast. Collected: issuer={}, class={}, id={}, \
             amount={} atoms, key={}.",
            s.issuer.as_deref().unwrap_or("(unset)"),
            s.class.as_deref().unwrap_or("(unset)"),
            s.id.as_deref().unwrap_or("(unset)"),
            s.amount.unwrap_or(0),
            s.key_path.as_deref().unwrap_or("(unset)"),
        ))
    }

    /// RWA burn is not implementable client-side yet. See [`Self::execute_rwa_issue`].
    async fn execute_rwa_burn(&mut self) -> Result<()> {
        let s = &self.rwa_state;
        let (issuer, class, id, version) = self.rwa_params();
        let asset_id = self
            .rwa_asset_id()
            .unwrap_or_else(|_| "(underivable)".to_string());
        Err(anyhow::anyhow!(
            "RWA burn is NOT implemented. The node exposes only the read-only \
             /api/rwa/derive and /api/rwa/{{asset_id}} routes — there is no burn endpoint, \
             so nothing was signed or broadcast. Collected: issuer={issuer}, class={class}, \
             id={id}, version={version}, resolved asset={asset_id}, key={}.",
            s.key_path.as_deref().unwrap_or("(unset)"),
        ))
    }

    async fn execute_rwa_info(&mut self) -> Result<()> {
        let asset_id = self.rwa_asset_id()?;
        let result = self.client.rwa_detail(&asset_id)?;
        self.output = serde_json::to_string_pretty(&result)?;
        self.show_output = true;
        Ok(())
    }

    async fn execute_nft_info(&mut self) -> Result<()> {
        let asset_id = self.nft_state.asset_id.clone().unwrap_or_default();
        let result = self.client.nft_detail(&asset_id)?;
        self.output = serde_json::to_string_pretty(&result)?;
        self.show_output = true;
        Ok(())
    }

    async fn execute_nft_collection(&mut self) -> Result<()> {
        let collection_id = self.nft_state.collection_id.clone().unwrap_or_default();
        let result = self.client.collection_detail(&collection_id)?;
        self.output = serde_json::to_string_pretty(&result)?;
        self.show_output = true;
        Ok(())
    }

    async fn execute(&mut self, item: MenuItem) -> Result<()> {
        self.output.clear();
        self.show_output = true;

        match item {
            MenuItem::Head => {
                let result = self.client.head()?;
                self.output = serde_json::to_string_pretty(&result)?;
            }
            MenuItem::P2p => {
                let result = self.client.p2p()?;
                self.output = serde_json::to_string_pretty(&result)?;
            }
            MenuItem::Bootstrap => {
                let result = self.client.bootstrap()?;
                self.output = serde_json::to_string_pretty(&result)?;
            }
            MenuItem::State => {
                let result = self.client.state()?;
                self.output = serde_json::to_string_pretty(&result)?;
            }
            MenuItem::Blocks => {
                let result = self.client.blocks()?;
                self.output = serde_json::to_string_pretty(&result)?;
            }
            MenuItem::Balance => {
                self.start_input(
                    "Enter address (kvnc...dag or 64-hex): ".to_string(),
                    InputMode::BalanceAddress,
                );
            }
            MenuItem::Keygen => {
                let wallet = crate::Wallet::generate()?;
                let key_path = "kovanica.key";
                wallet.save(&PathBuf::from("kovanica.key"), false)?;
                let addr = wallet.address();
                let mut output = String::new();
                output.push_str(&format!("Wrote key to {key_path} (keep it secret)\n"));
                output.push_str(&format!("address (kvnc): {}\n", addr.to_kvnc()));
                output.push_str(&format!("address (hex):  {}", addr.to_hex()));
                self.output = output;
                self.show_output = true;
            }
            MenuItem::Address => {
                self.start_input(
                    "Enter key file path (default: kovanica.key): ".to_string(),
                    InputMode::AddressKeyPath,
                );
            }
            MenuItem::Send => {
                self.send_state = SendState::default();
                self.start_input(
                    "Enter key file path (default: kovanica.key): ".to_string(),
                    InputMode::Send(SendStep::KeyPath),
                );
            }
            MenuItem::Htlc => {
                self.htlc_state = HtlcState::default();
                self.start_input(
                    "HTLC subcommand (create/redeem/refund/balance): ".to_string(),
                    InputMode::Htlc(HtlcStep::SubCommand),
                );
            }
            MenuItem::Offer => {
                self.offer_state = OfferState::default();
                self.start_input(
                    "Offer subcommand (create/verify): ".to_string(),
                    InputMode::Offer(OfferStep::SubCommand),
                );
            }
            MenuItem::Rwa => {
                self.rwa_state = RwaState::default();
                self.start_input(
                    "RWA subcommand (derive/issue/burn/info): ".to_string(),
                    InputMode::Rwa(RwaStep::SubCommand),
                );
            }
            MenuItem::Nft => {
                self.nft_state = NftState::default();
                self.start_input(
                    "NFT subcommand (info/collection): ".to_string(),
                    InputMode::Nft(NftStep::SubCommand),
                );
            }
            MenuItem::Quit => {
                return Err(anyhow::anyhow!("quit"));
            }
        }
        Ok(())
    }
}

fn ui(f: &mut Frame, app: &App) {
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(30), Constraint::Percentage(70)])
        .split(f.area());

    let items: Vec<ListItem> = MenuItem::all()
        .iter()
        .enumerate()
        .map(|(idx, item)| {
            let style = if Some(idx) == app.menu_state.selected() {
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(Color::White)
            };
            ListItem::new(Line::from(Span::styled(item.label(), style)))
        })
        .collect();

    let menu = List::new(items)
        .block(Block::default().borders(Borders::ALL).title("Kovanica TUI"))
        .highlight_style(
            Style::default()
                .fg(Color::Black)
                .bg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol(">> ");

    f.render_stateful_widget(menu, chunks[0], &mut app.menu_state.clone());

    let (output_title, output_text) = if let Some(prompt) = &app.input_prompt {
        (
            "Input".to_string(),
            Text::from(format!("{prompt}{}", app.input_buffer)),
        )
    } else if app.show_output {
        ("Output".to_string(), Text::from(app.output.clone()))
    } else {
        (
            "Output".to_string(),
            Text::from("Select a command from the menu (Enter to execute, Q to quit)"),
        )
    };

    let output_block = Block::default().borders(Borders::ALL).title(output_title);
    let output = Paragraph::new(output_text)
        .block(output_block)
        .wrap(Wrap { trim: true });
    f.render_widget(output, chunks[1]);

    let footer_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1),
            Constraint::Length(2),
            Constraint::Length(1),
        ])
        .split(Rect {
            x: f.area().x,
            y: f.area().y + f.area().height - 4,
            width: f.area().width,
            height: 4,
        });

    let help_text = if app.input_prompt.is_some() {
        "Type input | Enter: Submit | Esc: Cancel"
    } else {
        "↑/↓: Navigate | Enter: Execute | Q: Quit"
    };
    let help = Paragraph::new(help_text)
        .style(Style::default().fg(Color::Gray))
        .alignment(Alignment::Center);
    f.render_widget(help, footer_chunks[0]);

    let contact = Paragraph::new(vec![
        Line::from(vec![
            Span::styled("Contact: ", Style::default().fg(Color::Cyan)),
            Span::styled("dev@kovanica.online", Style::default().fg(Color::White)),
            Span::styled("  |  ", Style::default().fg(Color::Gray)),
            Span::styled(
                "security@kovanica.online",
                Style::default().fg(Color::White),
            ),
        ]),
        Line::from(vec![
            Span::styled("by: ", Style::default().fg(Color::Cyan)),
            Span::styled(
                "github.com/BetterCallDzuks",
                Style::default()
                    .fg(Color::White)
                    .add_modifier(Modifier::UNDERLINED),
            ),
        ]),
    ])
    .alignment(Alignment::Center);
    f.render_widget(contact, footer_chunks[1]);

    let version = Paragraph::new(format!("v{}", env!("CARGO_PKG_VERSION")))
        .style(Style::default().fg(Color::DarkGray))
        .alignment(Alignment::Center);
    f.render_widget(version, footer_chunks[2]);
}

pub fn run(client: Client) -> Result<()> {
    let rt = Runtime::new()?;
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut app = App::new(client);
    let result = rt.block_on(run_app(&mut terminal, &mut app));

    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )?;
    terminal.show_cursor()?;

    result
}

async fn run_app<B: ratatui::backend::Backend>(
    terminal: &mut Terminal<B>,
    app: &mut App,
) -> Result<()> {
    loop {
        terminal.draw(|f| ui(f, app))?;

        if let Event::Key(key) = event::read()? {
            if key.kind == KeyEventKind::Press {
                if app.input_prompt.is_some() {
                    match key.code {
                        KeyCode::Char(c) => app.input_buffer.push(c),
                        KeyCode::Backspace => {
                            app.input_buffer.pop();
                        }
                        KeyCode::Enter => {
                            if let Err(e) = app.submit_input().await {
                                if e.to_string() != "quit" {
                                    app.output = format!("Error: {}", e);
                                    app.show_output = true;
                                }
                            }
                        }
                        KeyCode::Esc => {
                            app.input_prompt = None;
                            app.input_buffer.clear();
                            app.input_mode = InputMode::Normal;
                        }
                        _ => {}
                    }
                } else {
                    match key.code {
                        KeyCode::Char('q') | KeyCode::Char('Q') => return Ok(()),
                        KeyCode::Up => app.previous(),
                        KeyCode::Down => app.next(),
                        KeyCode::Enter => {
                            if let Some(selected) = app.menu_state.selected() {
                                let item = MenuItem::all()[selected];
                                if item == MenuItem::Quit {
                                    return Ok(());
                                }
                                if let Err(e) = app.execute(item).await {
                                    if e.to_string() != "quit" {
                                        app.output = format!("Error: {}", e);
                                    }
                                }
                            }
                        }
                        _ => {}
                    }
                }
            }
        }
    }
}
