//! Light-node config. The chain id is whatever the operator configured.
//! The live testnet uses 1337. This file does not rewrite it.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

/// File name inside the data directory.
pub const CONFIG_FILE: &str = "config.json";

/// Operator config for one light node.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct LightConfig {
    /// Full-node RPC base URL. `/rpc` is appended when missing.
    pub rpc: String,
    /// Chain id committed to by seals and transaction signatures.
    #[serde(rename = "chainId")]
    pub chain_id: u64,
    /// Committee epoch. Rotation is not live, so this stays 0.
    pub epoch: u64,
    /// Keystore file name, relative to the data directory.
    pub keystore: PathBuf,
}

impl LightConfig {
    /// Defaults for a local node on chain 1337.
    pub fn local_default() -> Self {
        Self {
            rpc: "http://127.0.0.1:8545".into(),
            chain_id: 1337,
            epoch: 0,
            keystore: PathBuf::from("keystore.json"),
        }
    }

    /// Load `config.json` from `dir`.
    pub fn load(dir: &Path) -> Result<Self> {
        let path = dir.join(CONFIG_FILE);
        let text = fs::read_to_string(&path).with_context(|| {
            format!("reading {} (run `kovanica-lightnode init`)", path.display())
        })?;
        serde_json::from_str(&text).with_context(|| format!("parsing {}", path.display()))
    }

    /// Write `config.json`.
    pub fn save(&self, dir: &Path) -> Result<()> {
        fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
        let path = dir.join(CONFIG_FILE);
        let text = serde_json::to_string_pretty(self).context("encoding light-node config")?;
        fs::write(&path, text).with_context(|| format!("writing {}", path.display()))
    }

    /// Absolute or data-dir-relative keystore path.
    pub fn keystore_path(&self, dir: &Path) -> PathBuf {
        if self.keystore.is_absolute() {
            self.keystore.clone()
        } else {
            dir.join(&self.keystore)
        }
    }
}
