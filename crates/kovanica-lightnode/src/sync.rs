//! Follow sealed committed-leader headers.
//!
//! The first accepted header is a checkpoint: the seal quorum is checked
//! and the parent digest is not. Every later header must name the previous
//! leader digest and the next height. A rejected seal is not written.

use std::fs;
use std::path::Path;

use anyhow::{bail, Context, Result};
use kovanica_light::verify_sealed_header;
use kovanica_types::{Committee, Hash, LeaderHeader};

use crate::config::LightConfig;
use crate::rpc::RpcClient;

/// File name of the last header whose seals verified.
pub const HEADER_FILE: &str = "last-header.json";

/// What `sync` learned from the full node.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SyncOutcome {
    /// The node has not stored a sealed header.
    NoHeader,
    /// The light node accepted `header` (and any headers between the
    /// previous checkpoint and it).
    Verified {
        /// Committed-leader height now stored.
        height: u64,
        /// Header hash.
        hash: Hash,
    },
}

/// Load the last accepted header, if this data directory has one.
pub fn load_header(dir: &Path) -> Result<Option<LeaderHeader>> {
    let path = dir.join(HEADER_FILE);
    if !path.exists() {
        return Ok(None);
    }
    let text = fs::read_to_string(&path).with_context(|| format!("reading {}", path.display()))?;
    let header =
        serde_json::from_str(&text).with_context(|| format!("parsing {}", path.display()))?;
    Ok(Some(header))
}

/// Persist a header that has already passed [`verify_sealed_header`].
pub fn save_header(dir: &Path, header: &LeaderHeader) -> Result<()> {
    fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    let path = dir.join(HEADER_FILE);
    let text = serde_json::to_string_pretty(header).context("encoding leader header")?;
    let tmp = dir.join(format!("{HEADER_FILE}.tmp"));
    fs::write(&tmp, text).with_context(|| format!("writing {}", tmp.display()))?;
    fs::rename(&tmp, &path).with_context(|| format!("replacing {}", path.display()))?;
    Ok(())
}

/// Download and verify headers, then store only those that passed.
pub fn sync_rpc(dir: &Path, cfg: &LightConfig, rpc: &RpcClient) -> Result<SyncOutcome> {
    let Some(latest) = rpc.latest_header()? else {
        return Ok(SyncOutcome::NoHeader);
    };
    let committee = rpc.committee(cfg.epoch)?;
    let stored = load_header(dir)?;
    match stored {
        None => {
            accept_and_store(
                dir,
                cfg.chain_id,
                &committee,
                &latest,
                &rpc.seals(latest.committed_height)?,
                None,
            )?;
            Ok(SyncOutcome::Verified {
                height: latest.committed_height,
                hash: latest.hash(),
            })
        }
        Some(stored) if latest.committed_height < stored.committed_height => {
            bail!(
                "full node height {} is behind the stored header {}",
                latest.committed_height,
                stored.committed_height
            )
        }
        Some(stored) if latest.committed_height == stored.committed_height => {
            if latest.hash() != stored.hash() {
                bail!(
                    "full node header at height {} does not match the stored header",
                    stored.committed_height
                );
            }
            accept_and_store(
                dir,
                cfg.chain_id,
                &committee,
                &latest,
                &rpc.seals(latest.committed_height)?,
                None,
            )?;
            Ok(SyncOutcome::Verified {
                height: latest.committed_height,
                hash: latest.hash(),
            })
        }
        Some(mut parent) => {
            for height in parent.committed_height.saturating_add(1)..=latest.committed_height {
                let Some(header) = rpc.header(Some(height))? else {
                    bail!("full node has no leader header at height {height}");
                };
                let seals = rpc.seals(height)?;
                accept_and_store(
                    dir,
                    cfg.chain_id,
                    &committee,
                    &header,
                    &seals,
                    Some(&parent),
                )?;
                parent = header;
            }
            Ok(SyncOutcome::Verified {
                height: parent.committed_height,
                hash: parent.hash(),
            })
        }
    }
}

/// Verify `header` against `parent` and write it. On failure the previous file stays.
pub fn accept_and_store(
    dir: &Path,
    chain_id: u64,
    committee: &Committee,
    header: &LeaderHeader,
    seals: &[kovanica_types::CommitSeal],
    parent: Option<&LeaderHeader>,
) -> Result<()> {
    verify_sealed_header(chain_id, committee, header, seals, parent).with_context(|| {
        format!(
            "rejected leader header at height {}",
            header.committed_height
        )
    })?;
    save_header(dir, header)
}

/// Linux runs under systemd. Windows runs the same executable as a service.
#[cfg(windows)]
pub fn platform_note() -> &'static str {
    "Windows: install this executable as a service that runs `kovanica-lightnode run`. A tray UI is not part of this binary."
}

/// Linux runs under systemd. Windows runs the same executable as a service.
#[cfg(not(windows))]
pub fn platform_note() -> &'static str {
    "Linux: run `kovanica-lightnode run` under systemd. The unit file is installed separately. A tray UI is not part of this binary."
}
