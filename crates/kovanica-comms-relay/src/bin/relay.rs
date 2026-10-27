//! `kovanica-comms-relay` binary — store-and-forward relay HTTP server (§4).
//!
//! Binds `KOVANICA_RELAY_BIND` (default `127.0.0.1:8787`), initialises tracing and
//! serves until `SIGINT`/`SIGTERM`.

use std::net::SocketAddr;

use kovanica_comms_relay::RelayServer;
use tracing::{error, info};
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::fmt().with_env_filter(filter).init();

    let bind =
        std::env::var("KOVANICA_RELAY_BIND").unwrap_or_else(|_| "127.0.0.1:8787".to_string());
    let addr: SocketAddr = bind
        .parse()
        .map_err(|e| anyhow::anyhow!("invalid KOVANICA_RELAY_BIND {bind:?}: {e}"))?;

    let server = RelayServer::new(addr);
    let handle = match server.start().await {
        Ok(handle) => handle,
        Err(e) => {
            error!(%addr, error = %e, "failed to bind relay");
            return Err(e.into());
        }
    };
    info!(%addr, "kovanica-comms-relay up");
    let _ = handle.await;
    Ok(())
}
