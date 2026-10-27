//! Library surface of the `kovanica` command-line wallet.
//!
//! The `kovanica` binary (`src/main.rs`) and other tools such as `kovanica-faucet`
//! and `generate-validators` consume these modules via `kovanica_cli::...`.

pub mod amount;
pub mod comms;
pub mod contracts;
pub mod node;
pub mod output;
pub mod rpc;
pub mod stake;
pub mod tui;
pub mod tx;
pub mod wallet;

#[cfg(test)]
mod version {
    /// `1.0.0` is reserved for testnet launch. The console stays pre-1.0.
    #[test]
    fn package_version_stays_before_testnet_launch() {
        let version = env!("CARGO_PKG_VERSION");
        assert!(version.starts_with("0."), "{version}");
        assert_ne!(version, "1.0.0");
    }
}
