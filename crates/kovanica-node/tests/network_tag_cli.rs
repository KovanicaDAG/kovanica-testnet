//! `kovanica-node network-tag` prints the tag the node would log, without
//! starting a node. A different or missing bundle file changes that tag.

use std::path::Path;
use std::process::Command;

fn write_bundle(dir: &Path) {
    std::fs::write(
        dir.join("validators.json"),
        format!(
            r#"[{{"address":"{}","stake":50000000000000}}]"#,
            "11".repeat(32)
        ),
    )
    .unwrap();
    std::fs::write(dir.join("founder_premine.hex"), "44".repeat(32)).unwrap();
    std::fs::write(
        dir.join("funded_accounts.toml"),
        format!(
            "[[account]]\naddress = \"{}\"\nbalance = 1000\n",
            "22".repeat(32)
        ),
    )
    .unwrap();
    std::fs::write(
        dir.join("genesis_validators.toml"),
        format!(
            "chain_id = 4\n[[validator]]\naddress = \"{}\"\nstake = 50000000000000\n",
            "33".repeat(32)
        ),
    )
    .unwrap();
}

fn write_config(dir: &Path, data_dir: &Path, treasury: &str) -> String {
    let path = dir.join("config.toml");
    let data_str = data_dir.display().to_string().replace('\\', "/");
    let body = format!(
        "chain_id = 4\nrun_validator = false\ndata_dir = \"{data_str}\"\ntreasury_address = \"{treasury}\"\nlisten_addr = \"127.0.0.1:0\"\n"
    );
    std::fs::write(&path, &body).unwrap();
    path.to_string_lossy().into_owned()
}

/// Digest-relevant overrides must not leak in from the developer environment.
fn network_tag(config: &str) -> String {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_kovanica-node"));
    cmd.args(["network-tag", "--config", config]);
    cmd.env("RUST_LOG", "off");
    for var in [
        "KOVANICA_DATA_DIR",
        "KOVANICA_TREASURY_ADDRESS",
        "KOVANICA_CHAIN_ID",
        "KOVANICA_BOOTNODES",
        "KOVANICA_VALIDATOR_KEY",
        "KOVANICA_LISTEN_ADDR",
    ] {
        cmd.env_remove(var);
    }
    let output = cmd.output().expect("run kovanica-node network-tag");
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    assert!(
        output.status.success(),
        "network-tag failed: {}\n{}",
        stdout,
        String::from_utf8_lossy(&output.stderr)
    );
    stdout.trim().to_string()
}

#[test]
fn network_tag_cli_matches_the_node_and_changes_when_a_bundle_file_changes() {
    let dir = tempfile::tempdir().expect("tempdir");
    let data = dir.path().join("data");
    std::fs::create_dir(&data).unwrap();
    write_bundle(&data);
    let treasury = "55".repeat(32);
    let config = write_config(dir.path(), &data, &treasury);

    let tag = network_tag(&config);
    // Same fixture and treasury as `sync_status_network_tag_equals_the_startup_log`,
    // which locks this string to the startup log and `kovanica_syncStatus`.
    assert_eq!(tag, "4-2bd89b0649c4ecbd");

    std::fs::write(data.join("founder_premine.hex"), "66".repeat(32)).unwrap();
    let changed = network_tag(&config);
    assert_ne!(changed, tag, "changing one file must change the tag");

    std::fs::remove_file(data.join("funded_accounts.toml")).unwrap();
    let missing = network_tag(&config);
    assert_ne!(missing, tag, "a missing file must change the tag");
    assert_ne!(missing, changed);

    // Restoring the bundle restores the tag. The command does not keep state.
    write_bundle(&data);
    assert_eq!(network_tag(&config), tag);
}
