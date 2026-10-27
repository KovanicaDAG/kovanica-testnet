//! `kovanica-node --check-config` must reject consensus-parameter environment
//! overrides on a shared chain, and accept them on a development chain.
//!
//! This is the operator-facing contract from PRO-23's acceptance criteria: a
//! node on chain 1 or chain 4 that is started with, say,
//! `KOVANICA_ROUND_DURATION_MS=250` must fail at config check time instead of
//! booting and voting on rules its peers do not run.

use std::process::Command;

/// Minimal config that passes validation: a non-validator node with no key
/// requirement and the local chain by default.
fn config_file(chain_id: u64) -> (tempfile::TempDir, String) {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("config.toml");
    let data_str = dir
        .path()
        .join("data")
        .display()
        .to_string()
        .replace('\\', "/");
    let body = format!("chain_id = {chain_id}\nrun_validator = false\ndata_dir = \"{data_str}\"\n");
    std::fs::write(&path, body).expect("write config");
    (dir, path.to_string_lossy().into_owned())
}

/// Run `--check-config` with a clean environment, then the given overrides.
fn check_config(path: &str, envs: &[(&str, &str)]) -> std::process::Output {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_kovanica-node"));
    cmd.arg("--check-config").arg("--config").arg(path);
    // Do not inherit a developer's KOVANICA_* environment: the outcome must be
    // decided by the overrides this test sets.
    for var in [
        "KOVANICA_ROUND_DURATION_MS",
        "KOVANICA_MYSTICGHOST",
        "KOVANICA_VRF_LEADER",
        "KOVANICA_CHAIN_ID",
        "KOVANICA_VALIDATOR_KEY",
        "KOVANICA_BOOTNODES",
    ] {
        cmd.env_remove(var);
    }
    for (key, value) in envs {
        cmd.env(key, value);
    }
    cmd.output().expect("run kovanica-node --check-config")
}

fn stderr(output: &std::process::Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

#[test]
fn check_config_accepts_a_plain_public_chain_config() {
    let (_dir, path) = config_file(4);
    let out = check_config(&path, &[]);
    assert!(
        out.status.success(),
        "chain 4 without overrides must pass, stderr: {}",
        stderr(&out)
    );
}

#[test]
fn check_config_rejects_overrides_on_chain_4() {
    let (_dir, path) = config_file(4);
    for (var, value) in [
        ("KOVANICA_ROUND_DURATION_MS", "250"),
        ("KOVANICA_MYSTICGHOST", "false"),
        ("KOVANICA_VRF_LEADER", "false"),
    ] {
        let out = check_config(&path, &[(var, value)]);
        assert!(
            !out.status.success(),
            "{var} on chain 4 must fail the config check"
        );
        let err = stderr(&out);
        assert!(err.contains(var), "the error must name {var}, got: {err}");
        assert!(
            err.contains("chain_id 4"),
            "the error must name the chain, got: {err}"
        );
    }
}

#[test]
fn check_config_rejects_overrides_on_chain_1() {
    let (_dir, path) = config_file(1);
    let out = check_config(&path, &[("KOVANICA_ROUND_DURATION_MS", "250")]);
    assert!(
        !out.status.success(),
        "chain 1 must reject a round-duration override"
    );
    assert!(stderr(&out).contains("KOVANICA_ROUND_DURATION_MS"));
}

#[test]
fn check_config_allows_overrides_on_local_and_devnet() {
    for chain in [3u64, 1337] {
        let (_dir, path) = config_file(chain);
        let out = check_config(&path, &[("KOVANICA_ROUND_DURATION_MS", "250")]);
        assert!(
            out.status.success(),
            "chain {chain} must allow the override, stderr: {}",
            stderr(&out)
        );
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(
            stdout.contains("round_duration_ms=250"),
            "the override must take effect on chain {chain}, got: {stdout}"
        );
    }
}

/// The deployed testnet compose must not set consensus parameters: the node
/// rejects them on chain 2, so a compose file that sets one now fails to boot.
/// (This test exists because `docker-compose.yml` did exactly that, with values
/// equal to the defaults — the break would have been invisible until deploy.)
#[test]
fn deploy_compose_does_not_set_frozen_consensus_vars() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docker-compose.yml");
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("reading {}: {e}", path.display()));
    for var in [
        "KOVANICA_ROUND_DURATION_MS",
        "KOVANICA_MYSTICGHOST",
        "KOVANICA_VRF_LEADER",
    ] {
        // Assignment only: the file is allowed to *mention* a variable in a
        // comment explaining why it is absent.
        let assigned = text
            .lines()
            .map(str::trim)
            .any(|line| line.starts_with(&format!("{var}:")));
        assert!(
            !assigned,
            "docker-compose.yml assigns {var}, which the node rejects on a shared chain; \
             remove the assignment (the built-in defaults are the production values) or run a \
             dev chain"
        );
    }
}

/// `funded_accounts.toml` pre-funds arbitrary balances. It is a testnet/dev
/// convenience and must be refused on mainnet (chain 1) at config-check time,
/// before anything is minted.
#[test]
fn check_config_rejects_funded_accounts_on_mainnet() {
    let (dir, path) = config_file(1);
    std::fs::create_dir_all(dir.path().join("data")).expect("create data dir");
    std::fs::write(
        dir.path().join("data").join("funded_accounts.toml"),
        "[[account]]\naddress = \"1111111111111111111111111111111111111111111111111111111111111111\"\nbalance = 1000\n",
    )
    .expect("write funded accounts");

    let out = check_config(&path, &[]);
    assert!(
        !out.status.success(),
        "chain 1 with funded_accounts.toml must fail the config check"
    );
    let err = stderr(&out);
    assert!(
        err.contains("funded_accounts.toml"),
        "the error must name the file, got: {err}"
    );
}

/// The same file is fine on a testnet.
#[test]
fn check_config_accepts_funded_accounts_on_testnet() {
    let (dir, path) = config_file(4);
    std::fs::create_dir_all(dir.path().join("data")).expect("create data dir");
    std::fs::write(
        dir.path().join("data").join("funded_accounts.toml"),
        "[[account]]\naddress = \"1111111111111111111111111111111111111111111111111111111111111111\"\nbalance = 1000\n",
    )
    .expect("write funded accounts");

    let out = check_config(&path, &[]);
    assert!(
        out.status.success(),
        "chain 4 must accept funded_accounts.toml, stderr: {}",
        stderr(&out)
    );
}

/// A mainnet genesis must declare a viable committee (15..=20). A ceremony file
/// with three validators is a testnet-shaped genesis and must be refused.
#[test]
fn check_config_rejects_too_few_genesis_validators_on_mainnet() {
    let (dir, path) = config_file(1);
    let data = dir.path().join("data");
    std::fs::create_dir_all(&data).expect("create data dir");
    std::fs::write(
        data.join("genesis_validators.toml"),
        format!(
            "chain_id = 1\n\n{}",
            (1..=3)
                .map(|i| format!(
                    "[[validator]]\naddress = \"{i:02x}{}\"\nstake = 50000000000000\n\n",
                    "00".repeat(31)
                ))
                .collect::<String>()
        ),
    )
    .expect("write genesis validators");

    let out = check_config(&path, &[]);
    assert!(
        !out.status.success(),
        "chain 1 with 3 genesis validators must fail the config check"
    );
    let err = stderr(&out);
    assert!(
        err.contains("has 3 validators") && err.contains("15..=20"),
        "the error must state the count and the bounds, got: {err}"
    );
}

/// The same set is fine on a testnet, which runs on a handful of nodes.
#[test]
fn check_config_accepts_few_genesis_validators_on_testnet() {
    let (dir, path) = config_file(4);
    let data = dir.path().join("data");
    std::fs::create_dir_all(&data).expect("create data dir");
    std::fs::write(
        data.join("genesis_validators.toml"),
        format!(
            "chain_id = 4\n\n{}",
            (1..=3)
                .map(|i| format!(
                    "[[validator]]\naddress = \"{i:02x}{}\"\nstake = 50000000000000\n\n",
                    "00".repeat(31)
                ))
                .collect::<String>()
        ),
    )
    .expect("write genesis validators");

    let out = check_config(&path, &[]);
    assert!(
        out.status.success(),
        "chain 4 must accept a 3-validator genesis, stderr: {}",
        stderr(&out)
    );
}
