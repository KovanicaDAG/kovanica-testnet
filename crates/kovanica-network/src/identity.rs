//! Persistent libp2p node identity and key-file hygiene.
//!
//! The libp2p identity is a *transport* key: it authenticates the noise
//! handshake and signs gossipsub envelopes, and it determines the node's
//! `PeerId`. It is deliberately separate from the validator signing key, and
//! this crate never reads the validator seed. Persisting it keeps the
//! `PeerId` stable across restarts so `/p2p/<id>` bootnode entries stay valid.

use std::fs;
use std::io::Write;
use std::path::Path;

use libp2p::identity::Keypair;

use crate::NetworkError;

/// Refuse secret key files that are readable or writable by group/other.
///
/// On unix the file must be a regular file with no group/other permission
/// bits (e.g. `0600` or `0400`). On other platforms this only checks that the
/// path is a regular file.
pub fn check_key_file_permissions(path: &Path) -> Result<(), NetworkError> {
    let meta = fs::metadata(path)
        .map_err(|e| NetworkError::Config(format!("key file {}: {e}", path.display())))?;
    if !meta.is_file() {
        return Err(NetworkError::Config(format!(
            "key file {} is not a regular file",
            path.display()
        )));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = meta.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            return Err(NetworkError::Config(format!(
                "key file {} has mode {mode:o}; it must not be accessible by group or others (chmod 600)",
                path.display()
            )));
        }
    }
    Ok(())
}

/// Load the node's libp2p identity from `path`, creating it (mode `0600`)
/// if it does not exist yet.
///
/// The file holds the 32-byte Ed25519 secret as hex. An existing file with
/// loose permissions or bad contents is an error: the node never silently
/// replaces an identity it was told to use.
pub fn load_or_create_node_identity(path: &Path) -> Result<Keypair, NetworkError> {
    let cfg_err =
        |msg: String| NetworkError::Config(format!("node identity {}: {msg}", path.display()));

    if !path.exists() {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent).map_err(|e| cfg_err(e.to_string()))?;
            }
        }
        let keypair = Keypair::generate_ed25519();
        let secret = keypair
            .clone()
            .try_into_ed25519()
            .map_err(|e| cfg_err(e.to_string()))?
            .secret();
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        match options.open(path) {
            Ok(mut file) => {
                file.write_all(hex::encode(secret.as_ref()).as_bytes())
                    .and_then(|_| file.sync_all())
                    .map_err(|e| cfg_err(e.to_string()))?;
                return Ok(keypair);
            }
            // Lost a creation race: fall through and load the winner's key.
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(cfg_err(e.to_string())),
        }
    }

    check_key_file_permissions(path)?;
    let raw = fs::read_to_string(path).map_err(|e| cfg_err(e.to_string()))?;
    let mut bytes = hex::decode(raw.trim()).map_err(|_| cfg_err("must contain hex".into()))?;
    if bytes.len() != 32 {
        return Err(cfg_err(format!(
            "expected a 32-byte ed25519 secret, got {} bytes",
            bytes.len()
        )));
    }
    // `ed25519_from_bytes` zeroizes the buffer it is given.
    Keypair::ed25519_from_bytes(&mut bytes).map_err(|e| cfg_err(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_is_created_once_and_reused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sub").join("p2p_node.key");
        let first = load_or_create_node_identity(&path).unwrap();
        let second = load_or_create_node_identity(&path).unwrap();
        assert_eq!(first.public().to_peer_id(), second.public().to_peer_id());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
    }

    #[test]
    fn corrupt_identity_is_an_error_not_replaced() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("p2p_node.key");
        fs::write(&path, "not hex").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        }
        assert!(load_or_create_node_identity(&path).is_err());
        assert_eq!(fs::read_to_string(&path).unwrap(), "not hex");
    }

    #[cfg(unix)]
    #[test]
    fn loose_permissions_are_rejected() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("secret.key");
        fs::write(&path, "00").unwrap();
        for mode in [0o644, 0o640, 0o604, 0o660] {
            fs::set_permissions(&path, fs::Permissions::from_mode(mode)).unwrap();
            assert!(check_key_file_permissions(&path).is_err(), "mode {mode:o}");
        }
        for mode in [0o600, 0o400] {
            fs::set_permissions(&path, fs::Permissions::from_mode(mode)).unwrap();
            assert!(check_key_file_permissions(&path).is_ok(), "mode {mode:o}");
        }
        assert!(check_key_file_permissions(dir.path()).is_err());
    }
}
