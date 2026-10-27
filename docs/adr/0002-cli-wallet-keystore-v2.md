# ADR 0002: `kovanica-cli` encrypted keystore v2

Implementation record for the CLI's encrypted v2 keystore and explicit v1 migration boundary; this does not decide consensus behavior.

**Status: Draft — implementation record; client CLI only**

**Consensus impact: client-only**

**Scope:** `crates/kovanica-cli` wallet and keystore commands. This ADR records behavior present in `wallet.rs` and `main.rs`; it is not a cryptographic audit, nor a claim that the separate, unresolved consensus ADR (ADR 0001) is ready for implementation or activation.

## 1. Context and rationale

The CLI needs to persist Ed25519 seed material without writing new wallet secrets in plaintext. Its v2 format uses a password-derived key and authenticated encryption, validates the metadata that defines the format, and checks that a decrypted seed belongs to the recorded identity. Existing v1 files have incompatible and weaker protection: they may contain a plaintext seed or use an unauthenticated repeated-BLAKE3-XOR transform. They are accepted only by the explicit migration path, so ordinary wallet commands do not silently treat legacy data as protected v2 data.

This is deliberately a `kovanica-cli` implementation boundary. It does **not** implement or claim universal encrypted keypair persistence in `kovanica-crypto`. In particular, it does not resolve unchecked `tasklist.md:34` (“Keypair persistence: Secure file storage (encrypted with passphrase)”) for that crate. The CLI's own keystore does not imply a change to consensus, ledger rules, node key storage, or `kovanica-crypto` APIs.

## 2. Implemented v2 format

New keystores use version `2`, Argon2id (version 0x13) with fixed parameters of 64 MiB memory, `t=3`, `p=4`, and a 32-byte derived key, followed by XChaCha20-Poly1305 authenticated encryption. Each new store gets a fresh 16-byte salt and 24-byte nonce from `OsRng`. The 32-byte seed is encrypted; the stored ciphertext is 48 bytes including the authentication tag.

Associated data binds the v2 domain/version and algorithm metadata, salt, nonce, address, and public key. Thus those fields cannot be substituted independently without authentication failure. On decryption the CLI also derives the public key and address from the recovered seed and checks them against the stored identity.

Loading is bounded to at most 64 KiB of input. The parser accepts only supported versions and the v2 schema: unknown fields are rejected, `encrypted` must be true, cipher/KDF identifiers and all numeric KDF parameters must match the supported fixed values, and salt, nonce, ciphertext, address, and public key must have valid lengths/encodings. The address field must use either the canonical `kvnc<hex>dag` encoding (32-byte payload + 4-byte BLAKE3 checksum, see [ADR-adjacent README section](../../README.md#adresni-format-kanonski)) or a bare lowercase 32-byte hex string, so that keystores written before the canonical format remain loadable; the public key must use lowercase hex. Decryption/authentication and the seed-derived identity check occur when a wallet command needs the secret; metadata-only parsing is not represented as successful secret recovery.

Persistence writes only encrypted v2 stores. The save path creates a temporary file in the destination's parent directory, sets mode `0600` on Unix, syncs the temporary file, and persists it atomically using the tempfile API. By default it refuses an existing destination; replacement is a separate explicit operation. The implementation refuses a symlink destination and, when replacing, a non-regular destination. Parent-directory sync is best effort (errors are ignored). These implementation details are not a guarantee of identical permission, atomicity, durability, or race behavior on every filesystem/platform.

## 3. v1 compatibility and migration

Ordinary `load` and wallet operations reject v1 with a migration-only error. Explicit `kovanica migrate` alone reads v1, under the same 64 KiB input limit, and validates the legacy schema and identity metadata. A plaintext v1 seed is recovered directly; an encrypted v1 seed is decoded using its historical repeated-BLAKE3-XOR scheme after prompting for the old passphrase. That scheme is unauthenticated: migration validates the recovered seed against the recorded public key and address, but this is not equivalent to cryptographic authentication of the v1 ciphertext.

Migration asks for a new, non-empty v2 passphrase twice, writes to a distinct destination (by default `<source>.v2.json`), reloads that file, decrypts it, and compares the recovered seed with the validated v1 seed. It leaves the source untouched unless `--replace-source` is requested. Source replacement requires a typed `REPLACE <source-path>` confirmation and then renames the already-verified destination over the source; it loads and checks the resulting source path again. The code checks that source and destination are regular non-symlink files before the replacement rename. As with save, do not interpret this as a platform-independent filesystem guarantee.

There is no general v1 support in ordinary wallet commands and no automatic migration. Operators must retain or back up the source until migration and any desired replacement have been verified.

## 4. Seed import/export and prompting

The raw import/export representation is exactly a 32-byte Ed25519 seed. The 24-word English BIP-39 phrase represents those same 256 bits of seed entropy directly: no BIP-39 passphrase and no HD derivation are applied. Import reads raw seed hex or the phrase through a hidden prompt; export requires an explicit format and typed confirmation. Secret import, secret export, and migration are rejected in `--json` mode. Routine JSON keystore summaries contain metadata only, not seed material.

Passphrases are obtained through interactive hidden prompts rather than command-line arguments. New passphrases are confirmed interactively; import/export and source replacement have typed confirmations as described above. `Zeroizing` is used for passphrase strings and a number of seed, key, decrypted-plaintext, and input buffers in the implementation. This is best-effort memory hygiene where implemented, not a promise that every transient copy is erased or that secrets never enter process/runtime-managed memory.

## 5. Consequences and threat boundaries

* New CLI keystores have authenticated encryption and fixed, validated KDF parameters; malformed, unsupported, oversized, or tampered v2 inputs fail closed.
* Legacy v1 files remain recoverable only through an explicit migration command. V1 XOR encryption offers no ciphertext authentication and should not be relied on for confidentiality or integrity.
* Encryption at rest does not protect against a compromised host, malware, a compromised CLI/runtime, passphrase capture, or an attacker who can inspect active unlocked secrets. It does not make weak passphrases safe or prevent offline guessing against a copied keystore.
* Sensitive interactive operations reduce accidental disclosure through argv and JSON output, but cannot protect secrets after terminal display or from a hostile local environment.
* This implementation covers the CLI wallet file path only. It makes no claim about `kovanica-crypto` keypair persistence or other consumers of that crate.

## 6. Verification references

The behavior above is cross-checked against `crates/kovanica-cli/src/wallet.rs` and `crates/kovanica-cli/src/main.rs`. Relevant in-source tests include:

* `v2_roundtrip_authenticates_password_and_metadata` and `rejects_hostile_kdf_and_unsupported_versions` — v2 round trip, wrong passphrase, bound metadata, fixed KDF values, malformed ciphertext, and unsupported versions.
* `rejects_oversized_keystore_while_reading_bounded_buffer` — bounded file read.
* `v1_plaintext_and_encrypted_are_identity_checked` and `v1_migration_keeps_source_and_verifies_v2_output` — migration-only recovery, identity check, source preservation, and verified v2 output.
* `atomic_save_refuses_overwrite_and_symlinks_and_sets_private_mode` — save behavior and Unix mode assertion.
* `raw_and_mnemonic_preserve_exact_entropy` — exact seed/phrase round trip.
* CLI security tests `secret_passphrases_are_not_cli_arguments`, `secret_export_is_rejected_in_json_mode`, `routine_keystore_json_contains_metadata_only`, and `cancelled_export_never_constructs_printable_secret` — prompting/argv boundary, JSON handling, metadata-only summary, and confirmation ordering.

These references identify checked-in tests; this ADR authoring does not assert that a test suite was run.
