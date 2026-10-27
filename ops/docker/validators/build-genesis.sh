#!/usr/bin/env bash
# Kept for compatibility: `generate.sh` now writes genesis_validators.toml
# directly (and reuses existing valN.pem seeds), so re-running it rebuilds
# genesis without rotating keys. This wrapper simply delegates.
set -euo pipefail
exec "$(dirname "$0")/generate.sh" "$@"
