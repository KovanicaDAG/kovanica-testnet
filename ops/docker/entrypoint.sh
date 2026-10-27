#!/usr/bin/env sh
#
# Kovanica node container entrypoint.
#
#   1. provision a persistent validator seed inside the data volume (unless the
#      operator already points KOVANICA_VALIDATOR_KEY at their own file), and
#   2. hand control to the node binary.
#
# Validator seeds are never baked into the image or the repository: they are
# generated on first boot and live only in the mounted data volume.

set -eu

# A node only starts when explicitly asked to (the image default is --help).
case "${1:-}" in
    --help|-h|--version|-V)
        exec kovanica-node "$@"
        ;;
esac

DATA_DIR="${KOVANICA_DATA_DIR:-/var/lib/kovanica}"
KEY_FILE="${KOVANICA_VALIDATOR_KEY:-$DATA_DIR/validator.key}"

if [ ! -s "$KEY_FILE" ]; then
    install -d -m 700 "$(dirname "$KEY_FILE")"
    umask 077
    # 32 bytes -> 64 hex chars; the node reads a 32-byte hex seed.
    head -c 32 /dev/urandom | od -An -v -tx1 | tr -d ' \n' > "$KEY_FILE"
    printf '\n' >> "$KEY_FILE"
    echo "entrypoint: generated validator seed at $KEY_FILE"
fi

# Let the node pick up the seed file (its own key never leaves the volume).
KOVANICA_VALIDATOR_KEY="$KEY_FILE"
export KOVANICA_VALIDATOR_KEY

exec kovanica-node "$@"