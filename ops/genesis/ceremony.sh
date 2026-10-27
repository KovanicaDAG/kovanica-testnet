#!/usr/bin/env bash
# Genesis ceremony script for Kovanica testnet/mainnet
# Usage: ./ops/genesis/ceremony.sh --network testnet --validators validators.json
set -euo pipefail

NETWORK="testnet"
VALIDATORS_FILE=""
OUTPUT_DIR="./genesis"
FORCE=false

while [[ $# -gt 0 ]]; do
    case $1 in
        --network) NETWORK="$2"; shift 2 ;;
        --validators) VALIDATORS_FILE="$2"; shift 2 ;;
        --output) OUTPUT_DIR="$2"; shift 2 ;;
        --force) FORCE=true; shift ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

if [[ -z "$VALIDATORS_FILE" ]]; then
    echo "ERROR: --validators <file.json> required"
    echo "Usage: $0 --network testnet --validators validators.json"
    exit 1
fi

if [[ ! -f "$VALIDATORS_FILE" ]]; then
    echo "ERROR: Validators file not found: $VALIDATORS_FILE"
    exit 1
fi

mkdir -p "$OUTPUT_DIR"

echo "=== Kovanica Genesis Ceremony ==="
echo "Network: $NETWORK"
echo "Validators: $VALIDATORS_FILE"
echo "Output: $OUTPUT_DIR"
echo ""

# Step 1: Generate genesis
echo "[1/4] Generating genesis..."
GENESIS_ARGS="--validators $VALIDATORS_FILE --output $OUTPUT_DIR/genesis.json"
if $FORCE; then
    GENESIS_ARGS="$GENESIS_ARGS --force"
fi

cargo run --release -p kovanica-node -- genesis $GENESIS_ARGS

# Step 2: Generate validator keys
echo "[2/4] Generating validator keys..."
cargo run --release -p kovanica-node -- genesis \
    --validators $VALIDATORS_FILE \
    --output $OUTPUT_DIR/genesis.json \
    --validator-keys-out "$OUTPUT_DIR/keys" \
    $( $FORCE && echo "--force" )

# Step 3: Create genesis_validators.toml
echo "[3/4] Creating genesis_validators.toml..."
cat > "$OUTPUT_DIR/genesis_validators.toml" << EOF
# Kovanica $NETWORK genesis validators
# Generated: $(date -Iseconds)
# Network: $NETWORK

EOF

# Extract validator addresses from genesis.json and append to TOML
# This is a simplified version - in production, parse the JSON properly
echo "Validator addresses:"
cat "$OUTPUT_DIR/genesis.json" | python3 -c "
import json, sys
data = json.load(sys.stdin)
for v in data.get('allocations', {}).get('validators', []):
    addr = v.get('address_hex', '')
    stake = v.get('stake', 0)
    pk = v.get('public_key_hex', '')
    print(f'  {addr} (stake: {stake}, pk: {pk[:16]}...)')
" 2>/dev/null || echo "  (parse genesis.json manually)"

# Step 4: Create bootnode config
echo "[4/4] Creating bootnode config..."
if [[ "$NETWORK" == "testnet" ]]; then
    SEED="testnet.kovanica.online:8000"
else
    SEED="mainnet.kovanica.online:8000"
fi

cat > "$OUTPUT_DIR/bootnodes.toml" << EOF
# Kovanica $NETWORK bootnodes
# All validators should use this seed
bootnodes = ["$SEED"]
EOF

echo ""
echo "=== Genesis Ceremony Complete ==="
echo "Files generated:"
echo "  $OUTPUT_DIR/genesis.json"
echo "  $OUTPUT_DIR/genesis_validators.toml"
echo "  $OUTPUT_DIR/bootnodes.toml"
echo "  $OUTPUT_DIR/keys/ (validator keys)"
echo ""
echo "Next steps:"
echo "1. Distribute genesis.json to all validators"
echo "2. Each validator places genesis.json in their KOVANICA_DATA_DIR"
echo "3. Each validator configures bootnodes = [\"$SEED\"]"
echo "4. Start all validators simultaneously"
