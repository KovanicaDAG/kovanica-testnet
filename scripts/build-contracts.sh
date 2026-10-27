#!/usr/bin/env bash
# scripts/build-contracts.sh — reproducible WASM build for all 4 contracts
# Usage: ./scripts/build-contracts.sh
# Output: target/contracts/*.wasm and prints SHA256 of each

set -euo pipefail

WORKSPACE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TARGET_DIR="${WORKSPACE_ROOT}/target/contracts"
BUILD_DIR="${WORKSPACE_ROOT}/target/contract-build"

echo "=== Kovanica WASM Contract Build ==="
echo "Workspace: ${WORKSPACE_ROOT}"
echo "Target dir: ${TARGET_DIR}"
echo "Build dir:  ${BUILD_DIR}"
echo ""

mkdir -p "${TARGET_DIR}"
mkdir -p "${BUILD_DIR}"

# Use the workspace Cargo
CARGO="${CARGO:-cargo}"
RUSTFLAGS="${RUSTFLAGS:- -C opt-level=z -C lto -C panic=abort -C codegen-units=1 --strip=debuginfo}"

echo "Building with RUSTFLAGS: ${RUSTFLAGS}"
echo ""

contracts=("kovanica-htlc" "kovanica-vault" "kovanica-multisig" "kovanica-token")

for contract in "${contracts[@]}"; do
    echo "=== Building ${contract} ==="
    
    # Build in isolated target dir to avoid lock contention with main build
    "${CARGO}" build \
        --manifest-path "${WORKSPACE_ROOT}/crates/${contract}/Cargo.toml" \
        --target wasm32-unknown-unknown \
        --release \
        --target-dir "${BUILD_DIR}" \
        2>&1 | tail -20
    
    # Find the built wasm (cargo uses underscores for hyphens in filenames)
    wasm_name="${contract//-/_}"
    wasm_path="${BUILD_DIR}/wasm32-unknown-unknown/release/${wasm_name}.wasm"
    
    if [[ ! -f "${wasm_path}" ]]; then
        echo "ERROR: ${wasm_path} not found"
        exit 1
    fi
    
    # Copy to final location
    cp "${wasm_path}" "${TARGET_DIR}/${contract}.wasm"
    
    # Print SHA256
    sha256=$(sha256sum "${wasm_path}" | awk '{print $1}')
    echo "SHA256: ${sha256}"
    echo ""
done

echo "=== All contracts built ==="
echo "Artifacts in ${TARGET_DIR}:"
ls -la "${TARGET_DIR}/"
echo ""

# Verify reproducibility - build twice and compare
echo "=== Verifying reproducibility (second build) ==="
BUILD_DIR_2="${WORKSPACE_ROOT}/target/contract-build-verify"
mkdir -p "${BUILD_DIR_2}"

for contract in "${contracts[@]}"; do
    "${CARGO}" build \
        --manifest-path "${WORKSPACE_ROOT}/crates/${contract}/Cargo.toml" \
        --target wasm32-unknown-unknown \
        --release \
        --target-dir "${BUILD_DIR_2}" \
        >/dev/null 2>&1
    
    wasm_name="${contract//-/_}"
    wasm_path_2="${BUILD_DIR_2}/wasm32-unknown-unknown/release/${wasm_name}.wasm"
    sha256_1=$(sha256sum "${TARGET_DIR}/${contract}.wasm" | awk '{print $1}')
    sha256_2=$(sha256sum "${wasm_path_2}" | awk '{print $1}')
    
    if [[ "${sha256_1}" == "${sha256_2}" ]]; then
        echo "✓ ${contract}: REPRODUCIBLE (${sha256_1})"
    else
        echo "✗ ${contract}: NOT REPRODUCIBLE"
        echo "  First:  ${sha256_1}"
        echo "  Second: ${sha256_2}"
        exit 1
    fi
done

echo ""
echo "=== All 4 contracts are REPRODUCIBLE ==="
echo "Final SHA256s:"
for contract in "${contracts[@]}"; do
    sha256=$(sha256sum "${TARGET_DIR}/${contract}.wasm" | awk '{print $1}')
    echo "  ${contract}: ${sha256}"
done