#!/bin/bash
# Build Tauri client and copy binary to release/
# Run from project root: ./scripts/build-client-release.sh
# Requires: npm, cargo, Go/Cargo on PATH (source scripts/env.sh first if needed)

set -e
ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT_DIR"

# Tauri CLI rejects CI=1 (wants true/false). Unset so build doesn't get invalid --ci.
unset CI

# Ensure target dir is inside repo so we can find the binary
export CARGO_TARGET_DIR="${ROOT_DIR}/client/src-tauri/target"

echo "[*] Building frontend..."
cd client && npm run build

echo "[*] Building Tauri client (release binary only, no bundles)..."
npx tauri build --no-bundle

# Binary name = Cargo.toml package name (apex-client)
BIN="${ROOT_DIR}/client/src-tauri/target/release/apex-client"
if [ ! -f "$BIN" ]; then
    echo "[!] Binary not found at $BIN"
    exit 1
fi

echo "[*] Copying apex-client to release/"
cp "$BIN" "${ROOT_DIR}/release/apex-client"
chmod +x "${ROOT_DIR}/release/apex-client"
echo "[+] Done: release/apex-client"
