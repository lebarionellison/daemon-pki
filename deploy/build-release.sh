#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

cd "${ROOT_DIR}"

cargo build --release -p daemon-pki-api --bin server

mkdir -p "${ROOT_DIR}/deploy/release"

cp \
    "${ROOT_DIR}/target/release/server" \
    "${ROOT_DIR}/deploy/release/daemon-pki-server"

chmod 0755 \
    "${ROOT_DIR}/deploy/release/daemon-pki-server"

echo
echo "Daemon PKI release binary created:"
echo "  deploy/release/daemon-pki-server"
