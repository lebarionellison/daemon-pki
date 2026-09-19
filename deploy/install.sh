#!/usr/bin/env bash
set -euo pipefail

INSTALL_DIR="/opt/daemon-pki"
DATA_DIR="/var/lib/daemon-pki"
CONFIG_DIR="/etc/daemon-pki"
ENV_FILE="${CONFIG_DIR}/daemon-pki.env"
SERVICE_USER="daemon-pki"
BINARY_SOURCE="${1:-./daemon-pki-server}"

if [[ "${EUID}" -ne 0 ]]; then
    echo "Run this installer as root."
    exit 1
fi

if [[ ! -f "${BINARY_SOURCE}" ]]; then
    echo "Binary not found: ${BINARY_SOURCE}"
    exit 1
fi

if ! id "${SERVICE_USER}" >/dev/null 2>&1; then
    useradd \
        --system \
        --home-dir "${INSTALL_DIR}" \
        --no-create-home \
        --shell /usr/sbin/nologin \
        "${SERVICE_USER}"
fi

install -d -m 0750 -o "${SERVICE_USER}" -g "${SERVICE_USER}" "${INSTALL_DIR}"
install -d -m 0700 -o "${SERVICE_USER}" -g "${SERVICE_USER}" "${DATA_DIR}"
install -d -m 0700 -o root -g root "${CONFIG_DIR}"

install \
    -m 0755 \
    -o root \
    -g root \
    "${BINARY_SOURCE}" \
    "${INSTALL_DIR}/daemon-pki-server"

install \
    -m 0644 \
    -o root \
    -g root \
    "./daemon-pki.service" \
    "/etc/systemd/system/daemon-pki.service"

if [[ ! -f "${ENV_FILE}" ]]; then
    install \
        -m 0600 \
        -o root \
        -g root \
        /dev/null \
        "${ENV_FILE}"

    echo
    echo "Created:"
    echo "  ${ENV_FILE}"
    echo
    echo "Add DAEMON_PKI_ISSUE_FINGERPRINTS to this file before starting the service."
fi

systemctl daemon-reload
systemctl enable daemon-pki.service

echo
echo "Daemon PKI installation complete."
echo
echo "Binary:  ${INSTALL_DIR}/daemon-pki-server"
echo "Data:    ${DATA_DIR}"
echo "Config:  ${ENV_FILE}"
echo "Service: daemon-pki.service"
echo
echo "Start with:"
echo "  systemctl start daemon-pki"
echo
echo "Check with:"
echo "  systemctl status daemon-pki"
