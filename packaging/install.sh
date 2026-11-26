#!/usr/bin/env bash
set -euo pipefail

# Ringwall Linux host installer
# Usage: sudo ./packaging/install.sh

if [[ "${EUID}" -ne 0 ]]; then
  echo "Please run as root (sudo ./packaging/install.sh)" >&2
  exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

if [[ ! -x "${ROOT_DIR}/bin/ringwalld" || ! -x "${ROOT_DIR}/bin/ringwallctl" ]]; then
  echo "Binaries not found in ${ROOT_DIR}/bin. Run 'make build' first." >&2
  exit 1
fi

install -d -m 0755 /usr/local/bin /usr/lib/ringwall /etc/ringwall/policies.d /run/ringwall-status
install -d -m 0700 /etc/ringwall/keys /var/log/ringwall /run/ringwall

install -m 0755 "${ROOT_DIR}/bin/ringwalld" /usr/local/bin/ringwalld
install -m 0755 "${ROOT_DIR}/bin/ringwallctl" /usr/local/bin/ringwallctl

if [[ -f "${ROOT_DIR}/internal/sensor/ringwall.bpf.o" ]]; then
  install -m 0644 "${ROOT_DIR}/internal/sensor/ringwall.bpf.o" /usr/lib/ringwall/ringwall.bpf.o
fi

if [[ ! -f /etc/ringwall/ringwall.yaml ]]; then
  install -m 0600 "${ROOT_DIR}/packaging/ringwall.yaml" /etc/ringwall/ringwall.yaml
fi

install -m 0644 "${ROOT_DIR}"/policies/*.yaml /etc/ringwall/policies.d/
install -m 0644 "${ROOT_DIR}/packaging/ringwalld.service" /etc/systemd/system/ringwalld.service
install -m 0644 "${ROOT_DIR}/packaging/sysctl-99-ringwall.conf" /etc/sysctl.d/99-ringwall.conf

sysctl --system >/dev/null 2>&1 || true
systemctl daemon-reload
systemctl enable --now ringwalld.service

echo "Ringwall installed and running."
echo "Guided Setup:  sudo ringwallctl setup"
echo "Check status:  sudo ringwallctl status"
echo "Run self-test: sudo ringwallctl simulate"
echo "Web Dashboard: http://127.0.0.1:9443 (root-only token in /run/ringwall/api.token)"
