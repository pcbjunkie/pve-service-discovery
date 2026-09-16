#!/usr/bin/env bash
set -euo pipefail

if [[ ${EUID} -ne 0 ]]; then
    echo "Run this installer as root on a Proxmox VE node." >&2
    exit 1
fi

for command in python3 pvesh pct systemctl install; do
    if ! command -v "${command}" >/dev/null 2>&1; then
        echo "Required command not found: ${command}" >&2
        exit 1
    fi
done

project_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)

install -m 0755 "${project_dir}/pve_service_discovery.py" /usr/local/sbin/pve-service-discovery
install -m 0644 "${project_dir}/pve-service-discovery.service" /etc/systemd/system/pve-service-discovery.service
install -m 0644 "${project_dir}/pve-service-discovery.timer" /etc/systemd/system/pve-service-discovery.timer

if [[ ! -e /etc/pve-service-discovery.ini ]]; then
    install -m 0644 "${project_dir}/pve-service-discovery.ini" /etc/pve-service-discovery.ini
else
    echo "Keeping existing /etc/pve-service-discovery.ini"
fi

systemctl daemon-reload
systemctl enable --now pve-service-discovery.timer

echo
echo "Installed pve-service-discovery."
echo "Preview: pve-service-discovery --dry-run"
echo "Run now: systemctl start pve-service-discovery.service"
echo "Logs:    journalctl -u pve-service-discovery.service"
echo
echo "The timer is active; its first automatic scan runs in about two minutes."
