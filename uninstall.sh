#!/usr/bin/env bash
set -euo pipefail

if [[ ${EUID} -ne 0 ]]; then
    echo "Run this uninstaller as root on a Proxmox VE node." >&2
    exit 1
fi

if [[ ${1:-} == "--remove-notes" && -x /usr/local/sbin/pve-service-discovery ]]; then
    /usr/local/sbin/pve-service-discovery --remove-managed-notes || {
        echo "Some managed Notes sections could not be removed; continuing uninstall." >&2
    }
fi

systemctl disable --now pve-service-discovery.timer 2>/dev/null || true
rm -f /etc/systemd/system/pve-service-discovery.timer
rm -f /etc/systemd/system/pve-service-discovery.service
rm -f /usr/local/sbin/pve-service-discovery
systemctl daemon-reload

echo "Removed pve-service-discovery."
echo "Configuration remains at /etc/pve-service-discovery.ini."
if [[ ${1:-} != "--remove-notes" ]]; then
    echo "Existing generated Notes blocks were left in place."
fi
