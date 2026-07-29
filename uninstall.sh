#!/usr/bin/env bash
# Uninstall Nexus Admin Assistant. Removes the service + code; PRESERVES state
# unless --purge is given (which also backs it up first).
set -euo pipefail

NAA_USER="${NAA_USER:-nexusadmin}"
NAA_DIR="${NAA_DIR:-/opt/nexus-admin-assistant}"
NAA_STATE="${NAA_STATE:-/var/lib/nexus-admin-assistant}"
NAA_SERVICE="${NAA_SERVICE:-nexus-admin-assistant}"
UNIT="/etc/systemd/system/${NAA_SERVICE}.service"
PURGE=0
[ "${1:-}" = "--purge" ] && PURGE=1

[ "$(id -u)" -eq 0 ] || { echo "Run as root"; exit 1; }

echo "==> Stopping $NAA_SERVICE"
systemctl disable --now "$NAA_SERVICE" 2>/dev/null || true
rm -f "$UNIT"
systemctl daemon-reload

echo "==> Removing code $NAA_DIR"
rm -rf "$NAA_DIR"

if [ "$PURGE" = "1" ]; then
  if [ -d "$NAA_STATE" ]; then
    BACKUP="/var/backups/naa-state-$(date +%Y%m%d%H%M%S).tar.gz"
    mkdir -p /var/backups
    tar -czf "$BACKUP" -C "$(dirname "$NAA_STATE")" "$(basename "$NAA_STATE")" 2>/dev/null || true
    echo "==> Backed up state to $BACKUP, then removing $NAA_STATE"
    rm -rf "$NAA_STATE"
  fi
  id "$NAA_USER" >/dev/null 2>&1 && userdel "$NAA_USER" 2>/dev/null || true
  echo "✓ Purged."
else
  echo "✓ Uninstalled. State preserved at $NAA_STATE (use --purge to remove)."
fi
