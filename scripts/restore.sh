#!/bin/bash
# ============================================================
# Security Rollback Script
# Restores system to pre-hardening state
# ============================================================
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'; BOLD='\033[1m'

log()  { echo -e "${GREEN}[[OK]]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
err()  { echo -e "${RED}[[FAIL]]${NC} $1"; }
info() { echo -e "${BLUE}[i]${NC} $1"; }

if [[ $EUID -ne 0 ]]; then
    err "Must run as root: sudo bash $0"
    exit 1
fi

BACKUP_DIR="/DATA/AppData/homelab-security/backups"

echo ""
echo -e "${BOLD}+==============================================+${NC}"
echo -e "${BOLD}|   SECURITY ROLLBACK                          |${NC}"
echo -e "${BOLD}+==============================================+${NC}"
echo ""
warn "This will revert security hardening changes."
warn "Use this if hardening broke something."
echo ""

# List available backups
echo "Available backups:"
if [[ -d "$BACKUP_DIR" ]]; then
    ls -1 "$BACKUP_DIR" 2>/dev/null | head -10
else
    err "No backup directory found"
    exit 1
fi

echo ""
read -p "Restore SSH config from backup? (y/N): " -n 1 -r
echo ""
if [[ $REPLY =~ ^[Yy]$ ]]; then
    LATEST=$(ls -t "$BACKUP_DIR"/sshd_config*.bak 2>/dev/null | head -1)
    if [[ -n "$LATEST" ]]; then
        cp "$LATEST" /etc/ssh/sshd_config
        systemctl restart sshd
        log "SSH config restored from $LATEST"
    else
        err "No SSH backup found"
    fi
fi

read -p "Disable UFW? (y/N): " -n 1 -r
echo ""
if [[ $REPLY =~ ^[Yy]$ ]]; then
    ufw --force disable
    log "UFW disabled"
fi

read -p "Stop fail2ban? (y/N): " -n 1 -r
echo ""
if [[ $REPLY =~ ^[Yy]$ ]]; then
    systemctl stop fail2ban
    systemctl disable fail2ban
    log "fail2ban stopped and disabled"
fi

echo ""
log "Rollback complete. Review your system state."
echo ""
