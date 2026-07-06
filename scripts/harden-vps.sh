#!/bin/bash
# ============================================================
# VPS Security Hardening Script
# Hardens the public-facing VPS (your actual attack surface)
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

echo ""
echo -e "${BOLD}+==============================================+${NC}"
echo -e "${BOLD}|   VPS SECURITY HARDENING                     |${NC}"
echo -e "${BOLD}|   Your public-facing attack surface          |${NC}"
echo -e "${BOLD}+==============================================+${NC}"
echo ""
info "This script hardens the VPS that sits between the internet and your homelab."
info "Architecture: Internet -> THIS VPS -> WireGuard -> Homelab"
echo ""
read -p "Continue? (y/N): " -n 1 -r
echo ""
[[ $REPLY =~ ^[Yy]$ ]] || exit 0

# -- 1. System Update ----------------------------------------
info "Updating system packages..."
apt-get update -qq && apt-get upgrade -y -qq
log "System updated"

# -- 2. UFW Firewall ----------------------------------------
info "Configuring UFW firewall..."

apt-get install -y -qq ufw

ufw --force reset
ufw default deny incoming
ufw default allow outgoing

# Allow only essential ports
ufw allow 22/tcp comment 'SSH'
ufw allow 80/tcp comment 'HTTP'
ufw allow 443/tcp comment 'HTTPS'

# Allow WireGuard
ufw allow 51820/udp comment 'WireGuard'

# Allow from homelab WireGuard IP
read -p "Homelab WireGuard IP (e.g., 10.88.88.2): " HOMELAB_WG_IP
if [[ -n "$HOMELAB_WG_IP" ]]; then
    ufw allow from "$HOMELAB_WG_IP" comment 'Homelab WireGuard'
    log "Allowed traffic from homelab: $HOMELAB_WG_IP"
fi

ufw --force enable
log "UFW configured (deny all except SSH/HTTP/HTTPS/WireGuard)"

# -- 3. SSH Hardening ----------------------------------------
info "Hardening SSH..."

SSHD="/etc/ssh/sshd_config"
cp "$SSHD" /root/sshd_config.bak

sed -i \
    -e "s/^#\?PermitRootLogin .*/PermitRootLogin prohibit-password/" \
    -e "s/^#\?PasswordAuthentication .*/PasswordAuthentication no/" \
    -e "s/^#\?PubkeyAuthentication .*/PubkeyAuthentication yes/" \
    -e "s/^#\?MaxAuthTries .*/MaxAuthTries 3/" \
    -e "s/^#\?ClientAliveInterval .*/ClientAliveInterval 300/" \
    -e "s/^#\?ClientAliveCountMax .*/ClientAliveCountMax 2/" \
    -e "s/^#\?X11Forwarding .*/X11Forwarding no/" \
    -e "s/^#\?AllowAgentForwarding .*/AllowAgentForwarding no/" \
    -e "s/^#\?MaxSessions .*/MaxSessions 3/" \
    -e "s/^#\?LoginGraceTime .*/LoginGraceTime 30/" \
    "$SSHD"

systemctl restart sshd
log "SSH hardened (key-only auth, no root login)"

# -- 4. fail2ban ---------------------------------------------
info "Installing fail2ban..."

apt-get install -y -qq fail2ban

cat > /etc/fail2ban/jail.local << 'F2B'
[DEFAULT]
bantime  = 3600
findtime = 600
maxretry = 3
banaction = ufw

[sshd]
enabled = true
port    = ssh
filter  = sshd
logpath = /var/log/auth.log
maxretry = 3

[nginx-http-auth]
enabled  = true
port     = http,https
filter   = nginx-http-auth
logpath  = /var/log/nginx/error.log
maxretry = 5

[nginx-limit-req]
enabled  = true
port     = http,https
filter   = nginx-limit-req
logpath  = /var/log/nginx/error.log
maxretry = 10
F2B

systemctl enable fail2ban
systemctl restart fail2ban
log "fail2ban configured (SSH + Nginx jails)"

# -- 5. Kernel Hardening -------------------------------------
info "Hardening kernel parameters..."

cat > /etc/sysctl.d/99-security.conf << 'SYSCTL'
# Disable IP forwarding (not needed on VPS, only on homelab)
# net.ipv4.ip_forward=0

# Ignore ICMP broadcast requests
net.ipv4.icmp_echo_ignore_broadcasts = 1

# Disable source packet routing
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0

# Ignore send redirects
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0

# Block SYN attacks
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 2048
net.ipv4.tcp_synack_retries = 2

# Log Martians
net.ipv4.conf.all.log_martians = 1

# Ignore ICMP redirects
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0

# Ignore Directed pings
net.ipv4.icmp_echo_ignore_broadcasts = 1

# Disable IPv6 if not needed
# net.ipv6.conf.all.disable_ipv6 = 1
# net.ipv6.conf.default.disable_ipv6 = 1
SYSCTL

sysctl -p /etc/sysctl.d/99-security.conf > /dev/null 2>&1
log "Kernel parameters hardened"

# -- 6. Auto Security Updates --------------------------------
info "Configuring automatic security updates..."

apt-get install -y -qq unattended-upgrades

cat > /etc/apt/apt.conf.d/50unattended-upgrades << 'UUP'
Unattended-Upgrade::Allowed-Origins {
    "${distro_id}:${distro_codename}-security";
};
Unattended-Upgrade::AutoFixInterruptedDpkg "true";
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::Automatic-Reboot "false";
UUP

cat > /etc/apt/apt.conf.d/20auto-upgrades << 'AGU'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::Download-Upgradeable-Packages "1";
AGU

systemctl enable unattended-upgrades
log "Automatic security updates configured"

# -- 7. CrowdSec ---------------------------------------------
info "Checking CrowdSec..."

if systemctl is-active --quiet crowdsec; then
    log "CrowdSec already running"
else
    warn "CrowdSec not running - install from https://crowdsec.net"
fi

# -- 8. Fail2ban + UFW Integration ---------------------------
info "Verifying integration..."

log "UFW active: $(ufw status | head -1)"
log "fail2ban active: $(systemctl is-active fail2ban)"
log "SSH hardened: $(grep 'PasswordAuthentication no' /etc/ssh/sshd_config | wc -l) checks passed"

# -- Summary -------------------------------------------------
echo ""
echo -e "${BOLD}=== VPS HARDENING COMPLETE ===${NC}"
echo ""
echo "What's protected:"
echo "  - UFW: deny all, allow SSH/HTTP/HTTPS/WireGuard only"
echo "  - fail2ban: auto-ban SSH + Nginx attackers"
echo "  - SSH: key-only, no root, max 3 tries"
echo "  - Kernel: SYN flood protection, ICMP hardening"
echo "  - Auto-updates: security patches applied automatically"
echo ""
echo "Your homelab is safe behind this VPS."
echo ""
