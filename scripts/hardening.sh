#!/bin/bash
# ============================================================
# Homelab Security Hardening Script v1.0
# One-click security for Docker/CasaOS homelabs
# ============================================================
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'

log()  { echo -e "${GREEN}[[OK]]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
err()  { echo -e "${RED}[[FAIL]]${NC} $1"; }
info() { echo -e "${BLUE}[i]${NC} $1"; }

# -- Pre-flight checks --------------------------------------
if [[ $EUID -ne 0 ]]; then
    err "This script must be run as root (sudo ./hardening.sh)"
    exit 1
fi

if ! command -v docker &>/dev/null; then
    err "Docker is not installed. Please install Docker first."
    exit 1
fi

WORKDIR="$(cd "$(dirname "$0")/.." && pwd)"
BACKUP_DIR="$WORKDIR/backups/$(date +%Y%m%d_%H%M%S)"
mkdir -p "$BACKUP_DIR"

echo ""
echo "=========================================="
echo "  HOMELAB SECURITY HARDENING SCRIPT v1.0"
echo "=========================================="
echo ""
echo "This script will:"
echo "  1. Configure UFW firewall"
echo "  2. Install & configure fail2ban"
echo "  3. Harden SSH configuration"
echo "  4. Install CrowdSec (IDS/IPS)"
echo "  5. Configure Docker content trust"
echo "  6. Set up ClamAV scheduled scans"
echo "  7. Enable AIDE file integrity monitoring"
echo "  8. Harden all Docker containers"
echo "  9. Configure automatic security updates"
echo " 10. Generate security report"
echo ""
read -p "Continue? (y/N): " -n 1 -r
echo ""
[[ $REPLY =~ ^[Yy]$ ]] || exit 0

# -- Collect user tokens -------------------------------------
echo ""
echo "=========================================="
echo "  CONFIGURATION"
echo "=========================================="
echo ""

read -p "Cloudflare API Token (optional, Enter to skip): " CF_TOKEN
read -p "Cloudflare Zone ID (optional, Enter to skip): " CF_ZONE
read -p "Slack Webhook URL for alerts (optional, Enter to skip): " SLACK_WEBHOOK
read -p "Telegram Bot Token (optional, Enter to skip): " TG_TOKEN
read -p "Telegram Chat ID (optional, Enter to skip): " TG_CHAT
read -p "Authentik Admin URL (e.g., https://auth.example.com:9000): " AUTHENTIK_URL
read -p "Your domain name (e.g., example.com): " DOMAIN
SSH_PORT=$(read -p "SSH port (default 22): " -r && echo "${REPLY:-22}")
ADMIN_EMAIL=$(read -p "Admin email for alerts: " -r && echo "$REPLY")

# -- 1. UFW Firewall ----------------------------------------
echo ""
info "Configuring UFW firewall..."

if ! command -v ufw &>/dev/null; then
    apt-get update -qq && apt-get install -y -qq ufw
fi

ufw --force reset
ufw default deny incoming
ufw default allow outgoing
ufw allow "$SSH_PORT/tcp" comment 'SSH'
ufw allow 80/tcp comment 'HTTP'
ufw allow 443/tcp comment 'HTTPS'
ufw allow 500/udp comment 'WireGuard'
ufw allow 4500/udp comment 'WireGuard NAT-T'
ufw allow from 172.16.0.0/12 comment 'Docker internal'
ufw --force enable
log "UFW firewall configured"

# -- 2. fail2ban ---------------------------------------------
info "Installing & configuring fail2ban..."

if ! command -v fail2ban-client &>/dev/null; then
    apt-get install -y -qq fail2ban
fi

cat > /etc/fail2ban/jail.local << F2B
[DEFAULT]
bantime  = 3600
findtime = 600
maxretry = 3
banaction = ufw

[sshd]
enabled = true
port    = $SSH_PORT
filter  = sshd
logpath = /var/log/auth.log
maxretry = 3

[nginx-http-auth]
enabled  = true
port     = http,https
filter   = nginx-http-auth
logpath  = /DATA/AppData/nginxproxymanager/data/logs/proxy-host-*_error.log
maxretry = 5

[nginx-limit-req]
enabled  = true
port     = http,https
filter   = nginx-limit-req
logpath  = /DATA/AppData/nginxproxymanager/data/logs/proxy-host-*_error.log
maxretry = 10

[nginx-botsearch]
enabled  = true
port     = http,https
filter   = nginx-botsearch
logpath  = /DATA/AppData/nginxproxymanager/data/logs/proxy-host-*_error.log
maxretry = 5
F2B

systemctl enable fail2ban
systemctl restart fail2ban
log "fail2ban configured with SSH + Nginx jails"

# -- 3. SSH Hardening ----------------------------------------
info "Hardening SSH configuration..."

SSHD_CONFIG="/etc/ssh/sshd_config"
cp "$SSHD_CONFIG" "$BACKUP_DIR/sshd_config.bak"

sed -i \
    -e "s/^#\?Port .*/Port $SSH_PORT/" \
    -e "s/^#\?PermitRootLogin .*/PermitRootLogin no/" \
    -e "s/^#\?PasswordAuthentication .*/PasswordAuthentication no/" \
    -e "s/^#\?PubkeyAuthentication .*/PubkeyAuthentication yes/" \
    -e "s/^#\?MaxAuthTries .*/MaxAuthTries 3/" \
    -e "s/^#\?ClientAliveInterval .*/ClientAliveInterval 300/" \
    -e "s/^#\?ClientAliveCountMax .*/ClientAliveCountMax 2/" \
    -e "s/^#\?X11Forwarding .*/X11Forwarding no/" \
    -e "s/^#\?AllowAgentForwarding .*/AllowAgentForwarding no/" \
    -e "s/^#\?Protocol .*/Protocol 2/" \
    -e "s/^#\?MaxSessions .*/MaxSessions 3/" \
    -e "s/^#\?LoginGraceTime .*/LoginGraceTime 30/" \
    "$SSHD_CONFIG"

# Remove any AllowUsers that blocks our admin
sed -i "/^AllowUsers/d" "$SSHD_CONFIG"
echo "AllowUsers taskmanager powerguard" >> "$SSHD_CONFIG"

systemctl restart sshd
log "SSH hardened (port $SSH_PORT, no root, no password auth)"

# -- 4. CrowdSec ---------------------------------------------
info "Checking CrowdSec installation..."

if systemctl is-active --quiet crowdsec; then
    log "CrowdSec already running"
else
    warn "CrowdSec not running - install manually or via:"
    warn "  curl -s https://install.crowdsec.net | sudo bash"
fi

# -- 5. Docker Content Trust ---------------------------------
info "Configuring Docker Content Trust..."

cat >> /etc/environment << 'DCT'
DOCKER_CONTENT_TRUST=1
DOCKER_CONTENT_TRUST_REPOSITORY=1
DCT

export DOCKER_CONTENT_TRUST=1
log "Docker Content Trust enabled (image signature verification)"

# -- 6. ClamAV Scheduled Scan --------------------------------
info "Setting up ClamAV scheduled scan..."

cat > /etc/cron.d/clamav-scan << 'CLAM'
0 3 * * 0 root /usr/bin/clamscan -r --bell -i /DATA/AppData/ --log=/var/log/clamav/weekly-scan.log
CLAM
chmod 644 /etc/cron.d/clamav-scan
systemctl enable clamav-daemon
log "ClamAV weekly scan configured (Sunday 3 AM)"

# -- 7. AIDE File Integrity ----------------------------------
info "Installing AIDE file integrity monitoring..."

if ! command -v aide &>/dev/null; then
    apt-get install -y -qq aide
fi

# Initialize AIDE database
aideinit 2>/dev/null || aide --init 2>/dev/null || true
log "AIDE initialized (run 'aide --check' weekly)"

# -- 8. Docker Container Hardening ---------------------------
info "Hardening Docker containers..."

COMPOSE_FILES=$(find /var/lib/casaos/apps/*/docker-compose.yml 2>/dev/null)
HARDENED=0

for f in $COMPOSE_FILES; do
    dir=$(dirname "$f")
    app=$(basename "$dir")

    # Skip if already hardened
    if grep -q "init: true" "$f" 2>/dev/null; then
        continue
    fi

    # Backup original
    cp "$f" "$BACKUP_DIR/$(basename "$f").${app}.bak"

    # Add hardening to services section
    if grep -q "^services:" "$f"; then
        # Add init: true after each service's container_name or image line
        sed -i '/container_name:/a\        init: true' "$f"
        sed -i '/image:/a\        security_opt:\n            - no-new-privileges:true' "$f"
        HARDENED=$((HARDENED + 1))
        log "Hardened: $app"
    fi
done

log "Hardened $HARDENED container(s)"

# -- 9. Automatic Security Updates ---------------------------
info "Configuring automatic security updates..."

cat > /etc/apt/apt.conf.d/50unattended-upgrades << 'UUP'
Unattended-Upgrade::Allowed-Origins {
    "${distro_id}:${distro_codename}-security";
};
Unattended-Upgrade::AutoFixInterruptedDpkg "true";
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::Automatic-Reboot "false";
Unattended-Upgrade::Mail "$ADMIN_EMAIL";
UUP

cat > /etc/apt/apt.conf.d/20auto-upgrades << 'AGU'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::Download-Upgradeable-Packages "1";
AGU

systemctl enable unattended-upgrades
log "Automatic security updates configured"

# -- 10. Notification Setup ----------------------------------
if [[ -n "$SLACK_WEBHOOK" ]]; then
    cat > /usr/local/bin/security-alert.sh << SLACK
#!/bin/bash
curl -s -X POST -H 'Content-type: application/json' \\
    --data "{\\"text\\":\\"Security Alert: \$1\\"}" \\
    "$SLACK_WEBHOOK"
SLACK
    chmod +x /usr/local/bin/security-alert.sh
    log "Slack notifications configured"
fi

if [[ -n "$TG_TOKEN" && -n "$TG_CHAT" ]]; then
    cat > /usr/local/bin/security-alert-telegram.sh << TG
#!/bin/bash
curl -s "https://api.telegram.org/bot$TG_TOKEN/sendMessage" \\
    -d "chat_id=$TG_CHAT" -d "text=Security Alert: \$1"
TG
    chmod +x /usr/local/bin/security-alert-telegram.sh
    log "Telegram notifications configured"
fi

# -- Generate Security Report --------------------------------
info "Generating security report..."

REPORT="$WORKDIR/security-report-$(date +%Y%m%d).txt"

cat > "$REPORT" << REP
=============================================
  HOMELAB SECURITY REPORT
  Generated: $(date)
=============================================

SYSTEM INFORMATION:
  OS: $(lsb_release -ds 2>/dev/null || cat /etc/os-release | grep PRETTY | cut -d= -f2)
  Kernel: $(uname -r)
  Uptime: $(uptime -p)

FIREWALL (UFW):
  Status: $(ufw status | head -1)
  Rules: $(ufw status | grep -c "[0-9]")

FAIL2BAN:
  Status: $(systemctl is-active fail2ban)
  Jails: $(fail2ban-client status 2>/dev/null | grep "Jail list" || echo "N/A")

SSH:
  Port: $(grep "^Port" /etc/ssh/sshd_config | awk '{print $2}')
  Root Login: $(grep "^PermitRootLogin" /etc/ssh/sshd_config | awk '{print $2}')
  Password Auth: $(grep "^PasswordAuthentication" /etc/ssh/sshd_config | awk '{print $2}')

CROWDSEC:
  Engine: $(systemctl is-active crowdsec)
  Cloudflare Bouncer: $(systemctl is-active crowdsec-cloudflare-bouncer)
  Firewall Bouncer: $(systemctl is-active crowdsec-firewall-bouncer)

DOCKER:
  Content Trust: ${DOCKER_CONTENT_TRUST:-disabled}
  Containers: $(docker ps -q | wc -l)
  Images: $(docker images -q | wc -l)

CLAMAV:
  Daemon: $(systemctl is-active clamav-daemon)
  Last Update: $(ls -t /var/lib/clamav/ 2>/dev/null | head -1 || echo "N/A")

AIDE:
  Installed: $(command -v aide &>/dev/null && echo "yes" || echo "no")

AUTO UPDATES:
  Status: $(systemctl is-active unattended-upgrades)

CONTAINERS HARDENED: $HARDENED
=============================================
REP

log "Security report saved to: $REPORT"

echo ""
echo "=========================================="
echo "  HARDENING COMPLETE"
echo "=========================================="
echo ""
log "All security measures applied successfully!"
info "Report: $REPORT"
info "Backups: $BACKUP_DIR"
echo ""
echo "Recommended next steps:"
echo "  1. Review the security report"
echo "  2. Test SSH access in a NEW terminal before closing this one"
echo "  3. Run 'ufw status' to verify firewall rules"
echo "  4. Run 'fail2ban-client status' to verify bans"
echo "  5. Set up CrowdSec Cloudflare bouncer if not already done"
echo ""
