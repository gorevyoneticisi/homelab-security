#!/bin/bash
# ============================================================
# Compliance Report Generator
# Generates a detailed security compliance report
# ============================================================
set -euo pipefail

REPORT_DIR="/DATA/AppData/homelab-security/reports"
mkdir -p "$REPORT_DIR"
REPORT="$REPORT_DIR/compliance-$(date +%Y%m%d_%H%M%S).txt"

{
echo "=============================================="
echo "  HOMELAB SECURITY COMPLIANCE REPORT"
echo "  Generated: $(date)"
echo "  Hostname: $(hostname)"
echo "=============================================="
echo ""

echo "1. SYSTEM INFORMATION"
echo "  OS: $(lsb_release -ds 2>/dev/null || cat /etc/os-release | grep PRETTY | cut -d= -f2)"
echo "  Kernel: $(uname -r)"
echo "  Uptime: $(uptime -p)"
echo "  RAM: $(free -h | awk '/Mem:/{print $2}')"
echo "  Disk: $(df -h / | awk 'NR==2{print $2}') ($(df -h / | awk 'NR==2{print $5}') used)"
echo ""

echo "2. FIREWALL (UFW)"
ufw status verbose 2>/dev/null || echo "  UFW not installed"
echo ""

echo "3. SSH CONFIGURATION"
grep -E "^(Port|PermitRootLogin|PasswordAuthentication|MaxAuthTries|X11Forwarding|AllowAgentForwarding)" /etc/ssh/sshd_config 2>/dev/null || echo "  SSH config not found"
echo ""

echo "4. INTRUSION DETECTION"
echo "  CrowdSec: $(systemctl is-active crowdsec 2>/dev/null || echo 'not running')"
echo "  fail2ban: $(systemctl is-active fail2ban 2>/dev/null || echo 'not running')"
echo "  CrowdSec decisions: $(cscli decisions list 2>/dev/null | wc -l || echo 'N/A')"
echo ""

echo "5. DOCKER SECURITY"
echo "  Content Trust: ${DOCKER_CONTENT_TRUST:-disabled}"
echo "  Running containers: $(docker ps -q 2>/dev/null | wc -l)"
echo "  Privileged: $(docker ps --format '{{.Names}}' 2>/dev/null | while read c; do docker inspect "$c" --format '{{.HostConfig.Privileged}}' 2>/dev/null | grep -q true && echo "$c"; done | wc -l)"
echo ""

echo "6. EXPOSED PORTS"
ss -tlnp 2>/dev/null | grep "0.0.0.0" | awk '{print "  " $4 " " $6}'
echo ""

echo "7. WIREGUARD VPN"
wg show 2>/dev/null || echo "  WireGuard not running"
echo ""

echo "8. FILE INTEGRITY"
echo "  AIDE: $(command -v aide &>/dev/null && echo 'installed' || echo 'not installed')"
echo "  rkhunter: $(command -v rkhunter &>/dev/null && echo 'installed' || echo 'not installed')"
echo ""

echo "9. ANTIVIRUS"
echo "  ClamAV: $(command -v clamscan &>/dev/null && echo 'installed' || echo 'not installed')"
echo "  Daemon: $(systemctl is-active clamav-daemon 2>/dev/null || echo 'not running')"
echo ""

echo "10. AUTOMATIC UPDATES"
echo "  Unattended-upgrades: $(systemctl is-active unattended-upgrades 2>/dev/null || echo 'not running')"
echo ""

echo "11. MONITORING"
echo "  Uptime Kuma: $(docker ps --format '{{.Names}}' 2>/dev/null | grep -qi uptime-kuma && echo 'running' || echo 'not running')"
echo "  Duplicati: $(docker ps --format '{{.Names}}' 2>/dev/null | grep -qi duplicati && echo 'running' || echo 'not running')"
echo ""

echo "=============================================="
echo "  END OF REPORT"
echo "=============================================="

} > "$REPORT"

echo ""
echo "Compliance report generated: $REPORT"
echo "Size: $(wc -c < "$REPORT") bytes"
echo ""
