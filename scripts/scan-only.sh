#!/bin/bash
# ============================================================
# Security Scan-Only - READ ONLY, makes NO changes
# Shows current security state with detailed explanations
# ============================================================
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; CYAN='\033[0;36m'; NC='\033[0m'; BOLD='\033[1m'

SCORE=0
MAX=100

pass()  { echo -e "  ${GREEN}[OK]${NC} $1"; SCORE=$((SCORE + 10)); }
warn()  { echo -e "  ${YELLOW}!${NC} $1"; SCORE=$((SCORE + 5)); }
fail()  { echo -e "  ${RED}[FAIL]${NC} $1"; }
info()  { echo -e "  ${BLUE}i${NC} $1"; }
detail(){ echo -e "    ${CYAN}->${NC} $1"; }
header(){ echo -e "\n${BOLD}${BLUE}=== $1 ===${NC}"; }

echo ""
echo -e "${BOLD}+==========================================================+${NC}"
echo -e "${BOLD}|         SECURITY STATE SCAN (READ ONLY)                  |${NC}"
echo -e "${BOLD}|         This scan makes ZERO changes to your system       |${NC}"
echo -e "${BOLD}+==========================================================+${NC}"
echo ""
info "Scanning your system... (this is safe, nothing will be modified)"
echo ""

# -- System Info ----------------------------------------------
header "SYSTEM INFORMATION"
detail "OS: $(lsb_release -ds 2>/dev/null || cat /etc/os-release | grep PRETTY | cut -d= -f2)"
detail "Kernel: $(uname -r)"
detail "Hostname: $(hostname)"
detail "IP: $(hostname -I | awk '{print $1}')"
detail "Uptime: $(uptime -p)"
detail "RAM: $(free -h | awk '/Mem:/{print $2}') total, $(free -h | awk '/Mem:/{print $3}') used"
detail "Disk: $(df -h / | awk 'NR==2{print $2}') total, $(df -h / | awk 'NR==2{print $5}') used"

# -- Network Exposure -----------------------------------------
header "1. NETWORK EXPOSURE"

# Check WireGuard
if ip link show wg0 &>/dev/null; then
    pass "WireGuard VPN is active"
    detail "Interface: wg0, Subnet: $(ip addr show wg0 | grep inet | awk '{print $2}')"
else
    warn "No WireGuard VPN detected"
    detail "Risk: Services may be directly exposed to the internet"
    detail "Fix: Set up WireGuard for secure remote access"
fi

# Check for public-facing ports
EXPOSED=$(ss -tlnp 2>/dev/null | grep "0.0.0.0" | wc -l)
if [[ $EXPOSED -gt 10 ]]; then
    warn "$EXPOSED services listening on all interfaces (0.0.0.0)"
    detail "Each is a potential attack surface from the internet"
else
    pass "Service exposure is reasonable ($EXPOSED services)"
fi

# Check specific dangerous ports
for port in 21 23 139 445 3389 5900; do
    if ss -tlnp 2>/dev/null | grep -q ":$port "; then
        warn "Dangerous port $port is open (FTP/SMB/RDP/VNC)"
        detail "This service should not be publicly accessible"
    fi
done

# Check SSH exposure
if ss -tlnp 2>/dev/null | grep -q ":22 "; then
    warn "SSH on default port 22 (bot magnet)"
    detail "Bot scanners constantly probe port 22"
fi

# -- Firewall -------------------------------------------------
header "2. FIREWALL STATUS"

if command -v ufw &>/dev/null; then
    status=$(ufw status 2>/dev/null | head -1)
    if [[ "$status" == *"active"* ]]; then
        pass "UFW firewall is active"
        detail "Rules: $(ufw status | grep -c "ALLOW") allow, $(ufw status | grep -c "DENY") deny"
    else
        warn "UFW is installed but INACTIVE"
        detail "Risk: No host firewall protection"
    fi
else
    warn "UFW is not installed"
    detail "Risk: No host-level firewall"
fi

# -- SSH ------------------------------------------------------
header "3. SSH CONFIGURATION"

SSHD="/etc/ssh/sshd_config"
if [[ -f "$SSHD" ]]; then
    port=$(grep "^Port " "$SSHD" | awk '{print $2}' || echo "22")
    root=$(grep "^PermitRootLogin" "$SSHD" | awk '{print $2}' || echo "not set")
    pw=$(grep "^PasswordAuthentication" "$SSHD" | awk '{print $2}' || echo "not set")
    tries=$(grep "^MaxAuthTries" "$SSHD" | awk '{print $2}' || echo "not set")

    detail "Port: $port"
    detail "Root login: $root"
    detail "Password auth: $pw"
    detail "Max auth tries: $tries"

    [[ "$port" != "22" ]] && pass "Non-standard SSH port" || warn "Default port 22"
    [[ "$root" == "no" || "$root" == "prohibit-password" ]] && pass "Root login restricted" || warn "Root login: $root"
    [[ "$pw" == "no" ]] && pass "Password auth disabled" || warn "Password auth: $pw"
    [[ "$tries" != "not set" && "$tries" -le 3 ]] && pass "Max auth tries: $tries" || warn "Max auth tries not limited"
else
    fail "SSH config not found"
fi

# -- Intrusion Detection --------------------------------------
header "4. INTRUSION DETECTION"

for svc in crowdsec fail2ban; do
    if systemctl is-active --quiet "$svc" 2>/dev/null; then
        pass "$svc: running"
    elif systemctl is-enabled --quiet "$svc" 2>/dev/null; then
        warn "$svc: enabled but not running"
    else
        warn "$svc: not installed"
    fi
done

# Check CrowdSec bouncers
for bouncer in crowdsec-cloudflare-bouncer crowdsec-firewall-bouncer; do
    if systemctl is-active --quiet "$bouncer" 2>/dev/null; then
        pass "$bouncer: running"
    fi
done

# -- Docker Security ------------------------------------------
header "5. DOCKER SECURITY"

CONTAINERS=$(docker ps -q 2>/dev/null | wc -l)
detail "Running containers: $CONTAINERS"

if [[ -n "${DOCKER_CONTENT_TRUST:-}" ]]; then
    pass "Docker Content Trust: enabled"
else
    warn "Docker Content Trust: not enabled"
    detail "Risk: Could pull tampered images"
fi

# Check privileged containers
PRIV=$(docker ps --format '{{.Names}}' 2>/dev/null | while read c; do
    docker inspect "$c" --format '{{.HostConfig.Privileged}}' 2>/dev/null | grep -q true && echo "$c"
done)
if [[ -z "$PRIV" ]]; then
    pass "No privileged containers"
else
    fail "Privileged containers: $PRIV"
    detail "Privileged containers have full host access"
fi

# Check init:true
NO_INIT=$(docker ps --format '{{.Names}}' 2>/dev/null | while read c; do
    init=$(docker inspect "$c" --format '{{.HostConfig.Init}}' 2>/dev/null)
    [[ "$init" != "true" ]] && echo "$c"
done | head -5)
if [[ -z "$NO_INIT" ]]; then
    pass "All containers have init:true"
else
    warn "Missing init:true: $NO_INIT"
fi

# -- File Integrity -------------------------------------------
header "6. FILE INTEGRITY MONITORING"

if command -v aide &>/dev/null; then
    pass "AIDE: installed"
    [[ -f /var/lib/aide/aide.db ]] && pass "AIDE database: initialized" || warn "AIDE database: not initialized"
else
    warn "AIDE: not installed"
    detail "AIDE detects unauthorized file changes"
fi

command -v rkhunter &>/dev/null && pass "rkhunter: installed" || info "rkhunter: not installed"

# -- Antivirus ------------------------------------------------
header "7. ANTIVIRUS"

if command -v clamscan &>/dev/null; then
    pass "ClamAV: installed"
    systemctl is-active --quiet clamav-daemon && pass "ClamAV daemon: running" || warn "ClamAV daemon: not running"
else
    warn "ClamAV: not installed"
fi

# -- Updates --------------------------------------------------
header "8. AUTOMATIC UPDATES"

systemctl is-active --quiet unattended-upgrades && pass "Unattended upgrades: active" || warn "Auto-updates: not configured"

# -- Monitoring -----------------------------------------------
header "9. MONITORING & BACKUP"

docker ps --format '{{.Names}}' 2>/dev/null | grep -qi "uptime-kuma" && pass "Monitoring: running" || warn "No uptime monitoring"
docker ps --format '{{.Names}}' 2>/dev/null | grep -qi "duplicati" && pass "Backup: running" || warn "No backup system"

# -- Score ----------------------------------------------------
header "SECURITY SCORE"
echo ""
echo -e "  ${BOLD}Score: $SCORE / 100${NC}"
echo ""

if [[ $SCORE -ge 80 ]]; then
    echo -e "  ${GREEN}${BOLD}EXCELLENT${NC} - Your system is well-secured"
elif [[ $SCORE -ge 60 ]]; then
    echo -e "  ${YELLOW}${BOLD}GOOD${NC} - Some improvements recommended"
elif [[ $SCORE -ge 40 ]]; then
    echo -e "  ${YELLOW}${BOLD}NEEDS WORK${NC} - Several security gaps found"
else
    echo -e "  ${RED}${BOLD}CRITICAL${NC} - Major security issues need immediate attention"
fi

echo ""
echo -e "  ${CYAN}To fix issues:${NC} sudo bash scripts/hardening.sh"
echo ""
