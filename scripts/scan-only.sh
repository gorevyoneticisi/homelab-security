#!/bin/bash
# ============================================================
# Security Scan-Only - READ ONLY, makes NO changes
# Shows current security state with detailed explanations
# ============================================================
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; CYAN='\033[0;36m'; NC='\033[0m'; BOLD='\033[1m'

SCORE=0
MAX=100
CHECKS=0   # number of pass/warn/fail checks actually run (info/detail excluded)

# Each check awards up to 10 points. CHECKS is what makes the score a
# real percentage instead of an unbounded sum that can exceed MAX.
pass()  { echo -e "  ${GREEN}[OK]${NC} $1"; SCORE=$((SCORE + 10)); CHECKS=$((CHECKS + 1)); }
warn()  { echo -e "  ${YELLOW}!${NC} $1";  SCORE=$((SCORE + 5));  CHECKS=$((CHECKS + 1)); }
fail()  { echo -e "  ${RED}[FAIL]${NC} $1";                        CHECKS=$((CHECKS + 1)); }
info()  { echo -e "  ${BLUE}i${NC} $1"; }
detail(){ echo -e "    ${CYAN}->${NC} $1"; }
header(){ echo -e "\n${BOLD}${BLUE}=== $1 ===${NC}"; }

# Scanners read UFW state and sshd -T drop-ins, both root-only. Fail fast
# with a clear message rather than dying part-way through with no score.
if [[ $EUID -ne 0 ]]; then
    echo -e "${YELLOW}[!]${NC} Run with sudo for full results:  sudo bash scripts/scan-only.sh"
    echo -e "    ${CYAN}(some checks need root: ufw status, sshd -T)${NC}"
    echo ""
fi

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
EXPOSED=$(ss -tlnp 2>/dev/null | grep "0.0.0.0" | wc -l) || true
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
    # `ufw status` needs root; without `|| true` pipefail + set -e abort the
    # whole scan here when run unprivileged.
    status=$(ufw status 2>/dev/null | head -1) || true
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

# Resolve an EFFECTIVE sshd setting.
# sshd's first-match-wins semantics + `Include sshd_config.d/*.conf` at line 24
# mean the main file alone is not authoritative. `sshd -T` applies it all.
# Falls back to walking drop-ins then the main file when sshd -T is
# unavailable (needs root to read the drop-ins).
#   sshd_opt <key> [default]   key is lowercase, as in `sshd -T` output
sshd_opt() {
    local key="$1" def="${2-not set}" val="" f
    if command -v sshd >/dev/null 2>&1; then
        val=$(sshd -T 2>/dev/null | awk -v k="$key" 'tolower($1)==k{print $2; exit}') || true
        [[ -n "$val" ]] && { printf '%s\n' "$val"; return 0; }
    fi
    for f in /etc/ssh/sshd_config.d/*.conf /etc/ssh/sshd_config; do
        [[ -f "$f" ]] || continue
        val=$(grep -iE "^[[:space:]]*${key}[[:space:]]+" "$f" 2>/dev/null | head -1 | awk '{print $2}') || true
        [[ -n "$val" ]] && { printf '%s\n' "$val"; return 0; }
    done
    printf '%s\n' "$def"
}

SSHD="/etc/ssh/sshd_config"
if [[ -f "$SSHD" ]]; then
    port=$(sshd_opt port 22)
    root=$(sshd_opt permitrootlogin)
    pw=$(sshd_opt passwordauthentication)
    tries=$(sshd_opt maxauthtries)

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

CONTAINERS=$(docker ps -q 2>/dev/null | wc -l) || true
detail "Running containers: $CONTAINERS"

if [[ -n "${DOCKER_CONTENT_TRUST:-}" ]]; then
    pass "Docker Content Trust: enabled"
else
    warn "Docker Content Trust: not enabled"
    detail "Risk: Could pull tampered images"
fi

# Check privileged containers
PRIV=$(docker ps --format '{{.Names}}' 2>/dev/null | while read c; do
    if docker inspect "$c" --format '{{.HostConfig.Privileged}}' 2>/dev/null | grep -q true; then
        echo "$c"
    fi
done || true)
if [[ -z "$PRIV" ]]; then
    pass "No privileged containers"
else
    fail "Privileged containers: $PRIV"
    detail "Privileged containers have full host access"
fi

# Check init:true
NO_INIT=$(docker ps --format '{{.Names}}' 2>/dev/null | while read c; do
    init=$(docker inspect "$c" --format '{{.HostConfig.Init}}' 2>/dev/null) || true
    if [[ "$init" != "true" ]]; then
        echo "$c"
    fi
done | head -5 || true)
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

# -- Memory & Swap -------------------------------------------
header "10. MEMORY & SWAP"

# Swap may be a block device or a plain file. For a file the filesystem
# it lives on is what matters, so resolve it first, then walk up the
# device ancestry looking for a dm-crypt mapping. LUKS volumes report
# TYPE=crypt from lsblk (verified against a throwaway LUKS loop device).
#   swap_encrypted <path>   0 = encrypted, 1 = plaintext or unknown
swap_encrypted() {
    local node="$1" parent typ
    if [[ ! -b "$node" ]]; then
        node=$(findmnt -no SOURCE --target "$node" 2>/dev/null) || return 1
    fi
    node="${node%%\[*}"
    while [[ -n "$node" && -b "$node" ]]; do
        typ=$(lsblk -ndo TYPE "$node" 2>/dev/null | head -1) || true
        [[ "$typ" == "crypt" ]] && return 0
        parent=$(lsblk -ndo PKNAME "$node" 2>/dev/null | head -1) || true
        [[ -z "$parent" ]] && break
        node="/dev/$parent"
    done
    return 1
}

HAS_ZRAM=false
CLEAR_SWAP=""
SWAP_COUNT=0
SWAP_LIST=$(swapon --show --noheadings 2>/dev/null) || true

while IFS= read -r sw; do
    [[ -z "$sw" ]] && continue
    SWAP_COUNT=$((SWAP_COUNT + 1))
    sdev=$(awk '{print $1}' <<< "$sw")
    detail "Swap: $sw"
    case "$sdev" in
        *zram*) HAS_ZRAM=true ;;
        *)  if ! swap_encrypted "$sdev"; then
                CLEAR_SWAP="${CLEAR_SWAP:+$CLEAR_SWAP, }$sdev"
            fi
            ;;
    esac
done <<< "$SWAP_LIST"

detail "Swappiness: $(cat /proc/sys/vm/swappiness 2>/dev/null || echo n/a)"

# Unencrypted swap is the one security-relevant state here: pages that
# hit disk keep their plaintext contents, so secrets cleared from RAM
# can still be recovered from the file. zram never leaves RAM at all.
# No swap at all is reported as info only, not a scored finding - it is
# a legitimate choice on a small server, not a vulnerability.
if [[ -n "$CLEAR_SWAP" ]]; then
    warn "Swap on unencrypted disk: $CLEAR_SWAP"
    detail "Risk: pages written to swap keep plaintext secrets on disk"
    detail "Fix: use compressed RAM swap (zram) or encrypt the volume"
elif [[ "$HAS_ZRAM" == true ]]; then
    pass "Compressed RAM swap (zram) active, nothing stored on disk"
elif [[ $SWAP_COUNT -gt 0 ]]; then
    pass "Swap on encrypted storage"
else
    info "No swap configured"
fi

# -- Score ----------------------------------------------------
header "SECURITY SCORE"

# Score is a real percentage: points earned vs points available.
# CHECKS*10 = the maximum these checks could have awarded, so the
# result is always 0..MAX and can never exceed 100.
if [[ $CHECKS -gt 0 ]]; then
    SCORE=$(( (SCORE * MAX) / (CHECKS * 10) ))
else
    SCORE=0
fi
if [[ $SCORE -gt $MAX ]]; then
    SCORE=$MAX
fi

echo ""
echo -e "  ${BOLD}Score: $SCORE / $MAX${NC}"
echo -e "  ${CYAN}(${CHECKS} checks run)${NC}"
echo ""

if [[ $SCORE -ge 90 ]]; then
    echo -e "  ${GREEN}${BOLD}EXCELLENT${NC} - Your system is well-secured"
elif [[ $SCORE -ge 60 ]]; then
    echo -e "  ${YELLOW}${BOLD}GOOD${NC} - Some improvements recommended"
elif [[ $SCORE -ge 40 ]]; then
    echo -e "  ${YELLOW}${BOLD}NEEDS WORK${NC} - Several security gaps found"
else
    echo -e "  ${RED}${BOLD}CRITICAL${NC} - Major security issues need immediate attention"
fi

echo ""
echo -e "  ${CYAN}Next:${NC} review each [FAIL]/! above and fix them manually."
echo -e "  ${YELLOW}Note:${NC} scripts/hardening.sh targets CasaOS + a VPS/WireGuard"
echo -e "        layout. On THIS box it resets UFW to allow 80/443/51820"
echo -e "        worldwide and sets AllowUsers to accounts that do not exist"
echo -e "        here - do not run it unreviewed."
echo ""
