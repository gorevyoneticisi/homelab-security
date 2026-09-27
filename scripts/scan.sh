#!/bin/bash
# ============================================================
# Homelab Security Scanner v2.0
# Interactive scan with warnings and recommendations
# ============================================================
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; CYAN='\033[0;36m'; NC='\033[0m'; BOLD='\033[1m'

pass()  { echo -e "  ${GREEN}[OK]${NC} $1"; }
fail()  { echo -e "  ${RED}[FAIL]${NC} $1"; }
warn()  { echo -e "  ${YELLOW}!${NC} $1"; }
info()  { echo -e "  ${BLUE}i${NC} $1"; }
header(){ echo -e "\n${BOLD}${BLUE}=== $1 ===${NC}"; }
tip()   { echo -e "  ${CYAN}->${NC} $1"; }

ISSUES=0
WARNINGS=0

echo ""
echo -e "${BOLD}+==============================================+${NC}"
echo -e "${BOLD}|   HOMELAB SECURITY SCANNER v2.0              |${NC}"
echo -e "${BOLD}|   Scanning your system for vulnerabilities   |${NC}"
echo -e "${BOLD}+==============================================+${NC}"
echo ""
info "This scan checks your system against security best practices."
info "Red items need immediate attention. Yellow items are recommendations."
echo ""

# -- 1. Network Exposure -------------------------------------
header "1. NETWORK EXPOSURE"

# Check if SSH is open to public
SSH_PORT=$(grep "^Port " /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}' || echo "22")
if ufw status 2>/dev/null | grep -q "$SSH_PORT.*ALLOW"; then
    fail "SSH port $SSH_PORT is open to ALL IPs"
    tip "Risk: Anyone on the internet can attempt to brute-force your SSH login."
    tip "Fix: Run 'sudo ufw delete allow $SSH_PORT/tcp' then 'sudo ufw allow from YOUR_IP to any port $SSH_PORT'"
    tip "Better: Install WireGuard or Tailscale for VPN-only access."
    ISSUES=$((ISSUES + 1))
else
    pass "SSH port $SSH_PORT is restricted or blocked"
fi

# Check for exposed Docker ports
EXPOSED=$(docker ps --format '{{.Ports}}' 2>/dev/null | grep "0.0.0.0" | wc -l) || true
if [[ $EXPOSED -gt 5 ]]; then
    warn "$EXPOSED services exposed to the internet via Docker"
    tip "Each exposed port is an attack surface. Consider using a reverse proxy (Nginx Proxy Manager)."
    WARNINGS=$((WARNINGS + 1))
else
    pass "Docker exposure is reasonable ($EXPOSED services)"
fi

# Check for WireGuard/VPN
if systemctl is-active --quiet wireguard 2>/dev/null || docker ps --format '{{.Names}}' 2>/dev/null | grep -qi "wireguard\|vpn"; then
    pass "VPN (WireGuard) is running"
else
    warn "No VPN detected - all services may be publicly accessible"
    tip "Recommendation: Install Tailscale or WireGuard for secure remote access."
    tip "Tailscale: curl -fsSL https://tailscale.com/install.sh | sh && sudo tailscale up"
    tip "WireGuard: sudo apt install wireguard && sudo wg-quick up wg0"
    WARNINGS=$((WARNINGS + 1))
fi

# Check for Cloudflare tunnel
if docker ps --format '{{.Names}}' 2>/dev/null | grep -qi "cloudflare\|tunnel"; then
    pass "Cloudflare Tunnel detected"
else
    info "No Cloudflare Tunnel - consider using one to hide your origin IP"
fi

# -- 2. Firewall ---------------------------------------------
header "2. FIREWALL"

if command -v ufw &>/dev/null; then
    status=$(ufw status 2>/dev/null | head -1) || true
    if [[ "$status" == *"active"* ]]; then
        pass "UFW is active"
        rules=$(ufw status | grep -c "ALLOW" || echo 0)
        info "  $rules allow rules configured"
    else
        fail "UFW is installed but INACTIVE"
        tip "Risk: No firewall protection. All ports are open to the internet."
        tip "Fix: sudo ufw enable"
        ISSUES=$((ISSUES + 1))
    fi
else
    fail "UFW is not installed"
    tip "Fix: sudo apt install ufw && sudo ufw enable"
    ISSUES=$((ISSUES + 1))
fi

# -- 3. SSH Security -----------------------------------------
header "3. SSH SECURITY"

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
    root=$(sshd_opt permitrootlogin)
    if [[ "$root" == "yes" ]]; then
        fail "SSH root login is ENABLED"
        tip "Risk: Attackers can brute-force the root account directly."
        tip "Fix: Set 'PermitRootLogin no' in /etc/ssh/sshd_config"
        ISSUES=$((ISSUES + 1))
    else
        pass "SSH root login is disabled"
    fi

    pw=$(sshd_opt passwordauthentication)
    if [[ "$pw" == "yes" ]]; then
        fail "SSH password authentication is ENABLED"
        tip "Risk: Vulnerable to brute-force attacks."
        tip "Fix: Use key-only auth. Set 'PasswordAuthentication no' in /etc/ssh/sshd_config"
        ISSUES=$((ISSUES + 1))
    else
        pass "SSH uses key-only authentication"
    fi

    port=$(sshd_opt port 22)
    if [[ "$port" == "22" || -z "$port" ]]; then
        warn "SSH is on default port 22"
        tip "Bot scanners constantly probe port 22. Moving to a non-standard port reduces noise."
        WARNINGS=$((WARNINGS + 1))
    else
        pass "SSH is on non-standard port $port"
    fi

    tries=$(sshd_opt maxauthtries "")
    if [[ -z "$tries" || "$tries" -gt 3 ]]; then
        warn "SSH MaxAuthTries is not set or too high ($tries)"
        tip "Recommended: MaxAuthTries 3"
        WARNINGS=$((WARNINGS + 1))
    else
        pass "SSH MaxAuthTries: $tries"
    fi
else
    fail "SSH config not found"
    ISSUES=$((ISSUES + 1))
fi

# -- 4. Intrusion Detection ----------------------------------
header "4. INTRUSION DETECTION"

for svc in crowdsec crowdsec-cloudflare-bouncer crowdsec-firewall-bouncer fail2ban; do
    if systemctl is-active --quiet "$svc" 2>/dev/null; then
        pass "$svc: running"
    elif systemctl is-enabled --quiet "$svc" 2>/dev/null; then
        warn "$svc: enabled but not running"
    else
        if [[ "$svc" == "fail2ban" ]]; then
            fail "$svc: not installed"
            tip "fail2ban protects SSH and Nginx from brute-force attacks."
            tip "Fix: sudo apt install fail2ban && sudo systemctl enable fail2ban"
            ISSUES=$((ISSUES + 1))
        else
            info "$svc: not installed (optional but recommended)"
        fi
    fi
done

# -- 5. Docker Security --------------------------------------
header "5. DOCKER SECURITY"

if [[ -n "${DOCKER_CONTENT_TRUST:-}" ]]; then
    pass "Docker Content Trust: enabled"
else
    warn "Docker Content Trust: not enabled"
    tip "DCT verifies image signatures. Without it, you could pull tampered images."
    tip "Fix: echo 'DOCKER_CONTENT_TRUST=1' >> /etc/environment"
    WARNINGS=$((WARNINGS + 1))
fi

# Check for privileged containers
priv=$(docker ps --format '{{.Names}}' 2>/dev/null | while read c; do
    if docker inspect "$c" --format '{{.HostConfig.Privileged}}' 2>/dev/null | grep -q true; then
        echo "$c"
    fi
done || true)
if [[ -n "$priv" ]]; then
    fail "Privileged containers detected: $priv"
    tip "Privileged containers have full host access. Use cap_add instead."
    ISSUES=$((ISSUES + 1))
else
    pass "No privileged containers"
fi

# Check for init: true
no_init=$(docker ps --format '{{.Names}}' 2>/dev/null | while read c; do
    init=$(docker inspect "$c" --format '{{.HostConfig.Init}}' 2>/dev/null) || true
    if [[ "$init" != "true" ]]; then
        echo "$c"
    fi
done | head -5 || true)
if [[ -n "$no_init" ]]; then
    warn "Containers missing init:true: $no_init"
    tip "Without init:true, zombie processes accumulate and never get reaped."
    WARNINGS=$((WARNINGS + 1))
else
    pass "All containers have init:true"
fi

# Check for no-new-privileges
no_np=$(docker ps --format '{{.Names}}' 2>/dev/null | while read c; do
    np=$(docker inspect "$c" --format '{{.HostConfig.SecurityOpt}}' 2>/dev/null) || true
    if [[ "$np" != *"no-new-privileges"* ]]; then
        echo "$c"
    fi
done | head -5 || true)
if [[ -n "$no_np" ]]; then
    warn "Containers without no-new-privileges: $no_np"
    tip "Without this, processes inside containers can escalate privileges."
    WARNINGS=$((WARNINGS + 1))
else
    pass "All containers have no-new-privileges"
fi

# -- 6. File Integrity ---------------------------------------
header "6. FILE INTEGRITY"

if command -v aide &>/dev/null; then
    pass "AIDE: installed"
    if [[ -f /var/lib/aide/aide.db.new ]] || [[ -f /var/lib/aide/aide.db ]]; then
        pass "AIDE database: initialized"
    else
        warn "AIDE database: not initialized"
        tip "Run 'sudo aideinit' to create the baseline database."
        WARNINGS=$((WARNINGS + 1))
    fi
else
    warn "AIDE: not installed (file integrity monitoring)"
    tip "AIDE detects unauthorized file changes - critical for detecting rootkits."
    tip "Fix: sudo apt install aide && sudo aideinit"
    WARNINGS=$((WARNINGS + 1))
fi

if command -v rkhunter &>/dev/null; then
    pass "rkhunter: installed"
else
    info "rkhunter: not installed (optional rootkit scanner)"
fi

# -- 7. Antivirus --------------------------------------------
header "7. ANTIVIRUS"

if command -v clamscan &>/dev/null; then
    pass "ClamAV: installed"
    systemctl is-active --quiet clamav-daemon && pass "ClamAV daemon: running" || warn "ClamAV daemon: not running"
else
    warn "ClamAV: not installed"
    tip "ClamAV scans for malware in files - especially important for uploaded content."
    tip "Fix: sudo apt install clamav clamav-daemon && sudo freshclam"
    WARNINGS=$((WARNINGS + 1))
fi

# -- 8. Automatic Updates ------------------------------------
header "8. AUTOMATIC UPDATES"

if systemctl is-active --quiet unattended-upgrades; then
    pass "Unattended security updates: active"
else
    warn "Automatic security updates: not configured"
    tip "Without auto-updates, known vulnerabilities remain unpatched."
    tip "Fix: sudo apt install unattended-upgrades && sudo dpkg-reconfigure -plow unattended-upgrades"
    WARNINGS=$((WARNINGS + 1))
fi

# -- 9. Monitoring & Backup ----------------------------------
header "9. MONITORING & BACKUP"

docker ps --format '{{.Names}}' 2>/dev/null | grep -qi "uptime-kuma" && pass "Uptime monitoring: running" || warn "Uptime monitoring: not running"
docker ps --format '{{.Names}}' 2>/dev/null | grep -qi "duplicati" && pass "Backup system: running" || warn "Backup system: not running"

# -- 10. Memory & Swap ---------------------------------------
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
    info "  swap: $sw"
    case "$sdev" in
        *zram*) HAS_ZRAM=true ;;
        *)  if ! swap_encrypted "$sdev"; then
                CLEAR_SWAP="${CLEAR_SWAP:+$CLEAR_SWAP, }$sdev"
            fi
            ;;
    esac
done <<< "$SWAP_LIST"

info "  swappiness: $(cat /proc/sys/vm/swappiness 2>/dev/null || echo n/a)"

# Unencrypted swap is the one security-relevant state here: pages that
# hit disk keep their plaintext contents, so secrets cleared from RAM
# can still be recovered from the file. zram never leaves RAM at all.
if [[ -n "$CLEAR_SWAP" ]]; then
    fail "Swap on unencrypted disk: $CLEAR_SWAP"
    tip "Risk: pages written to swap keep plaintext secrets on disk."
    tip "Fix: use compressed RAM swap (zram) or encrypt the volume."
    tip "zram: sudo apt install zram-tools  (RAM-backed, never hits disk)"
    ISSUES=$((ISSUES + 1))
elif [[ "$HAS_ZRAM" == true ]]; then
    pass "Compressed RAM swap (zram) active, nothing stored on disk"
elif [[ $SWAP_COUNT -gt 0 ]]; then
    pass "Swap on encrypted storage"
else
    info "No swap configured"
fi

# -- Summary -------------------------------------------------
echo ""
echo -e "${BOLD}+==============================================+${NC}"
echo -e "${BOLD}|              SCAN RESULTS                    |${NC}"
echo -e "${BOLD}+==============================================+${NC}"
echo ""

if [[ $ISSUES -eq 0 && $WARNINGS -eq 0 ]]; then
    echo -e "  ${GREEN}${BOLD}PERFECT! No issues found.${NC}"
elif [[ $ISSUES -eq 0 ]]; then
    echo -e "  ${YELLOW}${BOLD}$WARNINGS recommendation(s) found.${NC}"
    echo -e "  These are optional improvements for defense-in-depth."
else
    echo -e "  ${RED}${BOLD}$ISSUES critical issue(s) and $WARNINGS warning(s) found.${NC}"
    echo -e "  Run ${CYAN}sudo bash scripts/hardening.sh${NC} to fix all issues automatically."
fi

echo ""
echo -e "  ${CYAN}Next step:${NC} sudo bash scripts/hardening.sh"
echo ""
