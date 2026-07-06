#!/bin/bash
# ============================================================
# Security Scanner v4.0
# Scan -> Show all findings -> Ask what to fix -> Separate auto/manual
# ============================================================
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; CYAN='\033[0;36m'; MAGENTA='\033[0;35m'; NC='\033[0m'; BOLD='\033[1m'; DIM='\033[2m'

# Arrays to store findings
declare -a FINDINGS=()
declare -a AUTO_FIX=()
declare -a MANUAL_FIX=()
declare -a SUGGESTIONS=()

CRIT=0; HIGH=0; MED=0; LOW=0; PASS=0

add_finding() {
    local severity="$1" auto="$2" msg="$3" detail="$4"
    FINDINGS+=("[$severity] $msg|$detail|$auto")
    case $severity in
        CRIT) CRIT=$((CRIT+1));;
        HIGH) HIGH=$((HIGH+1));;
        MED)  MED=$((MED+1));;
        LOW)  LOW=$((LOW+1));;
    esac
}

add_pass() {
    local msg="$1"
    FINDINGS+=("[PASS] $msg||")
    PASS=$((PASS+1))
}

echo ""
echo -e "${BOLD}+==========================================================+${NC}"
echo -e "${BOLD}|         Security Scanner v4.0                    |\033[0m"
echo -e "${BOLD}|         Read-only scan -> show all -> ask what to fix       |\033[0m"
echo -e "${BOLD}+==========================================================+${NC}"
echo ""
info "Scanning your entire system... (this is safe, nothing will be changed)"
echo ""

info() { echo -e "  ${BLUE}[i]${NC} $1"; }

# ===========================================================
# PHASE 1: SCAN EVERYTHING
# ===========================================================

echo -e "\n${BOLD}${MAGENTA}=== PHASE 1: SCANNING ===${NC}"

# -- Network --
info "Scanning network exposure..."
PUB_PORTS=$(ss -tlnp 2>/dev/null | grep "0.0.0.0" | awk '{print $4}' | grep -oP ':\K[0-9]+' | sort -n | uniq)
DANGER="21 23 25 135 139 445 3389 5900"
for p in $DANGER; do
    if ss -tlnp 2>/dev/null | grep -q ":$p "; then
        add_finding CRIT auto "Dangerous port $p open to internet" "Service on port $p is publicly accessible"
    fi
done

if ip link show wg0 &>/dev/null; then
    add_pass "WireGuard VPN active"
else
    add_finding HIGH manual "No VPN detected" "All services may be directly internet-accessible"
fi

# -- Firewall --
info "Scanning firewall..."
if command -v ufw &>/dev/null; then
    if ufw status 2>/dev/null | grep -q "active"; then
        add_pass "UFW firewall active"
    else
        add_finding CRIT auto "UFW installed but INACTIVE" "No host firewall protection"
    fi
else
    add_finding CRIT auto "No host firewall (UFW not installed)" "All ports accessible from internet"
fi

# -- SSH --
info "Scanning SSH..."
SSHD="/etc/ssh/sshd_config"
if [[ -f "$SSHD" ]]; then
    port=$(grep "^Port " "$SSHD" | awk '{print $2}' || echo "22")
    root=$(grep "^PermitRootLogin" "$SSHD" | awk '{print $2}' || echo "not set")
    pw=$(grep "^PasswordAuthentication" "$SSHD" | awk '{print $2}' || echo "not set")

    [[ "$port" == "22" ]] && add_finding MED auto "SSH on default port 22" "Bot scanners constantly probe port 22"
    [[ "$root" != "no" && "$root" != "prohibit-password" ]] && add_finding CRIT auto "SSH root login enabled: $root" "Attackers can brute-force root directly"
    [[ "$pw" != "no" ]] && add_finding CRIT auto "SSH password authentication enabled" "Vulnerable to brute-force attacks"
fi

# -- Intrusion Detection --
info "Scanning intrusion detection..."
for svc in crowdsec fail2ban; do
    if systemctl is-active --quiet "$svc" 2>/dev/null; then
        add_pass "$svc running"
    elif systemctl is-enabled --quiet "$svc" 2>/dev/null; then
        add_finding HIGH auto "$svc enabled but NOT running"
    else
        [[ "$svc" == "crowdsec" ]] && add_finding HIGH auto "$svc not running" "No intrusion detection"
        [[ "$svc" == "fail2ban" ]] && add_finding MED auto "$svc not installed" "No brute-force protection"
    fi
done

# -- Docker --
info "Scanning Docker security..."
CONTAINERS=$(docker ps -q 2>/dev/null | wc -l)

PRIV=$(docker ps --format '{{.Names}}' 2>/dev/null | while read c; do
    docker inspect "$c" --format '{{.HostConfig.Privileged}}' 2>/dev/null | grep -q true && echo "$c"
done)
[[ -z "$PRIV" ]] && add_pass "No privileged containers" || add_finding CRIT manual "Privileged containers: $PRIV" "Full host access from container"

NO_INIT=$(docker ps --format '{{.Names}}' 2>/dev/null | while read c; do
    init=$(docker inspect "$c" --format '{{.HostConfig.Init}}' 2>/dev/null)
    [[ "$init" != "true" ]] && echo "$c"
done)
[[ -z "$NO_INIT" ]] && add_pass "All containers have init:true" || add_finding MED auto "Missing init:true: $NO_INIT" "Zombie processes accumulate"

NO_NP=$(docker ps --format '{{.Names}}' 2>/dev/null | while read c; do
    np=$(docker inspect "$c" --format '{{.HostConfig.SecurityOpt}}' 2>/dev/null)
    [[ "$np" != *"no-new-privileges"* ]] && echo "$c"
done)
[[ -z "$NO_NP" ]] && add_pass "All containers have no-new-privileges" || add_finding MED auto "Missing no-new-privileges: $NO_NP" "Processes can escalate privileges"

# -- Kernel --
info "Scanning kernel..."
if apt list --upgradable 2>/dev/null | grep -q "linux-image"; then
    add_finding HIGH manual "Kernel update available" "Patch kernel vulnerabilities"
fi

# -- Users --
info "Scanning user accounts..."
EMPTY_PW=$(awk -F: '($2 == "" || $2 == "!") {print $1}' /etc/shadow 2>/dev/null | wc -l)
[[ $EMPTY_PW -gt 0 ]] && add_finding CRIT auto "Empty passwords found: $EMPTY_PW user(s)" "Anyone can log in without password"

FAILED=$(grep "Failed password" /var/log/auth.log 2>/dev/null | tail -100 | wc -l)
[[ $FAILED -gt 50 ]] && add_finding HIGH manual "High failed logins: $FAILED" "Possible brute-force attack"

# -- File Integrity --
info "Scanning file integrity..."
command -v aide &>/dev/null || add_finding MED auto "AIDE not installed" "No file integrity monitoring"
command -v rkhunter &>/dev/null || add_pass "rkhunter installed"

# -- Antivirus --
info "Scanning antivirus..."
command -v clamscan &>/dev/null || add_finding MED auto "ClamAV not installed" "No malware scanning"

# -- Updates --
info "Scanning update configuration..."
systemctl is-active --quiet unattended-upgrades && add_pass "Auto-updates active" || add_finding HIGH auto "Auto-updates not configured"

# -- Cron --
info "Scanning cron jobs..."
SUSP=$(crontab -l 2>/dev/null | grep -i "curl\|wget\|nc\|netcat\|bash -i\|/dev/tcp" | wc -l)
[[ $SUSP -gt 0 ]] && add_finding CRIT manual "Suspicious cron jobs: $SUSP" "May indicate reverse shell" || add_pass "No suspicious cron jobs"

# -- Network Isolation --
info "Scanning Docker networks..."
NET_COUNT=$(docker network ls --format '{{.Name}}' 2>/dev/null | grep -v "^bridge$\|^host$\|^none$" | wc -l)
[[ $NET_COUNT -gt 5 ]] && add_pass "Good network isolation ($NET_COUNT networks)" || add_finding MED manual "Limited network isolation ($NET_COUNT networks)"

# ===========================================================
# PHASE 2: SHOW ALL FINDINGS
# ===========================================================

echo ""
echo -e "\n${BOLD}${MAGENTA}=== PHASE 2: ALL FINDINGS ===${NC}"
echo ""

AUTO_IDX=0
MANUAL_IDX=0

for f in "${FINDINGS[@]}"; do
    IFS='|' read -r header detail auto <<< "$f"
    IFS=']' read -r sev msg <<< "$header"
    sev="${sev#[}"
    msg="${msg# }"

    case $sev in
        CRIT) color="${RED}${BOLD}"; icon="!!!";;
        HIGH) color="${RED}"; icon=" ! ";;
        MED)  color="${YELLOW}"; icon=" ~ ";;
        LOW)  color="${CYAN}"; icon=" - ";;
        PASS) color="${GREEN}"; icon=" [OK] ";;
    esac

    if [[ "$sev" == "PASS" ]]; then
        echo -e "  ${color}${icon}${NC} $msg"
    else
        echo -e "  ${color}${icon}${NC} $msg"
        [[ -n "$detail" ]] && echo -e "      ${DIM}${detail}${NC}"

        if [[ "$auto" == "auto" ]]; then
            AUTO_IDX=$((AUTO_IDX + 1))
            echo -e "      ${GREEN}-> AUTO-PATCHABLE${NC} (script can fix this)"
        elif [[ "$auto" == "manual" ]]; then
            MANUAL_IDX=$((MANUAL_IDX + 1))
            echo -e "      ${YELLOW}-> MANUAL FIX${NC} (script cannot fix - you must do this)"
        fi
    fi
done

# ===========================================================
# PHASE 3: SCORE & ASK
# ===========================================================

echo ""
echo -e "${BOLD}${MAGENTA}=== PHASE 3: SUMMARY ===${NC}"
echo ""
echo -e "  ${RED}${BOLD}CRITICAL:${NC} $CRIT  ${RED}HIGH:${NC} $HIGH  ${YELLOW}MEDIUM:${NC} $MED  ${GREEN}PASS:${NC} $PASS"
echo -e "  ${GREEN}Auto-patchable:${NC} $AUTO_IDX"
echo -e "  ${YELLOW}Manual fixes:${NC} $MANUAL_IDX"
echo ""

if [[ $CRIT -eq 0 && $HIGH -eq 0 ]]; then
    echo -e "  ${GREEN}${BOLD}System is well-secured. No critical issues.${NC}"
    echo ""
    exit 0
fi

# ===========================================================
# PHASE 4: ASK WHAT TO FIX
# ===========================================================

echo -e "${BOLD}${MAGENTA}=== PHASE 4: WHAT DO YOU WANT TO FIX? ===${NC}"
echo ""

if [[ $AUTO_IDX -gt 0 ]]; then
    echo -e "  ${GREEN}The script can automatically fix ${AUTO_IDX} issue(s):${NC}"
    echo "    - UFW firewall configuration"
    echo "    - SSH hardening (disable root, disable passwords)"
    echo "    - fail2ban installation + configuration"
    echo "    - Docker container hardening (init, no-new-privileges)"
    echo "    - AIDE file integrity setup"
    echo "    - ClamAV installation"
    echo "    - Auto-updates configuration"
    echo ""
fi

if [[ $MANUAL_IDX -gt 0 ]]; then
    echo -e "  ${YELLOW}You must manually fix ${MANUAL_IDX} issue(s):${NC}"
    for f in "${FINDINGS[@]}"; do
        IFS='|' read -r header detail auto <<< "$f"
        IFS=']' read -r sev msg <<< "$header"
        if [[ "$auto" == "manual" && "$sev" != "PASS" ]]; then
            echo -e "    ${YELLOW}-${NC} $msg"
            [[ -n "$detail" ]] && echo -e "      ${DIM}  $detail${NC}"
        fi
    done
    echo ""
fi

echo -e "  ${CYAN}Options:${NC}"
echo "    1) Run auto-patch (fix everything the script can)"
echo "    2) Show manual fix instructions"
echo "    3) Both (auto-patch + show manual instructions)"
echo "    4) Exit (no changes)"
echo ""
read -p "  Choose [1-4]: " -n 1 -r
echo ""

case $REPLY in
    1) bash "$(dirname "$0")/hardening.sh" ;;
    2)
        echo ""
        echo -e "${BOLD}MANUAL FIX INSTRUCTIONS:${NC}"
        echo ""
        echo "The following issues require manual intervention:"
        echo ""
        echo "1. VPN SETUP:"
        echo "   Option A: Install Tailscale (easier)"
        echo "     curl -fsSL https://tailscale.com/install.sh | sh"
        echo "     sudo tailscale up"
        echo ""
        echo "   Option B: Install WireGuard (more control)"
        echo "     sudo apt install wireguard"
        echo "     sudo bash $(dirname "$0")/setup-vpn.sh"
        echo ""
        echo "2. KERNEL UPDATE:"
        echo "   sudo apt update && sudo apt upgrade"
        echo ""
        echo "3. SUSPICIOUS CRON JOBS:"
        echo "   crontab -l  (review all entries)"
        echo "   Edit: crontab -e  (remove suspicious lines)"
        echo ""
        echo "4. PRIVILEGED CONTAINERS:"
        echo "   Edit docker-compose.yml and remove 'privileged: true'"
        echo "   Replace with specific cap_add if needed"
        echo ""
        echo "5. DOCKER NETWORK ISOLATION:"
        echo "   Create separate networks for each app tier"
        echo "   docker network create app-tier"
        echo "   docker network create db-tier"
        echo "   docker network connect app-tier container-name"
        echo ""
        ;;
    3) bash "$(dirname "$0")/hardening.sh"; echo ""; echo -e "${YELLOW}Manual fixes:${NC}"; echo "  See option 2 for manual fix instructions." ;;
    4) echo "Exiting. No changes made." ;;
esac

echo ""
