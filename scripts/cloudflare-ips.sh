#!/bin/bash
# ============================================================
# Cloudflare Origin IP Restriction
# Only allows Cloudflare IPs to reach ports 80/443
# Prevents direct IP attacks bypassing Cloudflare
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
echo -e "${BOLD}|   CLOUDFLARE ORIGIN IP RESTRICTION            |${NC}"
echo -e "${BOLD}+==============================================+${NC}"
echo ""
info "This script restricts HTTP/HTTPS traffic to Cloudflare IPs only."
info "Your origin server will only accept connections from Cloudflare's network."
info "Direct IP attacks will be blocked at the firewall level."
echo ""
echo "What this does:"
echo "  1. Fetches current Cloudflare IP ranges"
echo "  2. Creates UFW rules allowing ONLY Cloudflare on ports 80/443"
echo "  3. Blocks all other traffic to those ports"
echo "  4. Sets up auto-update to keep IP ranges current"
echo ""
read -p "Continue? (y/N): " -n 1 -r
echo ""
[[ $REPLY =~ ^[Yy]$ ]] || exit 0

# -- Fetch Cloudflare IPs ------------------------------------
info "Fetching Cloudflare IP ranges..."

CF_IPV4=$(curl -s https://www.cloudflare.com/ips-v4 2>/dev/null)
CF_IPV6=$(curl -s https://www.cloudflare.com/ips-v6 2>/dev/null)

if [[ -z "$CF_IPV4" ]]; then
    err "Failed to fetch Cloudflare IPs. Check internet connection."
    exit 1
fi

log "Fetched $(echo "$CF_IPV4" | wc -l) IPv4 ranges, $(echo "$CF_IPV6" | wc -l) IPv6 ranges"

# -- Backup current UFW rules --------------------------------
BACKUP="/etc/ufw/cloudflare-backup-$(date +%Y%m%d_%H%M%S)"
ufw status verbose > "$BACKUP" 2>/dev/null
log "Current UFW rules backed up to: $BACKUP"

# -- Remove old Cloudflare rules if re-running ---------------
info "Cleaning old Cloudflare rules..."
ufw status numbered 2>/dev/null | grep "Cloudflare" | awk -F'[][]' '{print $2}' | sort -rn | while read num; do
    ufw --force delete "$num" 2>/dev/null || true
done

# -- Allow Cloudflare IPv4 -----------------------------------
info "Adding Cloudflare IPv4 rules..."

while IFS= read -r ip; do
    ip=$(echo "$ip" | tr -d '[:space:]')
    [[ -z "$ip" ]] && continue
    ufw allow from "$ip" to any port 80 proto tcp comment "Cloudflare IPv4 HTTP"
    ufw allow from "$ip" to any port 443 proto tcp comment "Cloudflare IPv4 HTTPS"
done <<< "$CF_IPV4"

log "Added IPv4 rules"

# -- Allow Cloudflare IPv6 -----------------------------------
if [[ -n "$CF_IPV6" ]]; then
    info "Adding Cloudflare IPv6 rules..."

    while IFS= read -r ip; do
        ip=$(echo "$ip" | tr -d '[:space:]')
        [[ -z "$ip" ]] && continue
        ufw allow from "$ip" to any port 80 proto tcp comment "Cloudflare IPv6 HTTP"
        ufw allow from "$ip" to any port 443 proto tcp comment "Cloudflare IPv6 HTTPS"
    done <<< "$CF_IPV6"

    log "Added IPv6 rules"
fi

# -- Block everything else on 80/443 -------------------------
info "Blocking non-Cloudflare traffic on ports 80/443..."

# Insert deny rules AFTER the Cloudflare allow rules
ufw deny in on eth0 to any port 80 proto tcp comment "Block non-CF HTTP"
ufw deny in on eth0 to any port 443 proto tcp comment "Block non-CF HTTPS"

log "Non-Cloudflare traffic blocked"

# -- Reload UFW ----------------------------------------------
ufw --force reload
log "UFW reloaded"

# -- Create auto-update script --------------------------------
info "Creating Cloudflare IP auto-updater..."

cat > /usr/local/bin/update-cloudflare-ips << 'UPDATER'
#!/bin/bash
# Auto-update Cloudflare IPs weekly
CF_IPV4=$(curl -s https://www.cloudflare.com/ips-v4)
CF_IPV6=$(curl -s https://www.cloudflare.com/ips-v6)

if [[ -z "$CF_IPV4" ]]; then
    echo "Failed to fetch Cloudflare IPs" | logger -t cloudflare-ips
    exit 1
fi

# Remove old Cloudflare rules
ufw status numbered 2>/dev/null | grep "Cloudflare" | awk -F'[][]' '{print $2}' | sort -rn | while read num; do
    ufw --force delete "$num" 2>/dev/null || true
done

# Add new IPv4 rules
while IFS= read -r ip; do
    ip=$(echo "$ip" | tr -d '[:space:]')
    [[ -z "$ip" ]] && continue
    ufw allow from "$ip" to any port 80 proto tcp comment "Cloudflare IPv4 HTTP"
    ufw allow from "$ip" to any port 443 proto tcp comment "Cloudflare IPv4 HTTPS"
done <<< "$CF_IPV4"

# Add new IPv6 rules
if [[ -n "$CF_IPV6" ]]; then
    while IFS= read -r ip; do
        ip=$(echo "$ip" | tr -d '[:space:]')
        [[ -z "$ip" ]] && continue
        ufw allow from "$ip" to any port 80 proto tcp comment "Cloudflare IPv6 HTTP"
        ufw allow from "$ip" to any port 443 proto tcp comment "Cloudflare IPv6 HTTPS"
    done <<< "$CF_IPV6"
fi

ufw --force reload
echo "$(date): Updated Cloudflare IPs ($(echo "$CF_IPV4" | wc -l) v4, $(echo "$CF_IPV6" | wc -l) v6)" | logger -t cloudflare-ips
UPDATER

chmod +x /usr/local/bin/update-cloudflare-ips
log "Auto-updater created: /usr/local/bin/update-cloudflare-ips"

# -- Set up cron job for weekly updates ----------------------
cat > /etc/cron.d/cloudflare-ips-update << 'CRON'
0 4 * * 0 root /usr/local/bin/update-cloudflare-ips
CRON
chmod 644 /etc/cron.d/cloudflare-ips-update
log "Weekly cron job set (every Sunday at 4 AM)"

# -- Verify --------------------------------------------------
echo ""
echo -e "${BOLD}=== VERIFICATION ===${NC}"
echo ""

echo "Cloudflare IPv4 ranges allowed:"
ufw status | grep "Cloudflare IPv4" | head -5
echo "  ... ($(ufw status | grep -c "Cloudflare IPv4") total)"
echo ""

echo "Non-Cloudflare blocking rules:"
ufw status | grep "Block non-CF"
echo ""

echo -e "${BOLD}=== DONE ===${NC}"
echo ""
log "Cloudflare origin IP restriction is now active!"
echo ""
echo "What's protected:"
echo "  - Ports 80/443 only accept traffic from Cloudflare's network"
echo "  - Direct IP attacks are blocked at the firewall"
echo "  - IP ranges auto-update every Sunday at 4 AM"
echo ""
echo "To manually update IPs: sudo /usr/local/bin/update-cloudflare-ips"
echo "To check status: sudo ufw status | grep Cloudflare"
echo "To temporarily allow all traffic: sudo ufw delete deny in on eth0 to any port 80"
echo ""
