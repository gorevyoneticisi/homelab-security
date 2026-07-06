#!/bin/bash
# ============================================================
# WireGuard VPN Setup for Homelab
# Secure remote access without exposing services publicly
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
echo -e "${BOLD}|   WIREGUARD VPN SETUP                        |${NC}"
echo -e "${BOLD}+==============================================+${NC}"
echo ""
info "WireGuard creates a secure VPN tunnel to your homelab."
info "You can access all services from anywhere without exposing them publicly."
echo ""
echo "Benefits:"
echo "  - Encrypt all traffic between your devices and homelab"
echo "  - Access services by internal IP (e.g., 10.0.0.2:4001)"
echo "  - No port forwarding needed on your router"
echo "  - Works behind NAT/firewalls"
echo ""
read -p "Continue? (y/N): " -n 1 -r
echo ""
[[ $REPLY =~ ^[Yy]$ ]] || exit 0

# -- Install WireGuard ---------------------------------------
info "Installing WireGuard..."

if ! command -v wg &>/dev/null; then
    apt-get update -qq && apt-get install -y -qq wireguard wireguard-tools
fi

log "WireGuard installed"

# -- Generate keys --------------------------------------------
info "Generating server keys..."

WG_DIR="/etc/wireguard"
mkdir -p "$WG_DIR"

if [[ ! -f "$WG_DIR/server_private.key" ]]; then
    umask 077
    wg genkey | tee "$WG_DIR/server_private.key" | wg pubkey > "$WG_DIR/server_public.key"
    log "Server keys generated"
else
    log "Server keys already exist"
fi

SERVER_PRIV=$(cat "$WG_DIR/server_private.key")
SERVER_PUB=$(cat "$WG_DIR/server_public.key")

# -- Get network info ----------------------------------------
info "Detecting network configuration..."

# Get default interface
DEFAULT_IF=$(ip route | awk '/default/ { print $5 }')
info "Default interface: $DEFAULT_IF"

# Get public IP
PUBLIC_IP=$(curl -s ifconfig.me 2>/dev/null || curl -s icanhazip.com 2>/dev/null)
info "Public IP: $PUBLIC_IP"

# -- Configure server ----------------------------------------
info "Configuring WireGuard server..."

cat > "$WG_DIR/wg0.conf" << WGC
[Interface]
PrivateKey = $SERVER_PRIV
Address = 10.0.0.1/24
ListenPort = 51820
PostUp = iptables -A FORWARD -i wg0 -j ACCEPT; iptables -t nat -A POSTROUTING -o $DEFAULT_IF -j MASQUERADE
PostDown = iptables -D FORWARD -i wg0 -j ACCEPT; iptables -t nat -D POSTROUTING -o $DEFAULT_IF -j MASQUERADE

# Client 1 (add more [Peer] sections for additional clients)
# [Peer]
# PublicKey = <client_public_key>
# AllowedIPs = 10.0.0.2/32
WGC

chmod 600 "$WG_DIR/wg0.conf"
log "Server configuration created"

# -- Enable IP forwarding ------------------------------------
info "Enabling IP forwarding..."

echo "net.ipv4.ip_forward=1" > /etc/sysctl.d/99-wireguard.conf
sysctl -p /etc/sysctl.d/99-wireguard.conf > /dev/null 2>&1
log "IP forwarding enabled"

# -- Start WireGuard -----------------------------------------
info "Starting WireGuard..."

systemctl enable wg-quick@wg0
systemctl start wg-quick@wg0
log "WireGuard started"

# -- Generate client config ----------------------------------
info "Generating client configuration..."

CLIENT_PRIV=$(wg genkey)
CLIENT_PUB=$(echo "$CLIENT_PRIV" | wg pubkey)
CLIENT_PRESHARED=$(wg genpsk)

cat > "$WG_DIR/client1.conf" << CLIENT
[Interface]
PrivateKey = $CLIENT_PRIV
Address = 10.0.0.2/24
DNS = 1.1.1.1

[Peer]
PublicKey = $SERVER_PUB
PresharedKey = $CLIENT_PRESHARED
Endpoint = $PUBLIC_IP:51820
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
CLIENT

chmod 600 "$WG_DIR/client1.conf"

# Add client to server config
cat >> "$WG_DIR/wg0.conf" << PEER

[Peer]
PublicKey = $CLIENT_PUB
PresharedKey = $CLIENT_PRESHARED
AllowedIPs = 10.0.0.2/32
PEER

# Restart to load new peer
systemctl restart wg-quick@wg0

log "Client configuration created: $WG_DIR/client1.conf"

# -- Create QR code ------------------------------------------
if command -v qrencode &>/dev/null; then
    info "Generating QR code for mobile..."
    qrencode -t ansiutf8 < "$WG_DIR/client1.conf"
    echo ""
    qrencode -o "$WG_DIR/client1-qr.png" < "$WG_DIR/client1.conf"
    log "QR code saved: $WG_DIR/client1-qr.png"
else
    warn "qrencode not installed - install with 'apt install qrencode' for QR codes"
fi

# -- Summary -------------------------------------------------
echo ""
echo -e "${BOLD}=== WIREGUARD SETUP COMPLETE ===${NC}"
echo ""
echo "Server:"
echo "  Public IP: $PUBLIC_IP"
echo "  Port: 51820/UDP"
echo "  Server Public Key: $SERVER_PUB"
echo "  VPN Subnet: 10.0.0.0/24"
echo ""
echo "Client Config:"
echo "  File: $WG_DIR/client1.conf"
echo "  VPN IP: 10.0.0.2"
echo ""
echo "To connect:"
echo "  1. Install WireGuard on your device"
echo "  2. Import client1.conf (or scan QR code)"
echo "  3. Connect to the VPN"
echo "  4. Access services via 10.0.0.x"
echo ""
echo "To add more clients:"
echo "  1. Generate keys: wg genkey | tee clientN.key | wg pubkey > clientN.pub"
echo "  2. Add [Peer] section to server config"
echo "  3. Create client config with the new keys"
echo ""
echo "Firewall:"
ufw allow 51820/udp comment 'WireGuard VPN'
log "UFW rule added for WireGuard port"
echo ""
