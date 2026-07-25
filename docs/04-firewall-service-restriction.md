# Firewall Service Restriction Guide

Guide for restricting service access to specific network interfaces (LAN, Tailscale, WireGuard).

## Overview

By default, Docker containers bind to `0.0.0.0` (all interfaces), making services accessible from any network. This guide restricts services to only trusted networks.

## Network Interfaces

Identify your network interfaces:

```bash
ip addr show | grep -E "inet |^[0-9]+:"
```

Typical interfaces:

| Interface | Subnet | Purpose |
|-----------|--------|---------|
| `eth0` | 192.168.1.0/24 | LAN (ethernet) |
| `tailscale0` | 100.x.x.x/32 | Tailscale VPN |
| `wg0` | YOUR_WG_SUBNET/24 | WireGuard VPN |
| `docker0` | 172.17.0.0/16 | Docker bridge |

## Restricting Services with iptables

### SMB (Ports 139/445)

**Risk:** EternalBlue, WannaCry, ransomware, remote code execution

```bash
# Allow from LAN, Tailscale, WireGuard
sudo iptables -I INPUT -p tcp -m multiport --dports 139,445 -s 192.168.1.0/24 -j ACCEPT
sudo iptables -I INPUT -p tcp -m multiport --dports 139,445 -s YOUR_TAILSCALE_IP/32 -j ACCEPT
sudo iptables -I INPUT -p tcp -m multiport --dports 139,445 -s YOUR_WG_SUBNET/24 -j ACCEPT

# Block all other traffic to SMB
sudo iptables -A INPUT -p tcp -m multiport --dports 139,445 -j DROP
```

### CUPS (Port 631)

**Risk:** CVE-2024-47176 (CUPS IPP arbitrary), remote code execution

```bash
# Allow from LAN and Tailscale
sudo iptables -I INPUT -p tcp --dport 631 -s 192.168.1.0/24 -j ACCEPT
sudo iptables -I INPUT -p tcp --dport 631 -s YOUR_TAILSCALE_IP/32 -j ACCEPT

# Block all other traffic to CUPS
sudo iptables -A INPUT -p tcp --dport 631 -j DROP
```

### MQTT (Ports 1883/9001)

**Risk:** Unauthorized IoT access, data exfiltration, device control

```bash
# Allow from LAN, Tailscale, Docker
sudo iptables -I INPUT -p tcp -m multiport --dports 1883,9001 -s 192.168.1.0/24 -j ACCEPT
sudo iptables -I INPUT -p tcp -m multiport --dports 1883,9001 -s YOUR_TAILSCALE_IP/32 -j ACCEPT
sudo iptables -I INPUT -p tcp -m multiport --dports 1883,9001 -s 172.17.0.0/16 -j ACCEPT

# Block all other traffic to MQTT
sudo iptables -A INPUT -p tcp -m multiport --dports 1883,9001 -j DROP
```

### FlareSolverr (Port 8191)

**Risk:** SSRF, Cloudflare bypass

```bash
# Allow from LAN, Tailscale, Docker
sudo iptables -I INPUT -p tcp --dport 8191 -s 192.168.1.0/24 -j ACCEPT
sudo iptables -I INPUT -p tcp --dport 8191 -s YOUR_TAILSCALE_IP/32 -j ACCEPT
sudo iptables -I INPUT -p tcp --dport 8191 -s 172.17.0.0/16 -j ACCEPT

# Block all other traffic
sudo iptables -A INPUT -p tcp --dport 8191 -j DROP
```

### Duplicati (Port 8200) — Localhost Only

**Risk:** Backup data exposure, ransomware target

```bash
# Allow from localhost only
sudo iptables -I INPUT -p tcp --dport 8200 -s 127.0.0.0/8 -j ACCEPT

# Block all other traffic
sudo iptables -A INPUT -p tcp --dport 8200 -j DROP
```

**Note:** Google Drive backup is outbound traffic, so localhost-only binding doesn't break it.

## Docker-Specific Restrictions

For Docker containers, you may need to add rules in the `DOCKER-USER` chain:

```bash
# Block external access to Duplicati
sudo iptables -I DOCKER-USER 1 -s 127.0.0.0/8 -p tcp --dport 8200 -j RETURN
sudo iptables -I DOCKER-USER 2 -p tcp --dport 8200 -j DROP
```

## Persisting Rules

```bash
# Save rules
sudo iptables-save > /etc/iptables/rules.v4

# Restore on boot
sudo apt-get install iptables-persistent
sudo netfilter-persistent save
```

## Verification

```bash
# Test from LAN (should work)
nc -z -w2 192.168.1.100 445 && echo "SMB: OPEN" || echo "SMB: BLOCKED"

# Test from localhost (should work for localhost-only services)
nc -z -w2 127.0.0.1 8200 && echo "Duplicati: OPEN" || echo "Duplicati: BLOCKED"
```

## Alternative: Bind to Localhost in Docker Compose

Instead of iptables, you can bind Docker services to localhost only:

```yaml
ports:
  - "127.0.0.1:8200:8200"  # Localhost only
  # Instead of:
  # - "8200:8200"            # All interfaces
```

**Pros:** Simpler, survives iptables flushes
**Cons:** Requires recreating containers
