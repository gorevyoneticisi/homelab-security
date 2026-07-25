# Security Layers Overview

Complete defense-in-depth strategy for homelab security.

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        ATTACK SURFACE                          │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  Layer 1: Cloudflare                                           │
│  ├── WAF Custom Rules (path blocking)                         │
│  ├── Bot Fight Mode (ML-based detection)                      │
│  ├── DDoS Protection                                           │
│  └── TLS Termination                                           │
│                                                                 │
│  Layer 2: CrowdSec                                             │
│  ├── Rate-Limiting Scenarios                                   │
│  ├── CVE Detection                                            │
│  ├── SSH Brute Force Protection                               │
│  ├── Cloudflare Bouncer (IP blocking at CF edge)              │
│  └── Firewall Bouncer (iptables blocking)                     │
│                                                                 │
│  Layer 3: iptables                                             │
│  ├── Service Restriction (SMB, CUPS, MQTT)                    │
│  ├── Datacenter IP Blocking                                   │
│  ├── Manual Bans                                              │
│  └── Docker DOCKER-USER Chain                                 │
│                                                                 │
│  Layer 4: Application                                          │
│  ├── IP Ban Middleware (3h bans)                              │
│  ├── CSRF Protection                                          │
│  ├── Bot User-Agent Detection                                 │
│  └── Exploit Path Detection                                   │
│                                                                 │
│  Layer 5: Network                                              │
│  ├── CGNAT (no public IP)                                     │
│  ├── WireGuard VPN                                            │
│  └── Tailscale                                                 │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

## Layer Details

### Layer 1: Cloudflare (Edge Protection)

**What it does:** Blocks attacks before they reach your server.

| Feature | Free Tier | Paid Tier |
|---------|-----------|-----------|
| WAF Custom Rules | 5 rules | Unlimited |
| Bot Fight Mode | Basic | Advanced |
| DDoS Protection | Yes | Yes |
| Rate Limiting | No | Yes |
| SSL/TLS | Yes | Yes |

**Setup:** See `01-cloudflare-waf-setup.md`

### Layer 2: CrowdSec (Intelligence-Based Protection)

**What it does:** Detects attacks using log analysis and community threat intelligence.

| Feature | Description |
|---------|-------------|
| Rate-Limiting | Ban IPs exceeding request thresholds |
| CVE Detection | Block known vulnerability exploits |
| SSH Protection | Detect brute force attempts |
| Community Intel | 31K+ known bad IPs |
| Cloudflare Bouncer | Block at Cloudflare edge |

**Setup:** See `02-crowdsec-rate-limiting.md`

### Layer 3: iptables (System-Level Protection)

**What it does:** Kernel-level packet filtering for services not behind Cloudflare.

| Feature | Description |
|---------|-------------|
| Service Restriction | Limit access to LAN/VPN only |
| Datacenter Blocking | Ban cloud provider IPs |
| Manual Bans | Block specific IPs |
| Docker Integration | Control container network access |

**Setup:** See `04-firewall-service-restriction.md`

### Layer 4: Application (Code-Level Protection)

**What it does:** Protects against attacks that bypass network layers.

| Feature | Description |
|---------|-------------|
| IP Ban Middleware | 3h bans for violations |
| CSRF Protection | Prevent cross-site request forgery |
| Bot Detection | Block known bot user-agents |
| Exploit Detection | Block known attack paths |

**Setup:** Integrated into application code.

### Layer 5: Network (Infrastructure Protection)

**What it does:** Limits attack surface through network architecture.

| Feature | Description |
|---------|-------------|
| CGNAT | No public IP on homelab |
| WireGuard | Encrypted tunnel to VPS |
| Tailscale | Mesh VPN for remote access |

## Ban Decision Matrix

| IP Type | CrowdSec Trigger | iptables Ban | App Ban | Total Ban |
|---------|------------------|--------------|---------|-----------|
| Residential | 10 req/60s | Manual | 5 violations | 1h-24h |
| Datacenter | 5 req/30s | Auto (5 violations) | Auto (1 violation) | 24h-7d |
| Proxy/VPN | 5 req/30s | Auto (3 violations) | Auto (1 violation) | 24h |
| Known Bad | Any | Immediate | Immediate | 7d |

## Monitoring Commands

```bash
# Check all layers
sudo cscli decisions list --limit 20        # CrowdSec bans
sudo iptables -S | grep DROP                # iptables rules
cat /var/lib/smart-ip-classifier/classified-ips.json | jq .  # IP classifications
docker logs app-container --tail 50         # App-level bans

# Check system health
docker ps --format "{{.Names}} | {{.Status}}"
curl -s -o /dev/null -w "%{http_code}" https://yourdomain.com/
```

## Emergency Procedures

### Block All Traffic (DDoS)

```bash
# Block everything except SSH and WireGuard
sudo iptables -I INPUT -p tcp --dport 80 -j DROP
sudo iptables -I INPUT -p tcp --dport 443 -j DROP
```

### Unblock an IP

```bash
# Remove from CrowdSec
sudo cscli decisions delete --ip X.X.X.X

# Remove from iptables
sudo iptables -D INPUT -s X.X.X.X -j DROP

# Remove from app bans
# Edit app ban file and remove the IP entry
```

### Emergency Flush All Rules

```bash
# WARNING: This removes ALL iptables rules
sudo iptables -F
sudo iptables -X
sudo iptables -P INPUT ACCEPT
sudo iptables -P FORWARD ACCEPT
sudo iptables -P OUTPUT ACCEPT
```
