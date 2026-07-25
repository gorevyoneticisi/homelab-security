# Smart IP Blocking Guide

Intelligent IP classification and banning system that combines CrowdSec rate-limiting with IP intelligence for smart ban decisions.

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    Smart IP Blocking                     │
├─────────────────────────────────────────────────────────┤
│                                                         │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐    │
│  │ CrowdSec    │  │ ip-api.com  │  │ iptables    │    │
│  │ Rate-Limit  │→ │ GeoIP       │→ │ System Bans │    │
│  │ Scenarios   │  │ Classifier  │  │             │    │
│  └─────────────┘  └─────────────┘  └─────────────┘    │
│         ↓                ↓                ↓             │
│  ┌─────────────────────────────────────────────────┐   │
│  │              Ban Decision Engine                 │   │
│  │  • Residential: 1h after 10 violations          │   │
│  │  • Datacenter: 24h after 5 violations           │   │
│  │  • Proxy/VPN: 24h after 3 violations            │   │
│  │  • Known bad: Auto-ban 24h                      │   │
│  └─────────────────────────────────────────────────┘   │
│                                                         │
└─────────────────────────────────────────────────────────┘
```

## Components

### 1. Smart IP Classifier Script

File: `scripts/smart-ip-classifier.sh`

Runs every 30 minutes via cron. Classifies IPs using ip-api.com:

```bash
# Check IP classification
GEO=$(curl -s "http://ip-api.com/json/$IP?fields=status,isp,org,as,hosting,proxy")
```

**Classification logic:**
- `hosting: true` → Datacenter IP
- `proxy: true` → Proxy/VPN IP
- Otherwise → Residential IP

**Ban thresholds:**

| IP Type | Violations Before Ban | Ban Duration |
|---------|----------------------|--------------|
| Residential | 10 | 1 hour |
| Datacenter | 5 | 24 hours |
| Proxy/VPN | 3 | 24 hours |
| Known bad (Azure, AWS, etc.) | 1 | 24 hours |

### 2. AI Scraper Blocker

File: `scripts/block-ai-scrapers.sh`

Runs every 6 hours. Blocks known AI scraper user agents:

```
GPTBot|ChatGPT-User|CCBot|Bytespider|Google-Extended|
anthropic-ai|ClaudeBot|FacebookBot|meta-externalagent|
PerplexityBot|YouBot|Timpibot|Diffbot
```

### 3. Datacenter IP Blocker

File: `scripts/block-datacenter-ips.sh`

Runs every 12 hours. Checks all IPs from last 24h of access logs against ip-api.com and bans datacenter IPs for 7 days.

## Installation

```bash
# Copy scripts
sudo cp scripts/smart-ip-classifier.sh /usr/local/bin/
sudo cp scripts/block-ai-scrapers.sh /usr/local/bin/
sudo cp scripts/block-datacenter-ips.sh /usr/local/bin/

# Make executable
sudo chmod +x /usr/local/bin/smart-ip-classifier.sh
sudo chmod +x /usr/local/bin/block-ai-scrapers.sh
sudo chmod +x /usr/local/bin/block-datacenter-ips.sh

# Install cron jobs
(crontab -l 2>/dev/null; echo "*/30 * * * * /usr/local/bin/smart-ip-classifier.sh") | crontab -
(crontab -l 2>/dev/null; echo "0 */6 * * * /usr/local/bin/block-ai-scrapers.sh") | crontab -
(crontab -l 2>/dev/null; echo "0 */12 * * * /usr/local/bin/block-datacenter-ips.sh") | crontab -
```

## IP Intelligence Sources

### ip-api.com (Free)

- **Rate limit:** 45 requests/minute
- **Data provided:** ISP, organization, AS number, hosting status, proxy detection
- **No API key required** for non-commercial use

### CrowdSec CTI API (Free Tier)

- **Rate limit:** 120 lookups/month (community), 1,500/month (premium)
- **Data provided:** Threat scores, classifications, behaviors, MITRE ATT&CK mapping
- **API key required:** Get from https://app.crowdsec.net

### MaxMind GeoLite2 (Free)

- **Rate limit:** Unlimited (local database)
- **Data provided:** Country, ASN, connection type
- **Requires registration:** https://www.maxmind.com/en/geolite2/signup

## Manual IP Management

```bash
# Ban an IP for 24 hours
sudo cscli decisions add --ip X.X.X.X --duration 24h --reason "Manual ban"

# Ban an IP for 7 days
sudo iptables -I INPUT -s X.X.X.X -j DROP

# Check current bans
sudo cscli decisions list --limit 20

# Check iptables rules
sudo iptables -S | grep DROP

# Remove a ban
sudo cscli decisions delete --ip X.X.X.X
sudo iptables -D INPUT -s X.X.X.X -j DROP
```

## Monitoring

```bash
# Check smart classifier logs
tail -f /var/log/smart-bans.log

# Check classified IPs
cat /var/lib/smart-ip-classifier/classified-ips.json | jq .

# Check violation counts
cat /var/lib/smart-ip-classifier/ip-violations.json | jq .

# Check CrowdSec alerts
sudo cscli alerts list --limit 20
```

## Resource Usage

- **ip-api.com:** 45 req/min free tier, ~1 req/sec in scripts
- **CrowdSec:** ~100MB RAM, minimal CPU
- **iptables:** Kernel-level, negligible overhead
- **Script execution:** ~30 seconds every 30 minutes

Total system impact: < 1% CPU, < 50MB additional RAM.
