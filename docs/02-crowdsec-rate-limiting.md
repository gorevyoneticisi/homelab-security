# CrowdSec Rate-Limiting Guide

Custom CrowdSec scenarios for rate-limit based banning with IP intelligence.

## Overview

CrowdSec detects attacks by analyzing logs and matching patterns against scenarios. Rate-limiting scenarios track request frequency per IP and ban when thresholds are exceeded.

## Architecture

```
Internet → Cloudflare (WAF + Bot Fight Mode)
  → CrowdSec (rate-limiting + IP intelligence)
    → iptables (system-level bans)
      → App-level bans (optional)
```

## Custom Rate-Limit Scenarios

### Scenario 1: 10+ Requests in 60 Seconds

File: `/etc/crowdsec/scenarios/custom-rate-limit.yaml`

```yaml
type: leaky
name: yourname/rate-limit-60s
description: "Detect IPs making 10+ requests in 60 seconds"
filter: "evt.Meta.log_type == 'http_access_log'"
leakspeed: 6s
capacity: 9
groupby: "evt.Meta.source_ip"
blackhole: 5m
labels:
  confidence: 1
  spoofable: 0
  classification:
    - attack.T1595
  behavior: "http:rate-limit"
  service: http
  label: "Rate Limit Exceeded"
  remediation: true
```

**How it works:**
- `type: leaky` — Leaky bucket algorithm (memory-efficient for high volume)
- `capacity: 9` — Bucket holds 9 events
- `leakspeed: 6s` — One event leaks every 6 seconds
- After 60 seconds with 10+ requests, bucket overflows → ban
- `blackhole: 5m` — Prevents duplicate alerts for same IP
- `remediation: true` — Automatically bans the IP

### Scenario 2: 5+ Requests in 30 Seconds (Aggressive Scanner)

File: `/etc/crowdsec/scenarios/custom-aggressive-scanner.yaml`

```yaml
type: leaky
name: yourname/aggressive-scanner
description: "Detect aggressive scanners - 5+ requests in 30 seconds"
filter: "evt.Meta.log_type == 'http_access_log'"
leakspeed: 6s
capacity: 4
groupby: "evt.Meta.source_ip"
blackhole: 5m
labels:
  confidence: 1
  spoofable: 0
  classification:
    - attack.T1595
  behavior: "http:scanner"
  service: http
  label: "Aggressive Scanner"
  remediation: true
```

**How it works:**
- `capacity: 4` — Bucket holds 4 events
- After 30 seconds with 5+ requests → ban
- Catches fast scanners that probe multiple paths quickly

## Installation

```bash
# Copy scenarios to CrowdSec
sudo cp custom-rate-limit.yaml /etc/crowdsec/scenarios/
sudo cp custom-aggressive-scanner.yaml /etc/crowdsec/scenarios/

# Restart CrowdSec
sudo systemctl restart crowdsec

# Verify scenarios are loaded
sudo cscli scenarios list | grep yourname
```

## Tuning

### Adjust Thresholds

Based on your traffic patterns:

| Traffic Level | Rate-Limit Scenario | Aggressive Scanner |
|---------------|--------------------|--------------------|
| Low (< 100 req/min) | 10 req/60s | 5 req/30s |
| Medium (100-1000 req/min) | 20 req/60s | 10 req/30s |
| High (> 1000 req/min) | 50 req/60s | 20 req/30s |

### Whitelist Legitimate IPs

If legitimate services (monitoring, search engines) trigger false positives:

```bash
# Add to CrowdSec allowlist
sudo cscli decisions add --ip X.X.X.X --duration 1h --type whitelist
```

## Built-in Scenarios to Enable

CrowdSec has 75+ built-in scenarios. Key ones for web apps:

```bash
# HTTP attack detection
sudo cscli scenarios enable crowdsecurity/http-crawl-non_statics
sudo cscli scenarios enable crowdsecurity/http-bad-user-agent
sudo cscli scenarios enable crowdsecurity/http-probing
sudo cscli scenarios enable crowdsecurity/http-sensitive-files
sudo cscli scenarios enable crowdsecurity/http-wordpress-scan

# SSH protection
sudo cscli scenarios enable crowdsecurity/ssh-bf
sudo cscli scenarios enable crowdsecurity/ssh-slow-bf

# CVE detection
sudo cscli scenarios enable crowdsecurity/CVE-2021-41773
sudo cscli scenarios enable crowdsecurity/CVE-2021-42013
```

## Monitoring

```bash
# View recent alerts
sudo cscli alerts list --limit 20

# View current bans
sudo cscli decisions list --limit 20

# View metrics
sudo cscli metrics
```
