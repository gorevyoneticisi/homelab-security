# Homelab Security Suite

A set of bash scripts for hardening Docker-based homelabs. Designed for systems behind CGNAT with a VPS reverse proxy.

## Architecture

```
Internet -> VPS (public IP) -> WireGuard -> Homelab (CGNAT)
```

## Requirements

- Ubuntu 20.04+ or Debian 11+
- Docker installed
- Root access (sudo)

## Quick Start

```bash
git clone https://github.com/gorevyoneticisi/homelab-security.git
cd homelab-security
sudo bash setup.sh
```

## Scripts

### setup.sh

Main menu with 10 options. Entry point for all tools.

### security-scan.sh

Comprehensive read-only security scanner. Checks 13 categories and assigns severity levels:

- Network exposure (public ports, VPN status)
- Firewall rules (UFW, iptables)
- SSH configuration (port, root login, password auth, key auth)
- Intrusion detection (CrowdSec, fail2ban)
- Docker security (privileged containers, init, resource limits)
- Kernel version and pending updates
- User accounts and authentication
- File integrity monitoring (AIDE, rkhunter)
- Antivirus (ClamAV)
- Automatic security updates
- Cron job analysis
- Docker network isolation
- SSL/TLS certificate status

Outputs findings as CRITICAL, HIGH, MEDIUM, or LOW. Labels each finding as auto-patchable or requiring manual action. Asks the user what to fix.

### scan.sh

Lighter interactive scanner. Checks the same categories with warnings and recommendations. Provides fix suggestions for each finding.

### scan-only.sh

Read-only scanner that produces a security score out of 100. No changes made to the system.

### hardening.sh

One-click homelab hardening. Applies 10 security layers:

1. UFW firewall (deny all, allow SSH/HTTP/HTTPS/WireGuard)
2. fail2ban with SSH and Nginx jails
3. SSH hardening (disable root login, disable password auth, custom port)
4. CrowdSec verification
5. Docker Content Trust
6. ClamAV scheduled weekly scans
7. AIDE file integrity database initialization
8. Docker container hardening (init, no-new-privileges)
9. Automatic security updates via unattended-upgrades
10. Slack/Telegram notification setup

Prompts for optional tokens: Cloudflare API token, Slack/Telegram webhook URL, Authentik URL, domain name.

### harden-vps.sh

VPS-specific hardening for the public-facing server:

- System package updates
- UFW firewall (deny all, allow SSH/HTTP/HTTPS/WireGuard)
- SSH hardening (prohibit-password root login, disable password auth)
- fail2ban with SSH and Nginx jails
- Kernel parameter hardening (SYN flood protection, ICMP hardening, source routing disabled)
- Automatic security updates

### cloudflare-ips.sh

Restricts HTTP/HTTPS traffic to Cloudflare IP ranges only:

- Fetches current Cloudflare IPv4 and IPv6 ranges
- Creates UFW rules allowing only Cloudflare on ports 80 and 443
- Blocks all other traffic to those ports
- Sets up weekly auto-update via cron (every Sunday at 4 AM)
- Backup script at /usr/local/bin/update-cloudflare-ips

### setup-vpn.sh

WireGuard VPN setup:

- Generates server and client key pairs
- Configures server with IP forwarding and NAT
- Creates client configuration with QR code for mobile
- Adds UFW rule for WireGuard port 51820
- Outputs connection instructions

### check-docker-networks.sh

Docker network isolation checker. Reports:

- Each container's network membership
- Exposed ports
- Privileged containers (critical finding)
- Containers running as root
- Containers without init:true
- Shared network analysis
- Internet exposure summary

### compliance-report.sh

Generates a detailed text compliance report covering all 11 security categories. Saves to reports/compliance-TIMESTAMP.txt. Suitable for audit trails or attaching to support tickets.

### restore.sh

Rollback script. Lists available backups and restores:

- SSH configuration from backup
- UFW disable option
- fail2ban stop option

## What the Scanner Checks

| Category | What It Finds |
|----------|---------------|
| Network | Public ports, VPN status, Cloudflare tunnel, dangerous services (FTP, SMB, VNC, RDP) |
| Firewall | UFW status, iptables rules, Docker firewall chain |
| SSH | Port, root login, password auth, key auth, max tries, idle timeout, login grace time |
| Intrusion Detection | CrowdSec engine/bouncers, fail2ban status/jails |
| Docker | Content trust, privileged containers, init, no-new-privileges, root user, memory limits |
| Kernel | Version, pending updates, SUID binaries, world-writable files, unowned files |
| Users | Shell access, empty passwords, failed login attempts |
| File Integrity | AIDE, rkhunter |
| Antivirus | ClamAV installation and daemon |
| Updates | Unattended security upgrades |
| Cron | Suspicious entries (curl, wget, nc, bash -i, /dev/tcp) |
| Docker Networks | Isolation, default bridge usage |
| SSL/TLS | Certificate expiry on HTTPS ports |

## Token Configuration

The hardening script prompts for optional tokens. These are used for integration and notifications:

- **Cloudflare API Token** -- for Cloudflare bouncer integration with CrowdSec
- **Slack Webhook URL** -- for sending security alerts to Slack
- **Telegram Bot Token and Chat ID** -- for sending security alerts to Telegram
- **Authentik URL** -- for forward authentication setup
- **Domain Name** -- for SSL certificate configuration
- **Admin Email** -- for receiving security notifications

## Network Context

This suite is designed for homelabs running behind CGNAT (Carrier-Grade NAT) on residential ISPs. The typical architecture is:

- **Homelab** -- runs on a local machine with no public IP (behind CGNAT)
- **VPS** -- has a public IP, acts as the reverse proxy
- **WireGuard** -- encrypted tunnel between VPS and homelab

Traffic flows: Internet -> VPS (public IP) -> WireGuard tunnel -> Homelab (private network)

The VPS is the actual attack surface. The harden-vps.sh script specifically targets VPS security. The homelab itself is protected by being behind the CGNAT and WireGuard tunnel.

## License

MIT License. See LICENSE file for details.
