#!/bin/bash
# ============================================================
# Homelab Security Suite - Main Entry Point v2.0
# ============================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

echo ""
echo -e "\033[1m+==========================================================+\033[0m"
echo -e "\033[1m|          HOMELAB SECURITY SUITE v2.0                     |\033[0m"
echo -e "\033[1m|          One-click security for Docker homelabs          |\033[0m"
echo -e "\033[1m+==========================================================+\033[0m"
echo ""
echo "Choose an option:"
echo ""
echo "  -- SCAN --------------------------------------"
echo "  1) security Scan (comprehensive, all vulnerabilities)"
echo "  2) Quick Scan (fast overview)"
echo "  3) Docker Network Isolation Check"
echo ""
echo "  -- HARDEN ------------------------------------"
echo "  4) Full Homelab Hardening"
echo "  5) VPS Hardening (your public attack surface)"
echo "  6) Cloudflare IP Restriction (80/443 only)"
echo "  7) Setup WireGuard VPN"
echo ""
echo "  -- REPORT ------------------------------------"
echo "  8) Generate Compliance Report"
echo "  9) View Latest Report"
echo ""
echo "  -- RECOVERY ----------------------------------"
echo "  10) Rollback (restore pre-hardening state)"
echo ""
read -p "Enter choice [1-10]: " -n 2 -r
echo ""

case $REPLY in
    1) sudo bash "$SCRIPT_DIR/scripts/security-scan.sh" ;;
    2) bash "$SCRIPT_DIR/scripts/scan.sh" ;;
    3) bash "$SCRIPT_DIR/scripts/check-docker-networks.sh" ;;
    4) bash "$SCRIPT_DIR/scripts/hardening.sh" ;;
    5) bash "$SCRIPT_DIR/scripts/harden-vps.sh" ;;
    6) bash "$SCRIPT_DIR/scripts/cloudflare-ips.sh" ;;
    7) bash "$SCRIPT_DIR/scripts/setup-vpn.sh" ;;
    8) bash "$SCRIPT_DIR/scripts/compliance-report.sh" ;;
    9) ls -t "$SCRIPT_DIR"/reports/compliance-*.txt 2>/dev/null | head -1 | xargs cat 2>/dev/null || echo "No report found. Run option 8 first." ;;
    10) bash "$SCRIPT_DIR/scripts/restore.sh" ;;
    *) echo "Invalid choice" ;;
esac
