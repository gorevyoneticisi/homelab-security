#!/bin/bash
# ============================================================
# Docker Network Isolation Checker
# Verifies containers are properly isolated
# ============================================================
set -euo pipefail

GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'; BOLD='\033[1m'

echo -e "${BOLD}+==============================================+${NC}"
echo -e "${BOLD}|   DOCKER NETWORK ISOLATION CHECKER           |${NC}"
echo -e "${BOLD}+==============================================+${NC}"
echo ""

# -- Check each container's network --------------------------
echo -e "${BOLD}Container Network Membership:${NC}"
echo ""

docker ps --format '{{.Names}}' 2>/dev/null | while read container; do
    networks=$(docker inspect "$container" --format '{{range $k, $v := .NetworkSettings.Networks}}{{$k}} {{end}}' 2>/dev/null)
    ports=$(docker inspect "$container" --format '{{range $k, $v := .NetworkSettings.Ports}}{{$k}} {{end}}' 2>/dev/null)
    privileged=$(docker inspect "$container" --format '{{.HostConfig.Privileged}}' 2>/dev/null)
    init=$(docker inspect "$container" --format '{{.HostConfig.Init}}' 2>/dev/null)
    user=$(docker inspect "$container" --format '{{.Config.User}}' 2>/dev/null)

    echo -e "  ${BLUE}$container${NC}"
    echo -e "    Networks: $networks"

    if [[ -n "$ports" ]]; then
        echo -e "    Exposed: $ports"
    fi

    if [[ "$privileged" == "true" ]]; then
        echo -e "    ${RED}PRIVILEGED: YES (DANGER)${NC}"
    fi

    if [[ "$init" != "true" ]]; then
        echo -e "    ${YELLOW}Init: NOT SET${NC}"
    fi

    if [[ -z "$user" || "$user" == "root" || "$user" == "0" ]]; then
        echo -e "    ${YELLOW}Running as: root${NC}"
    fi

    echo ""
done

# -- Check for shared networks -------------------------------
echo -e "${BOLD}Network Isolation Analysis:${NC}"
echo ""

docker network ls --format '{{.Name}}' 2>/dev/null | grep -v "^bridge$\|^host$\|^none$" | while read net; do
    containers=$(docker network inspect "$net" --format '{{range .Containers}}{{.Name}} {{end}}' 2>/dev/null)
    count=$(echo "$containers" | wc -w)

    if [[ $count -gt 1 ]]; then
        echo -e "  ${YELLOW}$net${NC} ($count containers)"
        echo "    Containers: $containers"

        # Check if sensitive services share networks
        for c in $containers; do
            case "$c" in
                *postgres*|*mysql*|*redis*|*mongo*)
                    echo -e "    ${RED}WARNING: Database on shared network!${NC}"
                    ;;
            esac
        done
    fi
done

# -- Check for direct internet exposure ----------------------
echo ""
echo -e "${BOLD}Internet Exposure:${NC}"
echo ""

docker ps --format '{{.Names}} {{.Ports}}' 2>/dev/null | grep "0.0.0.0" | while read name ports; do
    echo -e "  ${YELLOW}$name${NC}: $ports"
done

echo ""
echo -e "${BOLD}Recommendations:${NC}"
echo "  1. Databases should NOT be on the default bridge network"
echo "  2. Internal services should bind to 127.0.0.1 or Docker network only"
echo "  3. Use Nginx Proxy Manager as the sole public entry point"
echo "  4. All containers should have init:true and no-new-privileges"
echo ""
