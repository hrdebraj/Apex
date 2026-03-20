#!/usr/bin/env bash
#
# Apex C2 Framework — Quick Setup
#
# This script starts PostgreSQL + Redis via Docker/Podman,
# waits for them to be healthy, and launches the team server.
#
# Usage:
#   chmod +x setup.sh
#   ./setup.sh              # Start databases + team server
#   ./setup.sh --db-only    # Start databases only
#   ./setup.sh --stop       # Stop databases
#

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
COMPOSE_FILE="$SCRIPT_DIR/docker-compose.yml"
CONFIG_FILE="$SCRIPT_DIR/config.yaml"
TEAMSERVER="$SCRIPT_DIR/teamserver"

RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
NC='\033[0m'

banner() {
    echo -e "${CYAN}"
    echo '    █████╗ ██████╗ ███████╗██╗  ██╗'
    echo '   ██╔══██╗██╔══██╗██╔════╝╚██╗██╔╝'
    echo '   ███████║██████╔╝█████╗   ╚███╔╝ '
    echo '   ██╔══██║██╔═══╝ ██╔══╝   ██╔██╗ '
    echo '   ██║  ██║██║     ███████╗██╔╝ ██╗'
    echo '   ╚═╝  ╚═╝╚═╝     ╚══════╝╚═╝  ╚═╝'
    echo ''
    echo '       C O M M A N D  &  C O N T R O L'
    echo -e "${NC}"
}

compose_cmd() {
    if command -v docker &>/dev/null; then
        docker compose "$@"
    elif command -v podman &>/dev/null; then
        podman compose "$@"
    else
        echo -e "${RED}Error: neither docker nor podman found.${NC}"
        echo "Install Docker: https://docs.docker.com/engine/install/"
        exit 1
    fi
}

start_db() {
    echo -e "${CYAN}[*] Starting PostgreSQL + Redis...${NC}"
    compose_cmd -f "$COMPOSE_FILE" up -d

    echo -e "${CYAN}[*] Waiting for databases to be healthy...${NC}"
    for i in $(seq 1 30); do
        pg_ok=$(docker inspect --format='{{.State.Health.Status}}' apex-postgres 2>/dev/null || echo "waiting")
        redis_ok=$(docker inspect --format='{{.State.Health.Status}}' apex-redis 2>/dev/null || echo "waiting")
        if [ "$pg_ok" = "healthy" ] && [ "$redis_ok" = "healthy" ]; then
            echo -e "${GREEN}[+] PostgreSQL: healthy${NC}"
            echo -e "${GREEN}[+] Redis: healthy${NC}"
            return 0
        fi
        sleep 1
    done
    echo -e "${YELLOW}[!] Timeout waiting for databases. Check: docker ps${NC}"
    return 1
}

stop_db() {
    echo -e "${CYAN}[*] Stopping databases...${NC}"
    compose_cmd -f "$COMPOSE_FILE" down
    echo -e "${GREEN}[+] Databases stopped.${NC}"
}

start_server() {
    if [ ! -f "$TEAMSERVER" ]; then
        echo -e "${RED}Error: teamserver binary not found at $TEAMSERVER${NC}"
        exit 1
    fi
    if [ ! -x "$TEAMSERVER" ]; then
        chmod +x "$TEAMSERVER"
    fi

    echo ""
    echo -e "${GREEN}[+] Starting Apex Team Server...${NC}"
    echo -e "${CYAN}    Config:  $CONFIG_FILE${NC}"
    echo -e "${CYAN}    API:     http://0.0.0.0:8443${NC}"
    echo -e "${CYAN}    gRPC:    0.0.0.0:50051${NC}"
    echo -e "${CYAN}    Login:   admin / apex${NC}"
    echo ""
    exec "$TEAMSERVER"
}

# ── Main ──

banner

case "${1:-}" in
    --stop)
        stop_db
        ;;
    --db-only)
        start_db
        ;;
    *)
        start_db
        echo ""
        start_server
        ;;
esac
