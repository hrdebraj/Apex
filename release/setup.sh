#!/usr/bin/env bash
#
# Apex C2 Framework - Quick Setup
#
# Usage:
#   chmod +x setup.sh
#   ./setup.sh              # Check deps, start databases, launch team server
#   ./setup.sh --db-only    # Start databases only
#   ./setup.sh --stop       # Stop databases
#   ./setup.sh --check      # Check dependencies only
#

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
COMPOSE_FILE="$SCRIPT_DIR/docker-compose.yml"
CONFIG_FILE="$SCRIPT_DIR/config.yaml"
TEAMSERVER="$SCRIPT_DIR/teamserver"
AGENT_DIR="$SCRIPT_DIR/agent"

RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
NC='\033[0m'

banner() {
    echo -e "${CYAN}"
    cat <<'ART'
    ╔═══════════════════════════════════════════╗
    ║                                           ║
    ║     █████╗ ██████╗ ███████╗██╗  ██╗       ║
    ║    ██╔══██╗██╔══██╗██╔════╝╚██╗██╔╝       ║
    ║    ███████║██████╔╝█████╗   ╚███╔╝        ║
    ║    ██╔══██║██╔═══╝ ██╔══╝   ██╔██╗        ║
    ║    ██║  ██║██║     ███████╗██╔╝ ██╗       ║
    ║    ╚═╝  ╚═╝╚═╝     ╚══════╝╚═╝  ╚═╝       ║
    ║                                           ║
    ║       C O M M A N D  &  C O N T R O L     ║
    ╚═══════════════════════════════════════════╝
ART
    echo -e "${NC}"
}

ok()   { echo -e "  ${GREEN}[+]${NC} $1"; }
warn() { echo -e "  ${YELLOW}[!]${NC} $1"; }
fail() { echo -e "  ${RED}[-]${NC} $1"; }
info() { echo -e "  ${CYAN}[*]${NC} $1"; }

check_deps() {
    echo -e "${CYAN}Checking dependencies...${NC}"
    local missing=0

    # Docker / Podman
    if command -v docker &>/dev/null; then
        ok "Docker: $(docker --version 2>/dev/null | head -1)"
    elif command -v podman &>/dev/null; then
        ok "Podman: $(podman --version 2>/dev/null | head -1)"
    else
        fail "Docker or Podman: NOT FOUND"
        echo "       Install: https://docs.docker.com/engine/install/"
        missing=1
    fi

    # MinGW (Windows agent cross-compilation)
    if command -v x86_64-w64-mingw32-gcc &>/dev/null; then
        ok "MinGW: $(x86_64-w64-mingw32-gcc --version 2>/dev/null | head -1)"
    else
        warn "MinGW (x86_64-w64-mingw32-gcc): NOT FOUND"
        echo "       Windows agent builds will fail without it."
        echo "       Install: sudo apt install mingw-w64"
    fi

    # GCC (Linux agent native compilation)
    if command -v gcc &>/dev/null; then
        ok "GCC: $(gcc --version 2>/dev/null | head -1)"
    else
        warn "GCC: NOT FOUND"
        echo "       Linux agent builds will fail without it."
        echo "       Install: sudo apt install build-essential"
    fi

    # Agent source directory
    if [ -d "$AGENT_DIR" ] && [ -f "$AGENT_DIR/main.c" ]; then
        ok "Agent source: $AGENT_DIR"
    else
        fail "Agent source: NOT FOUND at $AGENT_DIR"
        echo "       The teamserver needs agent/ to compile payloads."
        missing=1
    fi

    # Config file
    if [ -f "$CONFIG_FILE" ]; then
        ok "Config: $CONFIG_FILE"
    else
        fail "Config: NOT FOUND at $CONFIG_FILE"
        missing=1
    fi

    # Teamserver binary
    if [ -f "$TEAMSERVER" ]; then
        ok "Teamserver binary: $TEAMSERVER"
    else
        fail "Teamserver binary: NOT FOUND"
        missing=1
    fi

    echo ""
    if [ $missing -eq 1 ]; then
        fail "Some required dependencies are missing. Fix them and try again."
        return 1
    fi
    ok "All required dependencies satisfied."
    return 0
}

compose_cmd() {
    if command -v docker &>/dev/null; then
        docker compose "$@"
    elif command -v podman &>/dev/null; then
        podman compose "$@"
    else
        fail "Neither docker nor podman found."
        exit 1
    fi
}

start_db() {
    info "Starting PostgreSQL + Redis..."
    compose_cmd -f "$COMPOSE_FILE" up -d

    info "Waiting for databases to be healthy..."
    for _ in $(seq 1 30); do
        pg_ok=$(docker inspect --format='{{.State.Health.Status}}' apex-postgres 2>/dev/null || echo "waiting")
        redis_ok=$(docker inspect --format='{{.State.Health.Status}}' apex-redis 2>/dev/null || echo "waiting")
        if [ "$pg_ok" = "healthy" ] && [ "$redis_ok" = "healthy" ]; then
            ok "PostgreSQL: healthy"
            ok "Redis: healthy"
            return 0
        fi
        sleep 1
    done
    warn "Timeout waiting for databases (30s). Check: docker ps"
    return 1
}

stop_db() {
    info "Stopping databases..."
    compose_cmd -f "$COMPOSE_FILE" down
    ok "Databases stopped."
}

start_server() {
    if [ ! -x "$TEAMSERVER" ]; then
        chmod +x "$TEAMSERVER"
    fi

    # Point agent_dir to our bundled agent source
    export APEX_AGENT_DIR="$AGENT_DIR"

    echo ""
    ok "Starting Apex Team Server..."
    info "Config:  $CONFIG_FILE"
    info "Agents:  $AGENT_DIR"
    info "API:     http://0.0.0.0:8443"
    info "gRPC:    0.0.0.0:50051"
    info "Login:   admin / apex"
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
        check_deps
        start_db
        ;;
    --check)
        check_deps
        ;;
    *)
        check_deps
        echo ""
        start_db
        echo ""
        start_server
        ;;
esac
