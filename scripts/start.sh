#!/bin/bash
# Start Apex: database (if needed) + team server
# Run from project root: ./scripts/start.sh

set -e
cd "$(dirname "$0")/.."

# Use docker or podman (podman provides docker-compose compat)
COMPOSE="docker compose"
command -v docker >/dev/null 2>&1 || COMPOSE="podman compose"

echo "[*] Starting Apex..."

# Ensure databases are running
if ! $COMPOSE -f deployments/docker-compose.yml ps -q postgres 2>/dev/null | grep -q .; then
    echo "[*] Starting PostgreSQL + Redis..."
    $COMPOSE -f deployments/docker-compose.yml up -d
    echo "[*] Waiting for PostgreSQL..."
    sleep 5
fi

# Build and run team server
echo "[*] Starting team server..."
make server-run
