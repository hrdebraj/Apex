# Apex C2 Framework — Release

Pre-built binaries for Linux x86_64.

## Quick Start

```bash
# 1. Extract
unzip apex-c2-v1.0.0-linux-amd64.zip
cd apex-c2

# 2. Start everything (databases + team server)
chmod +x setup.sh
./setup.sh

# 3. Launch the desktop client (in another terminal)
chmod +x apex-client
./apex-client
```

## What's included

| File | Description |
|------|-------------|
| `teamserver` | Go team server binary |
| `apex-client` | Tauri desktop operator client |
| `setup.sh` | One-command setup: starts PostgreSQL + Redis, then launches teamserver |
| `config.yaml` | Team server configuration (edit before production use) |
| `docker-compose.yml` | Docker Compose for PostgreSQL 16 + Redis 7 |
| `migrations/` | Database schema (auto-applied on first run) |
| `profiles/` | Pre-built malleable C2 profiles (7 profiles) |

## Commands

```bash
./setup.sh              # Start databases + team server
./setup.sh --db-only    # Start databases only
./setup.sh --stop       # Stop databases
```

## Default Credentials

- **Login**: `admin` / `apex`
- **API**: `http://0.0.0.0:8443`
- **gRPC**: `0.0.0.0:50051`

## Requirements

- Docker or Podman (for PostgreSQL + Redis)
- Linux x86_64

## Security

- Change `auth.jwt_secret` in `config.yaml` before production use
- Change the default `admin`/`apex` credentials after first login
- Enable TLS for the API and listeners in production
