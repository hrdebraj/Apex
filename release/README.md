# Apex C2 Framework - Release

Pre-built binaries for Linux x86_64 with everything needed to run.

## Quick Start

```bash
# 1. Extract
unzip apex-c2-v1.0.0-linux-amd64.zip
cd apex-c2

# 2. Start everything (checks deps, starts DB, launches teamserver)
chmod +x setup.sh teamserver apex-client
./setup.sh

# 3. Launch the desktop client (in another terminal)
./apex-client
```

## What's Included

| File/Directory | Description |
|---------------|-------------|
| `teamserver` | Go team server binary |
| `apex-client` | Tauri desktop operator client |
| `setup.sh` | One-command setup: checks deps, starts DB, launches teamserver |
| `config.yaml` | Team server configuration (edit before production) |
| `docker-compose.yml` | Docker Compose for PostgreSQL 16 + Redis 7 |
| `migrations/` | Database schema (auto-applied on first DB start) |
| `profiles/` | 8 pre-built malleable C2 profiles |
| `agent/` | Agent source code (compiled on-demand by teamserver when building payloads) |
| `bofs/` | Pre-compiled BOF templates (lateral movement, recon, persistence) |

## Commands

```bash
./setup.sh              # Check deps + start DB + teamserver
./setup.sh --db-only    # Start databases only
./setup.sh --stop       # Stop databases
./setup.sh --check      # Check dependencies only
```

## Dependencies

| Dependency | Required For | Install |
|-----------|-------------|---------|
| Docker or Podman | PostgreSQL + Redis | `sudo apt install docker.io` |
| MinGW | Windows agent builds | `sudo apt install mingw-w64` |
| GCC | Linux agent builds | `sudo apt install build-essential` |

The setup script checks all dependencies and warns about missing ones.

## Default Credentials

- **Login**: `admin` / `apex`
- **API**: `http://0.0.0.0:8443`
- **gRPC**: `0.0.0.0:50051`

## Security

- Change `auth.jwt_secret` in `config.yaml` before production use
- Change the default `admin`/`apex` credentials after first login
- Enable TLS for the API and listeners in production
