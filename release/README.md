# Apex C2 Framework - Release v2.1.0

Pre-built binaries for Linux x86_64 with everything needed to run.

## What's New (v2.1.0)

- **PPID Spoofing** — child processes spawn under `explorer.exe` to defeat EDR parent-chain analysis. Toggle at build time or runtime (`ppidspoof on/off`)
- **Malleable C2 Profiles** — YAML-based profiles inject `User-Agent` and beacon URI at compile time. 7 pre-built profiles (Amazon, Microsoft, Google, Cloudflare, Slack, GitHub, default)
- **PE TimeDateStamp Backdating** — builder patches on-disk PE timestamp to a random 2019-2023 date; runtime stomp randomizes via `__rdtsc()`
- **Windows Persistence** — `persist registry` (HKCU Run key), `persist schtask` (logon-triggered Scheduled Task), `persist remove` (cleanup both)
- **Agent Builder UI** — rebalanced two-column OPSEC layout, PPID Spoofing toggle with description, malleable profile selector
- **mTLS + Evasion fix** — Ekko ROP sleep disabled by default (`SLEEP_METHOD=0`) as it causes agent hang with mTLS; all other evasion features work correctly with mTLS

## Quick Start

```bash
# 1. Extract
unzip apex-c2-v2.0.0-linux-amd64.zip
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

## Building a Release

From the project root:

```bash
make package
```

This builds the team server and client, then copies everything into `release/`:
binaries, docker-compose, migrations, profiles, agent source, and BOF templates.

To build a distributable zip:

```bash
make package
cd release && zip -r ../apex-c2-v2.0.0-linux-amd64.zip .
```

## TLS & mTLS Certificate Setup

### HTTPS Listener (Server TLS)

Generate a self-signed cert for HTTPS listeners:

```bash
# Generate CA
openssl ecparam -genkey -name prime256v1 -out ca.key
openssl req -new -x509 -key ca.key -out ca.crt -days 365 -subj "/CN=Apex CA"

# Generate server cert signed by CA
openssl ecparam -genkey -name prime256v1 -out server.key
openssl req -new -key server.key -out server.csr -subj "/CN=192.168.10.135"
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -out server.crt -days 365
rm server.csr
```

When creating an HTTPS listener in the client, provide `server.crt` and `server.key`.

### mTLS Listener (Mutual TLS)

mTLS requires a CA to verify agent client certificates. The agent's client cert is automatically generated and embedded into the binary at build time — no cert files need to be sent to the target.

```bash
# Generate CA (used to sign both server and agent certs)
openssl ecparam -genkey -name prime256v1 -out ca.key
openssl req -new -x509 -key ca.key -out ca.crt -days 365 -subj "/CN=Apex mTLS CA"

# Generate server cert
openssl ecparam -genkey -name prime256v1 -out mtls-server.key
openssl req -new -key mtls-server.key -out mtls-server.csr -subj "/CN=192.168.10.135"
openssl x509 -req -in mtls-server.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -out mtls-server.crt -days 365
rm mtls-server.csr
```

When creating an mTLS listener, provide:
- **Cert**: `mtls-server.crt`
- **Key**: `mtls-server.key`
- **CA**: `ca.crt` (used to verify agent client certs)

If no CA is provided, the listener accepts any client certificate (no verification).

### Operator mTLS (Teamserver API)

To require client certificates for operator connections to the teamserver API:

```bash
# Generate operator client cert signed by same CA
openssl ecparam -genkey -name prime256v1 -out operator.key
openssl req -new -key operator.key -out operator.csr -subj "/CN=operator"
openssl x509 -req -in operator.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -out operator.crt -days 365
rm operator.csr

# Create PFX for import into client (legacy flag for Windows compatibility)
openssl pkcs12 -export -out operator.p12 -inkey operator.key \
  -in operator.crt -passout pass:
```

Enable in `config.yaml`:

```yaml
server:
  tls:
    enabled: true
    cert_file: "mtls-server.crt"
    key_file: "mtls-server.key"
    ca_file: "ca.crt"
    mutual_tls: true
```

Upload `operator.p12` via the client's **Settings > mTLS** page.

### Notes

- Replace `192.168.10.135` with your teamserver IP or domain
- Agent client certs are auto-generated by the builder and baked into the binary as PFX — no files are sent to the target
- Use the same CA for server and agent certs if you want the listener to verify agent identity
- Add `-legacy` flag to `openssl pkcs12` if importing PFX on older Windows versions

## Security

- Change `auth.jwt_secret` in `config.yaml` before production use
- Change the default `admin`/`apex` credentials after first login
- Enable TLS for the API and listeners in production
