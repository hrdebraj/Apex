# Apex C2 Framework

A modern, modular Command & Control framework built for red team operations and adversary simulation. Features a Go team server, Tauri + React operator client, and a C-based Windows agent with integrated evasion, BOF loading, and encrypted sleep.

```
      ___    ____  _______  __
     / _ |  / __ \/ __/ _ \/ /
    / __ | / /_/ / _// ___/\ \
   /_/ |_|/ .___/___/_/  /___/
         /_/  Team Server v0.1.0
```

---

## Table of Contents

- [Architecture Overview](#architecture-overview)
- [Feature Summary](#feature-summary)
- [Technology Stack](#technology-stack)
- [Fresh Machine Setup](#fresh-machine-setup)
- [Quick Start](#quick-start)
- [Project Structure](#project-structure)
- [Team Server](#team-server)
- [Operator Client](#operator-client)
- [Agent (Implant)](#agent-implant)
- [Agent Builder](#agent-builder)
- [Beacon Object Files (BOF)](#beacon-object-files-bof)
- [Evasion Capabilities](#evasion-capabilities)
- [Malleable C2 Profiles](#malleable-c2-profiles)
- [API Reference](#api-reference)
- [Database Schema](#database-schema)
- [Configuration Reference](#configuration-reference)
- [Deployment](#deployment)
- [Make Targets](#make-targets)
- [Security Considerations](#security-considerations)
- [Troubleshooting](#troubleshooting)

---

## Architecture Overview

```
┌──────────────────────┐       REST / SSE / gRPC         ┌───────────────────────┐
│    Apex Client       │◄───────────────────────────────►│   Apex Team Server    │
│  (Tauri + React)     │   JWT-authenticated sessions    │        (Go)           │
│                      │                                 │                       │
│  - Dashboard         │                                 │  ┌─────────────────┐  │
│  - Listeners         │                                 │  │   HTTP API      │  │
│  - Agents            │                                 │  │   (Chi router)  │  │
│  - Terminal          │                                 │  └────────┬────────┘  │
│  - Agent Builder     │                                 │           │           │
│  - Modules (BOF)     │                                 │  ┌────────┴────────┐  │
│  - Attack Graph      │                                 │  │   Event Hub     │  │
│  - MITRE ATT&CK      │                                 │  │   (SSE broker)  │  │
│  - Settings          │                                 │  └────────┬────────┘  │
└──────────────────────┘                                 │           │           │
                                                         │  ┌────────┴────────┐  │
                                              ┌──────────┤  │  Agent Manager  │  │
                                              │          │  │  Task Queue     │  │
                                              │          │  └────────┬────────┘  │
                                              │          └───────────┼───────────┘
                                              │                      │
                                     ┌────────┴──────┐    ┌─────────┴──────────┐
                                     │  PostgreSQL   │    │     Listeners      │
                                     │  (persistent  │    │  HTTP / HTTPS /    │
                                     │   storage)    │    │  TCP / DNS         │
                                     ├───────────────┤    └─────────┬──────────┘
                                     │    Redis      │              │
                                     │  (task queue  │         ┌────┴─────┐
                                     │   + pub/sub)  │         │  Agents  │
                                     └───────────────┘         │  (C/Win) │
                                                               └──────────┘
```

> For detailed architecture diagrams and data flow diagrams (DFD) suitable for Microsoft Threat Modeling Tool, see [ARCHITECTURE.md](ARCHITECTURE.md).

---

## Feature Summary

### Team Server

- Multi-protocol listeners (HTTP, HTTPS, TCP, DNS)
- JWT authentication with role-based access control (Admin, Operator, Readonly)
- Real-time event streaming via Server-Sent Events (SSE)
- Redis-backed task queue with pub/sub result delivery
- PostgreSQL persistence for agents, tasks, credentials, and operations log
- Malleable C2 profile support (YAML-based traffic shaping)
- gRPC service layer for programmatic access
- Agent deduplication (prevents duplicates from same host+user+IP within 24h)
- Server-side payload compilation with configurable evasion flags

### Operator Client

- Cross-platform Tauri desktop application (also runs in browser)
- Real-time dashboard with agent status and listener health
- Per-agent interactive terminal with command history
- Agent Builder UI with evasion toggle controls
- Modules page for BOF upload/management
- Attack graph visualization (using React Flow)
- Automatic MITRE ATT&CK technique mapping for commands
- OPSEC warning system (18 built-in rules with risk levels and alternatives)
- Multi-agent tabbed terminal sessions

### Agent (Windows Implant)

- HTTP/HTTPS beacon over WinHTTP
- Configurable sleep interval with jitter (runtime-adjustable from operator)
- Evasion suite: ETW patching, AMSI patching, ntdll unhooking, encrypted sleep
- In-memory BOF (Beacon Object File) loader with full BeaconAPI
- AES-256-CBC encryption via Windows CNG (ready for encrypted comms)
- XOR string obfuscation layer
- Multiple output formats: EXE, DLL, shellcode (.bin)
- Process listing, file download, directory navigation, shell execution
- Graceful exit command

---

## Technology Stack


| Component           | Technology                | Version   |
| ------------------- | ------------------------- | --------- |
| Team Server         | Go                        | 1.24+     |
| HTTP Router         | go-chi/chi/v5             | v5.x      |
| Authentication      | golang-jwt/jwt/v5, bcrypt | —         |
| Database            | PostgreSQL                | 16        |
| Queue / Pub-Sub     | Redis                     | 7         |
| gRPC                | google.golang.org/grpc    | —         |
| Serialization       | Protocol Buffers          | proto3    |
| Logging             | rs/zerolog                | —         |
| Client Framework    | Tauri                     | 2.5       |
| Client UI           | React, TypeScript         | 19.x, 5.8 |
| Build Tool          | Vite                      | 6.x       |
| State Management    | Zustand                   | 5.x       |
| Styling             | Tailwind CSS              | 4.x       |
| Icons               | Lucide React              | —         |
| Graph Visualization | @xyflow/react             | —         |
| Agent Language      | C (MinGW cross-compiled)  | —         |
| Agent Compiler      | x86_64-w64-mingw32-gcc    | —         |
| Containerization    | Docker / Podman           | —         |


---

## Fresh Machine Setup

### Ubuntu / Debian / Parrot OS

```bash
sudo apt update
sudo apt install -y build-essential git curl unzip

# Go (1.22+)
curl -sSf https://go.dev/install.sh | sh
# Reload shell: . "$HOME/.bashrc"

# Node.js (20+)
curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
sudo apt install -y nodejs

# Rust (for Tauri client)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
. "$HOME/.cargo/env"

# Tauri system dependencies
sudo apt install -y libwebkit2gtk-4.1-dev libgtk-3-dev libappindicator3-dev librsvg2-dev patchelf

# Protocol Buffers compiler
sudo apt install -y protobuf-compiler
go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest

# MinGW (Windows agent cross-compilation)
sudo apt install -y mingw-w64

# Docker & Docker Compose (for PostgreSQL + Redis)
sudo apt install -y docker.io docker-compose-plugin
sudo systemctl enable --now docker
sudo usermod -aG docker $USER
# Log out and back in for docker group
```

### Arch Linux

```bash
sudo pacman -S --needed base-devel git curl go nodejs npm rust protobuf mingw-w64-gcc docker docker-compose
go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest
```

### macOS

```bash
brew install go node protobuf mingw-w64 docker
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest
```

### Verify Installation

```bash
go version                          # 1.22+
node --version                      # v20+
rustc --version                     # 1.70+
protoc --version                    # 3.x+
x86_64-w64-mingw32-gcc --version    # MinGW
docker --version                    # 20+
```

---

## Quick Start

### 1. Clone and enter project

```bash
git clone https://github.com/your-org/apex.git
cd apex
```

### 2. Start databases

```bash
make db
```

Starts PostgreSQL 16 and Redis 7 via Docker Compose. The schema in `migrations/001_initial.sql` is applied automatically on first run.

### 3. Generate protobuf code

```bash
make proto
```

### 4. Configure team server

Edit `teamserver/config.yaml`:

- Set `server.agent_dir` to the absolute path of the `agent/` directory
- Update database credentials if not using defaults
- Change `auth.jwt_secret` for production

### 5. Build and run team server

```bash
make server-run
```

Listens on:

- **HTTP API**: `0.0.0.0:8443`
- **gRPC**: `0.0.0.0:50051`

### 6. Run the operator client

**Browser (development):**

```bash
make client-install
make client-dev
```

Open `http://localhost:1420`.

**Tauri desktop app:**

```bash
cd client && npm install && npm run tauri build
```

### 7. Login

Default credentials: `admin` / `apex`

### 8. Create a listener

Listeners > Create > HTTP > Set bind address and port (e.g., `192.168.0.109:8080`) > Start

### 9. Generate and deploy an agent

Agent Builder > Select listener > Configure evasion options > Generate Payload > Transfer EXE to target > Execute

---

## Project Structure

```
apex/
├── teamserver/                 # Go team server
│   ├── cmd/teamserver/         #   Entry point (main.go)
│   ├── internal/
│   │   ├── agents/             #   Agent manager, lifecycle, events
│   │   ├── api/                #   REST handlers, router, middleware, SSE hub
│   │   ├── auth/               #   JWT service, bcrypt, RBAC
│   │   ├── builder/            #   Payload compilation pipeline
│   │   ├── config/             #   YAML config loader
│   │   ├── db/                 #   PostgreSQL + Redis clients
│   │   ├── grpc/               #   gRPC service implementations
│   │   ├── listeners/          #   HTTP, HTTPS, TCP, DNS listener engines
│   │   ├── profile/            #   Malleable profile parser
│   │   ├── server/             #   Server orchestration, event hub
│   │   └── tasks/              #   Redis task queue + pub/sub
│   ├── pkg/proto/apexpb/       #   Generated protobuf Go code
│   ├── config.yaml             #   Server configuration
│   └── go.mod                  #   Go module definition
│
├── client/                     # Tauri + React operator client
│   ├── src/
│   │   ├── pages/              #   Dashboard, Listeners, Agents, Terminal,
│   │   │                       #   AgentBuilder, Modules, Graph, Mitre, Settings, Login
│   │   ├── stores/             #   Zustand stores (auth, agent, taskResult,
│   │   │                       #   terminal, mitre, opsec, listener)
│   │   ├── services/           #   API client, task, listener, payload, auth services
│   │   ├── components/         #   Layout, Sidebar, TopBar, AttackGraph
│   │   └── hooks/              #   useSSE, usePolling
│   ├── src-tauri/              #   Rust Tauri backend
│   ├── package.json
│   └── vite.config.ts
│
├── agent/                      # C Windows agent (implant)
│   ├── main.c                  #   Beacon loop, HTTP comms, command handlers
│   ├── evasion.h               #   ETW/AMSI patching, encrypted sleep, ntdll unhook
│   ├── bof.h                   #   COFF/BOF loader with BeaconAPI
│   ├── crypto.h                #   AES-256-CBC (CNG), XOR string encryption
│   └── Makefile                #   MinGW cross-compilation
│
├── proto/                      # Protobuf definitions
│   ├── common.proto            #   Shared types (Agent, Task, Listener, enums)
│   ├── auth.proto              #   AuthService RPCs
│   ├── agents.proto            #   AgentService RPCs
│   ├── listeners.proto         #   ListenerService RPCs
│   └── tasks.proto             #   TaskService RPCs
│
├── profiles/                   # Malleable C2 profiles
│   ├── default.yaml            #   Web analytics style
│   └── microsoft-graph.yaml    #   Microsoft Graph API style
│
├── migrations/
│   └── 001_initial.sql         # PostgreSQL schema (7 tables)
│
├── deployments/
│   ├── docker-compose.yml      # PostgreSQL + Redis containers
│   └── apex-teamserver.service # Systemd unit file
│
├── scripts/
│   ├── start.sh                # One-command startup (db + server)
│   └── generate-proto.sh       # Protobuf code generation
│
├── data/
│   └── bofs/                   # Uploaded BOF storage (runtime)
│
└── Makefile                    # Root build orchestration
```

---

## Team Server

### Overview

The team server is the central hub of the framework. It manages listeners, agents, tasks, and operator sessions. Written in Go, it exposes both an HTTP REST API (for the client) and a gRPC interface (for programmatic access).

### Components


| Package                  | Responsibility                                                                                                          |
| ------------------------ | ----------------------------------------------------------------------------------------------------------------------- |
| `agents/manager.go`      | In-memory agent registry, PostgreSQL persistence, agent dedup (hostname+user+IP), check-in tracking, event broadcasting |
| `api/router.go`          | Chi-based HTTP router with CORS, compression, JWT middleware                                                            |
| `api/task_handler.go`    | Task creation and listing endpoints                                                                                     |
| `api/payload_handler.go` | Payload generation, BOF upload/list/delete                                                                              |
| `api/events.go`          | SSE event hub for real-time streaming to clients                                                                        |
| `auth/service.go`        | JWT token generation/validation, bcrypt password hashing, RBAC enforcement                                              |
| `builder/builder.go`     | Agent compilation pipeline — resolves source, sets flags, runs `make clean && make`                                     |
| `config/config.go`       | YAML config loader for server, database, auth settings                                                                  |
| `db/postgres.go`         | PostgreSQL connection pool (pgx/v5)                                                                                     |
| `db/redis.go`            | Redis client (go-redis/v9)                                                                                              |
| `listeners/http.go`      | HTTP/HTTPS listener engine — agent registration, check-in, task dequeue, result ingestion                               |
| `listeners/tcp.go`       | TCP listener (length-prefixed framing)                                                                                  |
| `listeners/dns.go`       | DNS listener (base64-in-subdomain, TXT/A/AAAA responses)                                                                |
| `profile/profile.go`     | Malleable profile YAML parser                                                                                           |
| `tasks/queue.go`         | Redis-backed task queue (RPUSH/LPOP) with pub/sub result delivery                                                       |


### Authentication & Authorization


| Role       | Permissions                                                     |
| ---------- | --------------------------------------------------------------- |
| `admin`    | Full access — create operators, manage listeners, agents, tasks |
| `operator` | Create/manage listeners and tasks, view agents                  |
| `readonly` | View-only access to all resources                               |


- JWT tokens (HS256) with configurable expiry (default 24h)
- Passwords hashed with bcrypt
- Token passed via `Authorization: Bearer <token>` header or `?token=` query parameter (SSE)

### Real-Time Events (SSE)

The server pushes events to connected clients via Server-Sent Events at `GET /api/events`.


| Event Type           | Payload                                  | Trigger                                   |
| -------------------- | ---------------------------------------- | ----------------------------------------- |
| `connected`          | `{}`                                     | Client connects to SSE stream             |
| `agent:registered`   | Agent object                             | New agent registers or reuses existing ID |
| `agent:checked_in`   | `{ agent_id, timestamp }`                | Agent beacon check-in                     |
| `agent:disconnected` | `{ agent_id }`                           | Agent missed check-in threshold           |
| `agent:task_result`  | `{ task_id, agent_id, output, success }` | Task result received from agent           |


### Agent Communication Protocol

All agent communication uses HTTP POST to `/` on the listener.

**Registration (first check-in):**

```
POST / HTTP/1.1
Content-Type: application/json

{
  "sysinfo": {
    "hostname": "WORKSTATION",
    "username": "user",
    "os": "Windows",
    "arch": "amd64",
    "pid": 1234,
    "process_name": "agent.exe",
    "internal_ip": "10.0.0.5",
    "sleep": 5,
    "jitter": 20
  }
}

→ Response: { "agent_id": "uuid" }
```

**Subsequent check-ins:**

```
POST / HTTP/1.1
Content-Type: application/json
X-Agent-ID: <agent_id>

{}

→ Response: { "tasks": [{ "id": "uuid", "command": "whoami", "arguments": "base64..." }] }
```

**Result submission:**

```
POST / HTTP/1.1
Content-Type: application/json
X-Agent-ID: <agent_id>

{
  "results": [{
    "task_id": "uuid",
    "output": "base64-encoded-output",
    "success": true
  }]
}
```

---

## Operator Client

### Pages


| Page          | Route                  | Description                                                  |
| ------------- | ---------------------- | ------------------------------------------------------------ |
| Dashboard     | `/dashboard`           | Overview with agent count, listener status, recent activity  |
| Listeners     | `/listeners`           | Create, start, stop, and delete C2 listeners                 |
| Agents        | `/agents`              | Live agent table with hostname, user, OS, PID, last check-in |
| Terminal      | `/terminal?agent=<id>` | Per-agent interactive shell with command history             |
| Agent Builder | `/agent-builder`       | Configure and generate agent payloads with evasion options   |
| Modules       | `/modules`             | BOF upload/management, BYOVD configuration, evasion info     |
| Attack Graph  | `/graph`               | Visual attack path graph (React Flow)                        |
| MITRE ATT&CK  | `/mitre`               | Technique mapping for executed commands                      |
| Settings      | `/settings`            | Server connection and operator preferences                   |


### Terminal Commands

**Local commands (processed in the UI):**


| Command         | Description                 |
| --------------- | --------------------------- |
| `help`          | Show all available commands |
| `clear` / `cls` | Clear terminal output       |
| `agents`        | List all connected agents   |
| `use <id>`      | Select agent by ID prefix   |


**Agent commands (sent to the implant):**


| Command                    | Description                                 |
| -------------------------- | ------------------------------------------- |
| `whoami`                   | Display hostname\username with admin status |
| `getuid`                   | User info with PID and privilege level      |
| `ps`                       | Process listing (PID, PPID, Name)           |
| `pwd`                      | Print current working directory             |
| `cd <path>`                | Change directory                            |
| `dir` / `ls [path]`        | List directory contents                     |
| `download <path>`          | Download file from target                   |
| `shell <cmd>`              | Execute via cmd.exe                         |
| `exec <cmd>`               | Execute via cmd.exe (alias)                 |
| `sleep <sec> [jitter%]`    | Change beacon interval at runtime           |
| `bof <b64_obj> [b64_args]` | Execute BOF in-memory                       |
| `exit`                     | Terminate agent process                     |
| *any other*                | Passed directly to cmd.exe as shell command |


### OPSEC Warning System

The client includes 18 built-in OPSEC rules that warn operators before executing high-risk commands. Each rule includes a risk level (`low`, `medium`, `high`, `critical`) and suggests safer alternatives.

Examples:

- `whoami` → "Consider using token-based checks"
- `net user` → "Use WMI or LDAP queries instead"
- `mimikatz` → "Use BOFs or in-memory alternatives"
- `powershell` → "Avoid PowerShell; use BOFs or direct API calls"

### MITRE ATT&CK Integration

Commands are automatically mapped to MITRE ATT&CK techniques. The MITRE page displays a matrix of techniques exercised during the operation, grouped by tactic.

---

## Agent (Implant)

### Overview

The Apex agent is a single-binary Windows implant written in C. It beacons over HTTP/HTTPS using WinHTTP, executes operator commands, and returns results. All evasion features are compiled conditionally via preprocessor flags, allowing operators to tailor the binary's OPSEC profile.

### Source Files


| File        | Purpose                                                              |
| ----------- | -------------------------------------------------------------------- |
| `main.c`    | Beacon loop, HTTP POST, command dispatch, base64, JSON helpers       |
| `evasion.h` | ETW patching, AMSI patching, encrypted sleep (Ekko), ntdll unhooking |
| `bof.h`     | COFF object file loader with full BeaconAPI compatibility            |
| `crypto.h`  | AES-256-CBC via Windows CNG, XOR string encryption, CSPRNG           |


### Beacon Lifecycle

1. **Startup evasion** — Unhook ntdll, patch ETW, patch AMSI (if enabled)
2. **Registration** — POST sysinfo (hostname, user, OS, arch, PID, IP, sleep, jitter) → receive `agent_id`
3. **Beacon loop** — POST `{}` with `X-Agent-ID` → receive tasks → execute → POST results
4. **Sleep** — Encrypted sleep (Ekko) or plain `Sleep()` with jitter

### Built-in Commands


| Command        | Handler            | Description                                  |
| -------------- | ------------------ | -------------------------------------------- |
| `sleep`        | `handle_sleep_cmd` | Update beacon interval and jitter at runtime |
| `whoami`       | `handle_whoami`    | Hostname\username [ADMIN]                    |
| `getuid`       | `handle_getuid`    | Username, PID, admin status                  |
| `ps`           | `handle_ps`        | Process list via CreateToolhelp32Snapshot    |
| `pwd`          | `handle_pwd`       | GetCurrentDirectory                          |
| `cd`           | `handle_cd`        | SetCurrentDirectory                          |
| `bof`          | `handle_bof`       | In-memory COFF loader with BeaconAPI         |
| `download`     | `handle_download`  | Read file and return base64-encoded contents |
| `exit`         | —                  | Send final result, call ExitProcess          |
| `exec`/`shell` | `exec_cmd`         | cmd.exe /c with stdout/stderr capture        |
| *other*        | `exec_cmd`         | Treated as shell command                     |


### Compile-Time Options


| Flag                   | Default     | Effect                          |
| ---------------------- | ----------- | ------------------------------- |
| `C2_HOST`              | `127.0.0.1` | Callback host                   |
| `C2_PORT`              | `8080`      | Callback port                   |
| `USE_HTTPS`            | `0`         | Use HTTPS (1) or HTTP (0)       |
| `ENABLE_ETW_PATCH`     | `1`         | Patch EtwEventWrite at startup  |
| `ENABLE_AMSI_PATCH`    | `1`         | Patch AmsiScanBuffer at startup |
| `ENABLE_SLEEP_ENCRYPT` | `1`         | Ekko-style encrypted sleep      |
| `ENABLE_UNHOOK`        | `1`         | Unhook ntdll .text from disk    |


---

## Agent Builder

The Agent Builder page in the client configures and compiles agent payloads server-side. The builder runs `make clean && make <target>` in the agent directory with appropriate environment variables and preprocessor flags.

### Output Formats


| Format      | Make Target | Output      | Description                                     |
| ----------- | ----------- | ----------- | ----------------------------------------------- |
| EXE         | `exe`       | `agent.exe` | Standalone Windows executable                   |
| DLL         | `dll`       | `agent.dll` | DLL with DllMain entry (spawns beacon thread)   |
| Shellcode   | `shellcode` | `agent.bin` | Raw binary (copy of EXE, for process hollowing) |
| Service EXE | `exe`       | `agent.exe` | Standard EXE (for SCM persistence)              |


### OPSEC Toggles


| Option            | Agent Flag             | Description                               |
| ----------------- | ---------------------- | ----------------------------------------- |
| Sleep Obfuscation | `ENABLE_SLEEP_ENCRYPT` | Ekko-style memory encryption during sleep |
| Unhook ntdll      | `ENABLE_UNHOOK`        | Replace hooked ntdll from clean disk copy |
| ETW Patching      | `ENABLE_ETW_PATCH`     | Blind ETW-based EDR telemetry             |
| AMSI Patching     | `ENABLE_AMSI_PATCH`    | Bypass AMSI script/payload scanning       |


### Build Pipeline

```
Client (AgentBuilderPage)
  │  POST /api/payloads/generate
  │  { output_format, listener_id, callback_host, callback_port,
  │    sleep_obfuscation, unhook_ntdll, etw_patch, amsi_patch, ... }
  ▼
PayloadHandler.Generate()
  │  Resolve listener → c2_host, c2_port, use_https
  │  Build EvasionOpts from request flags
  ▼
builder.BuildBase64()
  │  ResolveAgentDir() → find agent/main.c
  │  Set env: C2_HOST, C2_PORT, USE_HTTPS, ENABLE_ETW_PATCH, ...
  │  exec: make -C agent/ clean
  │  exec: make -C agent/ exe|dll|shellcode
  │  Read output file → base64 encode
  ▼
Response → Client downloads binary
```

---

## Beacon Object Files (BOF)

### Overview

Apex includes a full in-memory COFF (Common Object File Format) loader that can execute Beacon Object Files — the same format used by Cobalt Strike. BOFs allow operators to run compiled C code directly in the agent's process without touching disk.

### BeaconAPI Compatibility

The following Cobalt Strike BeaconAPI functions are implemented:


| Function                       | Description                           |
| ------------------------------ | ------------------------------------- |
| `BeaconDataParse`              | Initialize argument parser            |
| `BeaconDataInt`                | Extract 4-byte integer from args      |
| `BeaconDataShort`              | Extract 2-byte short from args        |
| `BeaconDataLength`             | Remaining argument bytes              |
| `BeaconDataExtract`            | Extract length-prefixed byte buffer   |
| `BeaconOutput`                 | Append output (sent back to operator) |
| `BeaconPrintf`                 | Formatted output (printf-style)       |
| `BeaconUseToken`               | Impersonate a token                   |
| `BeaconRevertToken`            | Revert to self                        |
| `BeaconIsAdmin`                | Check if running as admin             |
| `BeaconGetSpawnTo`             | Get spawn-to process path             |
| `BeaconSpawnTemporaryProcess`  | Spawn a sacrificial process           |
| `BeaconInjectProcess`          | Inject into a process (stub)          |
| `BeaconInjectTemporaryProcess` | Inject into spawned process (stub)    |


### COFF Loader Features

- x86_64 relocation types: `ADDR64`, `ADDR32NB`, `REL32`, `REL32_1` through `REL32_5`
- External symbol resolution via `__imp_Library$Function` naming convention
- Automatic DLL loading for unresolved libraries
- IAT-style pointer creation for `__imp`_ prefixed symbols
- Entry point detection: `go` or `_go` function

### Usage

1. **Upload BOF** — Modules page > Upload BOF (.o or .obj file)
2. **Execute** — Terminal > `bof <base64_obj_data> [base64_args]`
3. **Output** — BOF output captured via BeaconOutput/BeaconPrintf and displayed in terminal

### BOF Management (Server)

BOFs are stored on disk in `data/bofs/` with metadata (name, size, SHA-256 hash, upload time). The API supports:

- `GET /api/payloads/bofs` — List all uploaded BOFs
- `POST /api/payloads/bofs` — Upload BOF (multipart form, field name: `bof`)
- `DELETE /api/payloads/bofs?id=<uuid>` — Delete a BOF

---

## Evasion Capabilities

### ETW Patching

Patches `EtwEventWrite` in `ntdll.dll` at agent startup. Replaces the function prologue with `xor eax, eax; ret` (3 bytes), causing all ETW events to silently succeed without recording telemetry. This blinds EDR solutions that rely on ETW providers for:

- Process creation events
- Image load events
- Thread creation events
- .NET assembly loading

### AMSI Patching

Patches `AmsiScanBuffer` in `amsi.dll` to return `E_INVALIDARG` (`0x80070057`). This bypasses the Antimalware Scan Interface used by:

- PowerShell script block logging
- Windows Defender real-time scanning of in-memory content
- Third-party AMSI consumers

The patch is applied only if `amsi.dll` is loaded (no-op otherwise).

### Encrypted Sleep (Ekko-style)

During sleep, the entire agent image (all sections) is encrypted in-memory using `SystemFunction032` (RC4/XOR from advapi32.dll). The process:

1. Make the image `PAGE_READWRITE` (remove execute)
2. Encrypt with a per-sleep random key derived from `GetTickCount()`, PID, image base, and sleep duration
3. `Sleep()` for the configured duration
4. Decrypt with the same key
5. Restore original memory protection

This prevents memory scanners from identifying the beacon during idle periods.

### ntdll Unhooking

Maps a clean copy of `ntdll.dll` from `C:\Windows\System32\ntdll.dll` using `SEC_IMAGE` mapping, then overwrites the in-memory `.text` section with the clean version. This removes:

- Inline hooks placed by EDR/AV products
- Detour patches on NT API functions
- Trampoline modifications

Executed before ETW/AMSI patching so that subsequent patches target clean function prologues.

### XOR String Encryption

The `crypto.h` module provides compile-time XOR encryption for string literals using a configurable key (`XOR_KEY`, default `0x41`). Encrypted strings are decrypted at first access, preventing static analysis tools from finding cleartext IOCs in the binary.

### AES-256-CBC Encryption

Full AES-256-CBC implementation via Windows CNG (BCrypt API):

- `aes_init()` — Initialize with 32-byte key and 16-byte IV
- `aes_encrypt()` — In-place encryption with PKCS7 padding
- `aes_decrypt()` — In-place decryption
- `crypto_random()` — CSPRNG via BCryptGenRandom

Ready for encrypted C2 communications and payload encryption.

---

## Malleable C2 Profiles

Profiles define how agent traffic appears on the network. Stored as YAML files in `profiles/`.

### Profile Structure

```yaml
name: "profile-name"
description: "Description"
sleep:
  interval: 60      # seconds between check-ins
  jitter: 15         # jitter percentage

user_agents:
  - "Mozilla/5.0 ..."

http:
  get:
    uri: ["/api/v1/analytics", "/api/v1/telemetry"]
    headers:
      Accept: "application/json"
    client:
      metadata: "header"
      output: "body"
    server:
      output: "body"
  post:
    uri: ["/api/v1/submit", "/api/v1/report"]
    headers:
      Content-Type: "application/json"
    client:
      output: "body"
    server:
      output: "body"
```

### Included Profiles


| Profile           | Style               | URIs                                                       |
| ----------------- | ------------------- | ---------------------------------------------------------- |
| `default`         | Web analytics API   | `/api/v1/analytics`, `/api/v1/telemetry`, `/api/v1/health` |
| `microsoft-graph` | Microsoft Graph API | `/v1.0/me/messages`, `/v1.0/me/drive/root/children`        |


---

## API Reference

### Authentication


| Method | Endpoint           | Description                  |
| ------ | ------------------ | ---------------------------- |
| `POST` | `/api/auth/login`  | Login (returns JWT)          |
| `POST` | `/api/auth/logout` | Logout                       |
| `GET`  | `/api/auth/me`     | Current operator info        |
| `POST` | `/api/operators`   | Create operator (admin only) |


### Listeners


| Method   | Endpoint                    | Description          |
| -------- | --------------------------- | -------------------- |
| `GET`    | `/api/listeners`            | List all listeners   |
| `POST`   | `/api/listeners`            | Create listener      |
| `GET`    | `/api/listeners/{id}`       | Get listener details |
| `POST`   | `/api/listeners/{id}/start` | Start listener       |
| `POST`   | `/api/listeners/{id}/stop`  | Stop listener        |
| `DELETE` | `/api/listeners/{id}`       | Delete listener      |


### Agents


| Method   | Endpoint           | Description       |
| -------- | ------------------ | ----------------- |
| `GET`    | `/api/agents`      | List all agents   |
| `GET`    | `/api/agents/{id}` | Get agent details |
| `DELETE` | `/api/agents/{id}` | Remove agent      |


### Tasks


| Method | Endpoint                      | Description           |
| ------ | ----------------------------- | --------------------- |
| `POST` | `/api/agents/{agentID}/tasks` | Create task for agent |
| `GET`  | `/api/agents/{agentID}/tasks` | List tasks for agent  |


**Create Task Body:**

```json
{
  "command": "whoami",
  "arguments": "optional args string"
}
```

### Payloads & BOFs


| Method   | Endpoint                       | Description            |
| -------- | ------------------------------ | ---------------------- |
| `POST`   | `/api/payloads/generate`       | Generate agent payload |
| `GET`    | `/api/payloads/bofs`           | List uploaded BOFs     |
| `POST`   | `/api/payloads/bofs`           | Upload BOF (multipart) |
| `DELETE` | `/api/payloads/bofs?id=<uuid>` | Delete BOF             |


### Profiles


| Method | Endpoint               | Description             |
| ------ | ---------------------- | ----------------------- |
| `GET`  | `/api/profiles`        | List malleable profiles |
| `GET`  | `/api/profiles/{name}` | Get profile details     |


### Events


| Method | Endpoint      | Description                 |
| ------ | ------------- | --------------------------- |
| `GET`  | `/api/events` | SSE stream (requires token) |


---

## Database Schema

Seven tables across PostgreSQL 16 with `pgcrypto` extension:

### operators


| Column          | Type        | Description                        |
| --------------- | ----------- | ---------------------------------- |
| `id`            | UUID (PK)   | Auto-generated                     |
| `username`      | VARCHAR(64) | Unique login name                  |
| `password_hash` | TEXT        | bcrypt hash                        |
| `role`          | VARCHAR(16) | `admin`, `operator`, or `readonly` |
| `created_at`    | TIMESTAMPTZ | Creation timestamp                 |
| `last_login`    | TIMESTAMPTZ | Last login time                    |


### listeners


| Column         | Type         | Description                          |
| -------------- | ------------ | ------------------------------------ |
| `id`           | UUID (PK)    | Auto-generated                       |
| `name`         | VARCHAR(128) | Human-friendly name                  |
| `protocol`     | VARCHAR(16)  | `http`, `https`, `dns`, `tcp`, `smb` |
| `bind_address` | VARCHAR(64)  | Default `0.0.0.0`                    |
| `bind_port`    | INTEGER      | Listener port                        |
| `status`       | VARCHAR(16)  | `active`, `inactive`, `error`        |
| `config`       | JSONB        | Additional configuration             |
| `created_at`   | TIMESTAMPTZ  | Creation timestamp                   |


### agents


| Column           | Type         | Description                 |
| ---------------- | ------------ | --------------------------- |
| `id`             | UUID (PK)    | Assigned at registration    |
| `hostname`       | VARCHAR(256) | Target hostname             |
| `username`       | VARCHAR(256) | Current user                |
| `os`             | VARCHAR(64)  | Operating system            |
| `arch`           | VARCHAR(32)  | Architecture                |
| `pid`            | INTEGER      | Process ID                  |
| `process_name`   | VARCHAR(256) | Agent binary path           |
| `internal_ip`    | VARCHAR(45)  | Internal IP                 |
| `external_ip`    | VARCHAR(45)  | External IP (from listener) |
| `sleep_interval` | INTEGER      | Beacon interval (seconds)   |
| `jitter`         | INTEGER      | Jitter percentage           |
| `listener_id`    | UUID (FK)    | Parent listener             |
| `first_seen`     | TIMESTAMPTZ  | First check-in              |
| `last_seen`      | TIMESTAMPTZ  | Last check-in               |


### tasks


| Column         | Type         | Description                                               |
| -------------- | ------------ | --------------------------------------------------------- |
| `id`           | UUID (PK)    | Auto-generated                                            |
| `agent_id`     | UUID (FK)    | Target agent                                              |
| `operator_id`  | UUID (FK)    | Issuing operator                                          |
| `command`      | VARCHAR(256) | Command name                                              |
| `arguments`    | BYTEA        | Command arguments                                         |
| `status`       | VARCHAR(16)  | `queued`, `delivered`, `completed`, `failed`, `cancelled` |
| `created_at`   | TIMESTAMPTZ  | Creation time                                             |
| `completed_at` | TIMESTAMPTZ  | Completion time                                           |


### task_results


| Column      | Type        | Description       |
| ----------- | ----------- | ----------------- |
| `id`        | UUID (PK)   | Auto-generated    |
| `task_id`   | UUID (FK)   | Parent task       |
| `agent_id`  | UUID (FK)   | Reporting agent   |
| `output`    | BYTEA       | Command output    |
| `success`   | BOOLEAN     | Execution success |
| `error`     | TEXT        | Error message     |
| `timestamp` | TIMESTAMPTZ | Result time       |


### credentials


| Column       | Type         | Description                                             |
| ------------ | ------------ | ------------------------------------------------------- |
| `id`         | UUID (PK)    | Auto-generated                                          |
| `agent_id`   | UUID (FK)    | Source agent                                            |
| `domain`     | VARCHAR(256) | Domain name                                             |
| `username`   | VARCHAR(256) | Credential username                                     |
| `secret`     | TEXT         | Password, hash, or token                                |
| `type`       | VARCHAR(32)  | `plaintext`, `ntlm`, `kerberos`, `certificate`, `token` |
| `source`     | VARCHAR(256) | Collection method                                       |
| `created_at` | TIMESTAMPTZ  | Collection time                                         |


### operations_log


| Column        | Type        | Description               |
| ------------- | ----------- | ------------------------- |
| `id`          | UUID (PK)   | Auto-generated            |
| `operator_id` | UUID (FK)   | Acting operator           |
| `agent_id`    | UUID (FK)   | Target agent              |
| `action`      | VARCHAR(64) | Action type               |
| `detail`      | JSONB       | Action metadata           |
| `mitre_id`    | VARCHAR(32) | MITRE ATT&CK technique ID |
| `timestamp`   | TIMESTAMPTZ | Event time                |


---

## Configuration Reference

### Team Server (`teamserver/config.yaml`)

```yaml
server:
  grpc_addr: "0.0.0.0:50051"       # gRPC listen address
  http_addr: "0.0.0.0:8443"        # HTTP API listen address
  agent_dir: "/path/to/agent"      # Agent source directory (for builder)
  tls:
    enabled: false                  # Enable TLS for HTTP API
    cert_file: ""                   # PEM certificate path
    key_file: ""                    # PEM key path
    ca_file: ""                     # CA certificate (mTLS)

database:
  postgres:
    host: "localhost"
    port: 5432
    user: "apex"
    password: "apex"
    dbname: "apex"
    sslmode: "disable"
  redis:
    addr: "localhost:6379"
    password: ""
    db: 0

auth:
  jwt_secret: "change-me-in-production"
  token_expiry: "24h"

logging:
  level: "debug"                    # trace, debug, info, warn, error
  pretty: true                      # Human-readable console output
```

---

## Deployment

### Docker Compose (Development)

```bash
make db          # Start PostgreSQL + Redis
make db-down     # Stop containers
make db-reset    # Wipe data and restart
```

`**deployments/docker-compose.yml**` provisions:

- **PostgreSQL 16 Alpine** — Port 5432, init from `migrations/001_initial.sql`
- **Redis 7 Alpine** — Port 6379
- Named volumes: `apex-pgdata`, `apex-redisdata`

### Systemd (Production)

```bash
# 1. Build the server
make server

# 2. Edit paths in the service file
vim deployments/apex-teamserver.service

# 3. Install and enable
sudo cp deployments/apex-teamserver.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now apex-teamserver

# 4. Check status
sudo systemctl status apex-teamserver
journalctl -u apex-teamserver -f
```

The systemd unit starts Docker containers (PostgreSQL + Redis) before launching the team server binary.

---

## Make Targets


| Target                | Description                                            |
| --------------------- | ------------------------------------------------------ |
| `make all`            | Generate protobuf + build server                       |
| `make proto`          | Regenerate Go code from `.proto` files                 |
| `make server`         | Build team server binary to `bin/teamserver`           |
| `make server-run`     | Build and run team server with config                  |
| `make run`            | Start databases + team server (via `scripts/start.sh`) |
| `make client-install` | Install client npm dependencies                        |
| `make client-dev`     | Start Vite dev server on port 1420                     |
| `make client-build`   | Production build of React client                       |
| `make client-tauri`   | Run Tauri desktop application                          |
| `make agent`          | Build agent EXE (requires MinGW)                       |
| `make db`             | Start PostgreSQL + Redis via Docker Compose            |
| `make db-down`        | Stop database containers                               |
| `make db-reset`       | Wipe volumes and restart databases                     |
| `make clean`          | Remove all build artifacts                             |


---

## Security Considerations

- **Change default credentials** — The seed operator `admin`/`apex` must be changed immediately
- **JWT secret** — Use a strong, random `auth.jwt_secret` (minimum 32 bytes)
- **TLS everywhere** — Enable TLS for the HTTP API, gRPC, and C2 listeners in production
- **Network isolation** — PostgreSQL and Redis should only be accessible from the team server
- **Reverse proxy** — Place the HTTP API behind a reverse proxy (nginx/caddy) for TLS termination and rate limiting
- **Agent OPSEC** — Disable unnecessary evasion features for each engagement to minimize footprint
- **BOF validation** — Only execute trusted BOFs; the loader runs arbitrary code in the agent's process
- **Credential storage** — The `credentials` table stores harvested secrets; encrypt at rest in production
- **Operations logging** — All operator actions are logged with MITRE ATT&CK IDs for audit and deconfliction

---

## Troubleshooting

### Agent not checking in

1. Verify the listener is started (green status in Listeners page)
2. Check that the callback host/port in the agent matches the listener
3. Ensure firewall rules allow inbound connections on the listener port
4. Check team server logs for incoming requests: `DBG Listener: incoming request`

### No command output in terminal

1. Verify SSE connection: look for `DBG SSE client connected` in server logs
2. Check that `agent_id` matches in task and result events
3. Ensure the agent binary was regenerated after code changes

### Build failures

1. Verify MinGW is installed: `x86_64-w64-mingw32-gcc --version`
2. Check that `server.agent_dir` in config points to the correct `agent/` directory
3. Review build output in server logs for compiler errors

### Database connection errors

1. Verify containers are running: `docker ps`
2. Check PostgreSQL connectivity: `psql -h localhost -U apex -d apex`
3. Check Redis connectivity: `redis-cli ping`

### SSE reconnection issues

1. The client auto-reconnects on SSE disconnection
2. If events are missed, refresh the page to re-sync agent state
3. Check browser DevTools Network tab for SSE stream status

---

## License

This software is intended for authorized security testing and research only. Unauthorized use against systems you do not own or have permission to test is illegal and unethical.