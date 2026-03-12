# Apex C2 Framework

A modern, modular Command & Control framework built for red team operations and adversary simulation. Features a Go team server, Tauri + React operator client, and multi-platform agents (Windows, Linux, macOS) with integrated evasion, BOF loading, token manipulation, and malleable C2 profiles.

```
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
```

<img width="1656" height="940" alt="image" src="https://github.com/user-attachments/assets/747c3eae-0d3f-45c3-9623-85167356b152" />


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
- [Agents](#agents)
  - [Windows Agent](#windows-agent)
  - [Linux Agent](#linux-agent)
  - [macOS Agent](#macos-agent)
- [Agent Builder](#agent-builder)
- [Token Manipulation (Windows)](#token-manipulation-windows)
- [Beacon Object Files (BOF)](#beacon-object-files-bof)
- [Evasion Capabilities](#evasion-capabilities)
  - [Windows Evasion](#windows-evasion)
  - [Linux Evasion](#linux-evasion)
  - [macOS Evasion](#macos-evasion)
- [Malleable C2 Profiles](#malleable-c2-profiles)
- [Listener Types](#listener-types)
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
                                    ┌───────────────────────────┐
                                    │     Apex Team Server      │
                                    │          (Go)             │
┌────────────────────┐              │                           │
│   Apex Client      │  REST/SSE   │  ┌──────┐ ┌───────────┐  │
│  (Tauri + React)   │◄═══════════►│  │Router │ │ Event Hub │  │
│                    │  JWT Auth    │  │(Chi)  │ │  (SSE)    │  │
│  - Dashboard       │              │  └──┬───┘ └─────┬─────┘  │
│  - Listeners       │              │     │           │        │
│  - Agents          │  gRPC+mTLS  │  ┌──┴───────────┴────┐   │
│  - Terminal        │◄═══════════►│  │   Agent Manager    │   │
│  - Agent Builder   │              │  │   Task Queue       │   │
│  - Modules (BOF)   │              │  └──┬───────────┬────┘   │
│  - Attack Graph    │              │     │           │        │
│  - MITRE ATT&CK    │              │  ┌──┴───┐ ┌────┴─────┐  │
│  - Settings        │              │  │  PG  │ │  Redis   │  │
└────────────────────┘              │  └──────┘ └──────────┘  │
                                    └──────────┬───────────────┘
                                               │
                              ┌────────────────┼────────────────┐
                              │                │                │
                    ┌─────────┴──────┐ ┌───────┴──────┐ ┌──────┴───────┐
                    │   Listeners    │ │   Listeners  │ │   Listeners  │
                    │ HTTP/HTTPS/mTLS│ │   TCP/DNS    │ │     SMB      │
                    └────────┬───────┘ └──────┬───────┘ └──────┬───────┘
                             │                │                │
                    ┌────────┴───────┐ ┌──────┴───────┐ ┌──────┴───────┐
                    │ Windows Agent  │ │ Linux Agent  │ │ macOS Agent  │
                    │  (C/WinHTTP)   │ │ (C/Sockets)  │ │ (C/Sockets)  │
                    │  EXE/DLL/BIN   │ │    ELF       │ │   Mach-O     │
                    └────────────────┘ └──────────────┘ └──────────────┘
```

> For detailed architecture diagrams and data flow diagrams (DFD) suitable for Microsoft Threat Modeling Tool, see [ARCHITECTURE.md](ARCHITECTURE.md).

---

## Feature Summary

### Team Server

- Multi-protocol listeners: HTTP, HTTPS, mTLS (mutual TLS), TCP, DNS, SMB
- JWT authentication with role-based access control (Admin, Operator, Readonly)
- Real-time event streaming via Server-Sent Events (SSE)
- Redis-backed task queue with pub/sub result delivery
- PostgreSQL persistence for agents, tasks, credentials, and operations log
- Malleable C2 profile support (YAML-based traffic shaping) with upload/management API
- gRPC service layer with auth interceptors for programmatic access
- Multi-platform agent builder (Windows, Linux, macOS) with per-platform evasion flags
- Agent deduplication (prevents duplicates from same host+user+IP within 24h)
- Server-side payload compilation pipeline

### Operator Client

- Cross-platform Tauri desktop application (also runs in browser)
- Real-time dashboard with agent status and listener health
- Per-agent interactive terminal with command history and tabbed sessions
- **Multi-platform Agent Builder** with Windows/Linux/macOS tabs and per-platform evasion toggles
- Modules page: BOF upload/management, malleable profile upload, evasion capability reference
- Attack graph visualization (React Flow)
- Automatic MITRE ATT&CK technique mapping
- OPSEC warning system (18 built-in rules with risk levels and safer alternatives)
- **Glitch/cyber-themed UI animations** — scan lines, RGB text glitch, pulse glow, card hover effects

### Windows Agent

- HTTP/HTTPS beacon over WinHTTP
- Configurable sleep interval with jitter (runtime-adjustable)
- Evasion: ETW patching, AMSI patching, ntdll unhooking, encrypted sleep (Ekko-style)
- In-memory BOF (Beacon Object File) loader with full Cobalt Strike BeaconAPI
- **Token manipulation**: steal_token, make_token, rev2self, getprivs, runas
- AES-256-CBC encryption via Windows CNG
- Multiple output formats: EXE, DLL, shellcode (.bin)
- Process listing, file download, directory navigation, shell execution

### Linux Agent

- HTTP beacon over raw TCP sockets (zero dependencies)
- Auto-daemonizes (forks to background, detaches from terminal)
- Evasion: ptrace anti-debug, TracerPid check, process name masking (`[kworker/u:0]`), argv overwrite, self-delete, LD_PRELOAD cleanup, sandbox/VM detection
- Same command set as Windows (adapted for POSIX: /bin/sh)
- Reports correct OS and architecture (amd64, arm64, arm)

### macOS Agent

- HTTP beacon over raw TCP sockets (zero dependencies)
- Auto-daemonizes
- Evasion: PT_DENY_ATTACH, sysctl P_TRACED check, process name masking, self-delete via `_NSGetExecutablePath`, DYLD environment cleanup, sandbox/VM detection
- LaunchAgent persistence support
- Same command set as Windows/Linux

---

## Technology Stack

| Component           | Technology                | Notes         |
| ------------------- | ------------------------- | ------------- |
| Team Server         | Go                        | 1.24+         |
| HTTP Router         | go-chi/chi/v5             | v5.x          |
| Authentication      | golang-jwt/jwt/v5, bcrypt |               |
| Database            | PostgreSQL                | 16            |
| Queue / Pub-Sub     | Redis                     | 7             |
| gRPC                | google.golang.org/grpc    |               |
| Serialization       | Protocol Buffers          | proto3        |
| Client Framework    | Tauri                     | 2.5           |
| Client UI           | React, TypeScript         | 19.x, 5.8    |
| Build Tool          | Vite                      | 6.x           |
| State Management    | Zustand                   | 5.x           |
| Styling             | Tailwind CSS              | 4.x           |
| Icons               | Lucide React              |               |
| Graph Visualization | @xyflow/react             |               |
| Windows Agent       | C (MinGW cross-compiled)  |               |
| Linux Agent         | C (GCC native)            |               |
| macOS Agent         | C (clang / osxcross)      |               |

---

## Fresh Machine Setup

### Ubuntu / Debian / Parrot OS

```bash
sudo apt update
sudo apt install -y build-essential git curl unzip

# Go (1.22+)
wget https://go.dev/dl/go1.26.1.linux-amd64.tar.gz
rm -rf /usr/local/go && tar -C /usr/local -xzf go1.26.1.linux-amd64.tar.gz
export PATH=$PATH:/usr/local/go/bin
source ~/.bashrc


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
```

### Verify Installation

```bash
go version                          # 1.22+
node --version                      # v20+
rustc --version                     # 1.70+
x86_64-w64-mingw32-gcc --version    # MinGW
gcc --version                       # GCC (Linux agent)
docker --version                    # 20+
```

---

## Quick Start

### 1. Clone and enter project

```bash
git clone https://github.com/hrdebraj/Apex.git
cd Apex
```

### 2. Start databases

```bash
make db
```

### 3. Configure team server

Edit `teamserver/config.yaml` — set `server.agent_dir`, database credentials, and `auth.jwt_secret`.

### 4. Build and run team server

```bash
make server-run
```

Listens on **HTTP API**: `0.0.0.0:8443` and **gRPC**: `0.0.0.0:50051`.

### 5. Run the operator client

```bash
cd client && npm install && npm run tauri dev
```

Or use the pre-built binary from `release/apex-client`.

### 6. Login

Default credentials: `admin` / `apex`

### 7. Create a listener and deploy

Listeners > Create > HTTP/HTTPS/mTLS > Start > Agent Builder > Select platform > Generate > Deploy

---

## Project Structure

```
apex/
├── teamserver/                     # Go team server
│   ├── cmd/teamserver/             #   Entry point (main.go)
│   ├── internal/
│   │   ├── agents/                 #   Agent manager, lifecycle, events
│   │   ├── api/                    #   REST handlers, router, SSE, profile & payload handlers
│   │   ├── auth/                   #   JWT, bcrypt, RBAC
│   │   ├── builder/                #   Multi-platform payload compilation pipeline
│   │   ├── config/                 #   YAML config loader
│   │   ├── db/                     #   PostgreSQL + Redis clients
│   │   ├── grpc/                   #   gRPC service implementations
│   │   ├── listeners/              #   HTTP, HTTPS, mTLS, TCP, DNS listener engines
│   │   ├── profile/                #   Malleable profile parser
│   │   ├── server/                 #   Server orchestration
│   │   └── tasks/                  #   Redis task queue + pub/sub
│   └── pkg/proto/apexpb/           #   Generated protobuf Go code
│
├── client/                         # Tauri + React operator client
│   ├── src/
│   │   ├── pages/                  #   Dashboard, Listeners, Agents, Terminal,
│   │   │                           #   AgentBuilder, Modules, Graph, Mitre, Settings
│   │   ├── stores/                 #   Zustand state management
│   │   ├── services/               #   API client, task, listener, payload services
│   │   ├── components/             #   Layout, Sidebar (glitch effects), TopBar
│   │   ├── styles/                 #   globals.css (glitch, scan line, pulse animations)
│   │   └── hooks/                  #   useSSE, usePolling
│   └── src-tauri/                  #   Rust Tauri backend
│
├── agent/                          # Multi-platform C agents
│   ├── main.c                      #   Windows beacon loop, HTTP (WinHTTP), command dispatch
│   ├── agent_posix.c               #   Linux/macOS beacon loop, HTTP (raw sockets)
│   ├── evasion.h                   #   Windows: ETW/AMSI patching, encrypted sleep, ntdll unhook
│   ├── evasion_linux.h             #   Linux: ptrace, process mask, self-delete, sandbox detect
│   ├── evasion_macos.h             #   macOS: PT_DENY_ATTACH, sysctl, DYLD cleanup
│   ├── bof.h                       #   COFF/BOF loader with BeaconAPI
│   ├── token.h                     #   Windows: steal_token, make_token, rev2self, getprivs, runas
│   ├── crypto.h                    #   AES-256-CBC (CNG), XOR string encryption
│   └── Makefile                    #   Multi-platform: exe, dll, shellcode, linux-elf, macos-macho
│
├── profiles/                       # Malleable C2 profiles (7 pre-built)
│   ├── amazon.yaml                 #   AWS-style traffic
│   ├── microsoft.yaml              #   Microsoft 365/Azure traffic
│   ├── google.yaml                 #   Google services traffic
│   ├── cloudflare.yaml             #   Cloudflare API traffic
│   ├── slack.yaml                  #   Slack API traffic
│   ├── github.yaml                 #   GitHub API v3 traffic
│   └── default.yaml                #   Generic web browsing traffic
│
├── proto/                          # Protobuf definitions
├── migrations/                     # PostgreSQL schema
├── deployments/                    # Docker Compose, systemd unit
├── release/                        # Pre-built binaries (teamserver, apex-client)
└── Makefile                        # Root build orchestration
```

---

## Team Server

### Components

| Package                  | Responsibility                                                        |
| ------------------------ | --------------------------------------------------------------------- |
| `agents/manager.go`      | Agent registry, PostgreSQL persistence, dedup, check-in, events       |
| `api/router.go`          | Chi HTTP router with CORS, JWT middleware                             |
| `api/payload_handler.go` | Multi-platform payload generation, BOF CRUD                          |
| `api/profile_handler.go` | Malleable profile list, upload, delete                                |
| `api/events.go`          | SSE event hub for real-time streaming                                 |
| `auth/service.go`        | JWT generation/validation, bcrypt, RBAC                               |
| `builder/builder.go`     | Multi-platform build pipeline (Windows/Linux/macOS)                   |
| `listeners/http.go`      | HTTP/HTTPS listener — registration, check-in, task delivery          |
| `listeners/mtls.go`      | mTLS listener — mutual certificate authentication                    |
| `listeners/tcp.go`       | TCP listener (length-prefixed framing)                                |
| `listeners/dns.go`       | DNS listener (TXT/A responses)                                        |
| `profile/profile.go`     | Malleable profile YAML parser                                         |
| `tasks/queue.go`         | Redis task queue with pub/sub result delivery                         |

### Authentication & Authorization

| Role       | Permissions                                                     |
| ---------- | --------------------------------------------------------------- |
| `admin`    | Full access — create operators, manage listeners, agents, tasks |
| `operator` | Create/manage listeners and tasks, view agents                  |
| `readonly` | View-only access to all resources                               |

### Real-Time Events (SSE)

| Event Type           | Trigger                         |
| -------------------- | ------------------------------- |
| `agent:registered`   | New agent registers             |
| `agent:checked_in`   | Agent beacon check-in           |
| `agent:disconnected` | Agent missed check-in threshold |
| `agent:task_result`  | Task result received from agent |

---

## Operator Client

### Pages

| Page          | Description                                                     |
| ------------- | --------------------------------------------------------------- |
| Dashboard     | Agent count, listener status, recent activity                   |
| Listeners     | Create HTTP/HTTPS/mTLS/TCP/DNS/SMB listeners                   |
| Agents        | Live agent table with OS, hostname, user, PID, last check-in   |
| Terminal      | Per-agent interactive shell with history and tabbed sessions    |
| Agent Builder | **Windows/Linux/macOS** tabs with per-platform evasion toggles |
| Modules       | BOF management, malleable profile upload, evasion reference     |
| Attack Graph  | Visual attack path graph                                        |
| MITRE ATT&CK  | Technique mapping for executed commands                         |
| Settings      | Server connection and operator preferences                      |

### Terminal Commands

**Agent commands (sent to implant):**

| Command                         | Description                              |
| ------------------------------- | ---------------------------------------- |
| `whoami`                        | Current user + admin/root status         |
| `getuid`                        | User info with PID and privilege         |
| `ps`                            | Process listing                          |
| `pwd`                           | Print current working directory          |
| `cd <path>`                     | Change directory                         |
| `download <path>`               | Download file from target                |
| `shell <cmd>`                   | Execute shell command                    |
| `sleep <sec> [jitter%]`         | Change beacon interval                   |
| `bof <b64_obj> [b64_args]`      | Execute BOF in-memory                    |
| `steal_token <pid>`             | Steal token from process (Windows)       |
| `make_token <user> <pass>`      | Create token with credentials (Windows)  |
| `rev2self`                      | Revert to original token (Windows)       |
| `getprivs`                      | List token privileges (Windows)          |
| `runas <user> <pass> <cmd>`     | Run command as another user (Windows)    |
| `exit`                          | Terminate agent                          |

---

## Agents

### Windows Agent

**Source**: `agent/main.c` + `evasion.h` + `bof.h` + `token.h` + `crypto.h`

| File        | Purpose                                                          |
| ----------- | ---------------------------------------------------------------- |
| `main.c`    | Beacon loop (WinHTTP), command dispatch, JSON/base64 helpers     |
| `evasion.h` | ETW/AMSI patching, encrypted sleep (Ekko), ntdll unhooking      |
| `bof.h`     | COFF loader with full Cobalt Strike BeaconAPI                    |
| `token.h`   | Token steal, make_token, rev2self, getprivs, runas               |
| `crypto.h`  | AES-256-CBC via Windows CNG, XOR encryption, CSPRNG              |

**Compile-time flags**: `ENABLE_ETW_PATCH`, `ENABLE_AMSI_PATCH`, `ENABLE_SLEEP_ENCRYPT`, `ENABLE_UNHOOK`

**Output formats**: EXE, DLL, Shellcode (.bin), Service EXE

### Linux Agent

**Source**: `agent/agent_posix.c` + `evasion_linux.h`

- Raw TCP socket HTTP client (zero external dependencies)
- Compiles natively on the team server with `gcc`
- Auto-daemonizes (double-fork, setsid, stdio redirect)
- Masquerades as `[kworker/u:0]` in process listings
- Reports OS as "Linux", detects architecture (amd64/arm64/arm)

**Compile-time flags**: `ENABLE_ANTI_DEBUG`, `ENABLE_PROC_MASK`, `ENABLE_SELF_DELETE`, `ENABLE_ENV_CLEAN`, `ENABLE_SANDBOX_CHECK`

**Output**: ELF binary

### macOS Agent

**Source**: `agent/agent_posix.c` + `evasion_macos.h` (shared POSIX source with `#ifdef __APPLE__`)

- Same raw socket HTTP client as Linux
- Cross-compilation requires `osxcross` toolchain (or native clang on macOS)
- Supports LaunchAgent persistence via plist generation

**Compile-time flags**: Same as Linux

**Output**: Mach-O binary

---

## Agent Builder

The Agent Builder UI provides **three platform tabs** — Windows, Linux, macOS — each with platform-specific output formats and evasion toggles.

### Build Pipeline

```
Client (AgentBuilderPage)
  │  POST /api/payloads/generate
  │  { platform, output_format, listener_id, evasion_opts... }
  ▼
PayloadHandler.Generate()
  │  Resolve platform → Windows/Linux/macOS
  │  Resolve listener → c2_host, c2_port, use_https
  │  Build EvasionOpts or PosixEvasionOpts
  ▼
builder.BuildBase64()
  │  ResolveAgentDir()
  │  Set env vars: C2_HOST, C2_PORT, platform evasion flags
  │  exec: make -C agent/ clean
  │  exec: make -C agent/ exe|dll|shellcode|linux-elf|macos-macho
  │  Read output → base64 encode
  ▼
Response → Client downloads binary
```

### Make Targets

| Platform | Target        | Compiler                | Output        |
| -------- | ------------- | ----------------------- | ------------- |
| Windows  | `exe`         | x86_64-w64-mingw32-gcc  | `agent.exe`   |
| Windows  | `dll`         | x86_64-w64-mingw32-gcc  | `agent.dll`   |
| Windows  | `shellcode`   | x86_64-w64-mingw32-gcc  | `agent.bin`   |
| Linux    | `linux-elf`   | gcc (native)            | `agent_linux` |
| macOS    | `macos-macho` | o64-clang / clang       | `agent_macos` |

---

## Token Manipulation (Windows)

The Windows agent includes Cobalt Strike-style token manipulation via `token.h`:

| Command                     | Windows API                      | Description                             |
| --------------------------- | -------------------------------- | --------------------------------------- |
| `steal_token <pid>`         | OpenProcess → DuplicateTokenEx   | Steal and impersonate a process token   |
| `make_token <user> <pass>`  | LogonUserA (NEW_CREDENTIALS)     | Create token with credentials           |
| `rev2self`                  | RevertToSelf                     | Revert to original process token        |
| `getprivs`                  | GetTokenInformation              | List all privileges (enabled/disabled)  |
| `runas <user> <pass> <cmd>` | CreateProcessWithLogonW          | Execute command as another user         |

---

## Beacon Object Files (BOF)

Full in-memory COFF loader compatible with Cobalt Strike BOFs. Supports x86_64 relocations, `__imp_Library$Function` symbol resolution, and these BeaconAPI functions:

`BeaconDataParse`, `BeaconDataInt`, `BeaconDataShort`, `BeaconDataLength`, `BeaconDataExtract`, `BeaconOutput`, `BeaconPrintf`, `BeaconUseToken`, `BeaconRevertToken`, `BeaconIsAdmin`, `BeaconGetSpawnTo`, `BeaconSpawnTemporaryProcess`, `BeaconInjectProcess`, `BeaconInjectTemporaryProcess`

### Available BOF Templates

| BOF           | MITRE   | Description                                              |
| ------------- | ------- | -------------------------------------------------------- |
| `whoami.o`    | T1033   | Current user/domain/privilege via Windows API            |
| `netstat.o`   | T1049   | Active connections without spawning netstat.exe           |
| `dir_list.o`  | T1083   | Directory enumeration via FindFirstFile/FindNextFile     |
| `reg_query.o` | T1012   | Registry key/value queries via RegOpenKeyEx              |
| `env_vars.o`  | T1082   | Dump all environment variables                           |
| `arp_table.o` | T1016   | Read ARP cache via GetIpNetTable                         |

### API

| Method   | Endpoint                       | Description                  |
| -------- | ------------------------------ | ---------------------------- |
| `GET`    | `/api/payloads/bofs`           | List uploaded BOFs           |
| `POST`   | `/api/payloads/bofs`           | Upload BOF (.o/.obj)         |
| `DELETE` | `/api/payloads/bofs?id=<uuid>` | Delete BOF                   |

---

## Evasion Capabilities

### Windows Evasion

| Technique          | Description                                                                       |
| ------------------ | --------------------------------------------------------------------------------- |
| ETW Patching       | Patches `EtwEventWrite` in ntdll.dll (`xor eax,eax; ret`) to blind EDR telemetry |
| AMSI Patching      | Patches `AmsiScanBuffer` to return `E_INVALIDARG`, bypassing script scanning     |
| Encrypted Sleep    | XOR-encrypts agent memory during sleep via `SystemFunction032` (Ekko-style)      |
| ntdll Unhooking    | Replaces hooked ntdll .text section from clean `SEC_IMAGE` disk mapping          |
| XOR String Encrypt | Compile-time XOR encryption of string literals                                    |
| AES-256-CBC        | Full CNG-based encryption ready for encrypted C2 comms                            |
| Token Manipulation | Steal, create, impersonate tokens; list privileges; run as other users           |

### Linux Evasion

| Technique          | Description                                                          |
| ------------------ | -------------------------------------------------------------------- |
| Anti-Debug         | `ptrace(PTRACE_TRACEME)` + `/proc/self/status` TracerPid check     |
| Process Masking    | `prctl(PR_SET_NAME)` + argv overwrite → appears as `[kworker/u:0]` |
| Self-Delete        | Unlinks binary from disk via `/proc/self/exe` readlink + unlink     |
| LD_PRELOAD Cleanup | Removes `LD_PRELOAD` and `LD_AUDIT` from environment               |
| Sandbox Detection  | Checks CPU count (<2), RAM (<1GB), uptime (<120s)                   |
| Timestomping       | Backdates file modification times via `utimensat`                    |

### macOS Evasion

| Technique          | Description                                                        |
| ------------------ | ------------------------------------------------------------------ |
| Anti-Debug         | `ptrace(PT_DENY_ATTACH)` + sysctl `P_TRACED` flag check          |
| Process Masking    | argv overwrite to hide true process name                           |
| Self-Delete        | `_NSGetExecutablePath` + realpath + unlink                         |
| DYLD Cleanup       | Strips `DYLD_INSERT_LIBRARIES`, `DYLD_FORCE_FLAT_NAMESPACE`, etc |
| Sandbox Detection  | sysctl CPU count + `hw.memsize` check                              |
| Persistence        | LaunchAgent plist writer for user-level persistence                |

---

## Malleable C2 Profiles

Profiles shape agent HTTP traffic to mimic legitimate services. Stored as YAML in `profiles/`. Upload via the Modules page or place files directly in the directory.

### Pre-built Profiles

| Profile      | Mimics              | Sleep | Jitter |
| ------------ | -------------------- | ----- | ------ |
| `amazon`     | AWS SDK/EC2          | 90s   | 25%    |
| `microsoft`  | Microsoft 365/Azure  | 75s   | 20%    |
| `google`     | Google Services      | 60s   | 20%    |
| `cloudflare` | Cloudflare API       | 45s   | 15%    |
| `slack`      | Slack API            | 55s   | 18%    |
| `github`     | GitHub API v3        | 70s   | 22%    |
| `default`    | Generic web traffic  | 60s   | 20%    |

### Profile API

| Method   | Endpoint               | Description             |
| -------- | ---------------------- | ----------------------- |
| `GET`    | `/api/profiles`        | List all profiles       |
| `POST`   | `/api/profiles`        | Upload profile (.yaml)  |
| `GET`    | `/api/profiles/{name}` | Get profile details     |
| `DELETE` | `/api/profiles/{name}` | Delete profile          |

---

## Listener Types

| Protocol | Description                                               | Agent Support        |
| -------- | --------------------------------------------------------- | -------------------- |
| HTTP     | Plain HTTP listener for agent check-ins                   | Windows, Linux, macOS |
| HTTPS    | TLS-encrypted HTTP with auto-generated or custom certs    | Windows, Linux, macOS |
| mTLS     | Mutual TLS — server and client both present certificates | Windows               |
| TCP      | Raw TCP with length-prefixed framing                      | Windows               |
| DNS      | DNS tunneling via subdomains and TXT records              | Windows               |
| SMB      | Named pipe communication (planned)                        | Windows               |

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

### Payloads

| Method | Endpoint                 | Description            |
| ------ | ------------------------ | ---------------------- |
| `POST` | `/api/payloads/generate` | Generate agent payload |

### Events

| Method | Endpoint      | Description                 |
| ------ | ------------- | --------------------------- |
| `GET`  | `/api/events` | SSE stream (requires token) |

---

## Database Schema

Seven tables across PostgreSQL 16: `operators`, `listeners`, `agents`, `tasks`, `task_results`, `credentials`, `operations_log`.

Key relationships:
- `agents.listener_id` → `listeners.id`
- `tasks.agent_id` → `agents.id`
- `task_results.task_id` → `tasks.id`
- `credentials.agent_id` → `agents.id`
- `operations_log.operator_id` → `operators.id`

---

## Configuration Reference

### Team Server (`teamserver/config.yaml`)

```yaml
server:
  grpc_addr: "0.0.0.0:50051"
  http_addr: "0.0.0.0:8443"
  agent_dir: "/path/to/agent"
  tls:
    enabled: false
    cert_file: ""
    key_file: ""
    ca_file: ""

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
  level: "debug"
  pretty: true
```

---

## Deployment

### Docker Compose (Development)

```bash
make db          # Start PostgreSQL + Redis
make db-down     # Stop containers
make db-reset    # Wipe data and restart
```

### Systemd (Production)

```bash
make server
sudo cp deployments/apex-teamserver.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now apex-teamserver
```

---

## Make Targets

| Target                | Description                                    |
| --------------------- | ---------------------------------------------- |
| `make all`            | Generate protobuf + build server               |
| `make server`         | Build team server binary                       |
| `make server-run`     | Build and run team server                      |
| `make client-install` | Install client npm dependencies                |
| `make client-dev`     | Start Vite dev server                          |
| `make client-build`   | Production build of React client               |
| `make agent`          | Build Windows agent EXE                        |
| `make db`             | Start PostgreSQL + Redis                       |
| `make clean`          | Remove all build artifacts                     |

---

## Security Considerations

- **Change default credentials** — `admin`/`apex` must be changed immediately
- **JWT secret** — Use a strong, random `auth.jwt_secret` (minimum 32 bytes)
- **TLS everywhere** — Enable TLS/mTLS for API, gRPC, and C2 listeners
- **Network isolation** — PostgreSQL and Redis should only be accessible from the team server
- **Agent OPSEC** — Disable unnecessary evasion features per engagement
- **BOF validation** — Only execute trusted BOFs
- **Token hygiene** — Use `rev2self` after token operations to prevent detection

---

## Troubleshooting

### Agent not checking in

1. Verify the listener is started (green status)
2. Check callback host/port matches the listener
3. Ensure firewall allows inbound on the listener port
4. Check server logs for `DBG Listener: incoming request`

### Build failures

1. Windows: verify MinGW — `x86_64-w64-mingw32-gcc --version`
2. Linux: verify GCC — `gcc --version`
3. macOS: verify osxcross or native clang
4. Check `server.agent_dir` in config

### Database connection errors

1. Verify containers: `docker ps`
2. Test PostgreSQL: `psql -h localhost -U apex -d apex`
3. Test Redis: `redis-cli ping`

---

## Roadmap / TODO

> Check off items as they are completed. Items marked 🔴 are critical gaps vs Cobalt Strike, 🟡 are important enhancements, and 🟢 are advanced/premium features.

### 🧠 Windows Agent — Evasion & Stealth

- [ ] 🔴 **Implement Ekko / Foliage encrypted sleep** — `encrypted_sleep()` in `evasion.h` is a stub calling plain `Sleep()`. Implement ROP-based timer sleep (Ekko / Foliage) so agent memory is XOR-encrypted while waiting.
- [ ] 🔴 **Indirect syscalls (HellsGate / HalosGate)** — Read SSNs directly from ntdll on disk and execute `syscall` inline, bypassing all user-mode hooks regardless of EDR re-hooking.
- [ ] 🔴 **Heap encryption during sleep** — XOR-encrypt malloc'd heap regions containing `g_agent_id`, C2 host, etc. during sleep so memory dumps reveal nothing.
- [ ] 🔴 **PE header stomping** — Overwrite `MZ`/`PE` magic and key header fields in-memory after load to defeat `pe-sieve` and memory scanners.
- [ ] 🔴 **PPID spoofing** — Set parent PID to `explorer.exe` / `svchost.exe` when spawning subprocesses to defeat parent-child chain anomaly detection.
- [ ] 🔴 **Replace `CreateProcessA` with `NtCreateUserProcess` syscall** — Avoid `CreateProcess` ETW events in `exec_cmd()`.
- [ ] 🟡 **Stack spoofing** — Spoof call stacks during sleep/wait states to defeat tools like `Hunt-Sleeping-Beacons`.
- [ ] 🟡 **Module stomping for execution** — Write shellcode into the `.text` section of a legitimate loaded DLL instead of new `VirtualAlloc(RWX)` memory to avoid private RWX IOC.
- [ ] 🟡 **Thread creation via `NtCreateThreadEx`** — Replace `CreateThread` with lower-level NT API to reduce event generation.
- [ ] 🟡 **Wire malleable profile headers to agent at build time** — Agent hardcodes `Mozilla/5.0`; inject profile URI, headers, and User-Agent as compile-time `-D` flags.
- [ ] 🟡 **Compile-time string/config encryption** — XOR or AES128-encrypt C2 host, port, and path literals; decrypt at runtime only.
- [ ] 🟡 **PE `TimeDateStamp` backdating** — Builder should set a plausible historical date after compile to defeat timestamp-based IOC rules.
- [ ] 🟢 **Heaven's Gate (32→64 bit transition)** — Execute syscalls via WOW64 Heaven's Gate for 32-bit evasion.
- [ ] 🟢 **Persistence modules** — Registry Run, Task Scheduler, COM hijack (Windows); LaunchAgent already exists for macOS.
- [ ] 🟢 **Alternative transports** — DNS-over-HTTPS, ICMP, Slack webhook implant variants to evade network DPI.

### 🐧 Linux / macOS Agent — Evasion & Capability

- [ ] 🔴 **Implement TLS/HTTPS in POSIX agent** — `http_post()` ignores `use_https` (`(void)use_https`). Add OpenSSL/mbedTLS static link for HTTPS beaconing. All Linux/macOS C2 is currently cleartext.
- [ ] 🔴 **`upload` command** — Neither agent has file upload (write to target). Add `handle_upload()` and a server-side receive endpoint.
- [ ] 🔴 **Multi-task per beacon** — Agent handles exactly one task per HTTP round-trip. Return and process a batch of queued tasks per beacon cycle.
- [ ] 🟡 **Built-in `ls`/`dir` command** — Avoid spawning a child `ls` process; implement using `readdir()` directly.
- [ ] 🟡 **Chunked file download** — Downloads hard-cap at 64 KB (`BUF_SIZE`). Implement multi-chunk requests for large files.
- [ ] 🟡 **Process injection on Linux** — Add `inject` using `ptrace()` + `mmap` or `memfd_create()` + `/proc/PID/mem`.
- [ ] 🟡 **Linux persistence commands** — cron, systemd user unit, `.bashrc`/`.profile` injection, setuid abuse.
- [ ] 🟢 **Unix domain socket / FIFO pivot channel** — Relay C2 traffic via named FIFO between agents for internal pivoting.

### 🖥️ Team Server — Protocol & Infrastructure

- [ ] 🔴 **Staged payload delivery** — Add a tiny stager (PS one-liner / shellcode dropper) that downloads the full payload at runtime. Reduces initial binary size and evades static AV.
- [ ] 🔴 **Payload obfuscation pipeline** — Pass built binary through `donut` (EXE→shellcode) or a custom packer/encoder before delivery.
- [ ] 🔴 **End-to-end encrypted C2 channel** — `crypto.h` has AES-256 but it is **never used for C2 comms**. Implement Curve25519 ECDH key exchange at first check-in, then AES-256-GCM for all traffic.
- [ ] 🟡 **Per-agent task batch queue** — Server returns multiple pending tasks per beacon; agent processes all and returns all results in one HTTP response.
- [ ] 🟡 **Kill date & working-hours constraint** — Configurable kill date and beacon window (e.g., Mon–Fri 09:00–18:00) to reduce after-hours detection.
- [ ] 🟡 **Domain fronting support** — Add `Host` header override on HTTP/HTTPS listeners for domain fronting.
- [ ] 🟡 **Redirector config generator** — Output Apache/Nginx redirector config so non-agent traffic is proxied to a legitimate site.
- [ ] 🟡 **SMB named-pipe listener** — Fully implement the planned Windows named-pipe listener (`\\.\pipe\<name>`) for internal pivoting.
- [ ] 🟡 **Agent auto-update** — Track agent version; push replacement payload to upgrade in-place.
- [ ] 🟡 **Multi-operator task locking** — Prevent two operators from sending conflicting tasks to the same agent simultaneously.
- [ ] 🟢 **P2P / pivot chains** — Agent relay mode that proxies C2 for another internal agent (SOCKS or named-pipe pivot).
- [ ] 🟢 **External C2 plugin API** — gRPC / REST hooks for third-party C2 channel plugins (Slack, Dropbox, DoH).

### 🔧 Team Server — Missing Core Features vs Cobalt Strike

- [ ] 🔴 **Credentials vault & auto-capture** — `credentials` table exists but nothing populates it. Add `hashdump`, `logonpasswords` (Mimikatz BOF), and auto-parse BOF output into the table.
- [ ] 🔴 **Keylogger** — `SetWindowsHookEx`-based keylogger running as a BOF, streaming output back.
- [ ] 🔴 **Screenshot** — `screenshot` command via Windows GDI `BitBlt` / Linux X11 `XGetImage`.
- [ ] 🔴 **Port scanner** — Built-in `portscan <CIDR> <ports>` TCP connect scan on the agent (no external tools needed).
- [ ] 🔴 **Lateral movement modules** — `wmiexec`, `psexec`, `smbexec`, `dcom` (BOF-based).
- [ ] 🟡 **Clipboard capture** — `GetClipboardData` (Windows) / `xclip`/`pbpaste` (POSIX).
- [ ] 🟡 **Webcam capture** — Windows DirectShow API / `gstreamer` on Linux.
- [ ] 🟡 **Token state display in terminal** — Current impersonated token should be shown in the terminal header bar.
- [ ] 🟡 **Full operations log UI** — `operations_log` table is only partially used. Log every task/result/operator action; surface in client.
- [ ] 🟡 **Credential-based auto-spray** — Use stored credentials against SMB, WinRM, SSH via BOFs.
- [ ] 🟢 **Active Directory recon BOFs** — `ldapsearch`, domain trust enum, SPN query, BloodHound ingestor.
- [ ] 🟢 **Kerberos attacks** — `asktgt`, Kerberoasting, AS-REP roasting using token manipulation infrastructure.

### 🎨 Operator Client — UI / UX

- [ ] 🔴 **Build out Attack Graph page** — `GraphPage.tsx` is 569 bytes / empty. Wire real agent & pivot data into `@xyflow/react`.
- [ ] 🔴 **Interactive file browser** — Tree-based UI calling `ls`/`pwd`/`cd` with drag-to-download and click-to-upload.
- [ ] 🔴 **Process tree visualisation** — Parse `ps` output into a hierarchical tree with icons, privilege indicators, and right-click actions (inject, kill, migrate).
- [ ] 🟡 **Terminal auto-complete & syntax highlighting** — Upgrade to CodeMirror / Monaco with command auto-complete and colourised output.
- [ ] 🟡 **Agent comparison view** — Side-by-side sysinfo diff when multiple agents are selected.
- [ ] 🟡 **Live beacon countdown timer** — Show countdown to next expected check-in in the Agents table.
- [ ] 🟡 **Shared operator notes (markdown scratchpad)** — Collaborative SSE-backed notes per operation, similar to CS Event Log.
- [ ] 🟡 **Light / stealth theme** — Toggle between glitch-dark and a clean professional-light theme.
- [ ] 🟡 **Configurable OPSEC rules** — Move the 18 hardcoded OPSEC rules to PostgreSQL; make them editable per engagement.
- [ ] 🟡 **Credential manager page** — Dedicated UI to view, tag, edit, and export the credentials table.
- [ ] 🟡 **Listener health heartbeat** — Real-time port-open check beyond just `running/stopped` status.
- [ ] 🟡 **Agent tagging & grouping** — Tag agents (e.g., `dc`, `workstation`) and filter by tag for large engagements.
- [ ] 🟡 **Exfil download manager** — Progress bars for chunked exfil, download history, per-file hash display.
- [ ] 🟢 **Integrated report generator** — One-click PDF / JSON export of full operation timeline with MITRE mappings and credentials.
- [ ] 🟢 **Command macros / playbooks** — Save command sequences as named playbooks and execute against any agent.

### 🔌 BOF Loader & Module System

- [ ] 🔴 **Fix IAT `VirtualAlloc` leak in `bof.h`** — `resolve_bof_import()` allocates memory for every `__imp_` symbol and never frees it. Track and free all IAT allocations.
- [ ] 🔴 **Implement `BeaconInjectProcess` / `BeaconInjectTemporaryProcess`** — Both are currently complete no-ops. Implement `VirtualAllocEx` + `WriteProcessMemory` + `CreateRemoteThread` injection.
- [ ] 🟡 **BOF argument packer in client UI** — Build a typed Pack API so operators specify string/int/bytes args and the client serialises them in the correct binary format (like CS's `bof_pack`).
- [ ] 🟡 **Expand built-in BOF library** — Add: `Seatbelt`, `Rubeus`, `SharpView`, `nanodump`, `unhook-bof`.
- [ ] 🟡 **Categorised BOF storage** — Tag BOFs by category (privesc, persistence, recon, lateral movement) in the database.
- [ ] 🟢 **x86 BOF support** — Add COFF loader for `IMAGE_FILE_MACHINE_I386` targets.

### ⚙️ DevOps, Build & Packaging

- [ ] 🔴 **Hermetic Docker build environment** — `Dockerfile.builder` with pinned MinGW/GCC versions for reproducible, deterministic payloads.
- [ ] 🟡 **CI/CD pipeline (GitHub Actions)** — Automated `go test ./...`, linting, and headless builder smoke-test on every push.
- [ ] 🟡 **Agent C unit tests** — Test harness for BOF loader, base64, JSON parser, and crypto functions.
- [ ] 🟡 **Build cache** — Cache compiled payloads keyed on `(platform, c2_host, c2_port, evasion_flags_hash)` in Redis/filesystem. Eliminate repeated 10–30 s builds.
- [ ] 🟡 **One-command installer script** — `setup.sh` installing all deps, building the server binary, and generating a self-signed TLS cert.
- [ ] 🟢 **Signed release binaries** — GPG-signed server releases with reproducible build attestation.
- [ ] 🟢 **Multi-teamserver federation** — Share agents, credentials, and op logs across teamserver instances via gRPC for large red team engagements.

### 🔒 Security Hardening

- [ ] 🔴 **Default HTTPS on REST API** — Auto-generate a self-signed cert at startup so the API is never exposed over plaintext by default.
- [ ] 🔴 **mTLS for operator client** — Optional mutual TLS between the Tauri client and teamserver so only clients with the right cert can connect, even with a stolen JWT.
- [ ] 🟡 **Rate limiting on check-in endpoint** — Redis-backed rate limiter per source IP to prevent fake agent registration floods.
- [ ] 🟡 **Agent IP allowlist** — Restrict which source IPs can register new agents.
- [ ] 🟡 **Enforce default credential change** — Refuse to start if `jwt_secret` is still `change-me-in-production`; force admin password change on first login.
- [ ] 🟡 **One-time payload download token** — Require a unique token per agent build download to prevent unauthorised payload retrieval.

---

## License

This software is intended for authorized security testing and research only. Unauthorized use against systems you do not own or have permission to test is illegal and unethical.
