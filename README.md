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

<img width="1696" height="916" alt="image" src="https://github.com/user-attachments/assets/e4ab124e-bb94-4e5c-81fc-12761322553c" />


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
- **Credentials vault** — auto-captured and manual entries, type-coded (NTLM/plaintext/Kerberos/token/cert), search & filter
- **Interactive file browser** — breadcrumb navigation, upload/download, Windows `dir` and Linux `ls -la` parsing
- **Process tree visualization** — expandable hierarchy, agent PID highlight, search, kill process
- Attack graph visualization (React Flow) — OS icons, agent stats, double-click to terminal
- Automatic MITRE ATT&CK technique mapping with tabbed matrix/timeline views
- OPSEC warning system (18 built-in rules with risk levels and safer alternatives)
- **Glitch/cyber-themed UI animations** — scan lines, RGB text glitch, pulse glow, card hover effects

### Windows Agent

- HTTP/HTTPS/mTLS beacon over WinHTTP
- **mTLS support**: embedded PFX client certificate compiled into the binary — no cert files needed on target
- **End-to-end encrypted C2**: ECDH-P256 key exchange at first check-in, AES-256-GCM for all traffic
- Configurable sleep interval with jitter (runtime-adjustable)
- Evasion: ETW patching, AMSI patching, ntdll unhooking, encrypted sleep (Ekko/Foliage)
- **Indirect syscalls** (HellsGate/HalosGate), NtCreateUserProcess, heap encryption, PE header stomping
- **UDRL** (User-Defined Reflective Loader) — DLL loading without PEB registration
- **Drip-Loading** — gradual memory allocation with jittered delays
- **Return Address Spoofing** — fake return addresses from signed Microsoft DLLs
- **Synthetic Stack Frames** — fabricated call chains during sleep (defeats Hunt-Sleeping-Beacons)
- **BlockDLLs** — block non-Microsoft DLLs in child processes (runtime toggle)
- **Argument Spoofing** — decoy command-line arguments in PEB (runtime toggle)
- In-memory BOF (Beacon Object File) loader with full Cobalt Strike BeaconAPI
- **Token manipulation**: steal_token, make_token, rev2self, getprivs, runas
- **Keylogger**: low-level keyboard hook with start/stop/dump commands
- **Screenshot capture**: GDI-based screen grab, saved server-side as BMP
- **Port scanner**: built-in TCP connect scan with CIDR and port range support
- Self-signed TLS cert bypass for HTTPS/mTLS listeners
- Multiple output formats: EXE, DLL, **true PIC shellcode** (.bin), Service EXE
- PIC shellcode: reflective PE loader stub (PEB walk → kernel32 → VirtualAlloc/LoadLibrary) + DLL; injects into any process without a PE loader
- Multi-task per beacon — processes multiple queued tasks per check-in
- Process listing, file upload/download, directory navigation, shell execution

### Linux Agent

- HTTP/HTTPS beacon over raw TCP sockets with optional OpenSSL TLS
- Auto-daemonizes (forks to background, detaches from terminal)
- Evasion: ptrace anti-debug, TracerPid check, process name masking (`[kworker/u:0]`), argv overwrite, self-delete, LD_PRELOAD cleanup, sandbox/VM detection
- **Screenshot capture**: via `scrot` / ImageMagick `import` fallback
- **Port scanner**: built-in TCP connect scan with CIDR support
- Multi-task per beacon, file upload/download
- Reports correct OS and architecture (amd64, arm64, arm)

### macOS Agent

- HTTP/HTTPS beacon over raw TCP sockets with optional OpenSSL TLS
- Auto-daemonizes
- Evasion: PT_DENY_ATTACH, sysctl P_TRACED check, process name masking, self-delete via `_NSGetExecutablePath`, DYLD environment cleanup, sandbox/VM detection
- LaunchAgent persistence support
- Same command set as Linux (screenshot, portscan, upload/download)

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

# Podman (rootless) instead of Docker — common on Kali with podman-docker
# sudo apt install -y podman podman-docker docker-compose-plugin
systemctl --user enable --now podman.socket   # creates /run/user/$UID/podman/podman.sock
# Optional: sudo touch /etc/containers/nodocker  # silence "Emulate Docker CLI" message
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
│   │   │   ├── credentials/            #   Credential vault: auto-capture, CRUD, regex parsers
│   │   ├── api/                    #   REST handlers, router, SSE, profile, payload & credential handlers
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
│   │   │   ├── pages/                  #   Dashboard, Listeners, Agents, Terminal, AgentBuilder,
│   │   │                           #   Modules, Graph, Mitre, Credentials, FileBrowser, ProcessTree, Settings
│   │   ├── stores/                 #   Zustand state management
│   │   ├── services/               #   API client, task, listener, payload, BOF packer services
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
│   ├── keylogger.h                 #   Windows: WH_KEYBOARD_LL hook, start/stop/dump
│   ├── screenshot.h                #   Windows: GDI screen capture to BMP
│   ├── portscan.h                  #   Cross-platform: TCP connect scan, CIDR, port ranges
│   ├── pic_loader.c                #   PIC reflective PE loader stub (PEB walk, PE mapper)
│   ├── gen_shellcode.c             #   Host tool: combines PIC stub + DLL → raw shellcode
│   └── Makefile                    #   Multi-platform: exe, dll, shellcode (PIC), linux-elf, macos-macho
│
├── tools/                          # Testing utilities
│   └── shellcode_loader.c          #   Sample loader for testing PIC shellcode (.bin)
│
├── bofs/                           # Beacon Object File templates
│   ├── bof_api.h                   #   BOF compatibility header (BeaconAPI declarations)
│   ├── lateral/                    #   psexec.c, scshell.c, wmiexec.c
│   ├── recon/                      #   netview.c (share enum), whoami_bof.c (token info)
│   └── persist/                    #   schtask.c, registry_run.c
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
| `credentials/vault.go`   | Credential store with auto-capture regex (SAM, NTLM, plaintext pairs) |
| `api/cred_handler.go`    | Credential CRUD REST endpoints                                        |

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

| Page          | Description                                                      |
| ------------- | ---------------------------------------------------------------- |
| Dashboard     | Agent count, listener status, recent activity                    |
| Listeners     | Create HTTP/HTTPS/mTLS/TCP/DNS/SMB listeners                    |
| Agents        | Live agent table with OS, hostname, user, PID, last check-in    |
| Terminal      | Per-agent interactive shell with history and tabbed sessions     |
| Agent Builder | **Windows/Linux/macOS** tabs with per-platform evasion toggles   |
| Modules       | BOF management, malleable profile upload, evasion reference      |
| Credentials   | Auto-captured & manual credential vault with type badges & search|
| File Browser  | Interactive directory navigation with upload/download            |
| Process Tree  | Expandable process hierarchy with search, agent highlight, kill  |
| Attack Graph  | Visual topology with OS icons, stats, double-click interaction   |
| MITRE ATT&CK  | Technique mapping with tabbed matrix/timeline views             |
| Settings      | Server connection, mTLS certificate upload, operator preferences |

### Terminal Commands

**Agent commands (sent to implant):**

| Command                              | Description                              |
| ------------------------------------ | ---------------------------------------- |
| `whoami`                             | Current user + admin/root status         |
| `getuid`                             | User info with PID and privilege         |
| `ps`                                 | Process listing                          |
| `pwd`                                | Print current working directory          |
| `cd <path>`                          | Change directory                         |
| `download <path>`                    | Download file from target                |
| `upload <path>`                      | Upload file to target                    |
| `shell <cmd>`                        | Execute shell command                    |
| `sleep <sec> [jitter%]`              | Change beacon interval                   |
| `screenshot`                         | Capture target screen (saved on server)  |
| `keylogger <start\|stop\|dump>`      | Keyboard logger (Windows)                |
| `portscan <ip/cidr> <ports>`         | Built-in TCP port scanner                |
| `bof <name> [args]`                  | Auto-resolve, fetch & execute BOF (Windows) |
| `steal_token <pid>`                  | Steal token from process (Windows)       |
| `make_token <user> <pass>`           | Create token with credentials (Windows)  |
| `rev2self`                           | Revert to original token (Windows)       |
| `getprivs`                           | List token privileges (Windows)          |
| `runas <user> <pass> <cmd>`          | Run command as another user (Windows)    |
| `blockdlls <on\|off>`                | Block non-MS DLLs in child processes     |
| `argspoof <on\|off>`                 | Spoof process arguments (PEB overwrite)  |
| `exit`                               | Terminate agent                          |

---

## Agents

### Windows Agent

**Source**: `agent/main.c` + `evasion.h` + `bof.h` + `token.h` + `crypto.h`

| File            | Purpose                                                          |
| --------------- | ---------------------------------------------------------------- |
| `main.c`        | Beacon loop (WinHTTP), command dispatch, multi-task processing   |
| `evasion.h`     | ETW/AMSI patching, encrypted sleep (Ekko), ntdll unhooking      |
| `bof.h`         | COFF loader with full Cobalt Strike BeaconAPI + IAT tracking     |
| `token.h`       | Token steal, make_token, rev2self, getprivs, runas               |
| `crypto.h`      | ECDH-P256, AES-256-GCM via Windows CNG, XOR encryption          |
| `keylogger.h`   | WH_KEYBOARD_LL hook, background thread, start/stop/dump         |
| `screenshot.h`  | GDI BitBlt screen capture, scaled BMP, base64 output            |
| `portscan.h`    | TCP connect scan, CIDR expansion, port ranges (cross-platform)  |
| `pic_loader.c`  | PIC reflective PE loader: PEB walk, export parsing, PE mapper   |
| `gen_shellcode.c`| Host combiner: patches offset marker, concatenates stub + DLL  |

**Compile-time flags**: `USE_MTLS`, `ENABLE_ETW_PATCH`, `ENABLE_AMSI_PATCH`, `ENABLE_SLEEP_ENCRYPT`, `ENABLE_UNHOOK`, `ENABLE_INDIRECT_SYSCALL`, `ENABLE_NT_PROCESS`, `ENABLE_HEAP_ENCRYPT`, `ENABLE_PE_STOMP`, `ENABLE_UDRL`, `ENABLE_DRIP_LOAD`, `ENABLE_RET_ADDR_SPOOF`, `ENABLE_SYNTHETIC_FRAMES`, `ENABLE_BLOCK_DLLS`, `ENABLE_ARG_SPOOF`

**Output formats**: EXE, DLL, **PIC Shellcode** (.bin), Service EXE

**Shellcode generation pipeline**:
```
make shellcode
 ├─ 1. Compile agent as DLL (all evasion flags preserved)
 ├─ 2. Compile PIC stub (pic_loader.c) → raw binary via objcopy
 ├─ 3. gen_shellcode patches PE offset marker, concatenates stub + DLL
 └─ Output: agent.bin (true PIC — executes at any address, no PE loader needed)
```

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
  │  For shellcode: DLL build → PIC stub compile → gen_shellcode combine
  │  Read output → base64 encode
  ▼
Response → Client downloads binary
```

### Make Targets

| Platform | Target        | Compiler                | Output        |
| -------- | ------------- | ----------------------- | ------------- |
| Windows  | `exe`         | x86_64-w64-mingw32-gcc  | `agent.exe`   |
| Windows  | `dll`         | x86_64-w64-mingw32-gcc  | `agent.dll`   |
| Windows  | `shellcode`   | x86_64-w64-mingw32-gcc  | `agent.bin` (PIC) |
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

### BOF Execution — By Name

The operator terminal supports **BOF-by-name execution**. Upload a `.o` / `.obj` file via the Modules page, then run it by name — the client automatically resolves the BOF, fetches its binary data from the server, packs arguments, and sends everything to the agent. No manual base64 encoding required.

```
bof whoami_bof                          # No args
bof netview 192.168.1.5                 # Default: wide string arg
bof psexec Z:target Z:svc Z:cmd.exe    # Explicit wide strings
bof custom_bof i:443 z:narrow_str      # Mixed types
```

### Argument Packer

The client includes a built-in argument packer compatible with `BeaconDataParse`. Typed prefixes control the binary format:

| Prefix | Type | Binary Format |
| ------ | ---- | ------------- |
| *(none)* | Wide string (UTF-16LE) | `[4-byte len][wchar data + null]` |
| `Z:` | Wide string (explicit) | Same as above |
| `z:` | Narrow string (UTF-8) | `[4-byte len][char data + null]` |
| `i:` | 32-bit integer | `[4-byte LE value]` |
| `s:` | 16-bit short | `[2-byte LE value]` |
| `b:` | Raw binary blob | `[4-byte len][base64-decoded bytes]` |

> **Note:** BOFs are Windows-only. The terminal blocks execution on Linux/macOS agents with a clear error.

### Available BOF Templates

**Lateral Movement:**

| BOF              | MITRE   | Description                                              |
| ---------------- | ------- | -------------------------------------------------------- |
| `psexec.o`       | T1021.002 | PsExec-style remote service creation via SCM           |
| `scshell.o`      | T1543.003 | SCShell — hijack existing service binary path          |
| `wmiexec.o`      | T1047   | WMI remote command execution via COM                     |

**Reconnaissance:**

| BOF              | MITRE   | Description                                              |
| ---------------- | ------- | -------------------------------------------------------- |
| `netview.o`      | T1135   | SMB share enumeration via NetShareEnum                   |
| `whoami_bof.o`   | T1033   | Extended token info: user, groups, privileges            |

**Persistence:**

| BOF              | MITRE   | Description                                              |
| ---------------- | ------- | -------------------------------------------------------- |
| `schtask.o`      | T1053.005 | Scheduled task creation (ONLOGON/DAILY/ONSTART)        |
| `registry_run.o` | T1547.001 | HKCU Run key persistence                              |

### API

| Method   | Endpoint                        | Description                          |
| -------- | ------------------------------- | ------------------------------------ |
| `GET`    | `/api/payloads/bofs`            | List uploaded BOFs                   |
| `GET`    | `/api/payloads/bofs/{id}/data`  | Fetch BOF binary as base64           |
| `POST`   | `/api/payloads/bofs`            | Upload BOF (.o/.obj)                 |
| `DELETE` | `/api/payloads/bofs?id=<uuid>`  | Delete BOF                           |

---

## Evasion Capabilities

### Windows Evasion

| Technique               | Flag                       | Description                                                               |
| ----------------------- | -------------------------- | ------------------------------------------------------------------------- |
| ETW Patching            | `ENABLE_ETW_PATCH`         | Patches `EtwEventWrite` to `xor eax,eax; ret` — blinds all ETW telemetry |
| AMSI Patching           | `ENABLE_AMSI_PATCH`        | Patches `AmsiScanBuffer` to return `E_INVALIDARG`                         |
| Sleep Obfuscation       | `SLEEP_METHOD` (0/1/2)     | Ekko (WaitableTimer) or Foliage (NtDelayExecution) + heap XOR encryption  |
| Heap Encryption         | `ENABLE_HEAP_ENCRYPT`      | XOR-encrypts agent ID, C2 host/port during sleep with BCryptGenRandom key |
| ntdll Unhooking         | `ENABLE_UNHOOK`            | Replaces hooked ntdll .text from clean `SEC_IMAGE` disk mapping           |
| Indirect Syscalls       | `ENABLE_INDIRECT_SYSCALL`  | HellsGate/HalosGate SSN resolution; syscall from own RWX stub            |
| NtCreateUserProcess     | `ENABLE_NT_PROCESS`        | Direct NT syscall for process creation; suppresses ETW ProcessCreate      |
| PE Header Stomping      | `ENABLE_PE_STOMP`          | Wipes MZ/NT headers in-memory; defeats pe-sieve, Moneta, dump forensics  |
| UDRL                    | `ENABLE_UDRL`              | Reflective DLL loader without PEB registration; invisible to module enum  |
| Drip-Loading            | `ENABLE_DRIP_LOAD`         | Gradual 4KB page allocation with 50-500ms jitter; avoids large alloc IOCs |
| Return Addr Spoofing    | `ENABLE_RET_ADDR_SPOOF`    | Spoofs return addresses with RET gadgets from signed Microsoft DLLs       |
| Synthetic Stack Frames  | `ENABLE_SYNTHETIC_FRAMES`  | Fake RtlUserThreadStart→BaseThreadInitThunk chain during sleep            |
| BlockDLLs               | `ENABLE_BLOCK_DLLS`        | Blocks non-Microsoft DLLs in child processes via mitigation policy        |
| Argument Spoofing       | `ENABLE_ARG_SPOOF`         | Decoy args in PEB; real command written after CREATE_SUSPENDED            |
| Token Manipulation      | (always on)                | steal_token, make_token, rev2self, getprivs, runas                        |
| ECDH-P256 + AES-256-GCM | (always on)                | Key exchange at first check-in, GCM encryption for all C2 traffic         |
| mTLS Client Cert        | `USE_MTLS`                 | Embeds PFX in binary via PFXImportCertStore; presents via WinHTTP         |

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

| Protocol | Description                                                          | Agent Support        |
| -------- | -------------------------------------------------------------------- | -------------------- |
| HTTP     | Plain HTTP listener for agent check-ins                              | Windows, Linux, macOS |
| HTTPS    | TLS-encrypted HTTP with auto-generated or custom certs               | Windows, Linux, macOS |
| mTLS     | Mutual TLS — agent cert embedded in binary at build time, no files on target | Windows               |
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

### Credentials

| Method   | Endpoint                | Description                    |
| -------- | ----------------------- | ------------------------------ |
| `GET`    | `/api/credentials`      | List all captured credentials  |
| `POST`   | `/api/credentials`      | Add credential manually        |
| `DELETE` | `/api/credentials/{id}` | Delete credential              |

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
    enabled: true              # HTTPS enabled by default (auto-generates self-signed cert)
    cert_file: ""              # leave empty to auto-generate
    key_file: ""               # leave empty to auto-generate
    ca_file: "certs/ca.crt"    # CA for operator mTLS (optional)
    mutual_tls: true           # require operator client certificates

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
- **HTTPS by default** — The API server auto-generates a self-signed TLS certificate at startup
- **mTLS for operators** — Enable `mutual_tls: true` in config to require client certificates from operator clients. Upload operator cert/key via Settings page
- **mTLS for agents** — When building agents for an mTLS listener, the builder generates a unique client certificate and embeds it directly in the binary (PFX) — no cert files needed on target
- **End-to-end encrypted C2** — ECDH-P256 key exchange at first check-in, AES-256-GCM for all subsequent traffic
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

1. Verify containers: `docker ps` or `podman ps`
2. **Podman rootless:** if you see `Cannot connect ... podman.sock`, run:
   `systemctl --user enable --now podman.socket` then `make db` again (do **not** use `sudo make db` — the socket is per-user).
3. Test PostgreSQL: `psql -h localhost -U apex -d apex`
4. Test Redis: `redis-cli ping`

### Agent stops after BOF execution / no BOF result

1. **OPSEC confirmation** — When you type `y` to confirm a risky command, ensure you're not in a state where `y` gets sent as a separate task. The client now intercepts `y`/`n` before sending to the agent.
2. **BOF crash** — A buggy or incompatible BOF can crash the agent process (access violation, etc.). The agent has no SEH around BOF execution (MinGW limitation), so the whole process exits. Use only trusted, tested BOFs; verify BOFs in an isolated VM first.
3. **Argument format** — Ensure BOF arguments use the correct packer prefixes (`Z:` for wide strings, `z:` for narrow, etc.). Mismatched formats can cause the BOF to read invalid memory and crash.

---

## Roadmap

See [GitHub Issues](https://github.com/hrdebraj/Apex/issues) for the full backlog. Key areas of active development:

- **Staged payload delivery** — Tiny stager that downloads full payload at runtime
- **Payload obfuscation pipeline** — `donut` or custom packer/encoder before delivery
- **Domain fronting** — `Host` header override for HTTP/HTTPS listeners
- **P2P / pivot chains** — Agent relay mode for internal proxying
- **Active Directory BOFs** — `ldapsearch`, Kerberoasting, BloodHound integration
- **Hermetic Docker build** — Pinned MinGW/GCC for reproducible payloads

---

## License

This software is intended for authorized security testing and research only. Unauthorized use against systems you do not own or have permission to test is illegal and unethical.
