# Apex C2 Framework — Architecture & Data Flow Diagrams

This document provides detailed architecture diagrams and Data Flow Diagrams (DFDs) for the Apex C2 framework. All diagrams use Mermaid syntax compatible with GitHub Markdown rendering. The DFD notation follows Microsoft Threat Modeling Tool conventions with processes, data stores, data flows, external entities, and trust boundaries.

---

## Table of Contents

- [System Context Diagram - DFD Level 0](#system-context-diagram---dfd-level-0)
- [Component Architecture - DFD Level 1](#component-architecture---dfd-level-1)
- [Task Execution Sequence](#task-execution-sequence)
- [Agent Communication Sequence](#agent-communication-sequence)
- [Authentication Flow](#authentication-flow)
- [Payload Generation Flow](#payload-generation-flow)
- [BOF Execution Flow](#bof-execution-flow)
- [Agent Internal Architecture](#agent-internal-architecture)
- [Network Topology](#network-topology)
- [Database Entity Relationship](#database-entity-relationship)
- [Trust Boundaries](#trust-boundaries)
- [Data Store Inventory](#data-store-inventory)
- [Process Inventory](#process-inventory)
- [External Entity Inventory](#external-entity-inventory)
- [Data Flow Inventory](#data-flow-inventory)
- [STRIDE Threat Mapping](#stride-threat-mapping)
- [Microsoft Threat Modeling Tool Elements](#microsoft-threat-modeling-tool-elements)

---

## System Context Diagram - DFD Level 0

Highest-level view showing the Apex system and all external entities.

```mermaid
flowchart TB
    subgraph TB1["Trust Boundary: C2 Infrastructure"]
        direction TB
        APEX["Apex Team Server\n(Go Process)\nHTTP API :8443\ngRPC :50051"]
        PG[("PostgreSQL\n(Agents, Tasks,\nCredentials, Ops Log)")]
        RD[("Redis\n(Task Queue,\nPub/Sub Results)")]
    end

    OP["Operator Client\n(Tauri + React)"]
    TGT["Target Host\n(Windows Agent)"]

    OP -->|"REST API + JWT\nHTTPS :8443"| APEX
    APEX -->|"SSE Events\nagent:registered\nagent:task_result"| OP
    TGT -->|"HTTP POST /\nSysinfo, Results"| APEX
    APEX -->|"HTTP Response\nAgent ID, Tasks"| TGT
    APEX -->|"SQL Queries\npgx Pool"| PG
    APEX -->|"RPUSH, LPOP\nPUBLISH, SUBSCRIBE"| RD
```

---

## Component Architecture - DFD Level 1

Internal decomposition of the Apex Team Server into processes and data stores.

```mermaid
flowchart TB
    subgraph CLIENT["Operator Client - Tauri/React"]
        TERM["Terminal Page"]
        BUILDER_UI["Agent Builder Page"]
        MODULES_UI["Modules Page"]
    end

    subgraph SERVER["Trust Boundary: Team Server Process"]
        direction TB
        ROUTER["HTTP API Router\nChi v5 + CORS + JWT MW"]
        AUTH["Auth Service\nJWT HS256 + bcrypt"]
        TASK_H["Task Handler\nCreate + List"]
        AGENT_H["Agent Handler\nList + Get + Remove"]
        PAYLOAD_H["Payload Handler\nGenerate + BOF CRUD"]
        EVT["Event Hub\nSSE Broker"]
        LISTENER["HTTP/HTTPS Listener\nhandleCheckIn"]
        AGENT_MGR["Agent Manager\nRegister + Dedup + CheckIn"]
        TASK_Q["Task Queue\nRedis RPUSH/LPOP"]
        BLDR["Payload Builder\nmake clean + make exe"]
    end

    subgraph STORAGE["Trust Boundary: Data Layer"]
        PG[("PostgreSQL\noperators, agents,\ntasks, task_results,\ncredentials, operations_log")]
        RD[("Redis\napex:tasks:agentID\napex:results:agentID")]
        BOF_FS[("BOF Storage\ndata/bofs/\n.o and .obj files")]
        SRC_FS[("Agent Source\nagent/main.c\nevasion.h, bof.h, crypto.h")]
    end

    AGENT["Target Host\nWindows Agent"]

    TERM -->|"POST /api/agents/id/tasks"| ROUTER
    BUILDER_UI -->|"POST /api/payloads/generate"| ROUTER
    MODULES_UI -->|"POST /api/payloads/bofs"| ROUTER
    ROUTER --> AUTH
    ROUTER --> TASK_H
    ROUTER --> AGENT_H
    ROUTER --> PAYLOAD_H
    EVT -->|"SSE Stream"| CLIENT
    TASK_H -->|"Enqueue"| TASK_Q
    TASK_Q --> RD
    AGENT_H --> AGENT_MGR
    AGENT_MGR --> PG
    PAYLOAD_H --> BLDR
    PAYLOAD_H --> BOF_FS
    BLDR --> SRC_FS
    AUTH --> PG
    AGENT -->|"HTTP POST /"| LISTENER
    LISTENER -->|"Dequeue Tasks"| TASK_Q
    LISTENER -->|"Register/CheckIn"| AGENT_MGR
    LISTENER -->|"PublishResult"| RD
    AGENT_MGR -->|"BroadcastEvent"| EVT
```

---

## Task Execution Sequence

End-to-end flow from operator command to result display.

```mermaid
sequenceDiagram
    participant OP as Operator Client
    participant API as HTTP API Router
    participant AUTH as Auth Service
    participant TQ as Task Queue - Redis
    participant LIS as HTTP Listener
    participant AGT as Windows Agent
    participant EVT as Event Hub - SSE
    participant MGR as Agent Manager

    OP->>API: POST /api/agents/agentID/tasks
    Note over OP,API: Header: Authorization Bearer JWT
    API->>AUTH: Validate JWT token
    AUTH-->>API: Claims: operator_id, role
    API->>TQ: Enqueue(agentID, command, args)
    TQ->>TQ: RPUSH apex:tasks:agentID
    API-->>OP: 201 Created - Task ID

    Note over AGT,LIS: Agent check-in every ~5 seconds
    AGT->>LIS: POST / with X-Agent-ID header
    LIS->>TQ: Dequeue(agentID)
    TQ->>TQ: LPOP apex:tasks:agentID
    TQ-->>LIS: Task JSON
    LIS-->>AGT: Response with task payload

    Note over AGT: Execute command
    AGT->>AGT: cmd.exe /c or built-in handler
    AGT->>LIS: POST / with results array
    Note over AGT,LIS: task_id + base64 output + success

    LIS->>TQ: PublishResult via Redis PUBLISH
    LIS->>MGR: BroadcastTaskResult
    MGR->>EVT: Forward event
    EVT->>OP: SSE event agent:task_result
    Note over OP: Display decoded output in Terminal
```

---

## Agent Communication Sequence

Registration and beacon lifecycle.

```mermaid
sequenceDiagram
    participant AGT as Windows Agent
    participant EVA as Evasion Module
    participant LIS as HTTP Listener
    participant MGR as Agent Manager
    participant PG as PostgreSQL
    participant RD as Redis
    participant EVT as Event Hub
    participant OP as Operator Client

    Note over AGT,EVA: Agent Startup
    AGT->>EVA: unhook_ntdll()
    EVA-->>AGT: Clean ntdll from disk
    AGT->>EVA: patch_etw()
    EVA-->>AGT: EtwEventWrite patched
    AGT->>EVA: patch_amsi()
    EVA-->>AGT: AmsiScanBuffer patched

    Note over AGT: Collect sysinfo
    AGT->>AGT: hostname, username, OS, arch, PID, IP

    AGT->>LIS: POST / with sysinfo JSON
    Note over AGT,LIS: No X-Agent-ID - first contact
    LIS->>MGR: RegisterOrReuse(agent, 24h dedup)
    MGR->>PG: INSERT or SELECT existing
    PG-->>MGR: Agent record
    MGR->>EVT: Broadcast agent:registered
    EVT->>OP: SSE agent:registered
    LIS-->>AGT: Response with agent_id

    loop Beacon Loop - every sleep_ms with jitter
        AGT->>LIS: POST / with X-Agent-ID
        LIS->>MGR: CheckIn(agentID)
        MGR->>EVT: Broadcast agent:checked_in
        LIS->>RD: Dequeue pending tasks
        alt Tasks pending
            RD-->>LIS: Task data
            LIS-->>AGT: Task in response
            AGT->>AGT: Execute command
            AGT->>LIS: POST / with results
            LIS->>RD: PUBLISH result
            LIS->>MGR: BroadcastTaskResult
            MGR->>EVT: agent:task_result
            EVT->>OP: SSE with output
        else No tasks
            LIS-->>AGT: Empty response
        end
        AGT->>EVA: encrypted_sleep(ms)
        Note over AGT,EVA: XOR encrypt image then Sleep then decrypt
    end
```

---

## Authentication Flow

```mermaid
sequenceDiagram
    participant OP as Operator Client
    participant API as HTTP API
    participant AUTH as Auth Service
    participant PG as PostgreSQL

    OP->>API: POST /api/auth/login
    Note over OP,API: username + password in JSON body

    API->>AUTH: Authenticate(username, password)
    AUTH->>PG: SELECT password_hash, role FROM operators WHERE username = ?
    PG-->>AUTH: password_hash, role

    AUTH->>AUTH: bcrypt.Compare(password, hash)

    alt Valid credentials
        AUTH->>AUTH: Sign JWT with operator_id, username, role, exp
        AUTH-->>API: JWT token + operator info
        API-->>OP: 200 OK with token and operator
        Note over OP: Store JWT in authStore

        OP->>API: Subsequent requests
        Note over OP,API: Authorization: Bearer JWT

        OP->>API: GET /api/events?token=JWT
        Note over OP,API: SSE connection with token in query
    else Invalid credentials
        AUTH-->>API: Authentication failed
        API-->>OP: 401 Unauthorized
    end
```

---

## Payload Generation Flow

```mermaid
sequenceDiagram
    participant OP as Operator Client
    participant UI as Agent Builder Page
    participant API as Payload Handler
    participant LMGR as Listener Manager
    participant BLDR as Builder
    participant FS as Agent Source Files
    participant GCC as MinGW Compiler

    OP->>UI: Configure evasion toggles
    Note over UI: ETW, AMSI, Sleep Obf, Unhook, Output Format

    UI->>API: POST /api/payloads/generate
    Note over UI,API: listener_id, output_format, etw_patch, amsi_patch, sleep_obfuscation, unhook_ntdll

    API->>LMGR: Get listener by ID
    LMGR-->>API: bind_address, bind_port, protocol

    API->>API: Resolve c2_host, c2_port, use_https
    API->>API: Build EvasionOpts struct

    API->>BLDR: BuildBase64(agentDir, format, host, port, https, evasion)

    BLDR->>BLDR: Set environment variables
    Note over BLDR: C2_HOST, C2_PORT, USE_HTTPS, ENABLE_ETW_PATCH, ENABLE_AMSI_PATCH, ENABLE_SLEEP_ENCRYPT, ENABLE_UNHOOK

    BLDR->>GCC: exec make -C agent/ clean
    BLDR->>GCC: exec make -C agent/ exe
    GCC->>FS: Compile main.c + evasion.h + bof.h + crypto.h
    GCC-->>BLDR: agent.exe binary

    BLDR->>BLDR: Read binary and base64 encode
    BLDR-->>API: base64 payload + filename

    API-->>UI: GenerateResponse with payload_base64
    UI->>UI: Decode base64 to Blob
    UI->>OP: Browser download of agent.exe
```

---

## BOF Execution Flow

```mermaid
sequenceDiagram
    participant OP as Operator
    participant MOD as Modules Page
    participant API as Payload Handler
    participant FS as BOF Storage
    participant TERM as Terminal
    participant TQ as Task Queue
    participant AGT as Agent
    participant BOF as BOF Loader
    participant EVT as Event Hub

    Note over OP,MOD: Step 1 - Upload BOF
    OP->>MOD: Upload .o or .obj file
    MOD->>API: POST /api/payloads/bofs multipart
    API->>API: Validate extension and size
    API->>API: SHA-256 hash
    API->>FS: Save to data/bofs/uuid.o
    API-->>MOD: BOF entry with id, name, size, hash

    Note over OP,TERM: Step 2 - Execute BOF
    OP->>TERM: bof base64_obj_data base64_args
    TERM->>TQ: Create task command=bof arguments=data

    AGT->>TQ: Check-in dequeue
    TQ-->>AGT: Task with bof command

    AGT->>BOF: handle_bof(args)
    BOF->>BOF: Base64 decode BOF data
    BOF->>BOF: Parse COFF header and sections
    BOF->>BOF: Allocate section memory via VirtualAlloc
    BOF->>BOF: Apply x86_64 relocations
    BOF->>BOF: Resolve external imports
    Note over BOF: __imp_Library$Function convention
    BOF->>BOF: Find go or _go entry point
    BOF->>BOF: Call entry(args, args_len)
    Note over BOF: BeaconPrintf/BeaconOutput capture to buffer

    BOF-->>AGT: BOF output string

    AGT->>AGT: Base64 encode output
    AGT->>API: POST / with results
    API->>EVT: BroadcastTaskResult
    EVT->>OP: SSE agent:task_result
    Note over OP: Display BOF output in Terminal
```

---

## Agent Internal Architecture

```mermaid
flowchart TB
    subgraph STARTUP["Startup Sequence"]
        direction LR
        S1["unhook_ntdll\nClean ntdll .text\nfrom disk copy"]
        S2["patch_etw\nPatch EtwEventWrite\nxor eax,eax ret"]
        S3["patch_amsi\nPatch AmsiScanBuffer\nmov eax,E_INVALIDARG ret"]
        S4["Collect Sysinfo\nhostname, user,\nOS, arch, PID, IP"]
        S1 --> S2 --> S3 --> S4
    end

    subgraph BEACON["Beacon Loop"]
        direction TB
        POST["HTTP POST /\nWinHTTP API\nX-Agent-ID header"]
        PARSE["Parse Response\nJSON task extraction"]
        DISPATCH["Command Dispatcher"]

        POST --> PARSE --> DISPATCH

        subgraph COMMANDS["Command Handlers"]
            direction LR
            CMD_SHELL["Shell Exec\ncmd.exe /c\nstdout capture"]
            CMD_BUILTIN["Built-in\nwhoami, ps, pwd\ncd, getuid, download"]
            CMD_BOF["BOF Loader\nCOFF parse\nrelocation\nBeaconAPI"]
            CMD_SLEEP["Sleep Command\nRuntime interval\nand jitter change"]
            CMD_EXIT["Exit\nExitProcess"]
        end

        DISPATCH --> COMMANDS

        RESULT["POST Results\ntask_id + base64 output"]
        COMMANDS --> RESULT

        subgraph SLEEP["Encrypted Sleep"]
            direction TB
            SL1["VirtualProtect RW"]
            SL2["SystemFunction032\nXOR Encrypt Image"]
            SL3["Sleep with jitter"]
            SL4["SystemFunction032\nXOR Decrypt Image"]
            SL5["VirtualProtect RX"]
            SL1 --> SL2 --> SL3 --> SL4 --> SL5
        end

        RESULT --> SLEEP
        SLEEP --> POST
    end

    STARTUP --> BEACON
```

---

## Network Topology

```mermaid
flowchart TB
    subgraph OPNET["Operator Network"]
        direction TB
        WORKSTATION["Operator Workstation\nBrowser or Tauri App"]
        subgraph SRVHOST["Team Server Host"]
            direction LR
            SRV["Team Server\nGo Binary"]
            HTTPAPI["HTTP API :8443"]
            GRPC["gRPC :50051"]
            LISTENER["C2 Listener :8080"]
            PGDB[("PostgreSQL :5432")]
            RDDB[("Redis :6379")]
            SRV --- HTTPAPI
            SRV --- GRPC
            SRV --- LISTENER
            SRV --- PGDB
            SRV --- RDDB
        end
        WORKSTATION -->|"HTTPS :8443"| HTTPAPI
    end

    INTERNET["Internet / WAN"]

    subgraph TGTNET["Target Network"]
        direction TB
        HOST1["Compromised Host\nWindows\nagent.exe running"]
        HOST2["Other Hosts\nLateral Movement"]
        DC["Domain Controller"]
    end

    LISTENER <-->|"HTTP :8080\nBeacon every ~5s"| INTERNET
    INTERNET <-->|"Agent Traffic"| HOST1
    HOST1 -.->|"Potential\nLateral Movement"| HOST2
    HOST1 -.->|"Potential\nLateral Movement"| DC
```

---

## Database Entity Relationship

```mermaid
erDiagram
    operators {
        uuid id PK
        varchar username UK
        text password_hash
        varchar role
        timestamptz created_at
        timestamptz last_login
    }

    listeners {
        uuid id PK
        varchar name
        varchar protocol
        varchar bind_address
        int bind_port
        varchar status
        jsonb config
        timestamptz created_at
    }

    agents {
        uuid id PK
        varchar hostname
        varchar username
        varchar os
        varchar arch
        int pid
        varchar process_name
        varchar internal_ip
        varchar external_ip
        int sleep_interval
        int jitter
        uuid listener_id FK
        timestamptz first_seen
        timestamptz last_seen
    }

    tasks {
        uuid id PK
        uuid agent_id FK
        uuid operator_id FK
        varchar command
        bytea arguments
        varchar status
        timestamptz created_at
        timestamptz completed_at
    }

    task_results {
        uuid id PK
        uuid task_id FK
        uuid agent_id FK
        bytea output
        boolean success
        text error
        timestamptz timestamp
    }

    credentials {
        uuid id PK
        uuid agent_id FK
        varchar domain
        varchar username
        text secret
        varchar type
        varchar source
        timestamptz created_at
    }

    operations_log {
        uuid id PK
        uuid operator_id FK
        uuid agent_id FK
        varchar action
        jsonb detail
        varchar mitre_id
        timestamptz timestamp
    }

    operators ||--o{ tasks : "creates"
    operators ||--o{ operations_log : "performs"
    listeners ||--o{ agents : "hosts"
    agents ||--o{ tasks : "receives"
    agents ||--o{ task_results : "produces"
    agents ||--o{ credentials : "harvests"
    agents ||--o{ operations_log : "target of"
    tasks ||--o{ task_results : "has"
```

---

## SSE Event Flow

```mermaid
flowchart LR
    subgraph SOURCES["Event Sources"]
        LIS["HTTP Listener\nAgent check-in"]
        TQ["Task Queue\nResult published"]
        MGR["Agent Manager\nRegister/Disconnect"]
    end

    subgraph HUB["Event Hub"]
        EVT["SSE Broker\nGo channels"]
    end

    subgraph EVENTS["SSE Event Types"]
        E1["agent:registered\nnew agent joined"]
        E2["agent:checked_in\nbeacon heartbeat"]
        E3["agent:disconnected\nmissed threshold"]
        E4["agent:task_result\ncommand output"]
    end

    subgraph CLIENTS["Connected Clients"]
        C1["Operator 1\nBrowser"]
        C2["Operator 2\nTauri App"]
    end

    LIS --> EVT
    TQ --> EVT
    MGR --> EVT
    EVT --> E1
    EVT --> E2
    EVT --> E3
    EVT --> E4
    E1 --> C1
    E1 --> C2
    E2 --> C1
    E2 --> C2
    E3 --> C1
    E3 --> C2
    E4 --> C1
    E4 --> C2
```

---

## Evasion Techniques Diagram

```mermaid
flowchart TB
    subgraph EVASION["Agent Evasion Suite"]
        direction TB
        subgraph STARTUP_EV["Startup Evasion"]
            direction LR
            UNHOOK["ntdll Unhook\nMap clean ntdll from disk\nOverwrite .text section\nRemoves EDR inline hooks"]
            ETW["ETW Patch\nPatch EtwEventWrite\n0x33 0xC0 0xC3\nxor eax,eax / ret"]
            AMSI["AMSI Patch\nPatch AmsiScanBuffer\nmov eax,0x80070057 / ret\nReturns E_INVALIDARG"]
        end

        subgraph RUNTIME_EV["Runtime Evasion"]
            direction LR
            SLEEP_ENC["Encrypted Sleep - Ekko\nSystemFunction032 XOR\nEncrypt image during sleep\nPer-sleep random key"]
            STR_ENC["String Encryption\nXOR obfuscation\nDecrypt at first use\nNo cleartext IOCs"]
            AES["AES-256-CBC Ready\nWindows CNG BCrypt\nSession key support\nCSPRNG via BCryptGenRandom"]
        end
    end

    subgraph BUILDER_FLAGS["Builder Compile Flags"]
        F1["ENABLE_UNHOOK=1"]
        F2["ENABLE_ETW_PATCH=1"]
        F3["ENABLE_AMSI_PATCH=1"]
        F4["ENABLE_SLEEP_ENCRYPT=1"]
    end

    F1 -.->|"controls"| UNHOOK
    F2 -.->|"controls"| ETW
    F3 -.->|"controls"| AMSI
    F4 -.->|"controls"| SLEEP_ENC
```

---

## Trust Boundaries

For Microsoft Threat Modeling Tool, define these trust boundaries:

| ID | Boundary Name | Description | Components Inside |
|----|--------------|-------------|-------------------|
| TB1 | C2 Infrastructure | Operator-controlled systems | Team Server, PostgreSQL, Redis, Client |
| TB2 | Team Server Process | Go process boundary | All server-side processes (P1-P8) |
| TB3 | Network Transport | HTTP/HTTPS between server and agent | Agent-to-listener data flows |
| TB4 | Target Network | Compromised host network | Agent process |
| TB5 | Agent Process | Agent memory space | Evasion, BOF loader, command execution |
| TB6 | Database Layer | Data persistence boundary | PostgreSQL, Redis |
| TB7 | Browser/Tauri | Client application boundary | React UI, Zustand stores |

### Trust Boundary Crossings

```mermaid
flowchart TB
    subgraph TB7["TB7: Client Application"]
        CLIENT["Operator Client"]
    end

    subgraph TB1["TB1: C2 Infrastructure"]
        subgraph TB2["TB2: Team Server Process"]
            API["HTTP API"]
            LISTENER["Listener"]
            BUILDER["Builder"]
        end
        subgraph TB6["TB6: Database Layer"]
            PG[("PostgreSQL")]
            RD[("Redis")]
        end
    end

    subgraph TB4["TB4: Target Network"]
        subgraph TB5["TB5: Agent Process"]
            AGENT["Agent"]
        end
    end

    CLIENT -->|"TC1: JWT Auth\nREST over HTTPS"| API
    API -->|"TC2: SSE Events\nover HTTPS"| CLIENT
    AGENT -->|"TC3: HTTP POST\nSysinfo + Results\nSpoofing risk"| LISTENER
    LISTENER -->|"TC4: HTTP Response\nTasks + Agent ID\nTampering risk"| AGENT
    API -->|"TC5: SQL/Redis\nInjection risk"| PG
    API -->|"TC6: Queue ops"| RD

    style TB7 fill:#1a3a5c,stroke:#4a9eff
    style TB1 fill:#1a3a2c,stroke:#4aff9e
    style TB2 fill:#2a4a3c,stroke:#5affae
    style TB6 fill:#3a2a1c,stroke:#ffaa4a
    style TB4 fill:#3a1a1a,stroke:#ff4a4a
    style TB5 fill:#4a2a2a,stroke:#ff6a6a
```

---

## Data Store Inventory

| ID | Name | Technology | Data Stored | Access |
|----|------|-----------|-------------|--------|
| DS1 | PostgreSQL | PostgreSQL 16 | operators, listeners, agents, tasks, task_results, credentials, operations_log | Team Server via pgx pool |
| DS2 | Redis | Redis 7 | Task queues `apex:tasks:{agentID}`, pub/sub channels `apex:results:{agentID}` | Team Server via go-redis |
| DS3 | Agent Source | Filesystem | main.c, evasion.h, bof.h, crypto.h, Makefile | Builder process |
| DS4 | BOF Storage | Filesystem `data/bofs/` | Uploaded .o/.obj COFF object files | Payload Handler |

---

## Process Inventory

| ID | Name | Technology | Input Data | Output Data | Trust Level |
|----|------|-----------|------------|-------------|-------------|
| P1 | HTTP API Router | Go, Chi | REST requests | JSON responses | High |
| P2 | Auth Service | Go, JWT, bcrypt | Credentials | JWT tokens | High |
| P3 | Task Handler | Go | Create task req | Task records | High |
| P4 | Task Queue | Go, Redis | Enqueue/dequeue | Tasks, results | High |
| P5 | Event Hub | Go, SSE | Events | SSE stream | High |
| P6 | HTTP Listener | Go, net/http | Agent POSTs | Task responses | Medium |
| P7 | Agent Manager | Go, pgx | Sysinfo, check-ins | Agent records | High |
| P8 | Payload Builder | Go, exec | Build config | Compiled binary | High |
| P9 | Terminal Page | React, TS | User commands | API calls | Medium |
| P2.1 | Evasion Module | C | Config flags | Patched memory | Low |
| P2.2 | Beacon Loop | C | Server responses | HTTP requests | Low |
| P2.3 | Command Executor | C | Task commands | Command output | Low |
| P2.4 | BOF Loader | C | COFF data | Execution output | Low |

---

## External Entity Inventory

| ID | Name | Description | Trust Level | Interactions |
|----|------|-------------|-------------|--------------|
| EE1 | Operator | Red team operator using Tauri/React client | Trusted | REST API, SSE |
| EE2 | Target Host | Windows machine running C agent | Untrusted | HTTP beacon |
| EE3 | MinGW Compiler | Cross-compiler invoked by builder | Trusted (local) | exec from builder |

---

## Data Flow Inventory

Complete list of data flows for Microsoft Threat Modeling Tool:

| ID | Source | Destination | Protocol | Data | Auth | Encrypted |
|----|--------|-------------|----------|------|------|-----------|
| DF1 | Client | API Router | HTTPS | REST requests + JWT | JWT Bearer | TLS optional |
| DF2 | API Router | Client | HTTPS | JSON responses | Session | TLS optional |
| DF3 | API Router | Client | SSE | Real-time events | JWT query | TLS optional |
| DF4 | Agent | Listener | HTTP/S | Registration sysinfo | None | TLS optional |
| DF5 | Listener | Agent | HTTP/S | Agent ID | None | TLS optional |
| DF6 | Agent | Listener | HTTP/S | Check-in + results | X-Agent-ID | TLS optional |
| DF7 | Listener | Agent | HTTP/S | Task payloads | None | TLS optional |
| DF8 | Task Handler | Redis | TCP | Task JSON RPUSH | None | No |
| DF9 | Listener | Redis | TCP | Dequeue LPOP | None | No |
| DF10 | Redis | Listener | TCP | Task data | None | No |
| DF11 | Listener | Redis | TCP | Result PUBLISH | None | No |
| DF12 | Agent Manager | PostgreSQL | TCP | Agent INSERT/UPDATE | Password | No |
| DF13 | Auth Service | PostgreSQL | TCP | Operator SELECT | Password | No |
| DF14 | Agent Manager | Event Hub | Internal | Agent events | N/A | N/A |
| DF15 | Builder | Source FS | Filesystem | Read source, write binary | OS perms | N/A |
| DF16 | Builder | MinGW | exec | Compile command | N/A | N/A |
| DF17 | Client | Builder | HTTPS | Build config | JWT | TLS optional |
| DF18 | Builder | Client | HTTPS | Binary base64 | JWT | TLS optional |
| DF19 | Client | BOF Store | HTTPS to FS | BOF upload | JWT | TLS optional |
| DF20 | BOF Store | Client | FS to HTTPS | BOF listing | JWT | TLS optional |

---

## STRIDE Threat Mapping

```mermaid
flowchart LR
    subgraph STRIDE["STRIDE Categories"]
        direction TB
        S["Spoofing\nAgent impersonation\nForge X-Agent-ID"]
        T["Tampering\nModify tasks or results\nin transit"]
        R["Repudiation\nOperator denies\nissuing command"]
        I["Information Disclosure\nCredentials or output\nleaked on network"]
        D["Denial of Service\nFlood listener with\nfake check-ins"]
        E["Elevation of Privilege\nJWT token theft\ngains admin access"]
    end

    subgraph FLOWS["Affected Data Flows"]
        F_AGENT["DF4-DF7\nAgent to Listener"]
        F_API["DF1-DF3\nClient to API"]
        F_DB["DF8-DF13\nServer to DB"]
    end

    S --> F_AGENT
    T --> F_AGENT
    T --> F_DB
    R --> F_API
    I --> F_AGENT
    I --> F_API
    D --> F_AGENT
    E --> F_API
```

---

## Microsoft Threat Modeling Tool Elements

Summary for recreating in Microsoft TMT:

**External Entities (Interactors):**
- Operator Client - Tauri/React desktop app (trusted)
- Target Host Agent - Windows C implant (untrusted)

**Processes:**
- HTTP API Router, Auth Service, Task Handler, Task Queue, Event Hub, HTTP Listener, Agent Manager, Payload Builder, BOF Loader (inside agent)

**Data Stores:**
- PostgreSQL (relational), Redis (queue + pub/sub), Agent Source (filesystem), BOF Storage (filesystem)

**Trust Boundaries:**
- C2 Infrastructure, Team Server Process, Network Transport, Target Network, Agent Process, Database Layer, Client Application

**Data Flows:**
- 20 flows as documented in the Data Flow Inventory table above
- Each with source, destination, protocol, data content, auth method, encryption status

---

*Generated for Apex C2 Framework v0.1.0. All Mermaid diagrams render natively on GitHub without HTML dependencies.*
