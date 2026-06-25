-- Apex C2 Framework - Initial Schema

CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- ─── Operators ───────────────────────────────────────────────

CREATE TABLE operators (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username      VARCHAR(64) UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role          VARCHAR(16) NOT NULL DEFAULT 'operator'
                  CHECK (role IN ('admin', 'operator', 'readonly')),
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_login    TIMESTAMPTZ
);

CREATE INDEX idx_operators_username ON operators (username);

-- Seed a default admin operator (password: "apex")
INSERT INTO operators (username, password_hash, role)
VALUES (
    'admin',
    crypt('apex', gen_salt('bf')),
    'admin'
);

-- ─── Listeners ───────────────────────────────────────────────

CREATE TABLE listeners (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name         VARCHAR(128) NOT NULL,
    protocol     VARCHAR(16) NOT NULL
                 CHECK (protocol IN ('http', 'https', 'dns', 'tcp', 'smb')),
    bind_address VARCHAR(64) NOT NULL DEFAULT '0.0.0.0',
    bind_port    INTEGER NOT NULL,
    status       VARCHAR(16) NOT NULL DEFAULT 'inactive'
                 CHECK (status IN ('active', 'inactive', 'error')),
    config       JSONB NOT NULL DEFAULT '{}',
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ─── Agents ──────────────────────────────────────────────────

CREATE TABLE agents (
    id             UUID PRIMARY KEY,
    hostname       VARCHAR(256),
    username       VARCHAR(256),
    os             VARCHAR(64),
    arch           VARCHAR(32),
    pid            INTEGER,
    process_name   VARCHAR(256),
    internal_ip    VARCHAR(45),
    external_ip    VARCHAR(45),
    sleep_interval INTEGER NOT NULL DEFAULT 60,
    jitter         INTEGER NOT NULL DEFAULT 0,
    listener_id    UUID REFERENCES listeners(id) ON DELETE SET NULL,
    first_seen     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_agents_listener ON agents (listener_id);
CREATE INDEX idx_agents_last_seen ON agents (last_seen DESC);

-- ─── Tasks ───────────────────────────────────────────────────

CREATE TABLE tasks (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    agent_id     UUID NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    operator_id  UUID NOT NULL REFERENCES operators(id),
    command      VARCHAR(256) NOT NULL,
    arguments    BYTEA,
    status       VARCHAR(16) NOT NULL DEFAULT 'queued'
                 CHECK (status IN ('queued', 'delivered', 'completed', 'failed', 'cancelled')),
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at TIMESTAMPTZ
);

CREATE INDEX idx_tasks_agent ON tasks (agent_id);
CREATE INDEX idx_tasks_status ON tasks (status);
CREATE INDEX idx_tasks_created ON tasks (created_at DESC);

-- ─── Task Results ────────────────────────────────────────────

CREATE TABLE task_results (
    id        UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    task_id   UUID NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
    agent_id  UUID NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    output    BYTEA,
    success   BOOLEAN NOT NULL DEFAULT false,
    error     TEXT,
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_task_results_task ON task_results (task_id);

-- ─── Credentials (harvested) ─────────────────────────────────

CREATE TABLE credentials (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    agent_id   UUID REFERENCES agents(id) ON DELETE SET NULL,
    domain     VARCHAR(256),
    username   VARCHAR(256) NOT NULL,
    secret     TEXT NOT NULL,
    type       VARCHAR(32) NOT NULL DEFAULT 'plaintext'
               CHECK (type IN ('plaintext', 'ntlm', 'kerberos', 'certificate', 'token')),
    source     VARCHAR(256),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_credentials_username ON credentials (username);

-- ─── Operations Log ──────────────────────────────────────────

CREATE TABLE operations_log (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    operator_id UUID REFERENCES operators(id),
    agent_id    UUID REFERENCES agents(id) ON DELETE SET NULL,
    action      VARCHAR(64) NOT NULL,
    detail      JSONB,
    mitre_id    VARCHAR(32),
    timestamp   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_opslog_timestamp ON operations_log (timestamp DESC);
CREATE INDEX idx_opslog_mitre ON operations_log (mitre_id) WHERE mitre_id IS NOT NULL;
