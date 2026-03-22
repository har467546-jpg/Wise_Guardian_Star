CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE IF NOT EXISTS assets (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    ip INET NOT NULL UNIQUE,
    hostname VARCHAR(255),
    os_name VARCHAR(128),
    owner VARCHAR(128),
    criticality VARCHAR(16) NOT NULL DEFAULT 'medium',
    status VARCHAR(16) NOT NULL DEFAULT 'unknown',
    tags JSONB NOT NULL DEFAULT '[]'::jsonb,
    metadata_json JSONB NOT NULL DEFAULT '{}'::jsonb,
    first_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT ck_assets_criticality CHECK (criticality IN ('low', 'medium', 'high', 'critical')),
    CONSTRAINT ck_assets_status CHECK (status IN ('online', 'offline', 'unknown'))
);

CREATE INDEX IF NOT EXISTS ix_assets_status_last_seen ON assets (status, last_seen_at DESC);
CREATE INDEX IF NOT EXISTS ix_assets_owner ON assets (owner);
CREATE INDEX IF NOT EXISTS ix_assets_tags_gin ON assets USING GIN (tags);

CREATE TABLE IF NOT EXISTS services (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    asset_id UUID NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    port INTEGER NOT NULL,
    protocol VARCHAR(8) NOT NULL DEFAULT 'tcp',
    service_name VARCHAR(128) NOT NULL,
    product VARCHAR(128),
    version VARCHAR(128),
    banner TEXT,
    state VARCHAR(16) NOT NULL DEFAULT 'open',
    detected_by VARCHAR(64) NOT NULL DEFAULT 'scanner',
    first_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_services_asset_port_protocol UNIQUE (asset_id, port, protocol),
    CONSTRAINT ck_services_port_range CHECK (port BETWEEN 1 AND 65535),
    CONSTRAINT ck_services_protocol CHECK (protocol IN ('tcp', 'udp')),
    CONSTRAINT ck_services_state CHECK (state IN ('open', 'closed', 'filtered', 'unknown'))
);

CREATE INDEX IF NOT EXISTS ix_services_asset_state ON services (asset_id, state);
CREATE INDEX IF NOT EXISTS ix_services_name_version ON services (service_name, version);
CREATE INDEX IF NOT EXISTS ix_services_last_seen ON services (last_seen_at DESC);

CREATE TABLE IF NOT EXISTS tasks (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    task_type VARCHAR(32) NOT NULL,
    target_cidr CIDR,
    status VARCHAR(16) NOT NULL DEFAULT 'pending',
    requested_by VARCHAR(128),
    parameters JSONB NOT NULL DEFAULT '{}'::jsonb,
    summary JSONB NOT NULL DEFAULT '{}'::jsonb,
    error_message TEXT,
    started_at TIMESTAMPTZ,
    finished_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT ck_tasks_type CHECK (task_type IN ('discovery', 'port_scan', 'service_scan', 'risk_scan')),
    CONSTRAINT ck_tasks_status CHECK (status IN ('pending', 'running', 'completed', 'failed', 'cancelled'))
);

CREATE INDEX IF NOT EXISTS ix_tasks_type_status_created ON tasks (task_type, status, created_at DESC);
CREATE INDEX IF NOT EXISTS ix_tasks_status_started ON tasks (status, started_at DESC);

CREATE TABLE IF NOT EXISTS scan_results (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    task_id UUID NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
    asset_id UUID REFERENCES assets(id) ON DELETE SET NULL,
    ip INET NOT NULL,
    hostname VARCHAR(255),
    icmp_alive BOOLEAN NOT NULL DEFAULT FALSE,
    tcp_alive BOOLEAN NOT NULL DEFAULT FALSE,
    open_ports JSONB NOT NULL DEFAULT '[]'::jsonb,
    services JSONB NOT NULL DEFAULT '[]'::jsonb,
    raw_result JSONB NOT NULL DEFAULT '{}'::jsonb,
    duration_ms INTEGER,
    scanned_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT ck_scan_results_duration CHECK (duration_ms IS NULL OR duration_ms >= 0)
);

CREATE INDEX IF NOT EXISTS ix_scan_results_task_scanned ON scan_results (task_id, scanned_at DESC);
CREATE INDEX IF NOT EXISTS ix_scan_results_asset_scanned ON scan_results (asset_id, scanned_at DESC);
CREATE INDEX IF NOT EXISTS ix_scan_results_ip ON scan_results (ip);
CREATE INDEX IF NOT EXISTS ix_scan_results_raw_result_gin ON scan_results USING GIN (raw_result);

CREATE TABLE IF NOT EXISTS findings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    asset_id UUID NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    service_id UUID REFERENCES services(id) ON DELETE SET NULL,
    task_id UUID REFERENCES tasks(id) ON DELETE SET NULL,
    rule_key VARCHAR(128) NOT NULL,
    title VARCHAR(255) NOT NULL,
    description TEXT NOT NULL,
    severity VARCHAR(16) NOT NULL,
    status VARCHAR(16) NOT NULL DEFAULT 'open',
    confidence NUMERIC(5,2),
    evidence JSONB NOT NULL DEFAULT '{}'::jsonb,
    first_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT ck_findings_severity CHECK (severity IN ('low', 'medium', 'high', 'critical')),
    CONSTRAINT ck_findings_status CHECK (status IN ('open', 'confirmed', 'ignored', 'fixed')),
    CONSTRAINT ck_findings_confidence CHECK (confidence IS NULL OR (confidence >= 0 AND confidence <= 100))
);

CREATE INDEX IF NOT EXISTS ix_findings_asset_status_severity ON findings (asset_id, status, severity);
CREATE INDEX IF NOT EXISTS ix_findings_service ON findings (service_id);
CREATE INDEX IF NOT EXISTS ix_findings_task ON findings (task_id);
CREATE INDEX IF NOT EXISTS ix_findings_rule_key ON findings (rule_key);
CREATE INDEX IF NOT EXISTS ix_findings_evidence_gin ON findings USING GIN (evidence);
