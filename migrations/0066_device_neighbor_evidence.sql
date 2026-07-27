-- 0066_device_neighbor_evidence.sql
-- Current, bounded LLDP/CDP physical-adjacency evidence. Each agent snapshot
-- replaces one configured device's rows; this is not a packet/log archive.

CREATE TABLE IF NOT EXISTS device_neighbor_evidence (
    tenant_id                 uuid             NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    evidence_id               text             NOT NULL,
    agent_id                  text             NOT NULL,
    local_device_address      text             NOT NULL,
    local_device_name         text             NOT NULL DEFAULT '',
    local_if_index            bigint           NOT NULL DEFAULT 0,
    local_port_id             text             NOT NULL,
    remote_chassis_id         text             NOT NULL DEFAULT '',
    remote_device_name        text             NOT NULL DEFAULT '',
    remote_port_id            text             NOT NULL,
    remote_management_address text             NOT NULL DEFAULT '',
    remote_platform           text             NOT NULL DEFAULT '',
    capabilities              text[]           NOT NULL DEFAULT '{}',
    protocol                  text             NOT NULL,
    confidence                double precision NOT NULL,
    observed_at               timestamptz      NOT NULL,
    fresh_until               timestamptz      NOT NULL,
    PRIMARY KEY (tenant_id, evidence_id),
    CHECK (length(evidence_id) BETWEEN 1 AND 64),
    CHECK (length(agent_id) BETWEEN 1 AND 128),
    CHECK (length(local_device_address) BETWEEN 1 AND 255),
    CHECK (length(local_device_name) <= 255),
    CHECK (local_if_index BETWEEN 0 AND 4294967295),
    CHECK (length(local_port_id) BETWEEN 1 AND 128),
    CHECK (length(remote_chassis_id) <= 256),
    CHECK (length(remote_device_name) <= 255),
    CHECK (length(remote_port_id) BETWEEN 1 AND 128),
    CHECK (length(remote_management_address) <= 255),
    CHECK (length(remote_platform) <= 255),
    CHECK (cardinality(capabilities) <= 32),
    CHECK (protocol IN ('lldp', 'cdp')),
    CHECK (confidence BETWEEN 0 AND 1),
    CHECK (fresh_until > observed_at)
);

CREATE INDEX IF NOT EXISTS device_neighbor_evidence_tenant_device_time_idx
    ON device_neighbor_evidence (tenant_id, local_device_address, observed_at DESC);

ALTER TABLE device_neighbor_evidence ENABLE ROW LEVEL SECURITY;
ALTER TABLE device_neighbor_evidence FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON device_neighbor_evidence;
CREATE POLICY tenant_isolation ON device_neighbor_evidence
  USING (tenant_id = NULLIF(current_setting('probectl.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('probectl.tenant_id', true), '')::uuid);

GRANT SELECT, INSERT, UPDATE, DELETE ON device_neighbor_evidence TO probectl_app;
