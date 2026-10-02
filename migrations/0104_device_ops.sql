-- 0104_device_ops.sql
-- PLAT-06 / RTP-08 / WEB-26: durable, tenant-scoped storage for device syslog
-- and the device configuration archive, which were process-memory only (lost on
-- restart, not shared between replicas). Each table carries tenant_id + FORCE
-- ROW LEVEL SECURITY from creation, so the tenant boundary is the database's,
-- never the handler's (guardrail 1).

CREATE TABLE IF NOT EXISTS device_syslog (
    id             uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id      uuid        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    device         text        NOT NULL,
    source_address text        NOT NULL DEFAULT '',
    facility       int         NOT NULL DEFAULT 0,
    severity       int         NOT NULL DEFAULT 0,
    severity_text  text        NOT NULL DEFAULT '',
    hostname       text        NOT NULL DEFAULT '',
    app_name       text        NOT NULL DEFAULT '',
    message        text        NOT NULL,
    raw            text        NOT NULL DEFAULT '',
    labels         jsonb       NOT NULL DEFAULT '{}',
    observed_at    timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS device_syslog_tenant_observed_idx ON device_syslog (tenant_id, observed_at DESC);
CREATE INDEX IF NOT EXISTS device_syslog_tenant_device_idx ON device_syslog (tenant_id, device, observed_at DESC);

CREATE TABLE IF NOT EXISTS device_configs (
    id            uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id     uuid        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    device        text        NOT NULL,
    source        text        NOT NULL DEFAULT '',
    version       int         NOT NULL,
    content       text        NOT NULL DEFAULT '',
    content_hash  text        NOT NULL,
    previous_hash text        NOT NULL DEFAULT '',
    drifted       boolean     NOT NULL DEFAULT false,
    observed_at   timestamptz NOT NULL DEFAULT now(),
    archived_at   timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, device, version)
);
CREATE INDEX IF NOT EXISTS device_configs_tenant_archived_idx ON device_configs (tenant_id, archived_at DESC);
CREATE INDEX IF NOT EXISTS device_configs_tenant_device_idx ON device_configs (tenant_id, device, version DESC);

DO $$
DECLARE
    t text;
BEGIN
    FOREACH t IN ARRAY ARRAY['device_syslog', 'device_configs']
    LOOP
        EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
        EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', t);
        EXECUTE format('DROP POLICY IF EXISTS tenant_isolation ON %I', t);
        EXECUTE format($pol$
            CREATE POLICY tenant_isolation ON %I
              USING (tenant_id = NULLIF(current_setting('probectl.tenant_id', true), '')::uuid)
              WITH CHECK (tenant_id = NULLIF(current_setting('probectl.tenant_id', true), '')::uuid)
        $pol$, t);
    END LOOP;
END $$;

GRANT SELECT, INSERT, UPDATE, DELETE ON device_syslog, device_configs TO probectl_app;
