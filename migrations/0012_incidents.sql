-- 0012_incidents.sql
-- Cross-plane incidents + their signal timeline (S17, F9). Tenant-owned:
-- tenant_id + Row-Level Security confine every row to its tenant (F50), so
-- correlation and the timeline API never cross tenants. Idempotent.
--
-- incident_signals is the extensible timeline: `plane` and `kind` are free-form
-- and `attributes` is jsonb, so future planes (threat / change / cost / SLO)
-- attach signals with no schema churn (S17 watch-out).

CREATE TABLE IF NOT EXISTS incidents (
    id            uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id     uuid        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    status        text        NOT NULL DEFAULT 'open',
    severity      text        NOT NULL DEFAULT 'info',
    severity_rank smallint    NOT NULL DEFAULT 1,
    title         text        NOT NULL DEFAULT '',
    target        text        NOT NULL DEFAULT '',
    prefix        text        NOT NULL DEFAULT '',
    started_at    timestamptz NOT NULL DEFAULT now(),
    last_seen_at  timestamptz NOT NULL DEFAULT now(),
    resolved_at   timestamptz,
    signal_count  integer     NOT NULL DEFAULT 0,
    created_at    timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS incidents_tenant_idx ON incidents (tenant_id);
-- Correlation reads open incidents most-recently-active first.
CREATE INDEX IF NOT EXISTS incidents_tenant_open_idx ON incidents (tenant_id, status, last_seen_at DESC);

CREATE TABLE IF NOT EXISTS incident_signals (
    id          uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id   uuid        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    incident_id uuid        NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
    plane       text        NOT NULL,
    kind        text        NOT NULL,
    severity    text        NOT NULL DEFAULT 'info',
    title       text        NOT NULL DEFAULT '',
    summary     text        NOT NULL DEFAULT '',
    target      text        NOT NULL DEFAULT '',
    prefix      text        NOT NULL DEFAULT '',
    attributes  jsonb       NOT NULL DEFAULT '{}',
    occurred_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS incident_signals_incident_idx ON incident_signals (incident_id, occurred_at);
CREATE INDEX IF NOT EXISTS incident_signals_tenant_idx ON incident_signals (tenant_id);

DO $$
DECLARE
    t text;
BEGIN
    FOREACH t IN ARRAY ARRAY['incidents', 'incident_signals']
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

GRANT SELECT, INSERT, UPDATE, DELETE ON incidents, incident_signals TO probectl_app;
