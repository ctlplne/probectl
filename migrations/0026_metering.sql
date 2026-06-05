-- 0026_metering.sql — S-T3 (MT): per-tenant metering, usage & quotas.
--
-- usage_records: aggregated usage per (tenant, meter, period). Billing data
-- ABOUT tenants, owned by the provider plane (like break_glass_grants):
-- written and read by probectl_provider via an explicit policy. It still
-- carries tenant_id + the standard tenant RLS policy so a tenant can read
-- ITS OWN usage through tenant-scoped paths (the watch-out: usage data is
-- itself tenant-scoped). It is provider-owned for silo purposes — never
-- copied into tenant silo schemas (billing stays pooled by design).
--
-- tenant_quotas: per-tenant creation limits (agents, tests), operator-set.
-- NULL = unlimited. Quotas gate control-plane resource creation only;
-- telemetry ingestion is never quota-dropped (fairness throttling is S-T7).
--
-- Idempotent + expand-only (CLAUDE.md §6).

CREATE TABLE IF NOT EXISTS usage_records (
    tenant_id    uuid        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    meter        text        NOT NULL,
    kind         text        NOT NULL DEFAULT 'counter'
                   CHECK (kind IN ('counter', 'gauge')),
    period_start timestamptz NOT NULL,
    period_end   timestamptz NOT NULL,
    value        bigint      NOT NULL DEFAULT 0,
    updated_at   timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, meter, period_start),
    CHECK (period_end > period_start)
);
CREATE INDEX IF NOT EXISTS usage_records_period_idx ON usage_records (period_start);

CREATE TABLE IF NOT EXISTS tenant_quotas (
    tenant_id  uuid        PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,
    max_agents integer,
    max_tests  integer,
    updated_at timestamptz NOT NULL DEFAULT now(),
    updated_by text        NOT NULL DEFAULT '',
    CHECK (max_agents IS NULL OR max_agents >= 0),
    CHECK (max_tests  IS NULL OR max_tests  >= 0)
);

-- Tenant-side RLS (a tenant may read its own usage/quotas via tenant-scoped
-- paths) + the explicit provider-plane policies (the provider writes
-- aggregates and reads across tenants for showback/export — the same
-- sanctioned pattern as provider_fleet_read in 0024).
DO $$
DECLARE
    t text;
BEGIN
    FOREACH t IN ARRAY ARRAY['usage_records', 'tenant_quotas']
    LOOP
        EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
        EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', t);
        EXECUTE format('DROP POLICY IF EXISTS tenant_isolation ON %I', t);
        EXECUTE format($pol$
            CREATE POLICY tenant_isolation ON %I
              USING (tenant_id = NULLIF(current_setting('probectl.tenant_id', true), '')::uuid)
              WITH CHECK (tenant_id = NULLIF(current_setting('probectl.tenant_id', true), '')::uuid)
        $pol$, t);
        EXECUTE format('DROP POLICY IF EXISTS provider_metering ON %I', t);
        EXECUTE format($pol$
            CREATE POLICY provider_metering ON %I
              FOR ALL TO probectl_provider USING (true) WITH CHECK (true)
        $pol$, t);
    END LOOP;
END $$;

GRANT SELECT ON usage_records, tenant_quotas TO probectl_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON usage_records, tenant_quotas TO probectl_provider;
