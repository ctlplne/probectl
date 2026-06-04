-- 0006_placeholders.sql
-- Placeholder tenant-owned tables so the tenant boundary and foreign keys exist
-- from M1. Real columns are added by their sprints: agents in S4/S5, tests in S7,
-- results in S6. Each carries tenant_id + RLS from creation (never retrofitted).
-- An agent belongs to exactly one tenant (F50/F1).

CREATE TABLE IF NOT EXISTS agents (
    id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id  uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name       text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, name)
);
CREATE INDEX IF NOT EXISTS agents_tenant_idx ON agents (tenant_id);

CREATE TABLE IF NOT EXISTS tests (
    id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id  uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name       text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS tests_tenant_idx ON tests (tenant_id);

CREATE TABLE IF NOT EXISTS results (
    id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id  uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS results_tenant_idx ON results (tenant_id);

DO $$
DECLARE
    t text;
BEGIN
    FOREACH t IN ARRAY ARRAY['agents', 'tests', 'results']
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
