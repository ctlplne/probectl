-- 0002_tenancy_core.sql
-- Tenant-first core: the Tenant -> Organization -> Team -> Project hierarchy plus
-- users and service accounts. `tenant_id` is the OUTERMOST scope on every
-- tenant-owned table from this first migration (F50/F24) — never added later.
--
-- Pooled isolation (F52-pooled) is enforced by Row-Level Security keyed on the
-- `probectl.tenant_id` GUC that internal/tenancy sets per transaction. When the GUC
-- is unset, current_setting(...) is NULL and no rows match — fail closed
-- (CLAUDE.md §7 guardrail 1). Identifiers are UUIDs + stable slugs so they map
-- cleanly onto OTel resource attributes (S6/S22).

-- The tenant registry. tenants is provider-scoped (the outermost entity), so it
-- is NOT itself tenant-owned: no tenant_id, no RLS.
CREATE TABLE IF NOT EXISTS tenants (
    id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    slug       text NOT NULL UNIQUE,
    name       text NOT NULL,
    status     text NOT NULL DEFAULT 'active'
                 CHECK (status IN ('active', 'suspended', 'offboarding', 'deleted')),
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS organizations (
    id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id  uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    slug       text NOT NULL,
    name       text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, slug)
);
CREATE INDEX IF NOT EXISTS organizations_tenant_idx ON organizations (tenant_id);

CREATE TABLE IF NOT EXISTS teams (
    id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id  uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    org_id     uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    slug       text NOT NULL,
    name       text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, org_id, slug)
);
CREATE INDEX IF NOT EXISTS teams_tenant_idx ON teams (tenant_id);
CREATE INDEX IF NOT EXISTS teams_org_idx ON teams (org_id);

CREATE TABLE IF NOT EXISTS projects (
    id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id  uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    team_id    uuid NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
    slug       text NOT NULL,
    name       text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, team_id, slug)
);
CREATE INDEX IF NOT EXISTS projects_tenant_idx ON projects (tenant_id);
CREATE INDEX IF NOT EXISTS projects_team_idx ON projects (team_id);

CREATE TABLE IF NOT EXISTS users (
    id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id    uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    email        text NOT NULL,
    display_name text NOT NULL DEFAULT '',
    status       text NOT NULL DEFAULT 'active'
                   CHECK (status IN ('active', 'suspended', 'disabled')),
    created_at   timestamptz NOT NULL DEFAULT now(),
    updated_at   timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, email)
);
CREATE INDEX IF NOT EXISTS users_tenant_idx ON users (tenant_id);

CREATE TABLE IF NOT EXISTS service_accounts (
    id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id  uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name       text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, name)
);
CREATE INDEX IF NOT EXISTS service_accounts_tenant_idx ON service_accounts (tenant_id);

-- Enable pooled-isolation RLS on every tenant-owned table created above.
-- ENABLE + FORCE so even the table owner is subject to the policy; the policy
-- matches rows to the per-transaction probectl.tenant_id GUC and fails closed when
-- it is unset.
DO $$
DECLARE
    t text;
BEGIN
    FOREACH t IN ARRAY ARRAY['organizations', 'teams', 'projects', 'users', 'service_accounts']
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
