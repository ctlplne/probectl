-- 0003_rbac.sql
-- RBAC foundation — SCHEMA ONLY. Enforcement (middleware that checks a caller's
-- permissions per route/resource) lands in S18; this sprint establishes the
-- tables so identity/roles exist and carry tenant_id. RBAC operates WITHIN a
-- resolved tenant (the tenant boundary is checked first, then RBAC).

-- Global permission catalog (not tenant-owned: the set of grantable actions is
-- the same for every tenant).
CREATE TABLE IF NOT EXISTS permissions (
    key         text PRIMARY KEY,
    description text NOT NULL DEFAULT ''
);

INSERT INTO permissions (key, description) VALUES
    ('tenant.read',  'Read tenant settings'),
    ('tenant.write', 'Modify tenant settings'),
    ('org.read',     'Read organizations/teams/projects'),
    ('org.write',    'Manage organizations/teams/projects'),
    ('test.read',    'Read tests and results'),
    ('test.write',   'Create and modify tests'),
    ('agent.read',   'Read agents'),
    ('agent.write',  'Manage agents'),
    ('audit.read',   'Read the tenant audit log')
ON CONFLICT (key) DO NOTHING;

CREATE TABLE IF NOT EXISTS roles (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id   uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    slug        text NOT NULL,
    name        text NOT NULL,
    description text NOT NULL DEFAULT '',
    is_system   boolean NOT NULL DEFAULT false,
    created_at  timestamptz NOT NULL DEFAULT now(),
    updated_at  timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, slug)
);
CREATE INDEX IF NOT EXISTS roles_tenant_idx ON roles (tenant_id);

CREATE TABLE IF NOT EXISTS role_permissions (
    tenant_id      uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    role_id        uuid NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    permission_key text NOT NULL REFERENCES permissions(key) ON DELETE CASCADE,
    PRIMARY KEY (role_id, permission_key)
);
CREATE INDEX IF NOT EXISTS role_permissions_tenant_idx ON role_permissions (tenant_id);

CREATE TABLE IF NOT EXISTS role_bindings (
    id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id    uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    subject_type text NOT NULL CHECK (subject_type IN ('user', 'service_account')),
    subject_id   uuid NOT NULL,
    role_id      uuid NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    scope_type   text NOT NULL DEFAULT 'tenant'
                   CHECK (scope_type IN ('tenant', 'org', 'team', 'project')),
    scope_id     uuid,
    created_at   timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, subject_type, subject_id, role_id, scope_type, scope_id)
);
CREATE INDEX IF NOT EXISTS role_bindings_tenant_idx ON role_bindings (tenant_id);
CREATE INDEX IF NOT EXISTS role_bindings_subject_idx ON role_bindings (tenant_id, subject_type, subject_id);

-- RLS on the tenant-owned RBAC tables (permissions is global, no RLS).
DO $$
DECLARE
    t text;
BEGIN
    FOREACH t IN ARRAY ARRAY['roles', 'role_permissions', 'role_bindings']
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
