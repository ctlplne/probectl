-- 0018_scim_abac.sql
-- Enterprise identity (S31, F25): SCIM 2.0 lifecycle + ABAC over RBAC.
--   * users gains the SCIM identity fields — external_id (the IdP's stable user id),
--     user_name (the SCIM userName, which may differ from email), and an
--     attributes jsonb for ABAC subject attributes (e.g. department).
--   * scim_tokens: per-tenant bearer tokens an IdP presents to /scim/v2. Like
--     sessions/mcp_tokens the lookup is PRE-TENANT (a token selects its own tenant)
--     and only the hash is stored, so a database read cannot mint a token.
--   * abac_policies: tenant-scoped attribute policies evaluated AFTER RBAC
--     (deny-override) — so a contractor or non-MFA subject can be denied an action
--     an RBAC role grants. RLS confines them to the tenant.
-- Idempotent + backward-compatible (additive columns, new tables).

ALTER TABLE users ADD COLUMN IF NOT EXISTS external_id text;
ALTER TABLE users ADD COLUMN IF NOT EXISTS user_name   text;
ALTER TABLE users ADD COLUMN IF NOT EXISTS attributes  jsonb NOT NULL DEFAULT '{}';
-- SCIM identifiers are unique within a tenant when present (partial unique).
CREATE UNIQUE INDEX IF NOT EXISTS users_tenant_external_idx ON users (tenant_id, external_id) WHERE external_id IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS users_tenant_username_idx ON users (tenant_id, user_name) WHERE user_name IS NOT NULL;

CREATE TABLE IF NOT EXISTS scim_tokens (
    id           uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id    uuid        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name         text        NOT NULL DEFAULT '',
    token_hash   bytea       NOT NULL UNIQUE,
    created_at   timestamptz NOT NULL DEFAULT now(),
    last_used_at timestamptz,
    revoked_at   timestamptz
);
CREATE INDEX IF NOT EXISTS scim_tokens_tenant_idx ON scim_tokens (tenant_id);
GRANT SELECT, INSERT, UPDATE, DELETE ON scim_tokens TO probectl_app;

CREATE TABLE IF NOT EXISTS abac_policies (
    id         uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id  uuid        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name       text        NOT NULL DEFAULT '',
    effect     text        NOT NULL DEFAULT 'deny' CHECK (effect IN ('allow', 'deny')),
    permission text        NOT NULL DEFAULT '*',
    subject    jsonb       NOT NULL DEFAULT '{}',
    resource   jsonb       NOT NULL DEFAULT '{}',
    priority   integer     NOT NULL DEFAULT 0,
    enabled    boolean     NOT NULL DEFAULT true,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS abac_policies_tenant_idx ON abac_policies (tenant_id);

DO $$
DECLARE
    t text;
BEGIN
    FOREACH t IN ARRAY ARRAY['abac_policies']
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
GRANT SELECT, INSERT, UPDATE, DELETE ON abac_policies TO probectl_app;

-- Permission keys gating directory administration: SCIM token + ABAC policy CRUD
-- and the user/group lifecycle (delegated admin within a tenant). Idempotent.
INSERT INTO permissions (key, description) VALUES
    ('directory.read',  'Read users/roles + SCIM config + ABAC policies'),
    ('directory.write', 'Manage users/roles, SCIM tokens, and ABAC policies (delegated admin)')
ON CONFLICT (key) DO NOTHING;

-- Grant directory admin to the default tenant's admin role; other tenants are
-- seeded at provisioning.
INSERT INTO role_permissions (tenant_id, role_id, permission_key)
    SELECT r.tenant_id, r.id, p.key
    FROM roles r CROSS JOIN permissions p
    WHERE r.tenant_id = '00000000-0000-0000-0000-000000000001'
      AND r.slug = 'admin'
      AND p.key IN ('directory.read', 'directory.write')
ON CONFLICT (role_id, permission_key) DO NOTHING;
