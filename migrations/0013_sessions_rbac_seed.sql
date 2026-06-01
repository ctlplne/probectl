-- 0013_sessions_rbac_seed.sql
-- Identity foundation (S18, F22): server-side sessions + the permission keys and
-- seeded system roles that RBAC enforcement uses. RBAC operates WITHIN a resolved
-- tenant — the tenant boundary (S2/RLS) is checked first, then RBAC. Idempotent.

-- Sessions are a GLOBAL table (no tenant RLS): a session is looked up by the
-- hash of its opaque token BEFORE any tenant context exists (the row reveals the
-- tenant). The token itself is the secret and is never stored — only its hash —
-- so a database read cannot mint a valid session (guardrail 6).
CREATE TABLE IF NOT EXISTS sessions (
    id            uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    token_hash    bytea       NOT NULL UNIQUE,
    tenant_id     uuid        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    user_id       uuid        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    email         text        NOT NULL DEFAULT '',
    display_name  text        NOT NULL DEFAULT '',
    mfa_satisfied boolean     NOT NULL DEFAULT false,
    expires_at    timestamptz NOT NULL,
    created_at    timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS sessions_expires_idx ON sessions (expires_at);

-- New permission keys for the planes added since S2 (alerting S16, incidents S17).
INSERT INTO permissions (key, description) VALUES
    ('alert.read',     'Read alert rules'),
    ('alert.write',    'Create and modify alert rules'),
    ('incident.read',  'Read incidents and timelines'),
    ('incident.write', 'Resolve / manage incidents')
ON CONFLICT (key) DO NOTHING;

-- Seed system roles for the default tenant (other tenants are seeded at
-- provisioning — the provider plane, S-T1). admin = all; editor = read + manage
-- tests/alerts/incidents; viewer = read-only.
INSERT INTO roles (tenant_id, slug, name, description, is_system) VALUES
    ('00000000-0000-0000-0000-000000000001', 'admin',  'Administrator', 'Full access within the tenant', true),
    ('00000000-0000-0000-0000-000000000001', 'editor', 'Editor',        'Read everything; manage tests, alerts, incidents', true),
    ('00000000-0000-0000-0000-000000000001', 'viewer', 'Viewer',        'Read-only', true)
ON CONFLICT (tenant_id, slug) DO NOTHING;

-- admin → every permission.
INSERT INTO role_permissions (tenant_id, role_id, permission_key)
    SELECT r.tenant_id, r.id, p.key
    FROM roles r CROSS JOIN permissions p
    WHERE r.tenant_id = '00000000-0000-0000-0000-000000000001' AND r.slug = 'admin'
ON CONFLICT (role_id, permission_key) DO NOTHING;

-- viewer → every read permission.
INSERT INTO role_permissions (tenant_id, role_id, permission_key)
    SELECT r.tenant_id, r.id, p.key
    FROM roles r CROSS JOIN permissions p
    WHERE r.tenant_id = '00000000-0000-0000-0000-000000000001' AND r.slug = 'viewer'
      AND p.key LIKE '%.read'
ON CONFLICT (role_id, permission_key) DO NOTHING;

-- editor → read everything + manage tests/alerts/incidents.
INSERT INTO role_permissions (tenant_id, role_id, permission_key)
    SELECT r.tenant_id, r.id, p.key
    FROM roles r CROSS JOIN permissions p
    WHERE r.tenant_id = '00000000-0000-0000-0000-000000000001' AND r.slug = 'editor'
      AND (p.key LIKE '%.read' OR p.key IN ('test.write', 'alert.write', 'incident.write'))
ON CONFLICT (role_id, permission_key) DO NOTHING;

-- The auth layer reads sessions via the pool (pre-tenant), so grant the login
-- role; netctl_app inherits DML on new public tables via ALTER DEFAULT PRIVILEGES.
GRANT SELECT, INSERT, DELETE ON sessions TO netctl_app;
