-- 0008_seed_default_tenant.sql
-- Seed a default Tenant -> Org -> Team -> Project so the single-tenant / dev
-- install works out of the box (the single-tenant case is just one tenant, no
-- separate code path — F50). Fixed UUIDs make this idempotent and referenceable.

INSERT INTO tenants (id, slug, name, status) VALUES
    ('00000000-0000-0000-0000-000000000001', 'default', 'Default Tenant', 'active')
ON CONFLICT (id) DO NOTHING;

-- Set the tenant GUC so RLS WITH CHECK passes for the child inserts when the
-- migration role is a non-superuser owner (a superuser bypasses RLS anyway).
-- Transaction-local: the migration runner wraps each migration in one tx.
SELECT set_config('probectl.tenant_id', '00000000-0000-0000-0000-000000000001', true);

INSERT INTO organizations (id, tenant_id, slug, name) VALUES
    ('00000000-0000-0000-0000-000000000010',
     '00000000-0000-0000-0000-000000000001', 'default', 'Default Org')
ON CONFLICT (id) DO NOTHING;

INSERT INTO teams (id, tenant_id, org_id, slug, name) VALUES
    ('00000000-0000-0000-0000-000000000020',
     '00000000-0000-0000-0000-000000000001',
     '00000000-0000-0000-0000-000000000010', 'default', 'Default Team')
ON CONFLICT (id) DO NOTHING;

INSERT INTO projects (id, tenant_id, team_id, slug, name) VALUES
    ('00000000-0000-0000-0000-000000000030',
     '00000000-0000-0000-0000-000000000001',
     '00000000-0000-0000-0000-000000000020', 'default', 'Default Project')
ON CONFLICT (id) DO NOTHING;
