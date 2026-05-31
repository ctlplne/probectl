-- 0001_baseline.sql
-- S1 baseline migration. Intentionally minimal: the tenant-first core schema
-- (tenants, organizations, teams, projects, users, RBAC, audit, ...) is
-- introduced in S2. This creates a single GLOBAL (non-tenant-owned) metadata
-- table used to record install-wide facts, and is safe to run repeatedly.

CREATE TABLE IF NOT EXISTS netctl_meta (
    key        text PRIMARY KEY,
    value      text NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT now()
);

INSERT INTO netctl_meta (key, value)
VALUES ('schema_baseline', 's1')
ON CONFLICT (key) DO NOTHING;
