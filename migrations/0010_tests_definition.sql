-- 0010_tests_definition.sql
-- Extend the tests placeholder (S2/0006) into the synthetic-test definition (S9).
-- tenant_id + Row-Level Security already exist from S2; these columns are
-- additive and idempotent. A test belongs to exactly one tenant; RLS confines
-- every row, so the CRUD API can never read or write across tenants (F50).

ALTER TABLE tests ADD COLUMN IF NOT EXISTS type             text    NOT NULL DEFAULT '';
ALTER TABLE tests ADD COLUMN IF NOT EXISTS target           text    NOT NULL DEFAULT '';
ALTER TABLE tests ADD COLUMN IF NOT EXISTS interval_seconds integer NOT NULL DEFAULT 60;
ALTER TABLE tests ADD COLUMN IF NOT EXISTS timeout_seconds  integer NOT NULL DEFAULT 3;
ALTER TABLE tests ADD COLUMN IF NOT EXISTS params           jsonb   NOT NULL DEFAULT '{}';
ALTER TABLE tests ADD COLUMN IF NOT EXISTS enabled          boolean NOT NULL DEFAULT true;
ALTER TABLE tests ADD COLUMN IF NOT EXISTS updated_at       timestamptz NOT NULL DEFAULT now();

-- Test names are unique within a tenant (CLI/UI ergonomics; yields 409 on a
-- duplicate). The index is per-tenant, so two tenants may reuse a name.
CREATE UNIQUE INDEX IF NOT EXISTS tests_tenant_name_idx ON tests (tenant_id, name);
