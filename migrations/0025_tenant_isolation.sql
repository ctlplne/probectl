-- 0025_tenant_isolation.sql — S-T2 (MT): per-tenant isolation model + residency.
--
-- The tenant record carries WHICH isolation model the tenant runs under
-- (pooled stays the default — CLAUDE.md §2, ratified) and an operator-facing
-- residency/data-plane name. The siloed/hybrid mechanics (schema/database
-- provisioning, routing, teardown) live in ee/silo and activate only with the
-- siloed_isolation license feature; these columns are core vocabulary so the
-- registry has one source of truth either way.
--
-- Idempotent + expand-only (CLAUDE.md §6).

ALTER TABLE tenants ADD COLUMN IF NOT EXISTS isolation_model text NOT NULL DEFAULT 'pooled';
ALTER TABLE tenants ADD COLUMN IF NOT EXISTS residency text NOT NULL DEFAULT '';

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'tenants_isolation_model_check'
    ) THEN
        ALTER TABLE tenants
            ADD CONSTRAINT tenants_isolation_model_check
            CHECK (isolation_model IN ('pooled', 'siloed', 'hybrid'));
    END IF;
END $$;
