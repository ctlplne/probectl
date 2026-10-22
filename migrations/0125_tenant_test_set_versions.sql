-- 0125_tenant_test_set_versions.sql — G9 / PLAT-13 (decision D-41,
-- docs/adr/central-test-distribution.md): agents PULL their tenant's central
-- test set as a signed bundle. The bundle's epoch is this per-tenant version,
-- a counter that only increases, so an agent can refuse a replayed or older
-- bundle without trusting any clock shared between control-plane replicas.
--
-- The version is bumped in the same transaction as every write to the tenant's
-- tests (internal/store/tests.go). A tenant with no row is at version 1 (the
-- first bump writes 2), so tests created before this migration are still
-- delivered to an agent that has applied nothing (version 0).
--
-- tenant_id is NON-NULL and the primary key from this, the table's first
-- migration (G7-1); FORCE RLS confines every row to the caller's tenant, and
-- the generic Postgres write fence (0086) rejects writes from an erased or
-- offboarding tenant.
--
-- agents.test_set_version records the version each agent last reported in its
-- heartbeat (the set it verified and applied), so GET /v1/agents can say
-- whether the agent runs the tenant's current tests. Nullable on purpose
-- (expand-only: no NOT NULL on an existing table); NULL reads as 0.
--
-- Idempotent + expand-only (CLAUDE.md §6).

CREATE TABLE IF NOT EXISTS tenant_test_set_versions (
  tenant_id  uuid PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,
  version    bigint NOT NULL DEFAULT 1,
  changed_at timestamptz NOT NULL DEFAULT now()
);

ALTER TABLE tenant_test_set_versions ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant_test_set_versions FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON tenant_test_set_versions;
CREATE POLICY tenant_isolation ON tenant_test_set_versions
  USING (tenant_id = NULLIF(current_setting('probectl.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('probectl.tenant_id', true), '')::uuid);
GRANT SELECT, INSERT, UPDATE, DELETE ON tenant_test_set_versions TO probectl_app;

DO $tenant_test_set_versions_write_fence$
BEGIN
    DROP TRIGGER IF EXISTS tenant_write_fence ON public.tenant_test_set_versions;
    CREATE TRIGGER tenant_write_fence
        BEFORE INSERT OR UPDATE ON public.tenant_test_set_versions
        FOR EACH ROW
        EXECUTE FUNCTION
            public.probectl_enforce_tenant_write_fence();
    ALTER TABLE public.tenant_test_set_versions
        ENABLE ALWAYS TRIGGER tenant_write_fence;
END
$tenant_test_set_versions_write_fence$;

ALTER TABLE agents ADD COLUMN IF NOT EXISTS test_set_version bigint;
