-- SPDX-License-Identifier: BUSL-1.1
--
-- Use of this source code is governed by the Business Source License 1.1
-- in the LICENSE file at the root of this repository; on its Change Date
-- each version converts to the Mozilla Public License 2.0.

CREATE TABLE IF NOT EXISTS public.instant_test_runs (
    tenant_id uuid NOT NULL CONSTRAINT instant_test_runs_tenant_fk
        REFERENCES public.tenants(id) ON DELETE CASCADE,
    id uuid NOT NULL,
    requested_by uuid NOT NULL,
    requested_with_mfa boolean NOT NULL,
    idempotency_key uuid NOT NULL,
    request_hash bytea NOT NULL CHECK (octet_length(request_hash) = 32),
    test_id uuid NOT NULL,
    test_updated_at timestamptz NOT NULL,
    definition_hash text NOT NULL CHECK (definition_hash ~ '^[0-9a-f]{64}$'),
    timeout_seconds integer NOT NULL CHECK (timeout_seconds BETWEEN 1 AND 300),
    created_at timestamptz NOT NULL,
    dispatch_until timestamptz NOT NULL CHECK (dispatch_until > created_at),
    retain_until timestamptz NOT NULL CHECK (retain_until > dispatch_until),
    PRIMARY KEY (tenant_id, id),
    UNIQUE (tenant_id, requested_by, idempotency_key),
    CONSTRAINT instant_test_runs_test_fk FOREIGN KEY (tenant_id, test_id)
        REFERENCES public.tests(tenant_id, id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS public.instant_test_assignments (
    tenant_id uuid NOT NULL,
    run_id uuid NOT NULL,
    agent_id uuid NOT NULL,
    agent_registered_at timestamptz NOT NULL,
    lease_id uuid,
    leased_at timestamptz,
    lease_until timestamptz,
    result_id uuid,
    result_hash bytea CHECK (octet_length(result_hash) = 32),
    result jsonb CHECK (jsonb_typeof(result) = 'object'),
    PRIMARY KEY (tenant_id, run_id, agent_id),
    UNIQUE (tenant_id, lease_id),
    UNIQUE (tenant_id, result_id),
    CONSTRAINT instant_test_assignments_run_fk FOREIGN KEY (tenant_id, run_id)
        REFERENCES public.instant_test_runs(tenant_id, id) ON DELETE CASCADE,
    CHECK (
        (lease_id IS NULL AND leased_at IS NULL AND lease_until IS NULL)
        OR (lease_id IS NOT NULL AND leased_at IS NOT NULL AND lease_until IS NOT NULL AND leased_at < lease_until)
    ),
    CHECK (
        (result_id IS NULL AND result_hash IS NULL AND result IS NULL)
        OR (result_id IS NOT NULL AND lease_id IS NOT NULL AND result_hash IS NOT NULL AND result IS NOT NULL)
    )
);

CREATE INDEX IF NOT EXISTS instant_test_runs_retention
    ON public.instant_test_runs (tenant_id, retain_until);
CREATE INDEX IF NOT EXISTS instant_test_runs_test
    ON public.instant_test_runs (tenant_id, test_id, created_at);
CREATE INDEX IF NOT EXISTS instant_test_assignments_pending
    ON public.instant_test_assignments (tenant_id, agent_id, run_id) WHERE result_id IS NULL;

ALTER TABLE public.instant_test_runs ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.instant_test_runs FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON public.instant_test_runs;
CREATE POLICY tenant_isolation ON public.instant_test_runs
    USING (tenant_id = NULLIF(current_setting('probectl.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('probectl.tenant_id', true), '')::uuid);
DROP TRIGGER IF EXISTS tenant_write_fence ON public.instant_test_runs;
CREATE TRIGGER tenant_write_fence BEFORE INSERT OR UPDATE ON public.instant_test_runs
    FOR EACH ROW EXECUTE FUNCTION public.probectl_enforce_tenant_write_fence();
ALTER TABLE public.instant_test_runs ENABLE ALWAYS TRIGGER tenant_write_fence;
GRANT SELECT, INSERT, DELETE ON public.instant_test_runs TO probectl_app;

ALTER TABLE public.instant_test_assignments ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.instant_test_assignments FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON public.instant_test_assignments;
CREATE POLICY tenant_isolation ON public.instant_test_assignments
    USING (tenant_id = NULLIF(current_setting('probectl.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('probectl.tenant_id', true), '')::uuid);
DROP TRIGGER IF EXISTS tenant_write_fence ON public.instant_test_assignments;
CREATE TRIGGER tenant_write_fence BEFORE INSERT OR UPDATE ON public.instant_test_assignments
    FOR EACH ROW EXECUTE FUNCTION public.probectl_enforce_tenant_write_fence();
ALTER TABLE public.instant_test_assignments ENABLE ALWAYS TRIGGER tenant_write_fence;
GRANT SELECT, INSERT, UPDATE, DELETE ON public.instant_test_assignments TO probectl_app;
