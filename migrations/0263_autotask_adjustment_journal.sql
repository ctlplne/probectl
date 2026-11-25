-- SPDX-License-Identifier: BUSL-1.1
--
-- Use of this source code is governed by the Business Source License 1.1
-- in the LICENSE file at the root of this repository; on its Change Date
-- each version converts to the Mozilla Public License 2.0.

-- One unresolved additive adjustment per tenant and vendor contract service.
-- Do not expire these rows with the audit log. A lost response must never turn
-- into permission to add the same units again.
CREATE TABLE IF NOT EXISTS public.psa_autotask_adjustment_pending (
    tenant_id uuid NOT NULL REFERENCES public.tenants(id) ON DELETE CASCADE,
    company_id bigint NOT NULL CHECK (company_id BETWEEN 1 AND 2147483647),
    contract_id bigint NOT NULL CHECK (contract_id BETWEEN 1 AND 2147483647),
    contract_service_id bigint NOT NULL CHECK (contract_service_id BETWEEN 1 AND 2147483647),
    requested_seq bigint NOT NULL CHECK (requested_seq > 0),
    effective_at timestamptz NOT NULL,
    previous_units bigint NOT NULL CHECK (previous_units BETWEEN 0 AND 2147483647),
    desired_units bigint NOT NULL CHECK (desired_units BETWEEN 0 AND 2147483647),
    PRIMARY KEY (tenant_id, company_id, contract_id, contract_service_id),
    CHECK (previous_units <> desired_units)
);

ALTER TABLE public.psa_autotask_adjustment_pending ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.psa_autotask_adjustment_pending FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS tenant_isolation ON public.psa_autotask_adjustment_pending;
CREATE POLICY tenant_isolation ON public.psa_autotask_adjustment_pending
    USING (tenant_id = NULLIF(current_setting('probectl.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('probectl.tenant_id', true), '')::uuid);

DROP TRIGGER IF EXISTS tenant_write_fence ON public.psa_autotask_adjustment_pending;
CREATE TRIGGER tenant_write_fence BEFORE INSERT ON public.psa_autotask_adjustment_pending
    FOR EACH ROW EXECUTE FUNCTION public.probectl_enforce_tenant_write_fence();
ALTER TABLE public.psa_autotask_adjustment_pending ENABLE ALWAYS TRIGGER tenant_write_fence;
-- An attempt may be reserved or resolved, never rewritten in place.
REVOKE UPDATE ON public.psa_autotask_adjustment_pending FROM probectl_app;
GRANT SELECT, INSERT, DELETE ON public.psa_autotask_adjustment_pending TO probectl_app;
