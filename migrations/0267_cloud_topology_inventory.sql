-- SPDX-License-Identifier: BUSL-1.1
--
-- Use of this source code is governed by the Business Source License 1.1
-- in the LICENSE file at the root of this repository; on its Change Date
-- each version converts to the Mozilla Public License 2.0.

CREATE TABLE IF NOT EXISTS public.cloud_topology_inventories (
    tenant_id uuid NOT NULL REFERENCES public.tenants(id) ON DELETE CASCADE,
    provider text NOT NULL CHECK (provider IN ('aws', 'azure', 'gcp')),
    account text NOT NULL CHECK (octet_length(account) BETWEEN 1 AND 256),
    location text NOT NULL CHECK (octet_length(location) BETWEEN 1 AND 128),
    observed_at timestamptz NOT NULL,
    inventory jsonb NOT NULL CHECK (jsonb_typeof(inventory) = 'object' AND octet_length(inventory::text) <= 2097152),
    PRIMARY KEY (tenant_id, provider, account, location)
);

ALTER TABLE public.cloud_topology_inventories ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.cloud_topology_inventories FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON public.cloud_topology_inventories;
CREATE POLICY tenant_isolation ON public.cloud_topology_inventories
    USING (tenant_id = NULLIF(current_setting('probectl.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('probectl.tenant_id', true), '')::uuid);
DROP TRIGGER IF EXISTS tenant_write_fence ON public.cloud_topology_inventories;
CREATE TRIGGER tenant_write_fence BEFORE INSERT OR UPDATE ON public.cloud_topology_inventories
    FOR EACH ROW EXECUTE FUNCTION public.probectl_enforce_tenant_write_fence();
ALTER TABLE public.cloud_topology_inventories ENABLE ALWAYS TRIGGER tenant_write_fence;
GRANT SELECT, INSERT, UPDATE, DELETE ON public.cloud_topology_inventories TO probectl_app;
