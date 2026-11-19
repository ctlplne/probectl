-- SPDX-License-Identifier: BUSL-1.1
-- Use of this source code is governed by the Business Source License 1.1
-- in the LICENSE file at the root of this repository; on its Change Date
-- each version converts to the Mozilla Public License 2.0.

-- The existing ALWAYS triggers in pooled and siloed observation tables call
-- this function. Report records, identities and administrative writes keep
-- their existing lifecycle rules.
CREATE OR REPLACE FUNCTION public.probectl_enforce_tenant_write_fence()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $tenant_write_fence$
DECLARE
    tenant_status text;
    tenant_fenced_at timestamptz;
    collection_ends_at timestamptz;
BEGIN
    IF NEW.tenant_id IS NULL THEN
        RAISE EXCEPTION 'tenant write is missing tenant_id' USING ERRCODE = '42501';
    END IF;

    PERFORM pg_advisory_xact_lock_shared(
        hashtextextended('tenant-write:' || NEW.tenant_id::text, 0)
    );
    SELECT status, audit_write_fenced_at, prospect_collection_ends_at
      INTO tenant_status, tenant_fenced_at, collection_ends_at
      FROM public.tenants
     WHERE id = NEW.tenant_id;

    IF NOT FOUND OR tenant_fenced_at IS NOT NULL OR tenant_status NOT IN ('active', 'suspended') THEN
        RAISE EXCEPTION 'tenant writes are fenced for lifecycle erasure' USING ERRCODE = '55000';
    END IF;
    IF collection_ends_at <= clock_timestamp() AND (
        TG_TABLE_NAME IN ('results', 'device_neighbor_evidence', 'device_collection_outcomes',
            'device_traps', 'device_counter_captures', 'device_counter_capture_sources', 'entity_evidence')
        OR (TG_TABLE_NAME = 'entity_fault_receipts' AND TG_OP = 'INSERT')
    ) THEN
        RAISE EXCEPTION 'prospect telemetry collection ended' USING ERRCODE = 'PZC01';
    END IF;
    RETURN NEW;
END
$tenant_write_fence$;

-- A replacement of the current neighbor snapshot may have zero incoming rows.
-- Admit it before the DELETE while leaving ordinary retention and erasure free
-- to remove observations. Only the bound tenant's collection status is used.
CREATE OR REPLACE FUNCTION public.probectl_require_tenant_collection(expected_tenant uuid)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $tenant_collection$
DECLARE
    tenant_status text;
    tenant_fenced_at timestamptz;
    collection_ends_at timestamptz;
BEGIN
    IF expected_tenant IS NULL OR
       NULLIF(current_setting('probectl.tenant_id', true), '') IS DISTINCT FROM expected_tenant::text THEN
        RAISE EXCEPTION 'tenant collection scope differs' USING ERRCODE = '42501';
    END IF;
    PERFORM pg_advisory_xact_lock_shared(
        hashtextextended('tenant-write:' || expected_tenant::text, 0)
    );
    SELECT status, audit_write_fenced_at, prospect_collection_ends_at
      INTO tenant_status, tenant_fenced_at, collection_ends_at
      FROM public.tenants WHERE id = expected_tenant;
    IF NOT FOUND OR tenant_fenced_at IS NOT NULL OR tenant_status NOT IN ('active', 'suspended') THEN
        RAISE EXCEPTION 'tenant writes are fenced for lifecycle erasure' USING ERRCODE = '55000';
    END IF;
    IF collection_ends_at <= clock_timestamp() THEN
        RAISE EXCEPTION 'prospect telemetry collection ended' USING ERRCODE = 'PZC01';
    END IF;
END
$tenant_collection$;

REVOKE ALL ON FUNCTION public.probectl_require_tenant_collection(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.probectl_require_tenant_collection(uuid) TO probectl_app;
