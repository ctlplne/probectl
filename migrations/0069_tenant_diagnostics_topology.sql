-- 0069_tenant_diagnostics_topology.sql
-- Give the least-privilege tenant role exactly the caller's topology metadata
-- without granting access to the provider-wide tenants registry. The
-- transaction-local tenant GUC is the first filter; callers also predicate the
-- returned tenant_id as defense in depth.

CREATE OR REPLACE FUNCTION public.probectl_current_tenant_topology()
RETURNS TABLE (tenant_id uuid, isolation_model text)
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
  SELECT t.id, t.isolation_model
    FROM public.tenants AS t
   WHERE t.id = NULLIF(pg_catalog.current_setting('probectl.tenant_id', true), '')::uuid
$$;

REVOKE ALL ON FUNCTION public.probectl_current_tenant_topology() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.probectl_current_tenant_topology() TO probectl_app;
