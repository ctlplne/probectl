-- 0062_current_tenant_identity.sql
-- X14: let the least-privilege application role display the authenticated
-- tenant's name without granting it SELECT over the provider-wide registry.
-- The SECURITY DEFINER body is pinned to public.tenants and reduces by the
-- transaction-local tenant GUC before returning anything.

CREATE OR REPLACE FUNCTION public.probectl_current_tenant_identity()
RETURNS TABLE (id uuid, slug text, name text)
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
  SELECT t.id, t.slug, t.name
    FROM public.tenants AS t
   WHERE t.id = NULLIF(pg_catalog.current_setting('probectl.tenant_id', true), '')::uuid
$$;

REVOKE ALL ON FUNCTION public.probectl_current_tenant_identity() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.probectl_current_tenant_identity() TO probectl_app;
