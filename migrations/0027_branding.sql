-- 0027_branding.sql — S-T4 (MT): per-tenant white-label branding.
--
-- tenant_branding: one row per branded tenant — the TenantBranding contract
-- (product name, inline logo data URI, login message, S8a token overrides as
-- jsonb, email branding, optional custom domain). provider_branding: the
-- provider's MASTER brand (a singleton) — the default for every tenant
-- without its own row. Resolution precedence: tenant → provider master →
-- the probectl default (in code).
--
-- Both are provider-plane configuration ABOUT tenants (configured from the
-- provider console; READ pre-auth via the public /branding endpoint through
-- the provider role): explicit provider policies like 0024/0026, plus the
-- standard tenant RLS on tenant_branding so a tenant could read its own brand
-- through tenant-scoped paths. Neither is copied into silo schemas (the
-- control plane serves branding; billing/config stays pooled by design).
--
-- Idempotent + expand-only (CLAUDE.md §6).

CREATE TABLE IF NOT EXISTS tenant_branding (
    tenant_id       uuid        PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,
    product_name    text        NOT NULL DEFAULT '',
    logo_data_uri   text        NOT NULL DEFAULT '',
    login_message   text        NOT NULL DEFAULT '',
    token_overrides jsonb       NOT NULL DEFAULT '{}'::jsonb,
    email_from_name text        NOT NULL DEFAULT '',
    email_footer    text        NOT NULL DEFAULT '',
    custom_domain   text,
    updated_at      timestamptz NOT NULL DEFAULT now(),
    updated_by      text        NOT NULL DEFAULT ''
);
-- One tenant per custom domain; NULLs (no domain) don't collide.
CREATE UNIQUE INDEX IF NOT EXISTS tenant_branding_domain_idx
    ON tenant_branding (custom_domain) WHERE custom_domain IS NOT NULL;

CREATE TABLE IF NOT EXISTS provider_branding (
    singleton       boolean     PRIMARY KEY DEFAULT true CHECK (singleton),
    product_name    text        NOT NULL DEFAULT '',
    logo_data_uri   text        NOT NULL DEFAULT '',
    login_message   text        NOT NULL DEFAULT '',
    token_overrides jsonb       NOT NULL DEFAULT '{}'::jsonb,
    email_from_name text        NOT NULL DEFAULT '',
    email_footer    text        NOT NULL DEFAULT '',
    updated_at      timestamptz NOT NULL DEFAULT now(),
    updated_by      text        NOT NULL DEFAULT ''
);

-- tenant_branding: tenant RLS + the explicit provider policy.
ALTER TABLE tenant_branding ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant_branding FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON tenant_branding;
CREATE POLICY tenant_isolation ON tenant_branding
  USING (tenant_id = NULLIF(current_setting('probectl.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('probectl.tenant_id', true), '')::uuid);
DROP POLICY IF EXISTS provider_branding_all ON tenant_branding;
CREATE POLICY provider_branding_all ON tenant_branding
  FOR ALL TO probectl_provider USING (true) WITH CHECK (true);

GRANT SELECT ON tenant_branding TO probectl_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON tenant_branding TO probectl_provider;
GRANT SELECT, INSERT, UPDATE, DELETE ON provider_branding TO probectl_provider;
