-- 0055: Per-tenant OIDC identity-provider configuration (H3).
--
-- client_secret_sealed contains only a self-describing value produced through
-- internal/tenantcrypto -> internal/crypto. The tenant id is bound into its
-- AEAD additional data, so moving ciphertext between tenants cannot decrypt.
-- This is tenant-owned security configuration: tenant_id and forced RLS exist
-- from the table's first statement, never as a later application-only filter.

CREATE TABLE IF NOT EXISTS tenant_idp (
    tenant_id             uuid        PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,
    issuer                text        NOT NULL,
    client_id             text        NOT NULL,
    client_secret_sealed  text        NOT NULL,
    redirect_url          text        NOT NULL,
    scopes                text[]      NOT NULL DEFAULT ARRAY['openid', 'email', 'profile']::text[],
    enabled               boolean     NOT NULL DEFAULT true,
    flags                 jsonb       NOT NULL DEFAULT '{}'::jsonb,
    created_at            timestamptz NOT NULL DEFAULT now(),
    updated_at            timestamptz NOT NULL DEFAULT now()
);

ALTER TABLE tenant_idp ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant_idp FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON tenant_idp;
CREATE POLICY tenant_isolation ON tenant_idp
  USING (tenant_id = NULLIF(current_setting('probectl.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('probectl.tenant_id', true), '')::uuid);

GRANT SELECT, INSERT, UPDATE, DELETE ON tenant_idp TO probectl_app;
