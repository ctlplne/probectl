-- 0048_otlp_tokens_strict_rls.sql
-- TENANT-003: OTLP token auth is pre-tenant, but direct table access must still
-- fail closed when the tenant GUC is unset. Runtime token verification goes
-- through one narrow SECURITY DEFINER function; all normal admin access remains
-- tenant-scoped by RLS.

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'probectl_otlp_auth') THEN
        CREATE ROLE probectl_otlp_auth NOLOGIN NOSUPERUSER NOBYPASSRLS;
    END IF;
END $$;

GRANT USAGE ON SCHEMA public TO probectl_otlp_auth;
GRANT SELECT, UPDATE ON otlp_tokens TO probectl_otlp_auth;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conname = 'otlp_tokens_tenant_id_fkey'
          AND conrelid = 'otlp_tokens'::regclass
    ) THEN
        ALTER TABLE otlp_tokens
            ADD CONSTRAINT otlp_tokens_tenant_id_fkey
            FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE NOT VALID;
    END IF;
END $$;

CREATE OR REPLACE FUNCTION otlp_authenticate_token(p_token_hash bytea)
RETURNS TABLE(tenant_id uuid)
LANGUAGE sql
SECURITY DEFINER
SET search_path = public
AS $$
    UPDATE otlp_tokens
       SET last_used_at = now()
     WHERE token_hash = p_token_hash
       AND revoked_at IS NULL
     RETURNING otlp_tokens.tenant_id
$$;

ALTER FUNCTION otlp_authenticate_token(bytea) OWNER TO probectl_otlp_auth;
REVOKE ALL ON FUNCTION otlp_authenticate_token(bytea) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION otlp_authenticate_token(bytea) TO probectl_app;

ALTER TABLE otlp_tokens ENABLE ROW LEVEL SECURITY;
ALTER TABLE otlp_tokens FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON otlp_tokens;
CREATE POLICY tenant_isolation ON otlp_tokens
  USING (
    current_user = 'probectl_otlp_auth'
    OR tenant_id = NULLIF(current_setting('probectl.tenant_id', true), '')::uuid
  )
  WITH CHECK (
    current_user = 'probectl_otlp_auth'
    OR tenant_id = NULLIF(current_setting('probectl.tenant_id', true), '')::uuid
  );

GRANT SELECT, INSERT, UPDATE ON otlp_tokens TO probectl_app;
