-- 0046_otlp_tokens.sql
-- WIRE-008: persistence-backed OTLP bearer token store. Config-only tokens
-- require a restart to revoke; this table enables hot-revocation via the admin
-- API (DELETE /v1/otlp-tokens/{id}) and survives restarts.
--
-- Design mirrors scim_tokens / mcp_tokens:
--   * Only the HASH of the token is stored — the plaintext never touches the DB.
--   * The table is PRE-TENANT (the token IS the tenant selector), so the auth
--     query runs without a tenant context; RLS is present but unset == unrestricted
--     (same pattern as 0040_mcp_tokens_rls).
--   * tenant_id is enforced explicitly in every List/Revoke query.
--   * Idempotent (CREATE TABLE IF NOT EXISTS + DROP POLICY IF EXISTS).

CREATE TABLE IF NOT EXISTS otlp_tokens (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id   uuid NOT NULL,
    name        text NOT NULL DEFAULT '',
    token_hash  bytea NOT NULL UNIQUE,
    created_at  timestamptz NOT NULL DEFAULT now(),
    last_used_at timestamptz,
    revoked_at  timestamptz
);

CREATE INDEX IF NOT EXISTS otlp_tokens_token_hash_idx ON otlp_tokens (token_hash)
    WHERE revoked_at IS NULL;
CREATE INDEX IF NOT EXISTS otlp_tokens_tenant_idx ON otlp_tokens (tenant_id)
    WHERE revoked_at IS NULL;

-- RLS: same pattern as mcp_tokens (0040). Pre-tenant auth path (no GUC set)
-- is unrestricted; any in-tenant query sees only that tenant's rows.
ALTER TABLE otlp_tokens ENABLE ROW LEVEL SECURITY;
ALTER TABLE otlp_tokens FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON otlp_tokens;
CREATE POLICY tenant_isolation ON otlp_tokens
  USING (
    NULLIF(current_setting('probectl.tenant_id', true), '') IS NULL
    OR tenant_id = NULLIF(current_setting('probectl.tenant_id', true), '')::uuid
  )
  WITH CHECK (
    NULLIF(current_setting('probectl.tenant_id', true), '') IS NULL
    OR tenant_id = NULLIF(current_setting('probectl.tenant_id', true), '')::uuid
  );

GRANT SELECT, INSERT, UPDATE ON otlp_tokens TO probectl_app;
