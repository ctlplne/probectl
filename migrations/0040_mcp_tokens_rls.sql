-- 0040_mcp_tokens_rls.sql
-- U-091: Row-Level Security for mcp_tokens. The table was created (0016)
-- without RLS because its Authenticate path is PRE-tenant: the token hash IS
-- the tenant selector, so the lookup runs before any tenant context exists
-- (same shape as sessions). That left zero DB-level defense for future
-- tenant-scoped queries against the table.
--
-- The policy below closes that gap without breaking the pre-tenant path:
--   * tenant context SET   -> rows are confined to that tenant (the standard
--     probectl.tenant_id GUC pattern, F50) — any future in-tenant query gets
--     storage-layer enforcement for free;
--   * tenant context UNSET -> unrestricted (exactly today's behavior), which
--     the pre-tenant Authenticate/Create/RevokeForUser pool paths require.
-- Defense-in-depth, strictly additive; fail-closed semantics whenever a
-- tenant context is present. Idempotent + backward-compatible.

ALTER TABLE mcp_tokens ENABLE ROW LEVEL SECURITY;
ALTER TABLE mcp_tokens FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON mcp_tokens;
CREATE POLICY tenant_isolation ON mcp_tokens
  USING (
    NULLIF(current_setting('probectl.tenant_id', true), '') IS NULL
    OR tenant_id = NULLIF(current_setting('probectl.tenant_id', true), '')::uuid
  )
  WITH CHECK (
    NULLIF(current_setting('probectl.tenant_id', true), '') IS NULL
    OR tenant_id = NULLIF(current_setting('probectl.tenant_id', true), '')::uuid
  );

-- The store needs UPDATE for revocation/last_used stamping (already used via
-- pool queries); make the grant explicit alongside 0016's SELECT/INSERT.
GRANT SELECT, INSERT, UPDATE ON mcp_tokens TO probectl_app;
