-- 0059_mcp_tokens_policy_idempotency.sql
-- W9: forward-only idempotency repair for 0040_mcp_tokens_rls.sql.
--
-- Numbered migrations are an append-only ledger, so 0040 is not rewritten.
-- Instead this migration converges the existing policy in place: ALTER when it
-- exists, CREATE when it does not. Re-running either branch reaches the same
-- definition without a DROP/CREATE gap. The catalog predicate is the guard
-- because PostgreSQL CREATE POLICY has no IF NOT EXISTS form.
--
-- The unset-tenant allowance is intentionally preserved for MCP token
-- authentication, where the token hash is the pre-tenant selector. Once a
-- tenant GUC is set, both reads and writes fail closed to that tenant.

DO $mcp_policy$
BEGIN
    IF EXISTS (
        SELECT 1
          FROM pg_policies
         WHERE schemaname = current_schema()
           AND tablename = 'mcp_tokens'
           AND policyname = 'tenant_isolation'
    ) THEN
        ALTER POLICY tenant_isolation ON mcp_tokens
          USING (
            NULLIF(current_setting('probectl.tenant_id', true), '') IS NULL
            OR tenant_id = NULLIF(current_setting('probectl.tenant_id', true), '')::uuid
          )
          WITH CHECK (
            NULLIF(current_setting('probectl.tenant_id', true), '') IS NULL
            OR tenant_id = NULLIF(current_setting('probectl.tenant_id', true), '')::uuid
          );
    ELSE
        CREATE POLICY tenant_isolation ON mcp_tokens
          USING (
            NULLIF(current_setting('probectl.tenant_id', true), '') IS NULL
            OR tenant_id = NULLIF(current_setting('probectl.tenant_id', true), '')::uuid
          )
          WITH CHECK (
            NULLIF(current_setting('probectl.tenant_id', true), '') IS NULL
            OR tenant_id = NULLIF(current_setting('probectl.tenant_id', true), '')::uuid
          );
    END IF;
END
$mcp_policy$;
