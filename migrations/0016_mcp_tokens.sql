-- 0016_mcp_tokens.sql
-- MCP bearer tokens (S25, F14): authenticate an MCP client to a tenant + the
-- owning user's RBAC. Like sessions, the lookup is PRE-TENANT (a token determines
-- its own tenant), so there is no RLS — only the token's HASH is stored (never the
-- token itself), and a row holds just tenant_id + user_id + metadata. The token
-- resolves to the user's effective permissions, which ARE tenant-scoped (RLS) when
-- loaded. Idempotent + backward-compatible.

CREATE TABLE IF NOT EXISTS mcp_tokens (
    id           uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id    uuid        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    user_id      uuid        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name         text        NOT NULL DEFAULT '',
    token_hash   bytea       NOT NULL UNIQUE,
    created_at   timestamptz NOT NULL DEFAULT now(),
    last_used_at timestamptz,
    revoked_at   timestamptz
);
CREATE INDEX IF NOT EXISTS mcp_tokens_tenant_idx ON mcp_tokens (tenant_id);

-- The auth layer reads/updates tokens via the pool (pre-tenant), like sessions;
-- grant the least-privilege login role DML on the table.
GRANT SELECT, INSERT, UPDATE, DELETE ON mcp_tokens TO probectl_app;
