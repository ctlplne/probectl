-- 0106_mcp_token_expiry_scopes.sql
-- INV-03/RT-02: API/MCP bearer tokens gain a MANDATORY expiry and an optional
-- scope subset. Before this a token, once minted, lived forever and carried the
-- full RBAC of its owner with no per-token list/revoke/scope surface. expires_at
-- is enforced in the pre-tenant auth read (an expired token authenticates to
-- nothing); scopes narrows the principal's effective permissions. expand-only +
-- idempotent + backward-compatible (existing rows: NULL expiry = no expiry, as
-- before; empty scopes = full RBAC, as before).

ALTER TABLE mcp_tokens ADD COLUMN IF NOT EXISTS expires_at timestamptz;
ALTER TABLE mcp_tokens ADD COLUMN IF NOT EXISTS scopes text[] NOT NULL DEFAULT '{}';

-- No new index: Authenticate resolves a token by its already-UNIQUE token_hash
-- and applies the expiry predicate (expires_at IS NULL OR expires_at > now())
-- as a filter on that single matched row, and List uses the existing
-- mcp_tokens_tenant_idx. There is no expiry-sweep query, so an expires_at index
-- would only add a write-path cost (and a lock to build it) for no read.

-- probectl_app already holds SELECT/INSERT/UPDATE/DELETE on mcp_tokens (0016);
-- the new columns inherit that grant.
