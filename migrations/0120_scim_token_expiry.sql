-- 0120_scim_token_expiry.sql — AUTHZ-08: SCIM bearer tokens could not expire.
--
-- scim_tokens (migration 0018) carried only created_at/last_used_at/revoked_at,
-- so a SCIM token stayed valid forever until an admin explicitly revoked it —
-- an IdP provisioning credential with no lifetime bound. Add an optional
-- expiry; ScimTokens.Authenticate rejects a token whose expires_at has passed
-- (401), the same way it already rejects a revoked one.
--
-- Nullable: NULL = non-expiring, so every existing row keeps working unchanged
-- (back-compatible). The column lives on the already-RLS-policied scim_tokens
-- table, so no new policy is needed.
--
-- Idempotent + expand-only (CLAUDE.md §6).

ALTER TABLE scim_tokens
    ADD COLUMN IF NOT EXISTS expires_at timestamptz;

COMMENT ON COLUMN scim_tokens.expires_at IS
    'Optional expiry for the SCIM bearer token; NULL = non-expiring. Enforced in ScimTokens.Authenticate (AUTHZ-08).';
