-- 0107_oidc_identity_binding.sql
-- AUTHZ-03: bind an SSO account to the ID token's STABLE (issuer, subject) pair
-- rather than the mutable, IdP-settable email claim. A first OIDC login records
-- (oidc_issuer, oidc_subject); later logins must present that same pair, a
-- second subject presenting the same email is refused, and a pre-provisioned
-- (SCIM) account links to its first OIDC subject exactly once. email_verified
-- is enforced at the callback.
-- Additive + idempotent (expand phase, zero-downtime): new nullable columns +
-- a partial unique index. Existing rows stay unbound until their next login,
-- so no backfill and no contract phase are needed here.

ALTER TABLE users ADD COLUMN IF NOT EXISTS oidc_issuer  text;
ALTER TABLE users ADD COLUMN IF NOT EXISTS oidc_subject text;

-- A given (issuer, subject) identity binds to exactly one user within a tenant;
-- the partial index also makes a concurrent double-bind fail closed.
-- lock-ok: users is an operator-scale identity table (bounded by seat count),
-- not a hot telemetry table.
CREATE UNIQUE INDEX IF NOT EXISTS users_tenant_oidc_idx
    ON users (tenant_id, oidc_issuer, oidc_subject)
    WHERE oidc_issuer IS NOT NULL AND oidc_subject IS NOT NULL;
