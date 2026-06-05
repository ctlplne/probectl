-- 0024_provider_plane.sql — S-T1 (MT): the provider/management plane.
--
-- Extends the S2 foundation (0004_provider.sql) with what the operator console
-- needs: operator credentials (password KDF hash + envelope-sealed TOTP secret —
-- MFA is mandatory in the provider domain), separation-of-duties roles, and the
-- tenant-consent leg of break-glass (a grant is PENDING until a tenant admin
-- consents; S2 modeled the operator/expiry/revocation legs).
--
-- Also creates probectl_provider: a least-privilege NOLOGIN role whose ONLY
-- power is SELECT over agents + tenants through an explicit provider_fleet_read
-- RLS policy. The provider plane's cross-tenant fleet view runs as this role,
-- so "spans tenants for operations only" is enforced at the storage layer
-- (CLAUDE.md §7 guardrail 1): it can count agent health everywhere but cannot
-- touch results, tests, incidents, or any telemetry table.
--
-- Idempotent + expand-only (CLAUDE.md §6).

-- Operator credentials + SoD role. password_hash is a one-way KDF string
-- (internal/crypto PBKDF2 format); totp_* columns hold the envelope-sealed
-- shared secret (never plaintext at rest — guardrail 6). enroll_token_hash
-- carries the one-time enrollment handshake (hash only, like sessions).
ALTER TABLE provider_operators ADD COLUMN IF NOT EXISTS role text NOT NULL DEFAULT 'operator';
ALTER TABLE provider_operators ADD COLUMN IF NOT EXISTS password_hash text NOT NULL DEFAULT '';
ALTER TABLE provider_operators ADD COLUMN IF NOT EXISTS totp_key_id text NOT NULL DEFAULT '';
ALTER TABLE provider_operators ADD COLUMN IF NOT EXISTS totp_wrapped_dek bytea;
ALTER TABLE provider_operators ADD COLUMN IF NOT EXISTS totp_ciphertext bytea;
ALTER TABLE provider_operators ADD COLUMN IF NOT EXISTS enroll_token_hash bytea;
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'provider_operators_role_check'
    ) THEN
        ALTER TABLE provider_operators
            ADD CONSTRAINT provider_operators_role_check
            CHECK (role IN ('admin', 'operator'));
    END IF;
END $$;

-- The tenant-consent leg of break-glass. A grant is usable ONLY when consented
-- (consented_at set by a tenant admin of the grant's tenant), unexpired, and
-- unrevoked. denied_at lets a tenant refuse loudly. use_count records how many
-- audited telemetry reads rode the grant.
ALTER TABLE break_glass_grants ADD COLUMN IF NOT EXISTS consented_by text;
ALTER TABLE break_glass_grants ADD COLUMN IF NOT EXISTS consented_at timestamptz;
ALTER TABLE break_glass_grants ADD COLUMN IF NOT EXISTS denied_by text;
ALTER TABLE break_glass_grants ADD COLUMN IF NOT EXISTS denied_at timestamptz;
ALTER TABLE break_glass_grants ADD COLUMN IF NOT EXISTS use_count integer NOT NULL DEFAULT 0;

-- The provider fleet-read role: NOLOGIN, NOBYPASSRLS (same posture as
-- probectl_app), reachable only via SET LOCAL ROLE inside a transaction.
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'probectl_provider') THEN
        CREATE ROLE probectl_provider NOLOGIN NOSUPERUSER NOBYPASSRLS;
    END IF;
END $$;

-- Fleet visibility = agents + the tenant registry + the provider-plane tables.
-- Deliberately NOT granted: tests, results, incidents, audit_events, or any
-- other tenant telemetry — the storage layer itself confines the provider
-- plane to operational metadata.
GRANT SELECT ON agents TO probectl_provider;
GRANT SELECT, INSERT, UPDATE ON tenants TO probectl_provider;
GRANT SELECT, INSERT, UPDATE ON provider_operators, break_glass_grants TO probectl_provider;
GRANT SELECT, INSERT ON provider_audit_events TO probectl_provider;

-- agents carries the standard tenant_isolation policy (GUC-keyed), which
-- correctly returns nothing for a cross-tenant reader. The provider fleet view
-- is the sanctioned exception: an explicit SELECT-ONLY policy for
-- probectl_provider. (Policies are permissive-OR'd per role; this one applies
-- only to probectl_provider, so probectl_app's scoping is unchanged.)
DROP POLICY IF EXISTS provider_fleet_read ON agents;
CREATE POLICY provider_fleet_read ON agents
    FOR SELECT TO probectl_provider USING (true);

-- The login/migration role must be able to assume probectl_provider (a
-- superuser always can; grant membership otherwise, mirroring 0007).
