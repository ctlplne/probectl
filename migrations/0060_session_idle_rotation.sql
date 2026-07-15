-- 0060_session_idle_rotation.sql
-- F500 session-management baseline: an absolute expiry is not enough because a
-- forgotten browser can otherwise stay authenticated for the whole TTL. Track
-- last activity for a database-enforced idle timeout and remember the effective
-- authorization fingerprint so a privilege change can rotate the opaque token.
-- Sessions remain global: their unguessable keyed token hash is resolved before
-- the request's tenant is known; the returned row establishes that tenant.

ALTER TABLE sessions
    ADD COLUMN IF NOT EXISTS last_activity_at timestamptz NOT NULL DEFAULT now();

ALTER TABLE sessions
    ADD COLUMN IF NOT EXISTS authorization_hash bytea NOT NULL DEFAULT '\x'::bytea;

-- A session's tenant and user used to have two independent foreign keys. That
-- proved both IDs existed, but did not prove the user belonged to that tenant.
-- The composite key makes that relationship a storage-layer invariant: even a
-- buggy caller cannot mint or rotate a tenant-B session for tenant-A's user.
-- lock-ok: users is an operator-scale identity table bounded by licensed seats,
-- not an ingestion/event table; transactional DDL keeps this migration atomic.
CREATE UNIQUE INDEX IF NOT EXISTS users_tenant_id_id_uidx ON users (tenant_id, id);

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conname = 'sessions_tenant_user_fk'
          AND conrelid = 'sessions'::regclass
    ) THEN
        ALTER TABLE sessions
            ADD CONSTRAINT sessions_tenant_user_fk
            FOREIGN KEY (tenant_id, user_id)
            REFERENCES users (tenant_id, id)
            ON DELETE CASCADE
            NOT VALID;
    END IF;
END $$;

-- VALIDATE scans existing rows without taking the ACCESS EXCLUSIVE lock used
-- by a directly-validating ADD CONSTRAINT. New rows were already checked from
-- the instant the NOT VALID constraint was added.
ALTER TABLE sessions VALIDATE CONSTRAINT sessions_tenant_user_fk;

-- Idle resolution touches last_activity_at, while rotation atomically replaces
-- one token-hash row with another. The login role needs UPDATE in addition to
-- the original SELECT/INSERT/DELETE grants.
GRANT SELECT, INSERT, UPDATE, DELETE ON sessions TO probectl_app;
