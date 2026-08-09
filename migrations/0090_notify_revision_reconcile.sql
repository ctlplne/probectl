-- 0090_notify_revision_reconcile.sql
-- Durable reconciliation cursor for incident -> ticket lifecycle mirrors.
-- The incident row is the durable source of truth; revision records the newest
-- signal_count successfully mirrored to a connector. After a process crash the
-- reconciler compares the tenant-scoped incident state to this cursor and
-- safely replays the stable receiver idempotency key.
-- probectl:no-tx: the pre-existing incident_integrations index must be built concurrently

ALTER TABLE incident_integrations
    ADD COLUMN IF NOT EXISTS revision integer NOT NULL DEFAULT 0;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'incident_integrations_revision_nonnegative'
    ) THEN
        ALTER TABLE incident_integrations
            ADD CONSTRAINT incident_integrations_revision_nonnegative CHECK (revision >= 0);
    END IF;
END $$;

CREATE INDEX CONCURRENTLY IF NOT EXISTS incident_integrations_reconcile_idx
    ON incident_integrations (tenant_id, status, revision, updated_at);
