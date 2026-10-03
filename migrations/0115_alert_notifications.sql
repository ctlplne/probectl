-- 0115_alert_notifications.sql
-- RTO-20: the per-series firing-since + last-notified that the alert engine
-- dedupes and renotifies against lived ONLY in the singleton leader's memory,
-- so when the lease moved to another replica a still-firing renotify=0
-- ("notify once") alert was delivered again. Persist that bookkeeping per
-- series (tenant-RLS) so a newly-elected leader rehydrates it and does NOT
-- re-notify, and so a renotify cadence resumes relative to the persisted
-- timestamp. Like alert_ops (0043), this is the volatile-stores ADR's
-- documented exception (docs/adr/volatile-stores.md): it is deleted when the
-- firing episode resolves. tenant_id is NON-NULL and indexed by the composite
-- primary key from this, the table's first migration (G7-1).

CREATE TABLE IF NOT EXISTS alert_notifications (
  tenant_id     uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  fingerprint   text NOT NULL,
  firing_since  timestamptz,
  last_notified timestamptz NOT NULL,
  updated_at    timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, fingerprint)
);

ALTER TABLE alert_notifications ENABLE ROW LEVEL SECURITY;
ALTER TABLE alert_notifications FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON alert_notifications;
CREATE POLICY tenant_isolation ON alert_notifications
  USING (tenant_id = NULLIF(current_setting('probectl.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('probectl.tenant_id', true), '')::uuid);
GRANT SELECT, INSERT, UPDATE, DELETE ON alert_notifications TO probectl_app;
