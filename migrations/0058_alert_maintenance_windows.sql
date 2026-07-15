-- 0058_alert_maintenance_windows.sql
-- Durable, tenant-owned alert maintenance windows. The evaluator keeps an
-- in-memory execution copy, but this table is the restart-safe source of truth.

CREATE TABLE IF NOT EXISTS alert_maintenance_windows (
  tenant_id  uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  id         text NOT NULL,
  name       text NOT NULL,
  reason     text NOT NULL DEFAULT '',
  starts_at  timestamptz NOT NULL,
  ends_at    timestamptz NOT NULL,
  recurrence text NOT NULL DEFAULT '',
  match      jsonb NOT NULL DEFAULT '{}'::jsonb,
  rule_ids   text[] NOT NULL DEFAULT '{}',
  created_by text NOT NULL DEFAULT '',
  audit_ref  text NOT NULL DEFAULT '',
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, id),
  CHECK (ends_at > starts_at),
  CHECK (recurrence IN ('', 'daily', 'weekly'))
);

CREATE INDEX IF NOT EXISTS alert_maintenance_windows_tenant_time_idx
  ON alert_maintenance_windows (tenant_id, starts_at, ends_at);

ALTER TABLE alert_maintenance_windows ENABLE ROW LEVEL SECURITY;
ALTER TABLE alert_maintenance_windows FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON alert_maintenance_windows;
CREATE POLICY tenant_isolation ON alert_maintenance_windows
  USING (tenant_id = NULLIF(current_setting('probectl.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('probectl.tenant_id', true), '')::uuid);

GRANT SELECT, INSERT, UPDATE, DELETE ON alert_maintenance_windows TO probectl_app;
