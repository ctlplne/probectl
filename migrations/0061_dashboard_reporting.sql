-- 0061_dashboard_reporting.sql
-- X14: durable, tenant-confined dashboard views and report artifacts.
-- The built-in destination is the tenant's local report inbox; no row contains
-- an implicit external endpoint and no schedule can create outbound traffic.

CREATE TABLE IF NOT EXISTS dashboard_views (
  tenant_id  uuid        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  id         text        NOT NULL,
  owner_id   text        NOT NULL,
  name       text        NOT NULL CHECK (length(name) BETWEEN 1 AND 120),
  preset     text        NOT NULL CHECK (preset IN ('operator', 'executive')),
  shared     boolean     NOT NULL DEFAULT false,
  definition jsonb       NOT NULL DEFAULT '{}'::jsonb,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, id)
);

CREATE INDEX IF NOT EXISTS dashboard_views_tenant_owner_updated_idx
  ON dashboard_views (tenant_id, owner_id, updated_at DESC);

ALTER TABLE dashboard_views ENABLE ROW LEVEL SECURITY;
ALTER TABLE dashboard_views FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON dashboard_views;
CREATE POLICY tenant_isolation ON dashboard_views
  USING (tenant_id = NULLIF(current_setting('probectl.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('probectl.tenant_id', true), '')::uuid);

CREATE TABLE IF NOT EXISTS dashboard_report_schedules (
  tenant_id      uuid        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  id             text        NOT NULL,
  dashboard_id   text        NOT NULL,
  owner_id       text        NOT NULL,
  name           text        NOT NULL CHECK (length(name) BETWEEN 1 AND 120),
  format         text        NOT NULL CHECK (format IN ('pdf', 'csv')),
  cadence        text        NOT NULL CHECK (cadence IN ('daily', 'weekly', 'monthly')),
  destination_id text        NOT NULL CHECK (destination_id = 'tenant-report-inbox'),
  enabled        boolean     NOT NULL DEFAULT true,
  next_run_at    timestamptz NOT NULL,
  last_run_at    timestamptz,
  created_at     timestamptz NOT NULL DEFAULT now(),
  updated_at     timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, id),
  FOREIGN KEY (tenant_id, dashboard_id)
    REFERENCES dashboard_views (tenant_id, id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS dashboard_report_schedules_tenant_due_idx
  ON dashboard_report_schedules (tenant_id, enabled, next_run_at);

ALTER TABLE dashboard_report_schedules ENABLE ROW LEVEL SECURITY;
ALTER TABLE dashboard_report_schedules FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON dashboard_report_schedules;
CREATE POLICY tenant_isolation ON dashboard_report_schedules
  USING (tenant_id = NULLIF(current_setting('probectl.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('probectl.tenant_id', true), '')::uuid);

CREATE TABLE IF NOT EXISTS dashboard_report_artifacts (
  tenant_id           uuid        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  id                  text        NOT NULL,
  dashboard_id        text        NOT NULL,
  schedule_id         text,
  format              text        NOT NULL CHECK (format IN ('pdf', 'csv')),
  media_type          text        NOT NULL CHECK (media_type IN ('application/pdf', 'text/csv')),
  filename            text        NOT NULL CHECK (length(filename) BETWEEN 1 AND 180),
  content             bytea       NOT NULL CHECK (octet_length(content) BETWEEN 1 AND 2097152),
  generated_by        text        NOT NULL,
  generated_at        timestamptz NOT NULL DEFAULT now(),
  absolute_from       timestamptz NOT NULL,
  absolute_to         timestamptz NOT NULL,
  provenance          jsonb       NOT NULL DEFAULT '[]'::jsonb,
  redaction_state     text        NOT NULL CHECK (length(redaction_state) BETWEEN 1 AND 120),
  coverage_limitations jsonb      NOT NULL DEFAULT '[]'::jsonb,
  PRIMARY KEY (tenant_id, id),
  FOREIGN KEY (tenant_id, dashboard_id)
    REFERENCES dashboard_views (tenant_id, id) ON DELETE CASCADE,
  FOREIGN KEY (tenant_id, schedule_id)
    REFERENCES dashboard_report_schedules (tenant_id, id) ON DELETE RESTRICT,
  CHECK (absolute_to > absolute_from)
);

CREATE INDEX IF NOT EXISTS dashboard_report_artifacts_tenant_generated_idx
  ON dashboard_report_artifacts (tenant_id, generated_at DESC);

ALTER TABLE dashboard_report_artifacts ENABLE ROW LEVEL SECURITY;
ALTER TABLE dashboard_report_artifacts FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON dashboard_report_artifacts;
CREATE POLICY tenant_isolation ON dashboard_report_artifacts
  USING (tenant_id = NULLIF(current_setting('probectl.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('probectl.tenant_id', true), '')::uuid);

GRANT SELECT, INSERT, UPDATE, DELETE ON dashboard_views TO probectl_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON dashboard_report_schedules TO probectl_app;
GRANT SELECT, INSERT, DELETE ON dashboard_report_artifacts TO probectl_app;
