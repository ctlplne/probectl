-- 0047_rollouts.sql
-- Staged fleet rollout state is operator intent, not rebuildable telemetry:
-- an in-flight rollout must survive a control-plane restart. Tenant-owned from
-- the first migration so pooled installs get storage-layer isolation.

CREATE TABLE IF NOT EXISTS rollout_plans (
  tenant_id  uuid        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  rollout_id text        NOT NULL,
  plan       jsonb       NOT NULL,
  revision   bigint      NOT NULL DEFAULT 1,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, rollout_id)
);

CREATE INDEX IF NOT EXISTS rollout_plans_tenant_updated_idx
  ON rollout_plans (tenant_id, updated_at DESC);

ALTER TABLE rollout_plans ENABLE ROW LEVEL SECURITY;
ALTER TABLE rollout_plans FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON rollout_plans;
CREATE POLICY tenant_isolation ON rollout_plans
  USING (tenant_id = NULLIF(current_setting('probectl.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('probectl.tenant_id', true), '')::uuid);

CREATE TABLE IF NOT EXISTS rollout_events (
  id         uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id  uuid        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  rollout_id text        NOT NULL,
  action     text        NOT NULL,
  plan       jsonb       NOT NULL DEFAULT '{}'::jsonb,
  created_at timestamptz NOT NULL DEFAULT now(),
  FOREIGN KEY (tenant_id, rollout_id)
    REFERENCES rollout_plans (tenant_id, rollout_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS rollout_events_tenant_rollout_idx
  ON rollout_events (tenant_id, rollout_id, created_at DESC);

ALTER TABLE rollout_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE rollout_events FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON rollout_events;
CREATE POLICY tenant_isolation ON rollout_events
  USING (tenant_id = NULLIF(current_setting('probectl.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('probectl.tenant_id', true), '')::uuid);

GRANT SELECT, INSERT, UPDATE, DELETE ON rollout_plans TO probectl_app;
GRANT SELECT, INSERT ON rollout_events TO probectl_app;
