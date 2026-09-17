-- DPR-067: the alert evaluator runs on ONE control replica (the "alert-evaluator"
-- cluster singleton). Its active set and heartbeat were replica-local memory, so
-- behind a Service most requests landed on a replica that answered "the alert
-- evaluator is not running for this tenant" and acks/silences failed. The leader
-- now publishes the active set and its heartbeat here after every pass, every
-- replica serves them, and operator actions (alert_ops) taken on any replica are
-- pulled back into the evaluator on its next pass.
CREATE TABLE IF NOT EXISTS alert_active_state (
  tenant_id              uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  fingerprint            text NOT NULL,
  evaluation_fingerprint text NOT NULL DEFAULT '',
  rule_id                text NOT NULL DEFAULT '',
  rule_name              text NOT NULL DEFAULT '',
  severity               text NOT NULL DEFAULT '',
  metric                 text NOT NULL DEFAULT '',
  labels                 jsonb NOT NULL DEFAULT '{}'::jsonb,
  value                  double precision NOT NULL DEFAULT 0,
  reason                 text NOT NULL DEFAULT '',
  since                  timestamptz NOT NULL,
  last_seen_at           timestamptz NOT NULL,
  updated_at             timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, fingerprint)
);
ALTER TABLE alert_active_state ENABLE ROW LEVEL SECURITY;
ALTER TABLE alert_active_state FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON alert_active_state;
CREATE POLICY tenant_isolation ON alert_active_state
  USING (tenant_id = NULLIF(current_setting('probectl.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('probectl.tenant_id', true), '')::uuid);
GRANT SELECT, INSERT, UPDATE, DELETE ON alert_active_state TO probectl_app;

CREATE TABLE IF NOT EXISTS alert_evaluator_status (
  tenant_id        uuid PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,
  evaluated_at     timestamptz NOT NULL,
  interval_seconds integer NOT NULL DEFAULT 30,
  updated_at       timestamptz NOT NULL DEFAULT now()
);
ALTER TABLE alert_evaluator_status ENABLE ROW LEVEL SECURITY;
ALTER TABLE alert_evaluator_status FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON alert_evaluator_status;
CREATE POLICY tenant_isolation ON alert_evaluator_status
  USING (tenant_id = NULLIF(current_setting('probectl.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('probectl.tenant_id', true), '')::uuid);
GRANT SELECT, INSERT, UPDATE, DELETE ON alert_evaluator_status TO probectl_app;
