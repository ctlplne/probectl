-- 0099_cost_budget_alerted.sql
-- DPR-080: cost and carbon totals were replica-local (shared consumer groups
-- over in-RAM engines), so reads behind the Service answered zeros or dollars
-- depending on the replica. Every replica now consumes the flow lanes in its own
-- view group; this table is the cluster-wide once-only gate for the budget-breach
-- signal (one incident per tenant × budget × month, never one per replica or per
-- replay).
CREATE TABLE IF NOT EXISTS cost_budget_alerted (
  tenant_id  uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  budget_key text NOT NULL,
  month      text NOT NULL,
  first_at   timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, budget_key, month)
);
ALTER TABLE cost_budget_alerted ENABLE ROW LEVEL SECURITY;
ALTER TABLE cost_budget_alerted FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON cost_budget_alerted;
CREATE POLICY tenant_isolation ON cost_budget_alerted
  USING (tenant_id = NULLIF(current_setting('probectl.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('probectl.tenant_id', true), '')::uuid);
GRANT SELECT, INSERT, DELETE ON cost_budget_alerted TO probectl_app;
