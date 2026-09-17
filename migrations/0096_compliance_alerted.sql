-- 0096_compliance_alerted.sql
-- DPR-073: the segmentation validator's verdicts, coverage and evidence were
-- replica-local memory fed by a SHARED consumer group, so behind a Service two
-- of three /v1/compliance and /v1/compliance/evidence reads answered "no
-- observations" and the signed evidence document differed per replica. Every
-- replica now consumes the flow/eBPF lanes in its own view group (full state
-- everywhere); this table is the cluster-wide once-only gate for the side
-- effects of a violation (incident signal, SIEM event) — the replica whose
-- INSERT wins exports it, replays after a rollout find the row and stay quiet.
CREATE TABLE IF NOT EXISTS compliance_alerted (
  tenant_id  uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  policy     text NOT NULL,
  rule       text NOT NULL,
  first_at   timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, policy, rule)
);
ALTER TABLE compliance_alerted ENABLE ROW LEVEL SECURITY;
ALTER TABLE compliance_alerted FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON compliance_alerted;
CREATE POLICY tenant_isolation ON compliance_alerted
  USING (tenant_id = NULLIF(current_setting('probectl.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('probectl.tenant_id', true), '')::uuid);
GRANT SELECT, INSERT, DELETE ON compliance_alerted TO probectl_app;
