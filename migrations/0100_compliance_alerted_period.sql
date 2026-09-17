-- 0100_compliance_alerted_period.sql
-- DPR-110: the segmentation once-only gate (0096) was keyed by
-- (tenant_id, policy, rule) with no period, so a violation's side effects — the
-- incident signal and the SIEM event — could fire EXACTLY ONCE for the life of
-- the deployment. An operator who remediated the misconfiguration and later saw
-- the same traffic return got silence, and an ongoing violation never reminded
-- anyone it was still there. The cost gate (0099) already keys its claims by
-- period (one incident per budget per month); segmentation claims now do the
-- same, so the gate still collapses replicas and replays inside a window and
-- re-arms when the window rolls over.
--
-- Expand-only: the column defaults to the empty period, so rows written by the
-- previous release simply never match a new claim.
ALTER TABLE compliance_alerted ADD COLUMN IF NOT EXISTS period text NOT NULL DEFAULT '';
ALTER TABLE compliance_alerted DROP CONSTRAINT IF EXISTS compliance_alerted_pkey;
-- lock-ok: compliance_alerted holds one row per tenant × policy × rule × period
-- — a handful per tenant, written only when a violation's export is claimed.
-- The brief lock cannot meet a queue, and a unique index cannot be built
-- CONCURRENTLY inside the migration transaction that just dropped the old key.
CREATE UNIQUE INDEX IF NOT EXISTS compliance_alerted_tenant_policy_rule_period
  ON compliance_alerted (tenant_id, policy, rule, period);
