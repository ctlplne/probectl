-- 0129: the L7 capture posture each eBPF agent reports (D-43 addendum (a)).
--
-- The agent reports, over its mTLS channel, whether L7 capture is enabled, the
-- consent tenant (kept only when it equals the certificate's tenant), the
-- workload scope, its local redaction mode, the mode capture actually runs
-- under, the floor it applied, and whether a capture source is attached. The
-- agent detail view shows it; the first consented report and every mode change
-- append agent.l7_capture.posture to the tenant's hash-chained audit stream.
--
-- agents already carries tenant_id NOT NULL + FORCE RLS; a new column inherits
-- the table's row security. Expand-only: nullable, no default rewrite, so
-- release N-1 keeps reading and writing every row unchanged (its explicit
-- column lists never name it).

ALTER TABLE agents ADD COLUMN IF NOT EXISTS l7_capture_posture jsonb;
