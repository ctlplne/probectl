-- 0052_tenant_retention_planes.sql — PRIVACY-003.
--
-- Expand tenant_retention from flow-only to per-plane clocks. NULL means the
-- deployment default remains in force; tenant values can only narrow retention.
-- The table is operator-scale (one row per tenant), so app validation owns the
-- >= 1 invariant alongside the existing flow column.

ALTER TABLE tenant_retention
  ADD COLUMN IF NOT EXISTS otel_retention_days integer,
  ADD COLUMN IF NOT EXISTS ebpf_retention_days integer,
  ADD COLUMN IF NOT EXISTS path_retention_days integer,
  ADD COLUMN IF NOT EXISTS audit_retention_days integer,
  ADD COLUMN IF NOT EXISTS ai_answer_retention_days integer,
  ADD COLUMN IF NOT EXISTS object_retention_days integer,
  ADD COLUMN IF NOT EXISTS derived_identity_retention_days integer;
