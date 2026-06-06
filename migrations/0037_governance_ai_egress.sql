-- 0037: per-tenant remote-AI egress consent (U-013, C7).
--
-- A REMOTE model endpoint sends tenant telemetry off-network. Beyond the
-- operator's config-time acknowledgment (PROBECTL_AI_EGRESS_ACK), each
-- TENANT must opt in: ai_remote_egress defaults to false and the analyzer
-- refuses remote synthesis for non-consenting tenants. Written by the
-- provider governance plane; read tenant-scoped (RLS).
--
-- Idempotent + expand-only (CLAUDE.md §6).

ALTER TABLE tenant_governance
    ADD COLUMN IF NOT EXISTS ai_remote_egress boolean NOT NULL DEFAULT false;
