-- 0035: Guarded agentic remediation (S-EE5, F44 — guardrail-critical).
--
-- remediation_proposals holds AI-PROPOSED network remediations and their human
-- decision trail. The ratified policy (human sign-off, guardrail 8): probectl
-- NEVER executes — "approved" is a recorded, audited human sign-off only; there
-- is no "executed" state. Ingested data can at most create a PROPOSED row (via
-- the proposal-only MCP tool); only an authenticated human with
-- remediation.approve can move it to approved, and only when approvals are
-- enabled and the blast radius is within the limit.
--
-- This is TENANT-OWNED data (proposals about a tenant's network): tenant-RLS,
-- erased with the tenant at offboarding (NOT on the provider deny list).
--
-- Idempotent + expand-only (CLAUDE.md §6).

CREATE TABLE IF NOT EXISTS remediation_proposals (
    id            uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id     uuid        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    kind          text        NOT NULL,
    title         text        NOT NULL,
    rationale     text        NOT NULL DEFAULT '',
    target        text        NOT NULL DEFAULT '',
    incident_id   text        NOT NULL DEFAULT '',
    dry_run       jsonb       NOT NULL DEFAULT '{}'::jsonb,
    state         text        NOT NULL DEFAULT 'proposed',
    proposed_by   text        NOT NULL DEFAULT '',
    decided_by    text        NOT NULL DEFAULT '',
    decision_note text        NOT NULL DEFAULT '',
    created_at    timestamptz NOT NULL DEFAULT now(),
    decided_at    timestamptz,
    CHECK (kind  IN ('reroute_suggestion', 'traffic_shift_suggestion', 'open_ticket', 'trustctl_renewal')),
    CHECK (state IN ('proposed', 'approved', 'rejected', 'applied'))
);

CREATE INDEX IF NOT EXISTS remediation_proposals_tenant_state_idx
    ON remediation_proposals (tenant_id, state, created_at DESC);

-- Tenant-RLS: a proposal is visible/decidable only within its own tenant.
ALTER TABLE remediation_proposals ENABLE ROW LEVEL SECURITY;
ALTER TABLE remediation_proposals FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON remediation_proposals;
CREATE POLICY tenant_isolation ON remediation_proposals
  USING (tenant_id = NULLIF(current_setting('probectl.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('probectl.tenant_id', true), '')::uuid);

GRANT SELECT, INSERT, UPDATE ON remediation_proposals TO probectl_app;

-- Two permissions, deliberately distinct: propose (the AI/operator files a
-- suggestion) and approve (the human sign-off). Both admin-seeded; the
-- single-admin-approve policy means any admin holding approve can sign off.
INSERT INTO permissions (key, description) VALUES
    ('remediation.propose', 'Propose a guarded remediation (a suggestion; never executed)'),
    ('remediation.approve', 'Approve/reject a remediation proposal (the recorded human sign-off)')
ON CONFLICT (key) DO NOTHING;

INSERT INTO role_permissions (tenant_id, role_id, permission_key)
    SELECT r.tenant_id, r.id, p.key
    FROM roles r
    CROSS JOIN (VALUES ('remediation.propose'), ('remediation.approve')) AS p(key)
    WHERE r.tenant_id = '00000000-0000-0000-0000-000000000001'
      AND r.slug = 'admin'
ON CONFLICT (role_id, permission_key) DO NOTHING;
