-- 0116_governance_write_permission.sql — AUD-12.
--
-- The tenant admin's self-service governance policy surface (GET/PUT
-- /v1/governance/policy, the Enterprise `governance` feature) needs a WRITE
-- permission to match the existing read permission. Migration 0033 seeded
-- `governance.read` (the tenant self-view of classification/redaction/retention/
-- residency); this adds `governance.write` so a tenant ADMIN can set the policy
-- — including the remote-AI egress consent (ai_remote_egress) — through the
-- audited API instead of an operator hand-editing SQL.
--
-- This grants a REQUEST-PATH RBAC permission only. It does NOT grant the tenant
-- app role any DML on tenant_governance: that provider-owned row stays
-- write-fenced off the app role (migration 0111 + the boot posture check). The
-- /v1 handler writes the row through the provider role inside a tenant-GUC-bound
-- maintenance transaction and appends the receipt to the tenant audit chain as
-- the app role (internal/govern.PolicyStore.SetTenantPolicy). Tenant isolation
-- stays at the storage layer; this is only who-may-ask (docs/guardrails.md G7-1).
--
-- Seeded for the TEMPLATE tenant's admin role exactly as 0033 seeded
-- governance.read, so tenants provisioned from the template inherit it.
--
-- Idempotent (ON CONFLICT DO NOTHING) and expand-only — no table/column change
-- (CLAUDE.md §6).

INSERT INTO permissions (key, description) VALUES
    ('governance.write', 'Update the tenant''s own data-governance policy (classification, redaction, and the remote-AI egress consent)')
ON CONFLICT (key) DO NOTHING;

INSERT INTO role_permissions (tenant_id, role_id, permission_key)
    SELECT r.tenant_id, r.id, 'governance.write'
    FROM roles r
    WHERE r.tenant_id = '00000000-0000-0000-0000-000000000001'
      AND r.slug = 'admin'
ON CONFLICT (role_id, permission_key) DO NOTHING;
