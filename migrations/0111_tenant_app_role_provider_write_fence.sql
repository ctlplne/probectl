-- 0111_tenant_app_role_provider_write_fence.sql — TEN-02 (docs/guardrails.md G7-1).
--
-- The tenant request-path role (probectl_app) must hold ONLY SELECT on the
-- provider-OWNED per-tenant CONFIG tables. These are MSP/provider-plane
-- settings — quota configuration, fairness bounds, data-governance/AI-egress
-- policy, and deployment branding — plus the MSP's own consumption metering.
-- The tenant reads its own row for the self-view; it never writes them. Every
-- legitimate write to these tables runs from the provider plane through the
-- probectl_provider role (internal/fairness, ee/billing, ee/governance), which
-- keeps full DML. The tenant must not be able to raise its own quota, widen its
-- own fairness bounds, relax its own governance/egress policy, or rewrite the
-- provider's billing input from a request-path (app-role) SQL path.
--
-- Why the grant exists at all: migration 0007 does
--   ALTER DEFAULT PRIVILEGES IN SCHEMA public
--     GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO probectl_app;
-- so every table created afterwards SILENTLY inherited write for probectl_app,
-- even though each of these tables' own migrations only `GRANT SELECT`. Narrow
-- them back to the intended least-privilege (SELECT) shape — exactly as 0075
-- and 0109 narrowed the audit tables after the same default-privilege spillover.
-- The matching boot self-check (internal/tenancy AssertPostureTx →
-- assertAppRoleWriteFence) fails closed if the write grant ever comes back.
--
-- NOT fenced here, on purpose — these carry a LEGITIMATE app-role tenant
-- self-service write, confined by each table's tenant_isolation RLS policy to
-- the tenant's OWN row, so they are genuinely tenant-writable and stay writable:
--   * tenant_retention — the tenant sets its own retention/erasure policy via
--     PUT /v1/lifecycle/retention (permission lifecycle.erase), a CORE
--     compliance right (CLAUDE.md §2); written under tenancy.InTenant in
--     internal/tenantlife (upsertRetentionPolicy).
--   * tenant_keys — the tenant rotates its own at-rest keys/BYOK via
--     POST /v1/security/keys/rotate (permission security.keys); the atomic
--     rotation RotateAtomic runs under tenancy.InTenant in ee/tenantkeys so the
--     key row and the tenant's RLS-confined rotation audit commit together.
--
-- Idempotent (REVOKE is a no-op when the privilege is already absent) and
-- expand-only — no column/table change (CLAUDE.md §6). SELECT is left intact for
-- each table's self-view. All five tables are created by earlier migrations
-- (0026/0027/0031/0033), so a bare REVOKE is safe here, matching 0075/0109.

REVOKE INSERT, UPDATE, DELETE ON public.tenant_branding   FROM probectl_app;
REVOKE INSERT, UPDATE, DELETE ON public.tenant_fairness    FROM probectl_app;
REVOKE INSERT, UPDATE, DELETE ON public.tenant_governance  FROM probectl_app;
REVOKE INSERT, UPDATE, DELETE ON public.tenant_quotas      FROM probectl_app;
REVOKE INSERT, UPDATE, DELETE ON public.usage_records      FROM probectl_app;
