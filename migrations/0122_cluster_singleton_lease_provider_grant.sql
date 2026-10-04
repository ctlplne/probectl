-- 0122_cluster_singleton_lease_provider_grant.sql — PLAT-19: singleton-task
-- writes verify the lease epoch inside their own transaction (pglease.Guard),
-- via the tenancy TxGuard hook. Some singleton tasks (audit retention/WORM,
-- tenant retention) write under the provider role through InProvider /
-- InTenantProviderMaintenance, so probectl_provider must be able to take the
-- FOR SHARE row-lock the epoch guard uses on the lease row. PostgreSQL requires
-- UPDATE privilege for any row-locking SELECT (SELECT alone is not enough), so
-- grant SELECT + UPDATE — exactly what probectl_app already holds (migration
-- 0054). cluster_singleton_leases is cluster-global coordination state with no
-- tenant_id (no RLS/policy involved); provider is already a trusted maintenance
-- role, so this is a bounded grant on a non-tenant table.
--
-- Idempotent + expand-only (CLAUDE.md §6).

GRANT SELECT, UPDATE ON cluster_singleton_leases TO probectl_provider;
