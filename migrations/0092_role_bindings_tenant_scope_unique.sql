-- SPDX-License-Identifier: MPL-2.0
--
-- DPR-015: tenant-scope role bindings must be idempotent.
--
-- role_bindings carries UNIQUE (tenant_id, subject_type, subject_id, role_id,
-- scope_type, scope_id), but a tenant-scope binding has scope_id NULL and
-- PostgreSQL treats NULLs as distinct in a unique constraint, so the
-- ON CONFLICT ... DO NOTHING in RoleBindings.Bind never fired: every SCIM
-- group re-add or bootstrap-admin re-run inserted another identical row.
--
-- 1. Collapse existing duplicates per tenant (RLS is forced on this table, so
--    the sweep sets the tenant context for each tenant in turn; the oldest
--    row of each duplicate set survives).
-- 2. Add a partial unique index for the tenant-scope shape so the conflict
--    target exists. role_bindings is an operator-scale table (one row per
--    user-role), so the index build is not a live-ingestion lock.
-- probectl:no-tx: CREATE INDEX CONCURRENTLY is rejected inside a PostgreSQL transaction
DO $$
DECLARE
    t uuid;
BEGIN
    FOR t IN SELECT id FROM tenants LOOP
        PERFORM set_config('probectl.tenant_id', t::text, true);
        DELETE FROM role_bindings dup
         USING role_bindings keep
         WHERE dup.tenant_id = t
           AND keep.tenant_id = t
           AND dup.scope_type = 'tenant' AND dup.scope_id IS NULL
           AND keep.scope_type = 'tenant' AND keep.scope_id IS NULL
           AND dup.subject_type = keep.subject_type
           AND dup.subject_id = keep.subject_id
           AND dup.role_id = keep.role_id
           AND (keep.created_at, keep.id) < (dup.created_at, dup.id);
    END LOOP;
    PERFORM set_config('probectl.tenant_id', '', true);
END
$$;

CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS role_bindings_tenant_scope_uniq
    ON role_bindings (tenant_id, subject_type, subject_id, role_id)
    WHERE scope_type = 'tenant' AND scope_id IS NULL;
