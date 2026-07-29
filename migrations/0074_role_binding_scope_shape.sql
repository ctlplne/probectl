-- 0074_role_binding_scope_shape.sql
-- Scoped RBAC is fail-closed only when tenant bindings have no resource id and
-- resource bindings always name one. Add the invariant online: NOT VALID checks
-- new writes immediately without scanning/locking the existing table. A later
-- release may validate it after operators have checked historical rows.

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
          FROM pg_constraint
         WHERE conname = 'role_bindings_scope_shape'
           AND conrelid = 'role_bindings'::regclass
    ) THEN
        ALTER TABLE role_bindings
            ADD CONSTRAINT role_bindings_scope_shape
            CHECK (
                (scope_type = 'tenant' AND scope_id IS NULL)
                OR (scope_type <> 'tenant' AND scope_id IS NOT NULL)
            ) NOT VALID;
    END IF;
END $$;
