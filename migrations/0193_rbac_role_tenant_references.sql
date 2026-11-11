-- SPDX-License-Identifier: BUSL-1.1
-- Use of this source code is governed by the Business Source License 1.1
-- in the LICENSE file at the root of this repository; on its Change Date
-- each version converts to the Mozilla Public License 2.0.

-- A child row's tenant RLS does not prove ownership of its role_id. Bind
-- both role grants and bindings to the same parent tenant at storage level.
-- Expand only: no grant or binding is deleted/reassigned. If historical
-- inconsistent references exist, validation refuses the upgrade unchanged;
-- an operator must resolve those records rather than silently lose access.
DO $rbac_tenant_roles$
DECLARE
    schema_name text;
    child_name text;
    constraint_name text;
BEGIN
    FOR schema_name IN
        SELECT 'public'::text
        UNION
        SELECT n.nspname::text FROM pg_namespace n
        JOIN public.tenants t ON n.nspname='t_' || replace(lower(t.id::text),'-','')
    LOOP
        IF to_regclass(format('%I.roles',schema_name)) IS NULL THEN CONTINUE; END IF;
        EXECUTE format('CREATE UNIQUE INDEX IF NOT EXISTS roles_tenant_identity_uidx ON %I.roles(tenant_id,id)',schema_name);
        FOREACH child_name IN ARRAY ARRAY['role_permissions','role_bindings']
        LOOP
            IF to_regclass(format('%I.%I',schema_name,child_name)) IS NULL THEN CONTINUE; END IF;
            constraint_name := child_name || '_tenant_role_fk';
            IF NOT EXISTS (SELECT 1 FROM pg_constraint
                WHERE conrelid=to_regclass(format('%I.%I',schema_name,child_name))
                  AND conname=constraint_name) THEN
                EXECUTE format('ALTER TABLE %I.%I ADD CONSTRAINT %I FOREIGN KEY(tenant_id,role_id) REFERENCES %I.roles(tenant_id,id) ON DELETE CASCADE NOT VALID',
                    schema_name,child_name,constraint_name,schema_name);
            END IF;
            EXECUTE format('ALTER TABLE %I.%I VALIDATE CONSTRAINT %I',schema_name,child_name,constraint_name);
        END LOOP;
    END LOOP;
END
$rbac_tenant_roles$;
